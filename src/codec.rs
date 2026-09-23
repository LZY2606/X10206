//! 版本化里德-所罗门纠删码：系统 Cauchy 矩阵 + GF(256)。
//!
//! `k` 个数据 shard、`m` 个校验 shard；生成矩阵 G 为 (k+m) × k，
//! 前 k 行为单位阵，后 m 行为 Cauchy 行。Cauchy 矩阵任意 k 行均可逆，
//! 因此任意 k 个 shard（含数据/校验混合）都能重建全部 shard。
//!
//! `codec_version` 切换 Cauchy 轴的构造方式：相同数据在不同版本下
//! 会得到不同校验字节，版本错配会在校验环节暴露。

use crate::gf;
use serde::{Deserialize, Serialize};

/// 版本化编码参数。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodingParams {
    pub k: usize,
    pub m: usize,
    pub codec_version: u32,
}

impl CodingParams {
    pub fn new(k: usize, m: usize, codec_version: u32) -> Self {
        assert!(k >= 1, "k must be >= 1");
        assert!(m >= 1, "m must be >= 1");
        assert!(k + m <= 256, "k+m must fit in GF(256)");
        Self { k, m, codec_version }
    }

    pub fn n(&self) -> usize {
        self.k + self.m
    }

    /// 完整 (k+m) × k 系统生成矩阵。
    pub fn generator(&self) -> Vec<Vec<u8>> {
        let n = self.n();
        let mut g = vec![vec![0u8; self.k]; n];
        for (i, row) in g.iter_mut().enumerate().take(self.k) {
            row[i] = 1;
        }
        for p in 0..self.m {
            let x = self.cauchy_x(p);
            for j in 0..self.k {
                let y = self.cauchy_y(j);
                g[self.k + p][j] = gf::inv(x ^ y);
            }
        }
        g
    }

    fn cauchy_y(&self, j: usize) -> u8 {
        match self.codec_version {
            0 => (2 * j) as u8,
            1 => (1 + 2 * j) as u8,
            other => panic!("unsupported codec version: {other}"),
        }
    }

    fn cauchy_x(&self, p: usize) -> u8 {
        match self.codec_version {
            0 => (255u8.wrapping_sub(2 * p as u8)),
            1 => (2 * p) as u8,
            other => panic!("unsupported codec version: {other}"),
        }
    }
}

/// GF(256) 上高斯-若尔当求逆，奇异时返回 None。
pub fn invert(matrix: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    let k = matrix.len();
    let mut a = matrix.to_vec();
    let mut inv = vec![vec![0u8; k]; k];
    for (i, row) in inv.iter_mut().enumerate() {
        row[i] = 1;
    }
    for col in 0..k {
        let pivot = (col..k).find(|&r| a[r][col] != 0)?;
        a.swap(pivot, col);
        inv.swap(pivot, col);
        let scale = gf::inv(a[col][col]);
        for j in 0..k {
            a[col][j] = gf::mul(a[col][j], scale);
            inv[col][j] = gf::mul(inv[col][j], scale);
        }
        for r in 0..k {
            if r == col || a[r][col] == 0 {
                continue;
            }
            let factor = a[r][col];
            for j in 0..k {
                a[r][j] ^= gf::mul(factor, a[col][j]);
                inv[r][j] ^= gf::mul(factor, inv[col][j]);
            }
        }
    }
    Some(inv)
}

/// 由 k 个数据 shard 编码全部 k+m 个 shard。
pub fn encode(params: &CodingParams, data: &[Vec<u8>]) -> Vec<Vec<u8>> {
    assert_eq!(data.len(), params.k);
    let len = data[0].len();
    assert!(data.iter().all(|d| d.len() == len), "shard lengths differ");
    let g = params.generator();
    let mut out = vec![vec![0u8; len]; params.n()];
    for (i, row) in g.iter().enumerate() {
        for (j, dj) in data.iter().enumerate() {
            gf::addmul(&mut out[i], row[j], dj);
        }
    }
    out
}

/// 用恰好 k 个收到的 shard 重建全部 shard。
///
/// `slots` 与 `shards` 等长且长度为 k：slots[i] 是 shard 编号。
pub fn reconstruct(
    params: &CodingParams,
    slots: &[usize],
    shards: &[Vec<u8>],
) -> Option<Vec<Vec<u8>>> {
    if slots.len() != params.k || shards.len() != params.k {
        return None;
    }
    let len = shards.first()?.len();
    if shards.iter().any(|s| s.len() != len) {
        return None;
    }
    let g = params.generator();
    let sub: Vec<Vec<u8>> = slots.iter().map(|&s| g[s].clone()).collect();
    let a_inv = invert(&sub)?;
    // data[j] = sum_r A_inv[j][r] * received[r]
    let mut data = vec![vec![0u8; len]; params.k];
    for j in 0..params.k {
        for r in 0..params.k {
            gf::addmul(&mut data[j], a_inv[j][r], &shards[r]);
        }
    }
    Some(encode(params, &data))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_data(k: usize, len: usize) -> Vec<Vec<u8>> {
        (0..k)
            .map(|i| (0..len).map(|b| ((i * 31 + b * 7) % 256) as u8).collect())
            .collect()
    }

    #[test]
    fn encode_systematic_prefix() {
        let p = CodingParams::new(3, 2, 0);
        let data = sample_data(3, 8);
        let coded = encode(&p, &data);
        assert_eq!(&coded[..3], data);
    }

    #[test]
    fn reconstruct_from_any_k_slots() {
        for version in 0..=1u32 {
            let p = CodingParams::new(3, 2, version);
            let data = sample_data(3, 16);
            let coded = encode(&p, &data);
            // 全部 C(5,3) 种取法都应恢复成功。
            for a in 0..5 {
                for b in (a + 1)..5 {
                    for c in (b + 1)..5 {
                        let slots = [a, b, c];
                        let shards: Vec<Vec<u8>> = slots.iter().map(|&s| coded[s].clone()).collect();
                        let recovered = reconstruct(&p, &slots, &shards).unwrap();
                        assert_eq!(recovered, coded, "version {version}, slots {slots:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn parity_diffs_across_versions() {
        let data = sample_data(2, 4);
        let v0 = encode(&CodingParams::new(2, 2, 0), &data);
        let v1 = encode(&CodingParams::new(2, 2, 1), &data);
        assert_ne!(v0[2], v1[2]);
    }
}
