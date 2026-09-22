//! 版本化擦除码参数与编解码。当前仅支持 version=1：
//! k 个数据块 + m 个校验块，使用 GF(2^8) 上的 Cauchy 编码矩阵，
//! 任意 k 个不同编号的块即可线性重建。

use crate::gf256::{div, invert, mul};
use serde::{Deserialize, Serialize};

pub const CODEC_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodingParams {
    pub version: u32,
    pub k: u32,
    pub m: u32,
}

impl CodingParams {
    pub fn new(k: u32, m: u32) -> Self {
        Self { version: CODEC_VERSION, k, m }
    }
    pub fn n(&self) -> usize {
        (self.k + self.m) as usize
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.version != CODEC_VERSION {
            return Err(format!(
                "不支持的编码版本 {}（仅支持 {}）",
                self.version, CODEC_VERSION
            ));
        }
        if self.k == 0 || self.m == 0 {
            return Err("k 与 m 必须为正数".to_string());
        }
        if (self.k + self.m) as usize > 256 {
            return Err("k+m 不能超过 256（GF(2^8) 块编号上限）".to_string());
        }
        Ok(())
    }
}

/// n×k Cauchy 编码矩阵，行 i（0..k）为数据单位行，行 i（k..n）为校验行。
/// 校验行使用 C[r][c] = 1 / (X[r] xor Y[c])，保证任意 k 行的方阵可逆。
pub fn coding_matrix(p: CodingParams) -> Vec<u8> {
    let n = p.n();
    let k = p.k as usize;
    let m = p.m as usize;
    let mut mat = vec![0u8; n * k];
    for i in 0..k {
        mat[i * k + i] = 1;
    }
    // Y = 0..k；X 取最小的 m 个不在 Y 中的域元素（确定性且无重复）。
    let ys: Vec<u8> = (0..k).map(|c| c as u8).collect();
    let mut xvals = Vec::with_capacity(m);
    let mut cand = 0u8;
    while xvals.len() < m {
        if !ys.contains(&cand) {
            xvals.push(cand);
        }
        cand = cand.wrapping_add(1);
    }
    for (r, &xv) in xvals.iter().enumerate() {
        for c in 0..k {
            let denom = xv ^ ys[c];
            mat[(k + r) * k + c] = div(1, denom).expect("Cauchy 分母非零");
        }
    }
    mat
}

/// 校验整 stripe：返回所有 n 个块。数据块不足时右侧补零到 shard_len。
pub fn encode(p: CodingParams, data_shards: &[Vec<u8>], shard_len: usize) -> Vec<Vec<u8>> {
    let k = p.k as usize;
    assert_eq!(data_shards.len(), k);
    let mat = coding_matrix(p);
    let mut out = Vec::with_capacity(p.n());
    for i in 0..k {
        let mut s = data_shards[i].clone();
        s.resize(shard_len, 0);
        out.push(s);
    }
    for i in k..p.n() {
        let mut parity = vec![0u8; shard_len];
        for c in 0..k {
            let coef = mat[i * k + c];
            for (t, &b) in out[c].iter().enumerate() {
                parity[t] ^= mul(coef, b);
            }
        }
        out.push(parity);
    }
    out
}

#[derive(Debug, Clone)]
pub struct PresentShard {
    pub index: usize,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RebuildResult {
    /// 参与线性求解的块编号。
    pub participants: Vec<usize>,
    /// 重建出的全部 n 个块（含在场块的核对拷贝）。
    pub shards: Vec<Vec<u8>>,
}

/// 用在场的 >=k 个块重建整个 stripe；在场块长度不一致或矩阵奇异时报错。
pub fn rebuild(p: CodingParams, present: &[PresentShard]) -> Result<RebuildResult, String> {
    let k = p.k as usize;
    let n = p.n();
    if present.len() < k {
        return Err(format!("可用块 {} 低于恢复下限 k={}", present.len(), k));
    }
    let mut idxs: Vec<usize> = present.iter().map(|s| s.index).collect();
    if idxs.iter().any(|&i| i >= n) {
        return Err("存在超出 k+m-1 的块编号".to_string());
    }
    idxs.sort_unstable();
    idxs.dedup();
    if idxs.len() != present.len() {
        return Err("同一次求解内块编号重复".to_string());
    }
    let shard_len = present[0].bytes.len();
    if shard_len == 0 {
        return Err("块长度为 0".to_string());
    }
    if present.iter().any(|s| s.bytes.len() != shard_len) {
        return Err("在场块长度不一致".to_string());
    }

    let mat = coding_matrix(p);
    let mut a = vec![0u8; k * k];
    for r in 0..k {
        for c in 0..k {
            a[r * k + c] = mat[idxs[r] * k + c];
        }
    }
    let inv = invert(&a, k).ok_or_else(|| "编码子矩阵奇异，无法求解".to_string())?;

    // data = inv * present
    let mut data = vec![vec![0u8; shard_len]; k];
    for r in 0..k {
        for t in 0..shard_len {
            let mut acc = 0u8;
            for c in 0..k {
                acc ^= mul(inv[r * k + c], present[c].bytes[t]);
            }
            data[r][t] = acc;
        }
    }
    let all = encode(p, &data, shard_len);

    // 核对未参与求解的多余在场块（>k 时）
    let participants = idxs[..k].to_vec();
    for extra in &idxs[k..] {
        let got = present
            .iter()
            .find(|s| s.index == *extra)
            .unwrap();
        if got.bytes != all[*extra] {
            return Err(format!("在场块 {} 与编码约束矛盾", extra));
        }
    }
    Ok(RebuildResult { participants, shards: all })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rebuild_any_k_shards() {
        let p = CodingParams::new(3, 2);
        let data = vec![vec![1, 9], vec![2, 8], vec![3, 7]];
        let all = encode(p, &data, 2);
        // 任意 3 个编号都应恢复出相同结果
        for missing in 0..5 {
            let present: Vec<PresentShard> = (0..5)
                .filter(|&i| i != missing)
                .map(|i| PresentShard { index: i, bytes: all[i].clone() })
                .collect();
            let r = rebuild(p, &present).unwrap();
            assert_eq!(r.shards, all);
        }
    }

    #[test]
    fn too_few_shards_and_bad_shard() {
        let p = CodingParams::new(3, 2);
        let data = vec![vec![1], vec![2], vec![3]];
        let mut all = encode(p, &data, 1);
        assert!(rebuild(p, &[PresentShard { index: 0, bytes: all[0].clone() }]).is_err());
        all[4][0] ^= 0xFF;
        let present = vec![0, 1, 3, 4]
            .into_iter()
            .map(|i| PresentShard { index: i, bytes: all[i].clone() })
            .collect();
        assert!(rebuild(p, &present).is_err());
    }
}
