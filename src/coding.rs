//! 版本化条带编码参数与 Reed-Solomon 风格重建（GF(256) Vandermonde）。

use crate::gf256;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

/// 当前编码参数版本号。参数演进时递增并保留旧版本解码能力。
pub const CODING_VERSION: u32 = 1;

/// 版本化编码参数。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodingParams {
    pub version: u32,
    /// 数据块数量 k。
    pub data_shards: u32,
    /// 校验块数量 m。
    pub parity_shards: u32,
    /// 每个条带每块的字节数。
    pub stripe_size: u32,
}

impl CodingParams {
    pub fn v1(data_shards: u32, parity_shards: u32, stripe_size: u32) -> Self {
        CodingParams {
            version: CODING_VERSION,
            data_shards,
            parity_shards,
            stripe_size,
        }
    }

    pub fn total_shards(&self) -> u32 {
        self.data_shards + self.parity_shards
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != CODING_VERSION {
            bail!("不支持的编码参数版本: {}", self.version);
        }
        if self.data_shards == 0 || self.data_shards > 128 {
            bail!("数据块数量越界: {}", self.data_shards);
        }
        if self.parity_shards == 0 || self.total_shards() > 255 {
            bail!("校验块数量越界: {}", self.parity_shards);
        }
        if self.stripe_size == 0 {
            bail!("条带块长度不能为 0");
        }
        Ok(())
    }
}

/// shard 编号 i 对应的 Vandermonde 行：alpha_i = i+1，行 = [alpha^0 .. alpha^(k-1)]。
fn vandermonde_row(shard_index: u32, k: u32) -> Vec<u8> {
    let alpha = gf256::exp((shard_index + 1) as u8);
    let mut row = Vec::with_capacity(k as usize);
    let mut power = 1u8;
    for _ in 0..k {
        row.push(power);
        power = gf256::mul(power, alpha);
    }
    row
}

/// 由 k 个数据块计算全部 m 个校验块。
pub fn encode_parity(params: &CodingParams, data: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
    params.validate()?;
    let k = params.data_shards as usize;
    let m = params.parity_shards as usize;
    let size = params.stripe_size as usize;
    if data.len() != k {
        bail!("数据块数量不符: 期望 {} 实得 {}", k, data.len());
    }
    for (i, block) in data.iter().enumerate() {
        if block.len() != size {
            bail!("数据块 {} 长度不符: 期望 {} 实得 {}", i, size, block.len());
        }
    }
    let mut parity = vec![vec![0u8; size]; m];
    for (p, out) in parity.iter_mut().enumerate() {
        let row = vandermonde_row((k + p) as u32, params.data_shards);
        for (i, block) in data.iter().enumerate() {
            let coef = row[i];
            if coef == 0 {
                continue;
            }
            for (byte_idx, &byte) in block.iter().enumerate() {
                out[byte_idx] = gf256::add(out[byte_idx], gf256::mul(coef, byte));
            }
        }
    }
    Ok(parity)
}

/// 用恰好 k 个块（任意编号）重建其余全部块。
/// `known`: (shard_index, bytes)，必须恰好 k 个且编号互不重复。
/// 返回全部 k+m 个块（已知位置保持原值，其余为重建结果）。
pub fn reconstruct(params: &CodingParams, known: &[(u32, Vec<u8>)]) -> Result<Vec<Vec<u8>>> {
    params.validate()?;
    let k = params.data_shards as usize;
    if known.len() != k {
        bail!("重建需要恰好 {} 个块，实得 {}", k, known.len());
    }
    let mut ordered: Vec<(u32, &Vec<u8>)> = known.iter().map(|(i, b)| (*i, b)).collect();
    ordered.sort_by_key(|(i, _)| *i);
    for w in ordered.windows(2) {
        if w[0].0 == w[1].0 {
            bail!("重建输入存在重复编号: {}", w[0].0);
        }
    }
    for (idx, bytes) in &ordered {
        if *idx >= params.total_shards() {
            bail!("shard 编号越界: {}", idx);
        }
        if bytes.len() != params.stripe_size as usize {
            bail!("shard {} 长度与条带参数不符", idx);
        }
    }
    let matrix: Vec<Vec<u8>> = ordered
        .iter()
        .map(|(i, _)| vandermonde_row(*i, params.data_shards))
        .collect();
    let rhs: Vec<Vec<u8>> = ordered.iter().map(|(_, b)| (*b).clone()).collect();
    let data = gf256::solve(&matrix, &rhs)
        .ok_or_else(|| anyhow::anyhow!("重建矩阵奇异（编号集合非法）"))?;
    let parity = encode_parity(params, &data)?;
    let mut all: Vec<Vec<u8>> = data;
    all.extend(parity);
    Ok(all)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> CodingParams {
        CodingParams::v1(3, 2, 8)
    }

    fn sample_data() -> Vec<Vec<u8>> {
        vec![
            vec![1, 2, 3, 4, 5, 6, 7, 8],
            vec![8, 7, 6, 5, 4, 3, 2, 1],
            vec![0, 255, 1, 254, 2, 253, 3, 252],
        ]
    }

    #[test]
    fn encode_reconstruct_roundtrip() {
        let p = params();
        let data = sample_data();
        let parity = encode_parity(&p, &data).unwrap();
        let mut all = data.clone();
        all.extend(parity.clone());
        for combo in [[0usize, 2, 4], [1, 3, 4], [0, 1, 2], [2, 3, 4]] {
            let known: Vec<(u32, Vec<u8>)> =
                combo.iter().map(|&i| (i as u32, all[i].clone())).collect();
            let rebuilt = reconstruct(&p, &known).unwrap();
            assert_eq!(rebuilt, all, "combo {:?}", combo);
        }
    }

    #[test]
    fn reject_wrong_count_and_dup() {
        let p = params();
        let data = sample_data();
        assert!(reconstruct(&p, &[(0, data[0].clone())]).is_err());
        assert!(reconstruct(
            &p,
            &[
                (0, data[0].clone()),
                (0, data[0].clone()),
                (1, data[1].clone())
            ]
        )
        .is_err());
    }
}
