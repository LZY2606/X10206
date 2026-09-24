//! 版本化纠删码：`rs-v1`，GF(2^8) 上的系统式 Vandermonde Reed-Solomon。
//! 数据行号 0..k 为单位阵，校验行号 k..k+m 的求值点即为其编号 x，
//! 系数 coeff[j] = x^j。任意 k 行构成的方阵可逆（任取的求值点互异）。

use crate::gf256::{gauss_solve, mul};
use anyhow::{bail, ensure, Result};

pub const CODEC_RS_V1: &str = "rs-v1";

pub fn supported(codec: &str) -> bool {
    codec == CODEC_RS_V1
}

/// 校验行 index（>= k）对应的 Vandermonde 系数，长度 k。
pub fn parity_coeff(index: usize, k: usize) -> Vec<u8> {
    assert!(index >= k, "parity shard index must be >= k");
    let x = index as u8;
    let mut coeff = vec![0u8; k];
    let mut power = 1u8;
    for c in coeff.iter_mut() {
        *c = power;
        power = mul(power, x);
    }
    coeff
}

/// 由 k 个数据块计算全部 k+m 块（前 k 块原样返回）。
pub fn encode(k: usize, m: usize, shard_size: usize, data: &[Vec<u8>]) -> Vec<Vec<u8>> {
    assert_eq!(data.len(), k);
    let mut out: Vec<Vec<u8>> = data.to_vec();
    for p in 0..m {
        let coeff = parity_coeff(k + p, k);
        let mut block = vec![0u8; shard_size];
        for j in 0..k {
            for b in 0..shard_size {
                block[b] ^= mul(coeff[j], data[j][b]);
            }
        }
        out.push(block);
    }
    out
}

/// 编号 index 对应编码矩阵中的一行。
fn matrix_row(index: usize, k: usize) -> Vec<u8> {
    if index < k {
        let mut row = vec![0u8; k];
        row[index] = 1;
        row
    } else {
        parity_coeff(index, k)
    }
}

/// 给定至少 k 个互异编号的块，重建全部 k+m 块。
/// 输入按编号排序；调用方保证 present.len() == k 且长度一致。
pub fn decode(
    k: usize,
    m: usize,
    shard_size: usize,
    present: &[(usize, Vec<u8>)],
) -> Result<Vec<Vec<u8>>> {
    ensure!(present.len() >= k, "need at least k shards, got {}", present.len());
    let used: Vec<(usize, Vec<u8>)> = present.iter().take(k).cloned().collect();
    let mut matrix = Vec::with_capacity(k * k);
    for (idx, _) in &used {
        matrix.extend_from_slice(&matrix_row(*idx, k));
    }
    let mut rhs = Vec::with_capacity(k * shard_size);
    for (_, bytes) in &used {
        ensure!(bytes.len() == shard_size, "shard length mismatch in decoder");
        rhs.extend_from_slice(bytes);
    }
    gauss_solve(&mut matrix, &mut rhs, k, k, shard_size);

    let mut data: Vec<Vec<u8>> = (0..k)
        .map(|r| rhs[r * shard_size..(r + 1) * shard_size].to_vec())
        .collect();
    // 若提供的是数据行，直接采用输入字节，规避任何潜在抄写误差。
    for (idx, bytes) in &used {
        if *idx < k {
            data[*idx] = bytes.clone();
        }
    }
    let full = encode(k, m, shard_size, &data);
    for (idx, bytes) in &used {
        if full[*idx] != *bytes {
            bail!("decoded stripe does not reproduce provided shard {}", idx);
        }
    }
    Ok(full)
}

/// 校验一组完整 stripe 是否满足编码关系。
pub fn verify_full(k: usize, full: &[Vec<u8>]) -> bool {
    let m = full.len() - k;
    let expected = encode(k, m, full[0].len(), &full[..k]);
    expected == full
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(k: usize, shard_size: usize) -> Vec<Vec<u8>> {
        (0..k)
            .map(|j| (0..shard_size).map(|b| (j * 31 + b * 7) as u8).collect())
            .collect()
    }

    #[test]
    fn encode_decode_any_k_subset() {
        let (k, m, sh) = (3, 2, 5);
        let full = encode(k, m, sh, &sample(k, sh));
        assert!(verify_full(k, &full));
        for missing in 0..=m {
            let present: Vec<(usize, Vec<u8>)> = full
                .iter()
                .enumerate()
                .filter(|(i, _)| *i < k + m - missing || *i >= k + m)
                .collect::<Vec<_>>()
                .into_iter()
                .take(k)
                .map(|(i, b)| (i, b.clone()))
                .collect();
            let rebuilt = decode(k, m, sh, &present).unwrap();
            assert_eq!(rebuilt, full);
        }
    }

    #[test]
    fn boundary_only_parity_survives() {
        let (k, m, sh) = (2, 2, 4);
        let full = encode(k, m, sh, &sample(k, sh));
        let present = vec![(2, full[2].clone()), (3, full[3].clone())];
        let rebuilt = decode(k, m, sh, &present).unwrap();
        assert_eq!(rebuilt, full);
    }

    #[test]
    fn flipped_shard_detected_via_cross_check() {
        let (k, m, sh) = (2, 2, 4);
        let full = encode(k, m, sh, &sample(k, sh));
        let mut bad = full.clone();
        bad[0][0] ^= 0xff;
        let present = vec![(0, bad[0].clone()), (2, bad[2].clone())];
        assert!(decode(k, m, sh, &present).is_err());
    }
}
