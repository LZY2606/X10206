//! 版本化 Reed-Solomon 系统码：k 个数据块 + m 个校验块，GF(2^8)。
use crate::field;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct EcParams {
    pub k: usize,
    pub m: usize,
    pub version: u32,
}

pub const SUPPORTED_VERSION: u32 = 1;

fn row(idx: usize, k: usize) -> Vec<u8> {
    if idx < k {
        let mut r = vec![0u8; k];
        r[idx] = 1;
        r
    } else {
        let x = idx as u8;
        let mut r = Vec::with_capacity(k);
        let mut p = 1u8;
        for _ in 0..k {
            r.push(p);
            p = field::mul(p, x);
        }
        r
    }
}

/// 由 k 个数据块计算全部 k+m 个块（前 k 个为原数据）。
pub fn encode(params: &EcParams, data: &[Vec<u8>]) -> Vec<Vec<u8>> {
    assert_eq!(params.version, SUPPORTED_VERSION, "不支持的编码版本");
    let k = params.k;
    let n = k + params.m;
    assert_eq!(data.len(), k);
    let len = data[0].len();
    let mut out = vec![vec![0u8; len]; n];
    for (i, d) in data.iter().enumerate() {
        assert_eq!(d.len(), len);
        out[i].copy_from_slice(d);
    }
    for idx in k..n {
        let r = row(idx, k);
        for (j, coef) in r.iter().enumerate() {
            if *coef == 0 {
                continue;
            }
            for (o, &v) in out[idx].iter_mut().zip(data[j].iter()) {
                *o ^= field::mul(*coef, v);
            }
        }
    }
    out
}

fn invert(mat: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    let n = mat.len();
    let mut a: Vec<Vec<u8>> = mat.to_vec();
    let mut inv: Vec<Vec<u8>> = (0..n)
        .map(|i| {
            let mut r = vec![0u8; n];
            r[i] = 1;
            r
        })
        .collect();
    for col in 0..n {
        let pivot = (col..n).find(|&r| a[r][col] != 0)?;
        a.swap(col, pivot);
        inv.swap(col, pivot);
        let d = field::inv(a[col][col]);
        for c in 0..n {
            a[col][c] = field::mul(a[col][c], d);
            inv[col][c] = field::mul(inv[col][c], d);
        }
        for r in 0..n {
            if r == col {
                continue;
            }
            let f = a[r][col];
            if f == 0 {
                continue;
            }
            for c in 0..n {
                a[r][c] ^= field::mul(f, a[col][c]);
                inv[r][c] ^= field::mul(f, inv[col][c]);
            }
        }
    }
    Some(inv)
}

/// 用任意 k 个 (编号, 内容) 重建全部 k+m 个块；失败返回 None。
pub fn decode(params: &EcParams, shards: &[(usize, Vec<u8>)]) -> Option<Vec<Vec<u8>>> {
    let k = params.k;
    if shards.len() < k {
        return None;
    }
    let chosen = &shards[..k];
    let mat: Vec<Vec<u8>> = chosen.iter().map(|(idx, _)| row(*idx, k)).collect();
    let inv = invert(&mat)?;
    let len = chosen[0].1.len();
    if chosen.iter().any(|(_, b)| b.len() != len) {
        return None;
    }
    let mut data = vec![vec![0u8; len]; k];
    for (di, rowv) in inv.iter().enumerate() {
        for (j, coef) in rowv.iter().enumerate() {
            if *coef == 0 {
                continue;
            }
            for (o, &v) in data[di].iter_mut().zip(chosen[j].1.iter()) {
                *o ^= field::mul(*coef, v);
            }
        }
    }
    Some(encode(params, &data))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> EcParams {
        EcParams { k: 3, m: 2, version: 1 }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let p = params();
        let data: Vec<Vec<u8>> = (0..3)
            .map(|i| (0..16).map(|j| (i * 31 + j * 7 + 1) as u8).collect())
            .collect();
        let full = encode(&p, &data);
        assert_eq!(full.len(), 5);
        // 丢掉 idx 1 和 idx 4，用 0,2,3 重建
        let avail: Vec<(usize, Vec<u8>)> = [0usize, 2, 3]
            .iter()
            .map(|&i| (i, full[i].clone()))
            .collect();
        let rebuilt = decode(&p, &avail).unwrap();
        assert_eq!(rebuilt, full);
    }
}
