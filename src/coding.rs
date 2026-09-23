//! 系统化 Vandermonde Reed-Solomon（GF(256)）。
//!
//! n = k + m 个 shard，点 x_i = alpha^i，系数矩阵 V[i][j] = x_i^j。
//! 任意 k 个 shard 可重建全部 n 个 shard；恰好 k 个即达到恢复下限。

use crate::gf256::Gf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodingParams {
    pub k: usize,
    pub m: usize,
}

impl CodingParams {
    pub fn n(&self) -> usize {
        self.k + self.m
    }
    pub fn valid(&self) -> bool {
        self.k >= 1 && self.m >= 1 && self.n() <= 256
    }
}

pub fn vandermonde(gf: &Gf, rows: &[usize], k: usize) -> Vec<Vec<u8>> {
    rows.iter()
        .map(|&i| {
            let x = gf.pow(i);
            let mut row = Vec::with_capacity(k);
            let mut acc = 1u8;
            for _ in 0..k {
                row.push(acc);
                acc = gf.mul(acc, x);
            }
            row
        })
        .collect()
}

/// 方阵求逆，奇异则 None。
pub fn invert(gf: &Gf, a: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    let k = a.len();
    if a.iter().any(|r| r.len() != k) || k == 0 {
        return None;
    }
    let mut m: Vec<Vec<u8>> = a.to_vec();
    let mut inv = vec![vec![0u8; k]; k];
    for (i, row) in inv.iter_mut().enumerate() {
        row[i] = 1;
    }
    for col in 0..k {
        let pivot = (col..k).find(|&r| m[r][col] != 0)?;
        m.swap(col, pivot);
        inv.swap(col, pivot);
        let pinv = gf.inv(m[col][col]);
        for j in 0..k {
            m[col][j] = gf.mul(m[col][j], pinv);
            inv[col][j] = gf.mul(inv[col][j], pinv);
        }
        for r in 0..k {
            if r == col {
                continue;
            }
            let factor = m[r][col];
            if factor == 0 {
                continue;
            }
            for j in 0..k {
                m[r][j] ^= gf.mul(factor, m[col][j]);
                inv[r][j] ^= gf.mul(factor, inv[col][j]);
            }
        }
    }
    Some(inv)
}

fn mat_vec(gf: &Gf, m: &[Vec<u8>], v: &[u8]) -> Vec<u8> {
    m.iter()
        .map(|row| {
            row.iter()
                .zip(v)
                .fold(0u8, |acc, (&a, &b)| acc ^ gf.mul(a, b))
        })
        .collect()
}

/// 由 k 个 data shard 生成 m 个 parity shard；shard 长度不同时右侧补零对齐。
pub fn encode(gf: &Gf, params: CodingParams, data: &[Vec<u8>]) -> Vec<Vec<u8>> {
    assert_eq!(data.len(), params.k);
    let shard_len = data.iter().map(|d| d.len()).max().unwrap_or(0);
    let vd = invert(gf, &vandermonde(gf, &(0..params.k).collect::<Vec<_>>(), params.k))
        .expect("data vandermonde must be invertible");
    let vp = vandermonde(
        gf,
        &(params.k..params.n()).collect::<Vec<_>>(),
        params.k,
    );
    // P = Vp * Vd^-1
    let pmat: Vec<Vec<u8>> = vp
        .iter()
        .map(|row| {
            (0..params.k)
                .map(|c| {
                    row.iter()
                        .enumerate()
                        .fold(0u8, |acc, (j, &e)| acc ^ gf.mul(e, vd[j][c]))
                })
                .collect()
        })
        .collect();
    let mut parity = vec![vec![0u8; shard_len]; params.m];
    for off in 0..shard_len {
        let col: Vec<u8> = data
            .iter()
            .map(|d| d.get(off).copied().unwrap_or(0))
            .collect();
        let out = mat_vec(gf, &pmat, &col);
        for (i, val) in out.into_iter().enumerate() {
            parity[i][off] = val;
        }
    }
    parity
}

#[derive(Debug, Clone)]
pub struct Available {
    pub index: usize,
    pub bytes: Vec<u8>,
}

/// 用恰好 k 个可用 shard 重建全部 n 个 shard。
pub fn recover(
    gf: &Gf,
    params: CodingParams,
    shard_len: usize,
    available: &[Available],
) -> Result<Vec<Vec<u8>>, String> {
    if available.len() != params.k {
        return Err(format!(
            "需要恰好 {} 个参与 shard，实际 {}",
            params.k,
            available.len()
        ));
    }
    let indices: Vec<usize> = available.iter().map(|a| a.index).collect();
    if indices.iter().any(|&i| i >= params.n()) {
        return Err("shard 编号超出 n".to_string());
    }
    if indices.iter().collect::<std::collections::HashSet<_>>().len() != params.k {
        return Err("参与 shard 编号重复".to_string());
    }
    if available.iter().any(|a| a.bytes.len() != shard_len) {
        return Err("shard 长度不一致".to_string());
    }
    let sub = vandermonde(gf, &indices, params.k);
    let sub_inv = invert(gf, &sub).ok_or("可用 shard 矩阵奇异")?;
    let full = vandermonde(gf, &(0..params.n()).collect::<Vec<_>>(), params.k);
    // 重建矩阵 R = V * sub^-1：输入是可用点上的值，输出全部点的值。
    let rmat: Vec<Vec<u8>> = full
        .iter()
        .map(|row| {
            (0..params.k)
                .map(|c| {
                    row.iter()
                        .enumerate()
                        .fold(0u8, |acc, (j, &e)| acc ^ gf.mul(e, sub_inv[j][c]))
                })
                .collect()
        })
        .collect();
    let mut out = vec![vec![0u8; shard_len]; params.n()];
    for off in 0..shard_len {
        let col: Vec<u8> = available.iter().map(|a| a.bytes[off]).collect();
        let vals = mat_vec(gf, &rmat, &col);
        for (i, val) in vals.into_iter().enumerate() {
            out[i][off] = val;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_any_k() {
        let gf = Gf::new();
        let params = CodingParams { k: 3, m: 2 };
        let data = vec![vec![1u8, 2, 3, 4], vec![5, 6, 7, 8], vec![9, 10, 11, 12]];
        let parity = encode(&gf, params, &data);
        let mut all = data.clone();
        all.extend(parity.clone());
        // 任意 k 个 shard（含 parity）都能重建
        for missing in 0..params.n() {
            let avail: Vec<_> = (0..params.n())
                .filter(|&i| i != missing)
                .take(params.k)
                .map(|i| Available {
                    index: i,
                    bytes: all[i].clone(),
                })
                .collect();
            let rec = recover(&gf, params, 4, &avail).unwrap();
            for i in 0..params.n() {
                assert_eq!(rec[i], all[i], "missing={missing} shard={i}");
            }
        }
    }
}
