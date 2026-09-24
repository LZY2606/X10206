//! Systematic Reed-Solomon over GF(256).
//!
//! The coding matrix is derived from a Cauchy matrix (`1 / (x XOR y)`) so that
//! every square subset of rows is invertible, then row-reduced so the first
//! `k` rows form the identity (systematic data shards). Any `k` of the `n`
//! shards therefore suffice to reconstruct every missing shard.

use crate::gf;

/// Invert a square GF(256) matrix via Gauss-Jordan elimination.
/// Returns `None` if the matrix is singular.
pub fn invert(matrix: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    let k = matrix.len();
    let mut a = vec![vec![0u8; 2 * k]; k];
    for (i, row) in enumerate(matrix) {
        a[i][..k].copy_from_slice(row);
        a[i][k + i] = 1;
    }
    for col in 0..k {
        let pivot = (col..k).find(|&r| a[r][col] != 0)?;
        if pivot != col {
            a.swap(pivot, col);
        }
        let p = a[col][col];
        if p != 1 {
            let pinv = gf::inv(p);
            for c in col..2 * k {
                a[col][c] = gf::mul(a[col][c], pinv);
            }
        }
        for r in 0..k {
            if r != col && a[r][col] != 0 {
                let factor = a[r][col];
                for c in col..2 * k {
                    a[r][c] ^= gf::mul(factor, a[col][c]);
                }
            }
        }
    }
    Some(a.into_iter().map(|row| row[k..].to_vec()).collect())
}

fn enumerate<T>(v: &[T]) -> impl Iterator<Item = (usize, &T)> {
    v.iter().enumerate()
}

/// Build the systematic `n x k` coding matrix for `k` data and `m` parity
/// shards (`n = k + m`).
pub fn coding_matrix(k: usize, m: usize) -> Vec<Vec<u8>> {
    let n = k + m;
    assert!(k >= 1 && m >= 0 && n + k <= 256, "invalid (k={k}, m={m})");
    // Cauchy matrix with disjoint X = {0..n-1}, Y = {255, 254, ...}.
    let mut cauchy = vec![vec![0u8; k]; n];
    for i in 0..n {
        for j in 0..k {
            let x = i as u8;
            let y = (255u8.wrapping_sub(j as u8));
            cauchy[i][j] = gf::inv(x ^ y);
        }
    }
    if m == 0 {
        return cauchy;
    }
    let top: Vec<Vec<u8>> = cauchy[..k].to_vec();
    let top_inv = invert(&top).expect("Cauchy subset must be invertible");
    let mut out = vec![vec![0u8; k]; n];
    for i in 0..n {
        for r in 0..k {
            let mut acc = 0u8;
            for j in 0..k {
                acc ^= gf::mul(cauchy[i][j], top_inv[j][r]);
            }
            out[i][r] = acc;
        }
    }
    out
}

/// Encode `k` data shards into all `n = k + m` shards (data shards included).
/// Every shard must share one length.
pub fn encode(data: &[Vec<u8>], k: usize, m: usize) -> Vec<Vec<u8>> {
    assert_eq!(data.len(), k);
    let len = data.first().map(|d| d.len()).unwrap_or(0);
    assert!(data.iter().all(|d| d.len() == len), "unequal shard lengths");
    let matrix = coding_matrix(k, m);
    let n = k + m;
    let mut out = vec![vec![0u8; len]; n];
    for (row_idx, row) in matrix.iter().enumerate() {
        for byte in 0..len {
            let mut acc = 0u8;
            for (j, coeff) in row.iter().enumerate() {
                acc ^= gf::mul(*coeff, data[j][byte]);
            }
            out[row_idx][byte] = acc;
        }
    }
    out
}

/// Reconstruct every shard from any `k` available `(position, bytes)` shards.
/// Positions index into the full `n = k + m` layout.
pub fn decode(
    available: &[(usize, Vec<u8>)],
    k: usize,
    m: usize,
) -> Option<Vec<Vec<u8>>> {
    let n = k + m;
    if available.len() != k {
        return None;
    }
    let mut positions: Vec<usize> = available.iter().map(|(p, _)| *p).collect();
    if positions.iter().any(|&p| p >= n) {
        return None;
    }
    positions.sort_unstable();
    positions.dedup();
    if positions.len() != k {
        return None;
    }
    let len = available[0].1.len();
    if available.iter().any(|(_, b)| b.len() != len) {
        return None;
    }
    let full = coding_matrix(k, m);
    let sub: Vec<Vec<u8>> = positions.iter().map(|&p| full[p].clone()).collect();
    let inv = invert(&sub)?;
    // Recover data shards D = inv * V.
    let mut data = vec![vec![0u8; len]; k];
    for r in 0..k {
        for byte in 0..len {
            let mut acc = 0u8;
            for (c, (_, shard)) in available.iter().enumerate() {
                acc ^= gf::mul(inv[r][c], shard[byte]);
            }
            data[r][byte] = acc;
        }
    }
    Some(encode(&data, k, m))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_singletons() {
        let (k, m) = (3, 2);
        let data = vec![vec![1u8, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];
        let all = encode(&data, k, m);
        for missing in 0..(k + m) {
            let avail: Vec<(usize, Vec<u8>)> = all
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != missing)
                .take(k)
                .map(|(i, b)| (i, b.clone()))
                .collect();
            let rebuilt = decode(&avail, k, m).unwrap();
            assert_eq!(rebuilt, all);
        }
    }

    #[test]
    fn any_k_subset_decodes() {
        let (k, m) = (2, 2);
        let data = vec![vec![10, 20], vec![30, 40]];
        let all = encode(&data, k, m);
        for combo in 0..(1usize << (k + m)) {
            if combo.count_ones() != k as u32 {
                continue;
            }
            let avail: Vec<(usize, Vec<u8>)> = (0..k + m)
                .filter(|i| combo & (1 << i) != 0)
                .map(|i| (i, all[i].clone()))
                .collect();
            assert_eq!(decode(&avail, k, m).unwrap(), all);
        }
    }
}
