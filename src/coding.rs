//! Versioned erasure coding.
//!
//! v1: Cauchy Reed-Solomon over GF(2^8).
//! Encoding matrix (n = data_shards + parity_shards rows, data_shards columns):
//!   rows 0..k  -> identity (systematic data shards)
//!   rows k..n  -> Cauchy matrix C[i][j] = 1/(x_i XOR y_j)
//!                 x_i = i + 1, y_j = j
//! Any k distinct rows are invertible while n <= 256 and the X/Y sets stay
//! disjoint (x_i in 1..=n-k, y_j in 0..k-1; disjoint when k-1 < 1, i.e.
//! guaranteed by construction below using y_j = j and x_i = k + i).
//!
//! We use x_i = (k + i) and y_j = j: X = {k, ..., n-1}, Y = {0, ..., k-1},
//! always disjoint, all entries nonzero since xor != 0.

use crate::gf;

pub const CODEC_V1: &str = "cauchy-rs-gf256-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CodingParams {
    pub data_shards: usize,
    pub parity_shards: usize,
    pub shard_size: usize,
}

impl CodingParams {
    pub fn validate(&self) -> Result<(), String> {
        if self.data_shards == 0 || self.parity_shards == 0 {
            return Err("data_shards and parity_shards must be positive".into());
        }
        let n = self.data_shards + self.parity_shards;
        if n > 256 {
            return Err("data_shards + parity_shards must not exceed 256".into());
        }
        if self.shard_size == 0 {
            return Err("shard_size must be positive".into());
        }
        Ok(())
    }
}

/// One parity (Cauchy) row of length k.
///
/// Labels use disjoint ranges so every Cauchy entry is nonzero:
///   X (parity labels) = 0 .. m-1
///   Y (data labels)   = m .. m+k-1
/// Because x != y for every pair, `x XOR y` is never zero, and the Cauchy
/// matrix (and any square submatrix formed with identity rows) is MDS.
fn cauchy_row(i: usize, k: usize, m: usize) -> Vec<u8> {
    let x = i as u8;
    ((m as u8)..(m as u8 + k as u8))
        .map(|y| gf::inv(x ^ y))
        .collect()
}

pub fn encoding_matrix(k: usize, m: usize) -> Vec<Vec<u8>> {
    let mut rows = Vec::with_capacity(k + m);
    for i in 0..k {
        let mut row = vec![0u8; k];
        row[i] = 1;
        rows.push(row);
    }
    for i in 0..m {
        rows.push(cauchy_row(i, k, m));
    }
    rows
}

pub fn parity_for_row(data: &[Vec<u8>], row: &[u8], shard_size: usize) -> Vec<u8> {
    let mut out = vec![0u8; shard_size];
    for (j, coeff) in row.iter().enumerate() {
        if *coeff == 0 {
            continue;
        }
        for b in 0..shard_size {
            out[b] ^= gf::mul(*coeff, data[j][b]);
        }
    }
    out
}

/// Encode full stripe data (length k * shard_size) into n shards.
pub fn encode(stripe: &[u8], p: CodingParams) -> Result<Vec<Vec<u8>>, String> {
    p.validate()?;
    let k = p.data_shards;
    if stripe.len() != k * p.shard_size {
        return Err(format!(
            "stripe length {} != {} * {}",
            stripe.len(),
            k,
            p.shard_size
        ));
    }
    let mut data = Vec::with_capacity(k);
    for j in 0..k {
        data.push(stripe[j * p.shard_size..(j + 1) * p.shard_size].to_vec());
    }
    let matrix = encoding_matrix(k, p.parity_shards);
    let mut shards = Vec::with_capacity(k + p.parity_shards);
    for row in &matrix[..k] {
        shards.push(parity_for_row(&data, row, p.shard_size));
    }
    for row in &matrix[k..] {
        shards.push(parity_for_row(&data, row, p.shard_size));
    }
    Ok(shards)
}

/// Invert a square matrix over GF(256). Returns error if singular.
fn invert(mat: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
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
        let pivot = (col..n).find(|&r| a[r][col] != 0).ok_or("singular matrix")?;
        a.swap(col, pivot);
        inv.swap(col, pivot);
        let pivot_val = a[col][col];
        let pinv = gf::inv(pivot_val);
        for c in 0..n {
            a[col][c] = gf::mul(a[col][c], pinv);
            inv[col][c] = gf::mul(inv[col][c], pinv);
        }
        for r in 0..n {
            if r == col {
                continue;
            }
            let factor = a[r][col];
            if factor == 0 {
                continue;
            }
            for c in 0..n {
                a[r][c] ^= gf::mul(factor, a[col][c]);
                inv[r][c] ^= gf::mul(factor, inv[col][c]);
            }
        }
    }
    Ok(inv)
}

/// Reconstruct all n shards from exactly k available shards.
/// `available` maps shard index -> shard bytes (length shard_size).
pub fn reconstruct(
    available: &[(usize, Vec<u8>)],
    p: CodingParams,
) -> Result<Vec<Vec<u8>>, String> {
    p.validate()?;
    let k = p.data_shards;
    let n = k + p.parity_shards;
    if available.len() != k {
        return Err(format!("need exactly {} available shards, got {}", k, available.len()));
    }
    for (idx, bytes) in available {
        if *idx >= n {
            return Err(format!("shard index {} out of range 0..{}", idx, n - 1));
        }
        if bytes.len() != p.shard_size {
            return Err(format!("shard {} length {} != {}", idx, bytes.len(), p.shard_size));
        }
    }
    let matrix = encoding_matrix(k, p.parity_shards);
    let sub: Vec<Vec<u8>> = available.iter().map(|(idx, _)| matrix[*idx].clone()).collect();
    let sub_inv = invert(&sub)?;

    // data[j] = sum_r sub_inv[j][r] * available[r]
    let mut data: Vec<Vec<u8>> = (0..k).map(|_| vec![0u8; p.shard_size]).collect();
    for (r, (_, shard)) in available.iter().enumerate() {
        for j in 0..k {
            let coeff = sub_inv[j][r];
            if coeff == 0 {
                continue;
            }
            for b in 0..p.shard_size {
                data[j][b] ^= gf::mul(coeff, shard[b]);
            }
        }
    }

    let mut out = Vec::with_capacity(n);
    for row in &matrix[..k] {
        out.push(parity_for_row(&data, row, p.shard_size));
    }
    for row in &matrix[k..] {
        out.push(parity_for_row(&data, row, p.shard_size));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_data_only() {
        let p = CodingParams { data_shards: 3, parity_shards: 2, shard_size: 4 };
        let stripe = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let shards = encode(&stripe, p).unwrap();
        let rebuilt = reconstruct(&[(0, shards[0].clone()), (1, shards[1].clone()), (2, shards[2].clone())], p).unwrap();
        assert_eq!(rebuilt, shards);
    }

    #[test]
    fn recover_missing_parity_and_data() {
        let p = CodingParams { data_shards: 3, parity_shards: 3, shard_size: 5 };
        let stripe = (0u8..15).collect::<Vec<_>>();
        let shards = encode(&stripe, p).unwrap();
        // Keep shard 0 (data), 3 (parity), 5 (parity): missing data 1,2 and parity 4.
        let avail = vec![(0, shards[0].clone()), (3, shards[3].clone()), (5, shards[5].clone())];
        let rebuilt = reconstruct(&avail, p).unwrap();
        assert_eq!(rebuilt, shards);
    }

    #[test]
    fn boundary_exact_k() {
        let p = CodingParams { data_shards: 4, parity_shards: 2, shard_size: 7 };
        let stripe = (0u8..28).map(|b| b.wrapping_mul(31)).collect::<Vec<_>>();
        let shards = encode(&stripe, p).unwrap();
        let avail: Vec<_> = (0..4).map(|i| (i, shards[i].clone())).collect();
        let rebuilt = reconstruct(&avail, p).unwrap();
        assert_eq!(rebuilt, shards);
    }

    #[test]
    fn too_few_shards_fails() {
        let p = CodingParams { data_shards: 3, parity_shards: 2, shard_size: 4 };
        let avail = vec![(0, vec![0; 4]), (1, vec![0; 4])];
        assert!(reconstruct(&avail, p).is_err());
    }
}

