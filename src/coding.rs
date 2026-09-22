//! Reed-Solomon style erasure coding over GF(2^8).
//!
//! Layout of the n x k generator matrix:
//!   rows 0..k      -> identity (the data shards)
//!   rows k..n      -> Cauchy rows `1 / ((i-k) XOR (n-k+j))`
//! Any k rows form an invertible matrix when n <= 256 and the X and Y
//! sets `{0..n-k}` and `{n-k..n}` are disjoint (guaranteed for n <= 256).

use crate::gf256::{cauchy_entry, mul, solve};

pub fn gen_row_coeff(row: usize, k: usize, n: usize) -> Vec<u8> {
    if row < k {
        let mut coeffs = vec![0u8; k];
        coeffs[row] = 1;
        coeffs
    } else {
        (0..k).map(|j| cauchy_entry(row - k, j, n, k)).collect()
    }
}

/// Encode k data shards into n shards (data first, then parity).
pub fn encode(data: &[Vec<u8>], n: usize, k: usize) -> Vec<Vec<u8>> {
    assert_eq!(data.len(), k, "expected k data shards");
    let len = data[0].len();
    assert!(data.iter().all(|d| d.len() == len), "data shards must share length");
    let mut shards: Vec<Vec<u8>> = data.to_vec();
    for row in k..n {
        let coeffs = gen_row_coeff(row, k, n);
        let mut out = vec![0u8; len];
        for byte_idx in 0..len {
            let mut acc = 0u8;
            for j in 0..k {
                acc ^= mul(coeffs[j], data[j][byte_idx]);
            }
            out[byte_idx] = acc;
        }
        shards.push(out);
    }
    shards
}

/// Reconstruct all n shards from any k available (row, bytes) pairs.
/// Returns the n uniform-length shards in row order.
pub fn reconstruct(available: &[(usize, Vec<u8>)], n: usize, k: usize) -> Option<Vec<Vec<u8>>> {
    if available.len() != k {
        return None;
    }
    let rows: Vec<usize> = available.iter().map(|(r, _)| *r).collect();
    if rows.iter().any(|r| *r >= n) {
        return None;
    }
    let unique = std::collections::HashSet::<usize>::from_iter(rows.iter().copied());
    if unique.len() != k {
        return None;
    }
    let len = available[0].1.len();
    if available.iter().any(|(_, b)| b.len() != len) {
        return None;
    }
    let mut coeff = vec![0u8; k * k];
    for (sel, &row) in rows.iter().enumerate() {
        let row_coeffs = gen_row_coeff(row, k, n);
        coeff[sel * k..(sel + 1) * k].copy_from_slice(&row_coeffs);
    }
    let mut data = vec![vec![0u8; len]; k];
    for byte_idx in 0..len {
        let rhs: Vec<u8> = available.iter().map(|(_, b)| b[byte_idx]).collect();
        let decoded = solve(&coeff, &rhs)?;
        for j in 0..k {
            data[j][byte_idx] = decoded[j];
        }
    }
    Some(encode(&data, n, k))
}

/// Check whether a shard's bytes satisfy the linear equations implied by
/// k known data rows: row `r` must equal `coeff_r . data` for every byte.
pub fn matches_linear(row: usize, bytes: &[u8], data: &[Vec<u8>], n: usize, k: usize) -> bool {
    if row >= n || bytes.len() != data[0].len() {
        return false;
    }
    let coeffs = gen_row_coeff(row, k, n);
    for byte_idx in 0..bytes.len() {
        let mut acc = 0u8;
        for j in 0..k {
            acc ^= mul(coeffs[j], data[j][byte_idx]);
        }
        if acc != bytes[byte_idx] {
            return false;
        }
    }
    true
}
