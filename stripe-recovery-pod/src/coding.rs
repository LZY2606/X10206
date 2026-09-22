//! Versioned erasure coding: systematic Cauchy Reed-Solomon over GF(2^8).
//!
//! The generator matrix is `[I_k ; C]` where `C` is a k-by-m Cauchy matrix
//! (`C[i][j] = 1 / (x_j + y_i)`). Any selection of k rows is invertible, so
//! any k of the n shards can reconstruct the stripe.

use crate::gf::{invert, Gf256};

/// Versioned coding parameters. Only `reed-solomon-cauchy-v1` is understood;
/// an unknown version is rejected rather than guessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodingParams {
    pub version: u32,
    pub k: usize,
    pub n: usize,
    /// Byte length of every shard in every stripe (zero-padded final stripe).
    pub shard_len: usize,
}

pub const CODING_SCHEME: &str = "reed-solomon-cauchy-v1";

impl CodingParams {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1 {
            return Err(format!(
                "unsupported coding version {} (this pod understands version 1)",
                self.version
            ));
        }
        if self.k == 0 || self.n <= self.k || self.n > 256 {
            return Err(format!("require 1 <= k < n <= 256, got k={} n={}", self.k, self.n));
        }
        if self.shard_len == 0 {
            return Err("shard_len must be positive".into());
        }
        Ok(())
    }
}

/// Build the n-by-k generator matrix.
pub fn generator(gf: &Gf256, params: CodingParams) -> Vec<Vec<u8>> {
    let CodingParams { k, n, .. } = params;
    let mut g = Vec::with_capacity(n);
    for r in 0..k {
        let mut row = vec![0u8; k];
        row[r] = 1;
        g.push(row);
    }
    // x_j = j, y_i = k + i: disjoint sets, so x_j + y_i is never zero.
    for i in 0..n - k {
        let y = (k + i) as u8;
        let row: Vec<u8> = (0..k).map(|j| gf.inv(j as u8 ^ y)).collect();
        g.push(row);
    }
    g
}

fn combine(gf: &Gf256, row: &[u8], data: &[Vec<u8>], shard_len: usize) -> Vec<u8> {
    let mut shard = vec![0u8; shard_len];
    for (j, &c) in row.iter().enumerate() {
        if c == 0 {
            continue;
        }
        if c == 1 {
            for t in 0..shard_len {
                shard[t] ^= data[j][t];
            }
        } else {
            for t in 0..shard_len {
                shard[t] ^= gf.mul(c, data[j][t]);
            }
        }
    }
    shard
}

/// Encode k data shards into n shards (first k equal the input).
pub fn encode(gf: &Gf256, params: CodingParams, data: &[Vec<u8>]) -> Vec<Vec<u8>> {
    assert_eq!(data.len(), params.k);
    for d in data {
        assert_eq!(d.len(), params.shard_len);
    }
    let g = generator(gf, params);
    g.iter()
        .map(|row| combine(gf, row, data, params.shard_len))
        .collect()
}

/// Reconstruct all n shards of a stripe from any `k` available shards.
///
/// `available` must contain exactly k `(shard_index, bytes)` pairs with equal
/// byte length. Returns the full ordered set of n reconstructed shards.
pub fn reconstruct(
    gf: &Gf256,
    params: CodingParams,
    available: &[(usize, Vec<u8>)],
) -> Result<Vec<Vec<u8>>, String> {
    params.validate()?;
    if available.len() != params.k {
        return Err(format!(
            "need exactly {} shards for reconstruction, got {}",
            params.k,
            available.len()
        ));
    }
    let shard_len = available[0].1.len();
    if shard_len != params.shard_len {
        return Err(format!(
            "shard length {} != manifest shard_len {}",
            shard_len, params.shard_len
        ));
    }
    let mut seen = vec![false; params.n];
    for (idx, bytes) in available {
        if *idx >= params.n {
            return Err(format!("shard index {} out of range n={}", idx, params.n));
        }
        if seen[*idx] {
            return Err(format!("duplicate shard index {} in one combination", idx));
        }
        seen[*idx] = true;
        if bytes.len() != shard_len {
            return Err(format!(
                "shard {} length {} differs from {} inside one combination",
                idx,
                bytes.len(),
                shard_len
            ));
        }
    }

    let g = generator(gf, params);
    let sub: Vec<Vec<u8>> = available.iter().map(|(idx, _)| g[*idx].clone()).collect();
    let inv = invert(gf, &sub).ok_or("selected k rows are singular")?;

    // Decode the k data shards: data[j][t] = xor_r inv[j][r] * avail[r][t].
    let mut data = vec![vec![0u8; shard_len]; params.k];
    for j in 0..params.k {
        for (r, (_, bytes)) in available.iter().enumerate() {
            let c = inv[j][r];
            if c == 0 {
                continue;
            }
            if c == 1 {
                for t in 0..shard_len {
                    data[j][t] ^= bytes[t];
                }
            } else {
                for t in 0..shard_len {
                    data[j][t] ^= gf.mul(c, bytes[t]);
                }
            }
        }
    }

    let out: Vec<Vec<u8>> = g
        .iter()
        .map(|row| combine(gf, row, &data, shard_len))
        .collect();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_k_subset_reconstructs() {
        let gf = Gf256::new();
        let k = 3;
        let n = 5;
        let len = 16;
        let params = CodingParams { version: 1, k, n, shard_len: len };
        let data: Vec<Vec<u8>> = (0..k)
            .map(|j| (0..len).map(|t| ((j * 31 + t * 7 + 5) & 0xff) as u8).collect())
            .collect();
        let all = encode(&gf, params, &data);
        let mut subsets = 0;
        for mask in 0u32..(1 << n) {
            if mask.count_ones() != k as u32 {
                continue;
            }
            subsets += 1;
            let avail: Vec<(usize, Vec<u8>)> = (0..n)
                .filter(|i| mask & (1 << i) != 0)
                .map(|i| (i, all[i].clone()))
                .collect();
            let rec = reconstruct(&gf, params, &avail).unwrap();
            assert_eq!(rec, all, "subset {:?}", avail.iter().map(|(i, _)| *i).collect::<Vec<_>>());
        }
        assert_eq!(subsets, 10);
    }

    #[test]
    fn rejects_unknown_version_and_wrong_length() {
        let gf = Gf256::new();
        assert!(CodingParams { version: 2, k: 2, n: 4, shard_len: 4 }.validate().is_err());
        let params = CodingParams { version: 1, k: 2, n: 4, shard_len: 4 };
        let avail = vec![(0, vec![1, 2, 3, 4]), (1, vec![1, 2, 3])];
        assert!(reconstruct(&gf, params, &avail).is_err());
    }
}
