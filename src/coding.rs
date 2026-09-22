//! Versioned Cauchy Reed-Solomon coding over GF(2^8).
//!
//! `codec_version` selects the exact generator-matrix construction so that an
//! import created with older parameters can never silently re-encode with a
//! different scheme. Version 1 uses a Cauchy matrix made systematic by a
//! right-multiplication with the inverse of its first `k x k` block.

use std::collections::BTreeMap;

use crate::gf256::{invert, Field};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodingParams {
    pub codec_version: u32,
    pub k: usize,
    pub n: usize,
    pub chunk_size: usize,
}

impl CodingParams {
    pub fn validate(&self) -> Result<(), String> {
        if self.codec_version != 1 {
            return Err(format!("unsupported codec_version {}", self.codec_version));
        }
        if self.k == 0 || self.n < self.k || self.n > 255 {
            return Err(format!("invalid (k,n)=({},{})", self.k, self.n));
        }
        if self.chunk_size == 0 {
            return Err("chunk_size must be positive".to_string());
        }
        Ok(())
    }

    pub fn parity_count(&self) -> usize {
        self.n - self.k
    }
}

/// Systematic Cauchy generator matrix (n x k). Any `k` rows are linearly
/// independent, which is the MDS property the recovery enumerator relies on.
pub fn generator_matrix(field: &Field, k: usize, n: usize) -> Vec<Vec<u8>> {
    assert!(k >= 1 && n >= k && n <= 255);
    let mut raw = vec![vec![0u8; k]; n];
    for i in 0..n {
        let x = (i as u8).wrapping_add(1); // {1 .. n}
        for j in 0..k {
            let y = 255u8.wrapping_sub(j as u8); // {255, 254, ...}
            let denom = x ^ y;
            assert!(denom != 0, "cauchy sets must be disjoint");
            raw[i][j] = field.inv(denom);
        }
    }
    let a: Vec<Vec<u8>> = raw[..k].to_vec();
    let a_inv = invert(field, &a).expect("top cauchy block must be invertible");
    let mut systematic = vec![vec![0u8; k]; n];
    for i in 0..n {
        for t in 0..k {
            let mut acc = 0u8;
            for j in 0..k {
                acc ^= field.mul(raw[i][j], a_inv[j][t]);
            }
            systematic[i][t] = acc;
        }
    }
    systematic
}

/// Encode `k` equal-length data shards into `n` shards (first `k` identical
/// to the input, i.e. systematic layout).
pub fn encode(
    field: &Field,
    params: CodingParams,
    data_shards: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, String> {
    params.validate()?;
    if data_shards.len() != params.k {
        return Err(format!("expected {} data shards", params.k));
    }
    let len = data_shards[0].len();
    if len != params.chunk_size {
        return Err(format!(
            "shard length {} != chunk_size {}",
            len, params.chunk_size
        ));
    }
    if data_shards.iter().any(|s| s.len() != len) {
        return Err("data shards must share one length".to_string());
    }
    let g = generator_matrix(field, params.k, params.n);
    let mut out = Vec::with_capacity(params.n);
    for i in 0..params.n {
        let mut shard = vec![0u8; len];
        for p in 0..len {
            let mut acc = 0u8;
            for j in 0..params.k {
                acc ^= field.mul(g[i][j], data_shards[j][p]);
            }
            shard[p] = acc;
        }
        out.push(shard);
    }
    Ok(out)
}

/// Recover missing shard indices from any `k` available shards.
pub fn recover(
    field: &Field,
    params: CodingParams,
    available: &[(usize, Vec<u8>)],
    missing: &[usize],
) -> Result<BTreeMap<usize, Vec<u8>>, String> {
    params.validate()?;
    if available.len() != params.k {
        return Err(format!("need exactly {} available shards", params.k));
    }
    let indices: Vec<usize> = available.iter().map(|(i, _)| *i).collect();
    if indices.iter().any(|i| *i >= params.n) || missing.iter().any(|i| *i >= params.n) {
        return Err("shard index out of range".to_string());
    }
    let len = available[0].1.len();
    if available.iter().any(|(_, b)| b.len() != len) {
        return Err("available shards disagree on length".to_string());
    }
    let g = generator_matrix(field, params.k, params.n);
    let sub: Vec<Vec<u8>> = indices.iter().map(|&i| g[i].clone()).collect();
    let sub_inv = invert(field, &sub).ok_or("selected rows are singular")?;

    // Coefficients c[t][j] such that recovered shard `missing[t]` equals
    // sum_j c[t][j] * available[j].
    let mut coeffs = vec![vec![0u8; params.k]; missing.len()];
    for (t, &mi) in missing.iter().enumerate() {
        for j in 0..params.k {
            let mut acc = 0u8;
            for r in 0..params.k {
                acc ^= field.mul(g[mi][r], sub_inv[r][j]);
            }
            coeffs[t][j] = acc;
        }
    }
    let mut result = BTreeMap::new();
    for (t, &mi) in missing.iter().enumerate() {
        let mut buf = vec![0u8; len];
        for p in 0..len {
            let mut acc = 0u8;
            for j in 0..params.k {
                acc ^= field.mul(coeffs[t][j], available[j].1[p]);
            }
            buf[p] = acc;
        }
        result.insert(mi, buf);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_k_rows_recover_every_shard() {
        let field = Field::new();
        let params = CodingParams {
            codec_version: 1,
            k: 3,
            n: 5,
            chunk_size: 8,
        };
        let data = vec![
            vec![1u8, 2, 3, 4, 5, 6, 7, 8],
            vec![9, 10, 11, 12, 13, 14, 15, 16],
            vec![17, 18, 19, 20, 21, 22, 23, 24],
        ];
        let all = encode(&field, params, &data).unwrap();
        // Remove every pair of shards and check recovery.
        for missing in &[[0usize, 1], [2, 4], [3, 4], [0, 3]] {
            let avail: Vec<(usize, Vec<u8>)> = (0..5)
                .filter(|i| !missing.contains(i))
                .map(|i| (i, all[i].clone()))
                .collect();
            let got = recover(&field, params, &avail, missing).unwrap();
            for &m in missing {
                assert_eq!(got[&m], all[m]);
            }
        }
    }
}
