//! Versioned Reed-Solomon codec over GF(2^8).
//!
//! A stripe consists of `k` data shards and `m` parity shards of equal length.
//! Any `k` surviving shards (data or parity) suffice to reconstruct all
//! missing shards. Coding parameters are part of the manifest version, so
//! different generations can use different layouts.

use crate::error::{Error, Result};
use crate::gf256::{cauchy_systematic, invert_matrix, mul};

/// Versioned coding parameters for one manifest revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodingParams {
    pub k: usize,
    pub m: usize,
}

impl CodingParams {
    pub fn n(&self) -> usize {
        self.k + self.m
    }

    pub fn validate(&self) -> Result<()> {
        if self.k == 0 || self.m == 0 {
            return Err(Error::InvalidManifest("k and m must be positive".into()));
        }
        if 2 * self.k + self.m > 256 {
            return Err(Error::InvalidManifest("k + m layout exceeds GF(2^8) capacity".into()));
        }
        Ok(())
    }
}

/// Encode `data_shards` (k rows) into k+m shards of equal length.
///
/// The final data shard is zero-padded to the longest row; the returned
/// `padded_len` allows callers to record the true length in the manifest.
pub fn encode(params: CodingParams, data_shards: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
    params.validate()?;
    let k = params.k;
    let m = params.m;
    if data_shards.len() != k {
        return Err(Error::InvalidManifest(format!(
            "expected {k} data shards, got {}",
            data_shards.len()
        )));
    }
    let len = data_shards.iter().map(|s| s.len()).max().unwrap_or(0);
    let mut rows = Vec::with_capacity(k + m);
    for s in data_shards {
        let mut row = s.clone();
        row.resize(len, 0);
        rows.push(row);
    }
    rows.resize(k + m, vec![0u8; len]);

    let g = cauchy_systematic(k, m);
    for p in 0..m {
        for byte_idx in 0..len {
            let mut acc = 0u8;
            for d in 0..k {
                acc ^= mul(g[k + p][d], rows[d][byte_idx]);
            }
            rows[k + p][byte_idx] = acc;
        }
    }
    Ok(rows)
}

/// Reconstruct every shard of a stripe from `k` (or more) survivors.
///
/// `present` maps global shard index `0..n` -> survivor bytes.
pub fn reconstruct(params: CodingParams, present: &[(usize, Vec<u8>)]) -> Result<Vec<Vec<u8>>> {
    params.validate()?;
    let k = params.k;
    let n = params.n();
    if present.len() < k {
        return Err(Error::BelowThreshold(present.len(), k));
    }
    let len = present[0].1.len();
    if len == 0 {
        return Err(Error::InvalidManifest("empty shard bytes".into()));
    }
    for (idx, bytes) in present {
        if *idx >= n {
            return Err(Error::InvalidManifest(format!("shard index {idx} >= n={n}")));
        }
        if bytes.len() != len {
            return Err(Error::LengthMismatch {
                expected: len,
                actual: bytes.len(),
            });
        }
    }

    let chosen: Vec<usize> = present.iter().take(k).map(|(idx, _)| *idx).collect();
    let g = cauchy_systematic(k, params.m);
    let sub: Vec<Vec<u8>> = chosen.iter().map(|&r| g[r].clone()).collect();
    let a_inv = invert_matrix(&sub).ok_or(Error::Decode("matrix singular".into()))?;

    // data[d][t] = sum_j a_inv[d][j] * survivor_j[t]
    let mut data = vec![vec![0u8; len]; k];
    for d in 0..k {
        for t in 0..len {
            let mut acc = 0u8;
            for (j, (_, bytes)) in present.iter().take(k).enumerate() {
                acc ^= mul(a_inv[d][j], bytes[t]);
            }
            data[d][t] = acc;
        }
    }

    let mut all = encode(params, &data)?;
    // Cross-check every extra survivor against the re-encoded stripe.
    for (idx, bytes) in present.iter().skip(k) {
        if &all[*idx] != bytes {
            return Err(Error::Decode(format!("survivor {idx} contradicts reconstruction")));
    }
    }
    // Trim padding off the last data shard is the caller's job (manifest owns
    // true lengths); callers verify against per-shard digests anyway.
    Ok(all)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_with_data() {
        let params = CodingParams { k: 3, m: 2 };
        let rows = encode(params, &[b"hello".to_vec(), b"world".to_vec(), b"!!".to_vec()]).unwrap();
        for &missing in &[0usize, 2, 3, 4] {
            let present: Vec<_> = rows
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != missing)
                .take(3)
                .map(|(i, r)| (i, r.clone()))
                .collect();
            let out = reconstruct(params, &present).unwrap();
            assert_eq!(out, rows);
        }
    }

    #[test]
    fn detects_corrupt_survivor() {
        let params = CodingParams { k: 2, m: 2 };
        let rows = encode(params, &[b"abcdef".to_vec(), b"zyxwvu".to_vec()]).unwrap();
        let mut corrupted = rows[0].clone();
        corrupted[0] ^= 0x01;
        // A corrupt row plus two honest witnesses: decode from the first k,
        // then the extra honest survivor contradicts the re-encoded stripe.
        let present = vec![
            (0, corrupted),
            (2, rows[2].clone()),
            (3, rows[3].clone()),
        ];
        assert!(reconstruct(params, &present).is_err());
    }
}
