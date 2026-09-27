//! Versioned erasure coding over GF(256).
//!
//! Two coded versions are supported so reconstruction parameters are explicit:
//! - `rs-v1`: systematic Reed-Solomon with Vandermonde parity rows.
//! - `rs-v2`: systematic Reed-Solomon with Cauchy parity rows.
//!
//! Both codes are MDS for the sizes used here: any `k` of the `k+m` shards
//! reconstruct every shard. Shards inside one stripe all share one length.

use crate::gf::{invert, Tables};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CodeVersion {
    #[serde(rename = "rs-v1")]
    V1,
    #[serde(rename = "rs-v2")]
    V2,
}

impl CodeVersion {
    pub fn as_str(self) -> &'static str {
        match self {
            CodeVersion::V1 => "rs-v1",
            CodeVersion::V2 => "rs-v2",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "rs-v1" => Some(CodeVersion::V1),
            "rs-v2" => Some(CodeVersion::V2),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodingParams {
    pub version: CodeVersion,
    pub k: u8,
    pub m: u8,
}

impl CodingParams {
    pub fn n(self) -> usize {
        self.k as usize + self.m as usize
    }

    pub fn validate(self) -> Result<(), String> {
        if self.k == 0 {
            return Err("k must be > 0".into());
        }
        if self.m == 0 {
            return Err("m must be > 0".into());
        }
        if (self.k as usize) < (self.m as usize) && self.version == CodeVersion::V2 {
            return Err("rs-v2 requires k >= m".into());
        }
        if self.n() > 256 {
            return Err("k + m must be <= 256".into());
        }
        Ok(())
    }

    /// Row `i` coefficients over the `k` data shards (identity for data rows).
    pub fn row(self, t: &Tables, i: usize) -> Vec<u8> {
        let k = self.k as usize;
        debug_assert!(i < self.n());
        if i < k {
            let mut row = vec![0u8; k];
            row[i] = 1;
            row
        } else {
            let p = (i - k) as u8;
            match self.version {
                CodeVersion::V1 => {
                    let base = (p + 1) as u8; // distinct nonzero x_p
                    let lb = t.log[base as usize];
                    (0..k).map(|j| t.exp[j * lb as usize]).collect()
                }
                CodeVersion::V2 => {
                    // Cauchy: coefficient 1/(x XOR y), x in [0,m), y in [m,m+k)
                    (0..k)
                        .map(|j| {
                            let xored = p ^ (self.m + j as u8);
                            debug_assert!(xored != 0);
                            t.inv(xored)
                        })
                        .collect()
                }
            }
        }
    }

    pub fn matrix(self, t: &Tables) -> Vec<Vec<u8>> {
        (0..self.n()).map(|i| self.row(t, i)).collect()
    }
}

/// Encode `k` data shards into `k+m` shards.
pub fn encode(params: CodingParams, data: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
    params.validate()?;
    let k = params.k as usize;
    if data.len() != k {
        return Err(format!("expected {k} data shards, got {}", data.len()));
    }
    let len = data.first().map(|d| d.len()).unwrap_or(0);
    if data.iter().any(|d| d.len() != len) {
        return Err("data shards must share one length".into());
    }
    let t = Tables::new();
    let matrix = params.matrix(&t);
    let mut out = Vec::with_capacity(params.n());
    for row in matrix {
        let mut shard = vec![0u8; len];
        for (j, d) in data.iter().enumerate() {
            let c = row[j];
            if c == 0 {
                continue;
            }
            for (out_byte, in_byte) in shard.iter_mut().zip(d) {
                *out_byte ^= t.mul(c, *in_byte);
            }
        }
        out.push(shard);
    }
    Ok(out)
}

/// Reconstruct every shard from exactly `k` available shards.
/// `available` maps shard index -> shard bytes; it must contain exactly `k`
/// entries with indices in `0..k+m` and equal lengths.
pub fn decode(
    params: CodingParams,
    available: &[(usize, Vec<u8>)],
) -> Result<Vec<Vec<u8>>, String> {
    params.validate()?;
    let k = params.k as usize;
    if available.len() != k {
        return Err(format!("need exactly {k} shards, got {}", available.len()));
    }
    let mut rows_sorted: Vec<(usize, Vec<u8>)> = available.to_vec();
    rows_sorted.sort_by_key(|(i, _)| *i);
    let mut indices = Vec::with_capacity(k);
    let shard_len = rows_sorted
        .first()
        .map(|(_, b)| b.len())
        .ok_or_else(|| "empty stripe".to_string())?;
    for (i, bytes) in &rows_sorted {
        if *i >= params.n() {
            return Err(format!("shard index {i} out of range"));
        }
        if bytes.len() != shard_len {
            return Err(format!("shard {i} length {} != {shard_len}", bytes.len()));
        }
        indices.push(*i);
    }
    indices.sort_unstable();
    indices.dedup();
    if indices.len() != k {
        return Err("duplicate shard indices in one candidate set".into());
    }

    let t = Tables::new();
    let full = params.matrix(&t);
    let sub: Vec<Vec<u8>> = indices.iter().map(|&i| full[i].clone()).collect();
    let sub_inv = invert(&t, sub).ok_or_else(|| "selected rows are singular".to_string())?;

    let mut recovered = Vec::with_capacity(params.n());
    for target in 0..params.n() {
        let mut shard = vec![0u8; shard_len];
        for (col, (_, in_bytes)) in rows_sorted.iter().enumerate() {
            let c = sub_inv[target][col];
            if c == 0 {
                continue;
            }
            for (out_byte, in_byte) in shard.iter_mut().zip(in_bytes) {
                *out_byte ^= t.mul(c, *in_byte);
            }
        }
        recovered.push(shard);
    }
    Ok(recovered)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Brute-force MDS check: every k-subset of rows must be invertible.
    #[test]
    fn codes_are_mds_for_supported_shapes() {
        let t = Tables::new();
        for version in [CodeVersion::V1, CodeVersion::V2] {
            for (k, m) in [(1usize, 1), (2, 2), (3, 2), (2, 3), (4, 3), (5, 1)] {
                if version == CodeVersion::V2 && k < m {
                    continue;
                }
                let params = CodingParams {
                    version,
                    k: k as u8,
                    m: m as u8,
                };
                let matrix = params.matrix(&t);
                let n = k + m;
                let mut mask: usize = (1usize << k) - 1;
                while mask < 1usize << n {
                    let sub: Vec<Vec<u8>> = (0..n)
                        .filter(|i| mask & (1 << i) != 0)
                        .map(|i| matrix[i].clone())
                        .collect();
                    assert!(
                        invert(&t, sub).is_some(),
                        "{:?} k={k} m={m} subset={mask:b} singular",
                        version
                    );
                    // Gosper's hack for the next k-bit mask.
                    let c = mask & mask.wrapping_neg();
                    let r = mask.wrapping_add(c);
                    mask = (((r ^ mask) >> 2) / c) | r;
                }
            }
        }
    }

    #[test]
    fn encode_decode_recovers_from_every_subset() {
        let data = vec![vec![1u8, 2, 3], vec![9, 8, 7], vec![5, 5, 6]];
        for version in [CodeVersion::V1, CodeVersion::V2] {
            let params = CodingParams {
                version,
                k: 3,
                m: 2,
            };
            let all = encode(params, &data).unwrap();
            for missing in 0..5 {
                let avail: Vec<(usize, Vec<u8>)> = (0..5)
                    .filter(|&i| i != missing)
                    .map(|i| (i, all[i].clone()))
                    .collect();
                let rec = decode(params, &avail).unwrap();
                assert_eq!(rec, all, "version {:?} missing {missing}", version);
            }
        }
    }
}
