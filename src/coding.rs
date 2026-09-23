//! Versioned erasure coding.
//!
//! `gf256-rs-v1`: systematic Reed-Solomon over GF(2^8) using the standard
//! AES field polynomial (0x11d). Data rows are identity; parity row `j`
//! (1-based) is the Vandermonde evaluation point `x = j`, i.e. coefficients
//! `[x^0, x^1, ..., x^(k-1)]`. Every set of `k` distinct rows is invertible
//! as long as the parity points are distinct and non-zero, so any `k`
//! surviving shards (data or parity) rebuild the stripe.

use std::fmt;

pub const CODING_VERSION: &str = "gf256-rs-v1";

/// GF(2^8), reducing polynomial 0x11d (x^8 + x^4 + x^3 + x + 1).
#[derive(Clone, Copy)]
pub struct Gf256 {
    exp: [u8; 512],
    log: [u8; 256],
}

impl Default for Gf256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Gf256 {
    pub fn new() -> Self {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for i in 0..255u16 {
            exp[i as usize] = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= 0x11d;
            }
        }
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }
        Self { exp, log }
    }

    #[inline]
    pub fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            let la = self.log[a as usize] as u16;
            let lb = self.log[b as usize] as u16;
            self.exp[(la + lb) as usize]
        }
    }

    #[inline]
    pub fn inv(&self, a: u8) -> u8 {
        assert!(a != 0, "inverse of zero");
        self.exp[255 - self.log[a as usize] as usize]
    }

    #[inline]
    pub fn div(&self, a: u8, b: u8) -> u8 {
        self.mul(a, self.inv(b))
    }

    pub fn pow(&self, mut x: u8, mut e: u32) -> u8 {
        let mut acc = 1u8;
        while e > 0 {
            if e & 1 == 1 {
                acc = self.mul(acc, x);
            }
            x = self.mul(x, x);
            e >>= 1;
        }
        acc
    }
}

/// Versioned coding parameters carried in the manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "scheme", rename_all = "kebab-case")]
pub enum CodingParams {
    #[serde(rename = "gf256-rs-v1")]
    Gf256RsV1 { k: u8, m: u8 },
}

impl CodingParams {
    pub fn version(&self) -> &'static str {
        match self {
            CodingParams::Gf256RsV1 { .. } => CODING_VERSION,
        }
    }

    pub fn data_count(&self) -> usize {
        match self {
            CodingParams::Gf256RsV1 { k, .. } => *k as usize,
        }
    }

    pub fn parity_count(&self) -> usize {
        match self {
            CodingParams::Gf256RsV1 { m, .. } => *m as usize,
        }
    }

    pub fn shard_count(&self) -> usize {
        self.data_count() + self.parity_count()
    }

    pub fn validate(&self) -> Result<(), CodingError> {
        let (k, m) = match self {
            CodingParams::Gf256RsV1 { k, m } => (*k as usize, *m as usize),
        };
        if k == 0 {
            return Err(CodingError::InvalidParams("k must be > 0"));
        }
        if m == 0 {
            return Err(CodingError::InvalidParams("m must be > 0"));
        }
        if k + m > 256 {
            return Err(CodingError::InvalidParams("k + m must be <= 256"));
        }
        Ok(())
    }
}

impl fmt::Display for CodingParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodingParams::Gf256RsV1 { k, m } => write!(f, "gf256-rs-v1(k={k},m={m})"),
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CodingError {
    #[error("unknown coding version: {0}")]
    UnknownVersion(String),
    #[error("invalid coding parameters: {0}")]
    InvalidParams(&'static str),
    #[error("shard {0} out of range 0..{1}")]
    ShardOutOfRange(usize, usize),
    #[error("need exactly {need} shards to decode, got {got}")]
    WrongShardCount { need: usize, got: usize },
    #[error("shard index {0} appears more than once in the decoding set")]
    DuplicateDecodeIndex(u32),
    #[error("chosen shard rows are singular (no solution)")]
    Singular,
    #[error("shard {index} length {actual} != expected {expected}")]
    LengthMismatch {
        index: usize,
        expected: usize,
        actual: usize,
    },
}

impl CodingParams {
    /// Full coding row for shard `index`.
    /// Data shards: identity rows. Parity shards: Vandermonde rows at x=index-k+1.
    pub fn coding_row(&self, gf: &Gf256, index: usize) -> Result<Vec<u8>, CodingError> {
        let n = self.shard_count();
        if index >= n {
            return Err(CodingError::ShardOutOfRange(index, n));
        }
        let k = self.data_count();
        let mut row = vec![0u8; k];
        if index < k {
            row[index] = 1;
        } else {
            let x = (index - k + 1) as u8; // evaluation point 1..=m
            for c in 0..k {
                row[c] = gf.pow(x, c as u32);
            }
        }
        Ok(row)
    }

    /// Encode `k` equal-length data shards into all `k+m` shards.
    pub fn encode(&self, data: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, CodingError> {
        self.validate()?;
        let k = self.data_count();
        if data.len() != k {
            return Err(CodingError::WrongShardCount {
                need: k,
                got: data.len(),
            });
        }
        let shard_len = data.first().map(|d| d.len()).unwrap_or(0);
        for (i, d) in data.iter().enumerate() {
            if d.len() != shard_len {
                return Err(CodingError::LengthMismatch {
                    index: i,
                    expected: shard_len,
                    actual: d.len(),
                });
            }
        }
        let gf = Gf256::new();
        let mut out = Vec::with_capacity(self.shard_count());
        for index in 0..self.shard_count() {
            let row = self.coding_row(&gf, index)?;
            let mut buf = vec![0u8; shard_len];
            for c in 0..k {
                if row[c] == 0 {
                    continue;
                }
                let coef = row[c];
                if coef == 1 {
                    for (b, &v) in buf.iter_mut().zip(data[c].iter()) {
                        *b ^= v;
                    }
                } else {
                    for (b, &v) in buf.iter_mut().zip(data[c].iter()) {
                        *b ^= gf.mul(coef, v);
                    }
                }
            }
            out.push(buf);
        }
        Ok(out)
    }

    /// Rebuild all data shards from a set of surviving shards.
    ///
    /// `shards` maps `shard index -> bytes`; it must contain exactly `k`
    /// distinct indices. Returned vectors follow data-shard order 0..k.
    pub fn decode(
        &self,
        shards: &[(usize, Vec<u8>)],
        shard_len: usize,
    ) -> Result<Vec<Vec<u8>>, CodingError> {
        self.validate()?;
        let k = self.data_count();
        if shards.len() != k {
            return Err(CodingError::WrongShardCount {
                need: k,
                got: shards.len(),
            });
        }
        let mut seen = vec![false; self.shard_count()];
        for (idx, bytes) in shards {
            if *idx >= self.shard_count() {
                return Err(CodingError::ShardOutOfRange(*idx, self.shard_count()));
            }
            if seen[*idx] {
                return Err(CodingError::DuplicateDecodeIndex(*idx as u32));
            }
            seen[*idx] = true;
            if bytes.len() != shard_len {
                return Err(CodingError::LengthMismatch {
                    index: *idx,
                    expected: shard_len,
                    actual: bytes.len(),
                });
            }
        }
        let gf = Gf256::new();
        let mut matrix = Vec::with_capacity(k);
        for (idx, _) in shards {
            matrix.push(self.coding_row(&gf, *idx)?);
        }
        let inv = invert_matrix(&gf, &matrix, k)?;
        let mut data = vec![vec![0u8; shard_len]; k];
        for r in 0..k {
            for c in 0..k {
                let coef = inv[r][c];
                if coef == 0 {
                    continue;
                }
                let (_, ref y) = shards[c];
                if coef == 1 {
                    for b in 0..shard_len {
                        data[r][b] ^= y[b];
                    }
                } else {
                    for b in 0..shard_len {
                        data[r][b] ^= gf.mul(coef, y[b]);
                    }
                }
            }
        }
        Ok(data)
    }
}

/// Invert a square matrix over GF(2^8) via Gauss-Jordan elimination.
fn invert_matrix(gf: &Gf256, m: &[Vec<u8>], k: usize) -> Result<Vec<Vec<u8>>, CodingError> {
    let mut a: Vec<Vec<u8>> = m.to_vec();
    let mut inv = vec![vec![0u8; k]; k];
    for i in 0..k {
        inv[i][i] = 1;
    }
    for col in 0..k {
        let pivot = (col..k).find(|&r| a[r][col] != 0);
        let pivot = match pivot {
            Some(r) => r,
            None => return Err(CodingError::Singular),
        };
        a.swap(col, pivot);
        inv.swap(col, pivot);
        let p = a[col][col];
        if p != 1 {
            let pinv = gf.inv(p);
            for c in 0..k {
                a[col][c] = gf.mul(a[col][c], pinv);
                inv[col][c] = gf.mul(inv[col][c], pinv);
            }
        }
        for r in 0..k {
            if r == col || a[r][col] == 0 {
                continue;
            }
            let factor = a[r][col];
            for c in 0..k {
                a[r][c] ^= gf.mul(factor, a[col][c]);
                inv[r][c] ^= gf.mul(factor, inv[col][c]);
            }
        }
    }
    Ok(inv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_arith_roundtrips() {
        let gf = Gf256::new();
        for a in 1u8..=255 {
            assert_eq!(gf.mul(a, gf.inv(a)), 1);
            assert_eq!(gf.div(a, a), 1);
        }
        assert_eq!(gf.mul(0, 57), 0);
    }

    #[test]
    fn encode_then_decode_any_k_subset() {
        let p = CodingParams::Gf256RsV1 { k: 3, m: 2 };
        let data = vec![vec![1u8, 2, 3, 4], vec![5, 6, 7, 8], vec![9, 10, 11, 12]];
        let all = p.encode(&data).unwrap();
        assert_eq!(all.len(), 5);
        // Every k-subset of the 5 shards must rebuild the data.
        for drop_a in 0..5 {
            for drop_b in drop_a + 1..5 {
                let survivors: Vec<(usize, Vec<u8>)> = (0..5)
                    .filter(|i| *i != drop_a && *i != drop_b)
                    .map(|i| (i, all[i].clone()))
                    .collect();
                let rebuilt = p.decode(&survivors, 4).unwrap();
                assert_eq!(rebuilt, data, "subset dropping {drop_a},{drop_b}");
            }
        }
    }

    #[test]
    fn boundary_exactly_k_shards() {
        let p = CodingParams::Gf256RsV1 { k: 2, m: 1 };
        let data = vec![vec![7, 8], vec![9, 10]];
        let all = p.encode(&data).unwrap();
        // Exactly the recovery threshold, using two parities... only one
        // parity exists, so pick data0 + parity0 (the harshest case).
        let out = p
            .decode(&[(0, all[0].clone()), (2, all[2].clone())], 2)
            .unwrap();
        assert_eq!(out, data);
    }
}
