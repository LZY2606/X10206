//! Versioned Reed-Solomon code over GF(256).
//!
//! A stripe holds `k` data shards and `m` parity shards; any `k` healthy
//! shards suffice to reconstruct the stripe. Two encoding parameter
//! versions are supported; the manifest records which one was used and
//! mixing versions inside a single stripe is rejected by enumeration.

use crate::gf256::Gf256;

/// Versioned encoding parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodecVersion {
    /// Parity row j evaluates at field element j+1.
    V1 = 1,
    /// Parity row j evaluates at field element 2*(j+1).
    V2 = 2,
}

impl CodecVersion {
    pub fn from_i64(v: i64) -> Option<Self> {
        match v {
            1 => Some(CodecVersion::V1),
            2 => Some(CodecVersion::V2),
            _ => None,
        }
    }

    pub fn as_i64(self) -> i64 {
        self as i64
    }

    /// Evaluation point for parity row `j` (0-based).
    pub fn eval_point(self, gf: &Gf256, j: usize) -> u8 {
        match self {
            CodecVersion::V1 => gf.exp[((j as u16 + 1) % 255) as usize],
            CodecVersion::V2 => gf.exp[((2 * j as u16 + 2) % 255) as usize],
        }
    }
}

/// One coefficient row of the encoding matrix, indexed over all `k+m` shards.
pub fn encoder_row(gf: &Gf256, version: CodecVersion, k: usize, shard: usize) -> Vec<u8> {
    let mut row = vec![0u8; k];
    if shard < k {
        row[shard] = 1;
    } else {
        let x = version.eval_point(gf, shard - k);
        for (c, coeff) in row.iter_mut().enumerate() {
            // x^c, c = 0..k-1
            *coeff = gf.pow(x, c as u32);
        }
    }
    row
}

/// Encode `k` data shards into `k + m` shards.
pub fn encode(gf: &Gf256, version: CodecVersion, k: usize, m: usize, data: &[Vec<u8>]) -> Vec<Vec<u8>> {
    assert_eq!(data.len(), k);
    let shard_len = data.first().map(|d| d.len()).unwrap_or(0);
    assert!(data.iter().all(|d| d.len() == shard_len));
    let mut out = Vec::with_capacity(k + m);
    for s in 0..k + m {
        let row = encoder_row(gf, version, k, s);
        let mut buf = vec![0u8; shard_len];
        if s < k {
            buf.copy_from_slice(&data[s]);
        } else {
            for byte in 0..shard_len {
                let mut acc = 0u8;
                for c in 0..k {
                    acc ^= gf.mul(row[c], data[c][byte]);
                }
                buf[byte] = acc;
            }
        }
        out.push(buf);
    }
    out
}

/// In-place Gaussian elimination solving `A x = b` over GF(256).
/// Returns `None` when the matrix is singular.
pub fn solve(gf: &Gf256, a: &[Vec<u8>], b: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    let rows = a.len();
    let cols = a[0].len();
    let width = b[0].len();
    debug_assert!(b.iter().all(|r| r.len() == width));
    let mut m: Vec<Vec<u8>> = a
        .iter()
        .zip(b.iter())
        .map(|(ar, br)| {
            let mut row = Vec::with_capacity(cols + width);
            row.extend_from_slice(ar);
            row.extend_from_slice(br);
            row
        })
        .collect();

    for col in 0..cols {
        let pivot = (col..rows).find(|&r| m[r][col] != 0)?;
        m.swap(col, pivot);
        let inv = gf.inv(m[col][col]);
        for v in m[col].iter_mut() {
            *v = gf.mul(*v, inv);
        }
        for r in 0..rows {
            if r == col {
                continue;
            }
            let factor = m[r][col];
            if factor == 0 {
                continue;
            }
            for c in col..cols + width {
                let sub = gf.mul(factor, m[col][c]);
                m[r][c] ^= sub;
            }
        }
    }
    Some(m.into_iter().take(cols).map(|mut r| r.split_off(cols)).collect())
}

/// Reconstruct a full stripe from any `k` present shards.
///
/// `present` maps shard index `(0..k+m)` to its bytes; exactly `k` entries
/// are expected. Returns all `k+m` shards (present shards echoed back).
pub fn reconstruct(
    gf: &Gf256,
    version: CodecVersion,
    k: usize,
    m: usize,
    present: &[(usize, Vec<u8>)],
) -> Option<Vec<Vec<u8>>> {
    assert_eq!(present.len(), k, "reconstruction requires exactly k shards");
    let indices: Vec<usize> = present.iter().map(|(i, _)| *i).collect();
    let shard_len = present[0].1.len();
    assert!(present.iter().all(|(_, b)| b.len() == shard_len));

    let a: Vec<Vec<u8>> = indices
        .iter()
        .map(|&s| encoder_row(gf, version, k, s))
        .collect();
    let b: Vec<Vec<u8>> = present.iter().map(|(_, bytes)| bytes.clone()).collect();
    let data = solve(gf, &a, &b)?;

    let mut full = encode(gf, version, k, m, &data);
    for (idx, bytes) in present {
        full[*idx] = bytes.clone();
    }
    Some(full)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_each_version_each_subset() {
        let gf = Gf256::new();
        for version in [CodecVersion::V1, CodecVersion::V2] {
            let (k, m) = (3, 2);
            let data = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];
            let coded = encode(&gf, version, k, m, &data);
            for missing in 0..k + m {
                let present: Vec<(usize, Vec<u8>)> = (0..k + m)
                    .filter(|&i| i != missing)
                    .map(|i| (i, coded[i].clone()))
                    .collect();
                let recovered = reconstruct(&gf, version, k, m, &present).unwrap();
                assert_eq!(recovered, coded, "version {:?} missing {}", version, missing);
            }
        }
    }

    #[test]
    fn versions_produce_distinct_parity() {
        let gf = Gf256::new();
        let data = vec![vec![10], vec![20], vec![30]];
        let v1 = encode(&gf, CodecVersion::V1, 3, 2, &data);
        let v2 = encode(&gf, CodecVersion::V2, 3, 2, &data);
        assert_ne!(v1[3], v2[3]);
    }
}
