//! Reed-Solomon over GF(2^8), primitive polynomial 0x11d, generator 3.
//!
//! Coding matrix:
//!   rows 0..k        -> identity  (data shards)
//!   rows k..k+m      -> Vandermonde [alpha_j^i], alpha_j = code_alpha + j
//! Any square subsystem formed from this layout is invertible as long as
//! parity alphas are non-zero and distinct from one another (they are also
//! distinct from the k implicit data locations, which map to 0..k distinct
//! field elements through the Vandermonde reading; the classic proof for the
//! [I; V] layout only requires parity alphas nonzero pairwise distinct).

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RsError {
    /// Present shards fewer than data shards k.
    BelowThreshold { have: usize, need: usize },
    /// Coefficient subsystem was singular: shard set is internally inconsistent.
    Singular,
    /// Present shards disagree about the length/offset.
    LengthMismatch,
    /// Recomputed parity does not match a present parity shard.
    ParityMismatch,
}

pub fn add(a: u8, b: u8) -> u8 {
    a ^ b
}

pub fn mul(a: u8, b: u8) -> u8 {
    let mut aa = a as u16;
    let mut bb = b;
    let mut acc: u16 = 0;
    while bb != 0 {
        if bb & 1 != 0 {
            acc ^= aa;
        }
        aa <<= 1;
        if aa & 0x100 != 0 {
            aa ^= 0x11d;
        }
        bb >>= 1;
    }
    acc as u8
}

pub fn pow(mut a: u8, mut exp: u32) -> u8 {
    let mut acc = 1u8;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = mul(acc, a);
        }
        a = mul(a, a);
        exp >>= 1;
    }
    acc
}

/// Inverse in GF(256); `inv(0)` is undefined and returns 0.
pub fn inv(a: u8) -> u8 {
    pow(a, 254)
}

/// One coefficient row for shard index `row` given code alpha.
fn coeff_row(k: usize, code_alpha: u8, row: usize) -> Vec<u8> {
    if row < k {
        let mut v = vec![0u8; k];
        v[row] = 1;
        v
    } else {
        // Vandermonde row: x^i for i in 0..k, x = code_alpha + (row - k)
        // (addition in the field is XOR, and distinct j give distinct x).
        let x = code_alpha ^ (row - k) as u8;
        let mut v = Vec::with_capacity(k);
        for i in 0..k {
            v.push(pow(x, i as u32));
        }
        v
    }
}

/// Full k+m by k coding matrix.
pub fn coding_matrix(k: usize, m: usize, code_alpha: u8) -> Vec<Vec<u8>> {
    (0..k + m).map(|r| coeff_row(k, code_alpha, r)).collect()
}

/// Encode k data shards into k+m shards. All input shards must be equal length.
pub fn encode(data: &[Vec<u8>], m: usize, code_alpha: u8) -> Result<Vec<Vec<u8>>, RsError> {
    let k = data.len();
    if k == 0 || data.iter().any(|d| d.len() != data[0].len()) {
        return Err(RsError::LengthMismatch);
    }
    let len = data[0].len();
    let mat = coding_matrix(k, m, code_alpha);
    let mut out = Vec::with_capacity(k + m);
    for row in &mat {
        let mut shard = vec![0u8; len];
        for (i, &c) in row.iter().enumerate() {
            if c == 0 {
                continue;
            }
            for (b, &v) in data[i].iter().enumerate() {
                shard[b] ^= mul(c, v);
            }
        }
        out.push(shard);
    }
    Ok(out)
}

/// Solve A * x = b over GF(256) using Gauss-Jordan elimination.
/// `a` is n x n, `b` is n x width. Returns Err(Singular) when A is singular.
fn solve(a: &[Vec<u8>], b: &[Vec<u8>], width: usize) -> Result<Vec<Vec<u8>>, RsError> {
    let n = a.len();
    let mut mat: Vec<Vec<u8>> = a
        .iter()
        .enumerate()
        .map(|(r, row)| {
            let mut v = Vec::with_capacity(n + width);
            v.extend_from_slice(row);
            v.extend_from_slice(&b[r]);
            v
        })
        .collect();

    for col in 0..n {
        let pivot = (col..n).find(|&r| mat[r][col] != 0);
        let pivot = match pivot {
            Some(p) => p,
            None => return Err(RsError::Singular),
        };
        mat.swap(col, pivot);
        let pinv = inv(mat[col][col]);
        for c in col..n + width {
            mat[col][c] = mul(mat[col][c], pinv);
        }
        for r in 0..n {
            if r == col || mat[r][col] == 0 {
                continue;
            }
            let factor = mat[r][col];
            for c in col..n + width {
                mat[r][c] ^= mul(factor, mat[col][c]);
            }
        }
    }
    Ok(mat.iter().map(|row| row[n..n + width].to_vec()).collect())
}

/// Present shard input: (shard index in 0..k+m, bytes).
pub struct Present {
    pub index: usize,
    pub bytes: Vec<u8>,
}

/// Reconstruct every shard of a stripe from any >= k present shards.
///
/// Verification: present shards are folded back through the full coding matrix.
/// A corrupted present shard manifests either as a singular subsystem or as a
/// parity/data mismatch against the other present shards.
pub fn reconstruct(
    k: usize,
    m: usize,
    code_alpha: u8,
    present: Vec<Present>,
) -> Result<Vec<Vec<u8>>, RsError> {
    let n = k + m;
    if present.len() < k {
        return Err(RsError::BelowThreshold {
            have: present.len(),
            need: k,
        });
    }
    let len = present[0].bytes.len();
    if present.iter().any(|p| p.bytes.len() != len) {
        return Err(RsError::LengthMismatch);
    }
    if present.iter().any(|p| p.index >= n) {
        return Err(RsError::LengthMismatch);
    }

    let full = coding_matrix(k, m, code_alpha);
    // Take the first k present rows (deterministically ordered by caller) to
    // form the solving subsystem; remaining rows are used purely for check.
    let sub: Vec<Vec<u8>> = present[..k].iter().map(|p| full[p.index].clone()).collect();
    let rhs: Vec<Vec<u8>> = present[..k].iter().map(|p| p.bytes.clone()).collect();

    let data = solve(&sub, &rhs, len)?;

    // Cross-check every extra present shard against reconstructed data.
    for p in &present[k..] {
        let row = &full[p.index];
        for (b, expected) in p.bytes.iter().enumerate() {
            let mut got = 0u8;
            for (i, &c) in row.iter().enumerate() {
                got ^= mul(c, data[i][b]);
            }
            if got != *expected {
                return Err(RsError::ParityMismatch);
            }
        }
    }

    encode(&data, m, code_alpha)
}

/// Check whether a full set of k+m shards satisfies the coding equations.
/// Missing entries are passed as None. Returns false below threshold as well.
pub fn verify_set(
    k: usize,
    m: usize,
    code_alpha: u8,
    shards: &[Option<Vec<u8>>],
) -> bool {
    let present: Vec<Present> = shards
        .iter()
        .enumerate()
        .filter_map(|(i, b)| {
            b.as_ref().map(|bytes| Present {
                index: i,
                bytes: bytes.clone(),
            })
        })
        .collect();
    if present.len() < k {
        return false;
    }
    reconstruct(k, m, code_alpha, present).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_any_k_subset() {
        let (k, m) = (3usize, 2usize);
        let data = vec![vec![1u8, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];
        let all = encode(&data, m, 1).unwrap();
        for missing in 0..n {
            let present: Vec<Present> = all
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != missing)
                .map(|(i, b)| Present {
                    index: i,
                    bytes: b.clone(),
                })
                .collect();
            let rec = reconstruct(k, m, 1, present).unwrap();
            assert_eq!(rec, all, "missing shard {missing}");
        }
    }

    #[test]
    fn bit_flip_detected() {
        let (k, m) = (3usize, 2usize);
        let data = vec![vec![1u8, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];
        let mut all = encode(&data, m, 1).unwrap();
        all[0][0] ^= 0x80;
        let present: Vec<Present> = all
            .into_iter()
            .enumerate()
            .map(|(i, b)| Present {
                index: i,
                bytes: b,
            })
            .collect();
        let err = reconstruct(k, m, 1, present).unwrap_err();
        assert!(matches!(err, RsError::ParityMismatch | RsError::Singular));
    }

    #[test]
    fn below_threshold() {
        let present = vec![Present {
            index: 0,
            bytes: vec![1u8],
        }];
        assert_eq!(
            reconstruct(3, 1, 1, present).unwrap_err(),
            RsError::BelowThreshold { have: 1, need: 3 }
        );
    }
}
