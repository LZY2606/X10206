//! Versioned erasure coding primitives.
//!
//! Version `rs-cauchy-v1` is a systematic Cauchy Reed-Solomon code over
//! GF(2^8): rows 0..k are the identity, row `k + p` for parity index `p`
//! is `[1 / (x_p XOR y_j)]` with `x_p = p as u8`, `y_j = (n - 1 - j) as u8`.
//! With `k + p_count <= 256` every square row-submatrix is invertible.

use crate::gf256::{add, inv, mul};

pub const CODE_VERSION: &str = "rs-cauchy-v1";
pub const MAX_SHARDS: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CodingParams {
    pub data: usize,
    pub parity: usize,
}

impl CodingParams {
    pub fn new(k: usize, p: usize) -> anyhow::Result<Self> {
        if k == 0 {
            anyhow::bail!("data shard count must be non-zero");
        }
        if p == 0 {
            anyhow::bail!("parity shard count must be non-zero");
        }
        if k + p > MAX_SHARDS {
            anyhow::bail!("k + parity must not exceed {MAX_SHARDS}");
        }
        Ok(Self { data: k, parity: p })
    }

    pub fn total(&self) -> usize {
        self.data + self.parity
    }
}

/// Row of the generator matrix for shard index `idx` (0..n), columns 0..k.
pub fn generator_row(params: CodingParams, idx: usize) -> Vec<u8> {
    let CodingParams { data: k, parity: p } = params;
    assert!(idx < k + p, "shard index out of range");
    if idx < k {
        let mut row = vec![0u8; k];
        row[idx] = 1;
        row
    } else {
        let pi = idx - k;
        let x = pi as u8;
        let n = (k + p) as u8;
        (0..k)
            .map(|j| {
                let y = n - 1 - j as u8;
                inv(add(x, y)).expect("cauchy denominator nonzero")
            })
            .collect()
    }
}

/// In-place Gaussian elimination of an augmented matrix `m` (rows x (cols+1)),
/// right-hand side included. Returns `None` if singular.
pub fn solve_in_place(m: &mut [Vec<u8>], k: usize) -> Option<()> {
    for col in 0..k {
        let pivot = (col..m.len()).find(|&r| m[r][col] != 0)?;
        m.swap(col, pivot);
        let pinv = inv(m[col][col])?;
        for c in col..m[col].len() {
            m[col][c] = mul(m[col][c], pinv);
        }
        for r in 0..m.len() {
            if r != col && m[r][col] != 0 {
                let factor = m[r][col];
                for c in col..m[r].len() {
                    m[r][c] ^= mul(factor, m[col][c]);
                }
            }
        }
    }
    Some(())
}

/// Invert a square GF(256) matrix; `None` if singular.
pub fn invert(matrix: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    let k = matrix.len();
    let mut aug: Vec<Vec<u8>> = matrix
        .iter()
        .enumerate()
        .map(|(r, row)| {
            let mut v = row.clone();
            v.extend((0..k).map(|c| if c == r { 1 } else { 0 }));
            v
        })
        .collect();
    solve_in_place(&mut aug, k)?;
    Some(aug.into_iter().map(|row| row[k..].to_vec()).collect())
}

/// Encode `data` (k shards) into n shards.
pub fn encode(params: CodingParams, data: &[Vec<u8>]) -> Vec<Vec<u8>> {
    assert_eq!(data.len(), params.data, "expected k data shards");
    let len = data[0].len();
    assert!(data.iter().all(|s| s.len() == len), "unequal shard lengths");
    let mut out = Vec::with_capacity(params.total());
    for idx in 0..params.total() {
        let row = generator_row(params, idx);
        if idx < params.data {
            out.push(data[idx].clone());
        } else {
            let mut shard = vec![0u8; len];
            for (j, coeff) in row.iter().enumerate() {
                for (t, b) in data[j].iter().enumerate() {
                    shard[t] ^= mul(*coeff, *b);
                }
            }
            out.push(shard);
        }
    }
    out
}

/// Reconstruct all n shards from exactly k available `(index, bytes)` pairs.
/// Returns `Err` if the chosen system is singular (should never happen for
/// valid code parameters) or input lengths disagree.
pub fn reconstruct(
    params: CodingParams,
    available: &[(usize, Vec<u8>)],
) -> anyhow::Result<Vec<Vec<u8>>> {
    let k = params.data;
    let n = params.total();
    if available.len() != k {
        anyhow::bail!("reconstruct needs exactly {k} shards, got {}", available.len());
    }
    let len = available[0].1.len();
    if len == 0 {
        anyhow::bail!("empty shards");
    }
    if available.iter().any(|(_, b)| b.len() != len) {
        anyhow::bail!("available shards have unequal lengths");
    }
    if available.iter().map(|(i, _)| *i).collect::<std::collections::BTreeSet<_>>().len() != k
        || available.iter().any(|(i, _)| *i >= n)
    {
        anyhow::bail!("duplicate or out-of-range shard indices");
    }

    let a: Vec<Vec<u8>> = available.iter().map(|(i, _)| generator_row(params, *i)).collect();
    let a_inv = invert(&a).ok_or_else(|| anyhow::anyhow!("singular coding matrix"))?;

    // data_j = sum_r a_inv[j][r] * avail_r
    let mut data: Vec<Vec<u8>> = (0..k).map(|_| vec![0u8; len]).collect();
    for (r, (_, shard)) in available.iter().enumerate() {
        for (j, coeff) in a_inv.iter().enumerate() {
            if coeff[r] == 0 {
                continue;
            }
            for (t, b) in shard.iter().enumerate() {
                data[j][t] ^= mul(coeff[r], *b);
            }
        }
    }
    Ok(encode(params, &data))
}

/// Check whether an *extra* witness shard (index >= 0, beyond the k used for
/// solving) agrees with the reconstructed data. Returns false on any
/// disagreement. Used as corruption evidence when more than k shards exist.
pub fn witness_agrees(params: CodingParams, all: &[Option<&Vec<u8>>], idx: usize) -> bool {
    let k = params.data;
    let n = params.total();
    if idx >= n {
        return false;
    }
    let Some(witness) = all[idx] else { return false };
    let row = generator_row(params, idx);
    let len = witness.len();
    if (0..k).any(|j| all[j].is_none_or(|s| s.len() != len)) {
        return false;
    }
    for (t, wb) in witness.iter().enumerate() {
        let mut expect = 0u8;
        for (j, coeff) in row.iter().enumerate() {
            expect ^= mul(*coeff, all[j].unwrap()[t]);
        }
        if expect != *wb {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cauchy_squares_are_invertible() {
        // exhaustive for small parameters (MDS: every k-subset invertible)
        for &(k, p) in &[(1usize, 1usize), (2, 1), (3, 2), (4, 3), (5, 3)] {
            let params = CodingParams::new(k, p).unwrap();
            for mask in 0u64..(1u64 << (k + p)) {
                if mask.count_ones() as usize != k {
                    continue;
                }
                let rows: Vec<Vec<u8>> = (0..k + p)
                    .filter(|i| mask & (1 << *i) != 0)
                    .map(|i| generator_row(params, i))
                    .collect();
                assert!(invert(&rows).is_some(), "singular subset {mask:b} for k={k} p={p}");
            }
        }
        // deterministic sampled subsets for larger parameters
        for &(k, p) in &[(10usize, 10usize), (16usize, 16usize), (32usize, 4usize)] {
            let params = CodingParams::new(k, p).unwrap();
            let n = k + p;
            let mut lcg: u64 = 0x1234_5678_9abc_def0;
            for _ in 0..40 {
                let mut picks: Vec<usize> = Vec::new();
                while picks.len() < k {
                    lcg = lcg.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    let i = (lcg >> 33) as usize % n;
                    if !picks.contains(&i) {
                        picks.push(i);
                    }
                }
                let rows: Vec<Vec<u8>> = picks.into_iter().map(|i| generator_row(params, i)).collect();
                assert!(invert(&rows).is_some(), "singular sampled subset for k={k} p={p}");
            }
        }
    }

    #[test]
    fn encode_is_systematic() {
        let params = CodingParams::new(3, 2).unwrap();
        let data = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];
        let shards = encode(params, &data);
        assert_eq!(&shards[..3], &data[..]);
    }

    #[test]
    fn recover_each_missing_subset() {
        let params = CodingParams::new(4, 3).unwrap();
        let data: Vec<Vec<u8>> = (0..4).map(|j| (0..13).map(|t| ((j * 31 + t * 7) ^ 0x5a) as u8).collect()).collect();
        let all = encode(params, &data);
        for mask in 0u64..(1u64 << 7) {
            if mask.count_ones() != 4 {
                continue;
            }
            let avail: Vec<(usize, Vec<u8>)> = (0..7)
                .filter(|i| mask & (1 << *i) != 0)
                .map(|i| (i, all[i].clone()))
                .collect();
            let rebuilt = reconstruct(params, &avail).unwrap();
            assert_eq!(rebuilt, all, "failed for subset {mask:b}");
        }
    }

    #[test]
    fn witness_detects_flip() {
        let params = CodingParams::new(3, 2).unwrap();
        let data = vec![vec![9, 8, 7], vec![6, 5, 4], vec![3, 2, 1]];
        let mut all: Vec<Option<Vec<u8>>> = encode(params, &data).into_iter().map(Some).collect();
        all[4].as_mut().unwrap()[1] ^= 0x01;
        let refs: Vec<Option<&Vec<u8>>> = all.iter().map(|o| o.as_ref()).collect();
        assert!(witness_agrees(params, &refs, 3));
        assert!(!witness_agrees(params, &refs, 4));
    }
}
