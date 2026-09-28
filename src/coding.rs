//! Version 1 Reed-Solomon over GF(2^8).
//!
//! Encoding matrix:
//!   rows 0..k      -> identity (data shards)
//!   rows k..k+m    -> Cauchy rows with y = k + j + 1, x = i
//!
//! Cauchy entries 1/(x XOR y) with x in 0..k, y in {k+1..k+m} guarantee
//! that every k-row selection of the n=k+m rows is invertible.

use crate::gf;

pub fn entry(row: usize, col: usize, k: usize) -> u8 {
    if row < k {
        if col == row { 1 } else { 0 }
    } else {
        let y = (row + 1) as u8;
        let x = col as u8;
        gf::inv(x ^ y)
    }
}

pub fn matrix(n: usize, k: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|r| (0..k).map(|c| entry(r, c, k)).collect())
        .collect()
}

/// Invert a square matrix over GF(2^8). Returns None if singular.
pub fn invert(a: &[Vec<u8>]) -> Option<Vec<Vec<u8>> {
    let s = a.len();
    let mut m: Vec<Vec<u8>> = vec![vec![0u8; 2 * s]; s];
    for r in 0..s {
        m[r][..s].copy_from_slice(&a[r]);
        m[r][s + r] = 1;
    }
    for col in 0..s {
        let pivot = (col..s).find(|&r| m[r][col] != 0)?;
        m.swap(col, pivot);
        let p = m[col][col];
        if p != 1 {
            let pinv = gf::inv(p);
            for v in m[col].iter_mut() {
                *v = gf::mul(*v, pinv);
            }
        }
        for r in 0..s {
            if r != col && m[r][col] != 0 {
                let f = m[r][col];
                for c in 0..2 * s {
                    let sub = gf::mul(f, m[col][c]);
                    m[r][c] ^= sub;
                }
            }
        }
    }
    Some(m.into_iter().map(|mut row| row.split_off(s)).collect())
}

/// Rebuild all n shards from any k available shards.
///
/// `rows[i]` is the encoding row index of `parts[i]`, `0..n`.
/// Returns all n shards of `shard_size` bytes, or None if the selected
/// submatrix is singular (should never happen with the Cauchy layout).
pub fn reconstruct(
    rows: &[usize],
    parts: &[Vec<u8>],
    k: usize,
    n: usize,
    shard_size: usize,
) -> Option<Vec<Vec<u8>>> {
    if rows.len() < k || parts.len() < k {
        return None;
    }
    let rows = &rows[..k];
    let parts = &parts[..k];
    let enc = matrix(n, k);
    let sub: Vec<Vec<u8>> = rows.iter().map(|&r| enc[r].clone()).collect();
    let inv = invert(&sub)?;

    let mut data: Vec<Vec<u8>> = (0..k).map(|_| vec![0u8; shard_size]).collect();
    for i in 0..k {
        for j in 0..k {
            let coef = inv[i][j];
            if coef == 0 {
                continue;
            }
            let p = &parts[j];
            for (idx, &b) in p.iter().enumerate() {
                data[i][idx] ^= gf::mul(coef, b);
            }
        }
    }
    let mut out = vec![vec![0u8; shard_size]; n];
    for r in 0..n {
        for c in 0..k {
            let coef = enc[r][c];
            if coef == 0 {
                continue;
            }
            for idx in 0..shard_size {
                out[r][idx] ^= gf::mul(coef, data[c][idx]);
            }
        }
    }
    Some(out)
}

/// Encode an object into exactly `num_stripes * (k+m)` shards of
/// `shard_size` bytes (last stripe padded with zeros).
pub fn encode_object(
    obj: &[u8],
    k: usize,
    m: usize,
    shard_size: usize,
) -> (usize, Vec<Vec<u8>>) {
    let n = k + m;
    let stripe_bytes = k * shard_size;
    let num_stripes = obj.len().div_ceil(stripe_bytes).max(1);
    let enc = matrix(n, k);
    let mut shards = vec![vec![0u8; shard_size]; num_stripes * n];
    for s in 0..num_stripes {
        let off = s * stripe_bytes;
        let mut data: Vec<Vec<u8>> = (0..k).map(|_| vec![0u8; shard_size]).collect();
        for i in 0..stripe_bytes {
            if let Some(&b) = obj.get(off + i) {
                data[i / shard_size][i % shard_size] = b;
            }
        }
        for r in 0..n {
            for c in 0..k {
                let coef = enc[r][c];
                if coef == 0 {
                    continue;
                }
                for idx in 0..shard_size {
                    shards[s * n + r][idx] ^= gf::mul(coef, data[c][idx]);
                }
            }
        }
    }
    (num_stripes, shards)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf_mul_identity() {
        assert_eq!(gf::mul(0x53, 1), 0x53);
        assert_eq!(gf::mul(0x53, gf::inv(0x53)), 1);
        for x in 1u16..256 {
            let x = x as u8;
            assert_eq!(gf::mul(x, gf::inv(x)), 1);
        }
    }

    #[test]
    fn invert_cauchy_selections() {
        let (k, m) = (3usize, 3usize);
        let n = k + m;
        let enc = matrix(n, k);
        // every k-subset of rows must be invertible
        fn combos(n: usize, k: usize, start: usize, cur: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
            if cur.len() == k {
                out.push(cur.clone());
                return;
            }
            for r in start..n {
                cur.push(r);
                combos(n, k, r + 1, cur, out);
                cur.pop();
            }
        }
        let mut out = Vec::new();
        combos(n, k, 0, &mut Vec::new(), &mut out);
        for rows in out {
            let sub: Vec<Vec<u8>> = rows.iter().map(|&r| enc[r].clone()).collect();
            assert!(invert(&sub).is_some(), "singular {:?}", rows);
        }
    }

    #[test]
    fn encode_recover_roundtrip() {
        let obj = b"the stripe recovery pod verifies every rebuilt byte".to_vec();
        let (k, m, size) = (3, 3, 8);
        let (ns, shards) = encode_object(&obj, k, m, size);
        assert!(ns >= 2);
        // keep rows {0, 2, 4} (1 data, 2 parity) for stripe 0
        let keep = [0usize, 2, 4];
        let rows: Vec<usize> = keep.to_vec();
        let parts: Vec<Vec<u8>> = keep.iter().map(|&r| shards[r].clone()).collect();
        let rebuilt = reconstruct(&rows, &parts, k, k + m, size).unwrap();
        for r in 0..k + m {
            assert_eq!(rebuilt[r], shards[r]);
        }
    }
}
