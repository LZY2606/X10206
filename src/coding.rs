//! Reed-Solomon style erasure coding on GF(256).
//!
//! Layout is systematic: rows `0..k` are data shards, rows `k..k+m` are
//! parity shards.  The generator uses a Cauchy block
//!
//! ```text
//!     G = [ I_k          ]
//!         [ C(Y, X)      ]   X = 0..k-1, Y = k..k+m-1
//! ```
//!
//! so any `k` rows form an invertible matrix and a stripe tolerates up to
//! `m` missing/corrupt shards.

use crate::gf::GfTables;

/// Cauchy entry `1 / (x XOR y)`; XOR is addition in GF(256).
#[inline]
fn cauchy(t: &GfTables, x: u8, y: u8) -> u8 {
    debug_assert_ne!(x, y);
    t.inv(x ^ y)
}

/// Full generator matrix with `n = k + m` rows and `k` columns.
pub fn generator(t: &GfTables, k: usize, n: usize) -> Vec<Vec<u8>> {
    let mut g = vec![vec![0u8; k]; n];
    for i in 0..k {
        g[i][i] = 1;
    }
    for row in k..n {
        for col in 0..k {
            g[row][col] = cauchy(t, col as u8, row as u8);
        }
    }
    g
}

/// Encode `k` data shards into `k + m` shards (data shards pass through).
pub fn encode(t: &GfTables, data: &[Vec<u8>], k: usize, m: usize) -> Vec<Vec<u8>> {
    assert_eq!(data.len(), k);
    let size = data.first().map(|d| d.len()).unwrap_or(0);
    for d in data {
        assert_eq!(d.len(), size, "data shard lengths must agree");
    }
    let n = k + m;
    let g = generator(t, k, n);
    let mut out = Vec::with_capacity(n);
    for row in 0..n {
        if row < k {
            out.push(data[row].clone());
            continue;
        }
        let mut buf = vec![0u8; size];
        for (col, shard) in data.iter().enumerate() {
            let coef = g[row][col];
            if coef == 0 {
                continue;
            }
            for (b, &v) in buf.iter_mut().zip(shard) {
                *b ^= t.mul(coef, v);
            }
        }
        out.push(buf);
    }
    out
}

/// Invert a `k x k` GF matrix via Gauss-Jordan elimination with an identity
/// block. Returns `None` when the matrix is singular.
pub fn invert(t: &GfTables, a: &[Vec<u8>], k: usize) -> Option<Vec<Vec<u8>>> {
    let mut m = vec![vec![0u8; 2 * k]; k];
    for r in 0..k {
        m[r][..k].copy_from_slice(&a[r]);
        m[r][k + r] = 1;
    }
    for col in 0..k {
        let pivot = (col..k).find(|&r| m[r][col] != 0)?;
        m.swap(col, pivot);
        let p = m[col][col];
        if p != 1 {
            let pi = t.inv(p);
            for v in m[col].iter_mut() {
                *v = t.mul(*v, pi);
            }
        }
        for r in 0..k {
            if r != col && m[r][col] != 0 {
                let f = m[r][col];
                for c in 0..2 * k {
                    m[r][c] ^= t.mul(f, m[col][c]);
                }
            }
        }
    }
    Some(m.into_iter().map(|row| row[k..].to_vec()).collect())
}

/// Reconstruct missing shard rows from any `k` present rows.
///
/// `present` maps row index -> shard bytes. All present shards must have the
/// same length. Returns a map containing *all* rows (present ones are echoed
/// back, missing ones are rebuilt).
pub fn reconstruct<'a>(
    t: &GfTables,
    present: &[(usize, &'a [u8])],
    k: usize,
    n: usize,
) -> Option<Vec<Vec<u8>>> {
    if present.len() != k {
        return None;
    }
    let size = present.first()?.1.len();
    if size == 0 || present.iter().any(|(_, b)| b.len() != size) {
        return None;
    }
    let rows: Vec<usize> = present.iter().map(|(r, _)| *r).collect();
    if rows.iter().any(|r| *r >= n) || rows.iter().collect::<std::collections::BTreeSet<_>>().len() != k {
        return None;
    }
    let g = generator(t, k, n);
    let sub: Vec<Vec<u8>> = rows.iter().map(|&r| g[r].clone()).collect();
    let inv = invert(t, &sub, k)?;

    let mut all = vec![None; n];
    for (r, bytes) in present {
        all[*r] = Some(bytes.to_vec());
    }

    // Recover the k data columns first.
    let mut data = vec![vec![0u8; size]; k];
    for i in 0..k {
        let dst = &mut data[i];
        for (slot, (_, bytes)) in inv[i].iter().zip(present) {
            if *slot == 0 {
                continue;
            }
            for (b, &v) in dst.iter_mut().zip(bytes.iter()) {
                *b ^= t.mul(*slot, v);
            }
        }
    }
    for (i, d) in data.iter().enumerate() {
        all[i] = Some(d.clone());
    }
    // Derive every still-missing (parity) row from the generator.
    for row in 0..n {
        if all[row].is_some() {
            continue;
        }
        let mut buf = vec![0u8; size];
        for col in 0..k {
            let coef = g[row][col];
            if coef == 0 {
                continue;
            }
            for (b, &v) in buf.iter_mut().zip(data[col].iter()) {
                *b ^= t.mul(coef, v);
            }
        }
        all[row] = Some(buf);
    }
    Some(all.into_iter().map(|x| x.unwrap()).collect())
}

/// Check whether a set of present rows is mutually consistent under the code.
///
/// With at least `k` rows we rebuild from the first `k` and compare the rest.
/// With fewer rows the code cannot prove anything, so the set is accepted
/// (feasibility is decided separately by the caller).
pub fn set_consistent(t: &GfTables, rows: &[(usize, &[u8])], k: usize, n: usize) -> bool {
    if rows.len() < k {
        return rows.iter().all(|(r, b)| *r < n && !b.is_empty());
    }
    let chosen: Vec<(usize, &[u8])> = rows.iter().take(k).map(|(r, b)| (*r, *b)).collect();
    let chosen_len = chosen.first().map(|(_, b)| b.len()).unwrap_or(0);
    if chosen_len == 0 || chosen.iter().any(|(_, b)| b.len() != chosen_len) {
        return false;
    }
    let rebuilt = match reconstruct(t, &chosen, k, n) {
        Some(v) => v,
        None => return false,
    };
    rows.iter().all(|(r, b)| rebuilt.get(*r).map(|v| v.as_slice()) == Some(*b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_and_recover_each_row() {
        let t = GfTables::init();
        let (k, m, n) = (3usize, 2usize, 5usize);
        let data = vec![vec![1u8, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];
        let shards = encode(&t, &data, k, m);
        for missing in 0..n {
            let present: Vec<(usize, &[u8])> = (0..n)
                .filter(|&r| r != missing)
                .take(k)
                .map(|r| (r, shards[r].as_slice()))
                .collect();
            let rebuilt = reconstruct(&t, &present, k, n).unwrap();
            assert_eq!(rebuilt[missing], shards[missing]);
        }
        assert!(set_consistent(
            &t,
            &shards.iter().enumerate().map(|(r, b)| (r, b.as_slice())).collect::<Vec<_>>(),
            k,
            n
        ));
        let mut bad = shards.clone();
        bad[4][1] ^= 0x01;
        let rows: Vec<(usize, &[u8])> = bad.iter().enumerate().map(|(r, b)| (r, b.as_slice())).collect();
        assert!(!set_consistent(&t, &rows, k, n));
    }
}
