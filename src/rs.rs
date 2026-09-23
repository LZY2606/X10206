//! Versioned Reed-Solomon style erasure coding over GF(2^8).
//!
//! Shard indices 0..k are systematic (identity rows); parity rows are
//! Vandermonde rows evaluated at x = 1..=m. Any k distinct shard indices
//! suffice to reconstruct the whole stripe.

use crate::gf::Gf;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct CodingParams {
    pub version: u32,
    pub k: usize,
    pub m: usize,
    pub shard_size: usize,
}

pub struct Coder {
    pub params: CodingParams,
    gf: Gf,
}

impl Coder {
    pub fn new(params: CodingParams) -> Self {
        assert!(params.k >= 1 && params.m >= 1);
        assert!(params.k + params.m <= 255);
        Coder {
            params,
            gf: Gf::new(),
        }
    }

    pub fn n(&self) -> usize {
        self.params.k + self.params.m
    }

    /// Encoding-matrix row for a shard index.
    fn row(&self, idx: usize) -> Vec<u8> {
        let k = self.params.k;
        if idx < k {
            let mut r = vec![0u8; k];
            r[idx] = 1;
            r
        } else {
            let x = (idx - k + 1) as u8; // 1..=m, distinct and non-zero
            let mut r = Vec::with_capacity(k);
            let mut pow = 1u8;
            for _ in 0..k {
                r.push(pow);
                pow = self.gf.mul(pow, x);
            }
            r
        }
    }

    /// Produce all n shards from k data shards.
    pub fn encode(&self, data: &[Vec<u8>]) -> Vec<Vec<u8>> {
        assert_eq!(data.len(), self.params.k);
        let shard_size = self.params.shard_size;
        let mut out: Vec<Vec<u8>> = data.to_vec();
        for idx in self.params.k..self.n() {
            let row = self.row(idx);
            let mut shard = vec![0u8; shard_size];
            for (j, &coef) in row.iter().enumerate() {
                if coef == 0 {
                    continue;
                }
                for b in 0..shard_size {
                    shard[b] ^= self.gf.mul(coef, data[j][b]);
                }
            }
            out.push(shard);
        }
        out
    }

    /// Given any >= k shards of a stripe, reconstruct every shard index.
    /// Returns None when the system is underdetermined or singular.
    pub fn reconstruct(
        &self,
        available: &BTreeMap<usize, Vec<u8>>,
    ) -> Option<BTreeMap<usize, Vec<u8>>> {
        let k = self.params.k;
        let shard_size = self.params.shard_size;
        if available.len() < k {
            return None;
        }
        let chosen: Vec<usize> = available.keys().take(k).cloned().collect();
        let rows: Vec<Vec<u8>> = chosen.iter().map(|&i| self.row(i)).collect();
        let inv = invert(&self.gf, &rows)?;

        // data[j] = sum_c inv[j][c] * shard[chosen[c]]
        let mut data = vec![vec![0u8; shard_size]; k];
        for j in 0..k {
            for (c, &ch) in chosen.iter().enumerate() {
                let coef = inv[j][c];
                if coef == 0 {
                    continue;
                }
                let s = &available[&ch];
                if s.len() != shard_size {
                    return None;
                }
                for b in 0..shard_size {
                    data[j][b] ^= self.gf.mul(coef, s[b]);
                }
            }
        }

        let mut out = BTreeMap::new();
        for idx in 0..self.n() {
            if let Some(s) = available.get(&idx) {
                out.insert(idx, s.clone());
                continue;
            }
            let row = self.row(idx);
            let mut shard = vec![0u8; shard_size];
            for (j, &coef) in row.iter().enumerate() {
                if coef == 0 {
                    continue;
                }
                for b in 0..shard_size {
                    shard[b] ^= self.gf.mul(coef, data[j][b]);
                }
            }
            out.insert(idx, shard);
        }
        Some(out)
    }
}

/// Gauss-Jordan inversion over GF(2^8). None when singular.
fn invert(gf: &Gf, rows: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    let n = rows.len();
    let mut a: Vec<Vec<u8>> = rows.to_vec();
    let mut inv: Vec<Vec<u8>> = (0..n)
        .map(|i| (0..n).map(|j| if i == j { 1 } else { 0 }).collect())
        .collect();

    for col in 0..n {
        let pivot = (col..n).find(|&r| a[r][col] != 0)?;
        a.swap(col, pivot);
        inv.swap(col, pivot);

        let p = a[col][col];
        if p != 1 {
            let invp = gf.div(1, p);
            for j in 0..n {
                a[col][j] = gf.mul(a[col][j], invp);
                inv[col][j] = gf.mul(inv[col][j], invp);
            }
        }
        for r in 0..n {
            if r == col {
                continue;
            }
            let f = a[r][col];
            if f == 0 {
                continue;
            }
            for j in 0..n {
                a[r][j] ^= gf.mul(f, a[col][j]);
                inv[r][j] ^= gf.mul(f, inv[col][j]);
            }
        }
    }
    Some(inv)
}
