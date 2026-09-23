//! Versioned Reed-Solomon style erasure coding over GF(2^8).
//!
//! Shard layout inside one stripe: indices `0..k` are data shards,
//! indices `k..k+m` are parity shards. Parity row `j` uses coefficients
//! `alpha^(j*i)` for data shard `i`, so any `k` of the `k+m` shards
//! reconstruct the full codeword.

use crate::field;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Params {
    pub version: u32,
    pub k: usize,
    pub m: usize,
    /// fixed shard payload size in bytes (shards are zero-padded to this)
    pub unit: usize,
}

impl Params {
    pub fn total(&self) -> usize {
        self.k + self.m
    }
    /// bytes of object data covered by one stripe
    pub fn stripe_bytes(&self) -> usize {
        self.k * self.unit
    }
    pub fn stripe_count(&self, object_len: u64) -> u64 {
        let sb = self.stripe_bytes() as u64;
        object_len.div_ceil(sb).max(1)
    }
}

/// Registry of versioned encoding parameters.
pub fn params_for_version(version: u32) -> Option<Params> {
    match version {
        1 => Some(Params { version: 1, k: 4, m: 2, unit: 64 }),
        2 => Some(Params { version: 2, k: 3, m: 2, unit: 32 }),
        _ => None,
    }
}

pub fn known_versions() -> Vec<Params> {
    vec![params_for_version(1).unwrap(), params_for_version(2).unwrap()]
}

/// Generator-matrix row for shard `idx` (data rows are unit vectors).
fn mat_row(idx: usize, k: usize) -> Vec<u8> {
    if idx < k {
        (0..k).map(|i| if i == idx { 1 } else { 0 }).collect()
    } else {
        let j = (idx - k) as u32;
        (0..k).map(|i| field::pow_alpha(j * i as u32)).collect()
    }
}

/// Compute the `m` parity shards from `k` data shards.
pub fn encode(data: &[Vec<u8>], p: &Params) -> Vec<Vec<u8>> {
    assert_eq!(data.len(), p.k);
    (0..p.m)
        .map(|j| {
            let mut out = vec![0u8; p.unit];
            for (i, d) in data.iter().enumerate() {
                let coef = field::pow_alpha((j as u32) * (i as u32));
                if coef == 0 {
                    continue;
                }
                for (b, &byte) in d.iter().enumerate().take(p.unit) {
                    out[b] = field::add(out[b], field::mul(coef, byte));
                }
            }
            out
        })
        .collect()
}

/// Reconstruct the full `k+m` codeword from any `>= k` present shards.
/// Returns `None` when fewer than `k` shards are present or the basis
/// matrix is singular (cannot happen for distinct shard indices).
pub fn reconstruct(present: &BTreeMap<usize, Vec<u8>>, p: &Params) -> Option<Vec<Vec<u8>>> {
    if present.len() < p.k {
        return None;
    }
    let basis: Vec<usize> = present.keys().take(p.k).cloned().collect();
    let mat: Vec<Vec<u8>> = basis.iter().map(|&i| mat_row(i, p.k)).collect();
    let inv = field::mat_invert(&mat)?;
    let mut data = vec![vec![0u8; p.unit]; p.k];
    for (row, inv_row) in inv.iter().enumerate() {
        for (col, &src_idx) in basis.iter().enumerate() {
            let coef = inv_row[col];
            if coef == 0 {
                continue;
            }
            let src = &present[&src_idx];
            for b in 0..p.unit {
                data[row][b] = field::add(data[row][b], field::mul(coef, src[b]));
            }
        }
    }
    let mut full = data.clone();
    full.extend(encode(&data, p));
    Some(full)
}

/// Verify that every present shard matches the codeword reconstructed
/// from the first `k` shards (stripe consistency / syndrome check).
pub fn consistent(present: &BTreeMap<usize, Vec<u8>>, p: &Params) -> Option<Vec<Vec<u8>>> {
    let full = reconstruct(present, p)?;
    for (&idx, bytes) in present {
        if full[idx] != *bytes {
            return None;
        }
    }
    Some(full)
}

/// Split an object payload into per-stripe data shards (zero-padded).
pub fn split_object(object: &[u8], p: &Params) -> Vec<Vec<Vec<u8>>> {
    let n = p.stripe_count(object.len() as u64) as usize;
    let mut stripes = Vec::with_capacity(n);
    for s in 0..n {
        let base = s * p.stripe_bytes();
        let mut shards = Vec::with_capacity(p.k);
        for i in 0..p.k {
            let start = (base + i * p.unit).min(object.len());
            let end = (start + p.unit).min(object.len());
            let mut shard = object[start..end].to_vec();
            shard.resize(p.unit, 0);
            shards.push(shard);
        }
        stripes.push(shards);
    }
    stripes
}

/// Full encode of an object: stripes -> shards (data + parity).
pub fn encode_object(object: &[u8], p: &Params) -> Vec<Vec<Vec<u8>>> {
    split_object(object, p)
        .iter()
        .map(|data| {
            let mut full = data.clone();
            full.extend(encode(data, p));
            full
        })
        .collect()
}

/// Assemble object bytes from per-stripe full codewords, trimming to `len`.
pub fn assemble_object(stripes: &[Vec<Vec<u8>>], p: &Params, len: u64) -> Vec<u8> {
    let mut out = Vec::new();
    for full in stripes {
        for shard in full.iter().take(p.k) {
            out.extend_from_slice(shard);
        }
    }
    out.truncate(len as usize);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_any_k() {
        let p = params_for_version(1).unwrap();
        let object: Vec<u8> = (0..200u32).map(|i| (i * 31 % 251) as u8).collect();
        let stripes = encode_object(&object, &p);
        // drop every possible pair of shards in stripe 0
        for drop_a in 0..p.total() {
            for drop_b in (drop_a + 1)..p.total() {
                let mut present = BTreeMap::new();
                for idx in 0..p.total() {
                    if idx != drop_a && idx != drop_b {
                        present.insert(idx, stripes[0][idx].clone());
                    }
                }
                let full = consistent(&present, &p).expect("reconstruct");
                assert_eq!(full, stripes[0], "dropped {drop_a},{drop_b}");
            }
        }
        assert_eq!(assemble_object(&stripes, &p, object.len() as u64), object);
    }
}
