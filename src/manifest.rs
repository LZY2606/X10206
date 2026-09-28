//! Versioned manifest / per-block sidecar format.
//!
//! Version 1: Reed-Solomon over GF(2^8), n=k+m rows, identity data rows
//! and Cauchy parity rows (see `crate::coding`).

use serde::{Deserialize, Serialize};

pub const CODE_V1: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct ManifestStripeShard {
    pub stripe_idx: usize,
    pub row: usize,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Manifest {
    pub code_version: u32,
    pub object_id: String,
    pub generation: u64,
    pub k: usize,
    pub m: usize,
    pub shard_size: usize,
    pub object_size: usize,
    pub object_digest: String,
    pub stripes: Vec<ManifestStripeShard>,
}

impl Manifest {
    pub fn n(&self) -> usize {
        self.k + self.m
    }
    pub fn num_stripes(&self) -> usize {
        self.object_size.div_ceil(self.k * self.shard_size).max(1)
    }
    /// Real data byte count inside a stripe (last stripe is shorter).
    pub fn stripe_data_len(&self, idx: usize) -> usize {
        let cap = self.k * self.shard_size;
        let start = idx * cap;
        self.object_size.saturating_sub(start).min(cap)
    }
    pub fn digest_for(&self, stripe_idx: usize, row: usize) -> Option<&str> {
        self.stripes
            .iter()
            .find(|s| s.stripe_idx == stripe_idx && s.row == row)
            .map(|s| s.digest.as_str())
    }
    /// True when this manifest's stripe list covers exactly its own
    /// claimed geometry. A mismatch marks the object length-suspect.
    pub fn geometry_consistent(&self) -> bool {
        if self.code_version != CODE_V1 {
            return false;
        }
        if self.k == 0 || self.m == 0 || self.shard_size == 0 {
            return false;
        }
        let expected = self.num_stripes() * self.n();
        if self.stripes.len() != expected {
            return false;
        }
        for s in &self.stripes {
            if s.stripe_idx >= self.num_stripes() || s.row >= self.n() {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Sidecar {
    pub shard_id: String,
    pub object_id: String,
    pub generation: u64,
    pub stripe_idx: usize,
    pub row: usize,
    pub code_version: u32,
    pub size: usize,
    pub digest: String,
    pub source: String,
}
