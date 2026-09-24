//! Shared domain types, manifest format and digest helpers.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Versioned manifest envelope. The version gates decoding semantics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// Manifest schema version; currently only `1` is supported.
    pub manifest_version: u32,
    pub object_id: String,
    pub object_digest: String,
    pub object_len: usize,
    /// Erasure-code parameter version. Different values may coexist on disk
    /// after a partial write; the bay treats them as different generations.
    pub generation: u64,
    pub data_shards: usize,
    pub parity_shards: usize,
    pub shard_len: usize,
    pub stripes: Vec<StripeSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeSpec {
    pub stripe_idx: usize,
    /// Logical row indices into the stripe (`0..data+parity`).
    pub shard_indexes: Vec<usize>,
    /// Digest of each shard's raw bytes, aligned with `shard_indexes`.
    pub shard_digests: Vec<String>,
    /// Logical data offset of this stripe inside the object.
    pub data_offset: usize,
    pub data_len: usize,
}

/// Sidecar digest of one received fragment, as imported (not necessarily
/// trustworthy - the bay verifies it against the manifest).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentDigest {
    pub object_id: String,
    pub stripe_idx: usize,
    pub shard_index: usize,
    pub generation: Option<u64>,
    pub sha256: String,
    pub len: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestBundle {
    pub manifests: Vec<Manifest>,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Recompute the object digest the same way the exporter does: concatenated
/// logical data of all stripes in order.
pub fn object_digest(stripe_data_in_order: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    for part in stripe_data_in_order {
        h.update(part);
    }
    hex::encode(h.finalize())
}

/// Health classification used by the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Health {
    Missing = 0,
    Suspect = 1,
    Degraded = 2,
    Healthy = 3,
}

impl Health {
    pub fn as_str(self) -> &'static str {
        match self {
            Health::Missing => "missing",
            Health::Suspect => "suspect",
            Health::Degraded => "degraded",
            Health::Healthy => "healthy",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BayError {
    #[error("sqlite error: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("io error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("bad manifest: {0}")]
    BadManifest(String),
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("storage fault injected ({0})")]
    InjectedFault(&'static str),
}

pub type BayResult<T> = Result<T, BayError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_stable() {
        assert_eq!(sha256_hex(b"abc").len(), 64);
        assert_eq!(sha256_hex(b""), sha256_hex(&[]));
        assert_eq!(object_digest(&[b"ab", b"c"]), sha256_hex(b"abc"));
    }
}
