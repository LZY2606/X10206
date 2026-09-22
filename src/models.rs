use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Versioned erasure-coding parameters carried by an object manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub object_id: String,
    pub version: u32,
    pub n: usize,
    pub k: usize,
    pub stripe_size: usize,
    pub stripe_count: usize,
    /// Highest generation that should be considered the complete write.
    #[serde(default)]
    pub generation: u64,
    /// Optional object digest over canonical data: all stripes, each exactly
    /// `stripe_size` bytes, concatenated in stripe order.
    #[serde(default)]
    pub object_digest: Option<String>,
    /// Expected per-shard digests, keyed `stripe_index:shard_index`.
    #[serde(default)]
    pub shard_digests: Option<std::collections::HashMap<String, String>>,
}

impl Manifest {
    pub fn expected_shard_digest(&self, stripe: usize, shard: usize) -> Option<&str> {
        self.shard_digests
            .as_ref()
            .and_then(|m| m.get(&format!("{stripe}:{shard}")))
            .map(|s| s.as_str())
    }

    pub fn valid(&self) -> Result<(), String> {
        if self.object_id.trim().is_empty() {
            return Err("manifest missing object_id".into());
        }
        if self.k == 0 || self.n < self.k || self.n > 256 {
            return Err(format!("invalid coding params n={} k={}", self.n, self.k));
        }
        if self.stripe_size == 0 || self.stripe_count == 0 {
            return Err("manifest requires positive stripe_size and stripe_count".into());
        }
        Ok(())
    }
}

/// One received fragment offered for import. Original bytes and the source
/// are preserved verbatim; the store never mutates them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentInput {
    pub object_id: String,
    pub version: u32,
    pub generation: u64,
    pub stripe_index: usize,
    pub shard_index: usize,
    pub source: String,
    pub bytes: String,
    /// Hex encoding of `bytes`: "hex" (default) or "base64".
    #[serde(default)]
    pub encoding: String,
}

#[derive(Debug, Clone)]
pub struct ImportAnomaly {
    pub code: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FragmentRecord {
    pub id: i64,
    pub object_id: String,
    pub version: u32,
    pub generation: u64,
    pub stripe_index: usize,
    pub shard_index: usize,
    pub source: String,
    pub length: usize,
    pub actual_digest: String,
    pub expected_digest: Option<String>,
    pub digest_ok: bool,
    pub state: String,
    pub excluded_reason: Option<String>,
}

/// Canonical object data is all stripes (each `stripe_size` bytes) concatenated.
pub fn canonical_object_digest(manifest: &Manifest, stripe_blobs: &[Vec<u8>]) -> String {
    let mut h = Sha256::new();
    assert_eq!(stripe_blobs.len(), manifest.stripe_count);
    for blob in stripe_blobs {
        assert_eq!(blob.len(), manifest.stripe_size);
        h.update(blob);
    }
    hex::encode(h.finalize())
}
