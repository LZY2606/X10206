//! Domain types, digest conventions and import-file formats.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Canonical digest rendering: `sha256:<lowercase hex>`.
pub fn digest_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("sha256:{}", hex::encode(h.finalize()))
}

pub fn normalize_digest(s: &str) -> String {
    let trimmed = s.trim().to_ascii_lowercase();
    if let Some(rest) = trimmed.strip_prefix("sha256:") {
        format!("sha256:{}", rest)
    } else {
        format!("sha256:{}", trimmed)
    }
}

/// Top-level import manifest (versioned encoding parameters live per object).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestFile {
    pub manifest_version: u32,
    pub objects: Vec<ObjectSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectSpec {
    pub id: String,
    pub name: String,
    pub coding_version: String,
    pub k: u8,
    pub m: u8,
    /// Bytes per data shard for every stripe except possibly the last one.
    pub stripe_size: u32,
    pub data_len: u64,
    /// Whole-object digest; null means the manifest did not carry it.
    #[serde(default)]
    pub digest: Option<String>,
    pub stripes: Vec<StripeSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeSpec {
    pub index: u32,
    /// Expected generation; fragments of other generations are evidence.
    pub generation: u64,
    /// Manifest-declared shard length for this stripe.
    pub shard_len: u32,
    /// One entry per shard position (length k+m); null = digest unknown.
    #[serde(default)]
    pub shard_digests: Vec<Option<String>>,
}

/// `incoming/fragments.json`: provenance for every received raw fragment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentsLog {
    pub fragments: Vec<FragmentArrival>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentArrival {
    pub fragment_id: String,
    pub object_id: String,
    pub stripe_index: u32,
    pub shard_index: u8,
    pub generation: u64,
    /// Path relative to `incoming/` (normally `fragments/<id>.bin`).
    pub file: String,
    #[serde(default)]
    pub digest: Option<String>,
    pub source: String,
    pub received_at: String,
}

/// A raw fragment with its provenance, as kept after import.
#[derive(Debug, Clone, Serialize)]
pub struct FragmentRecord {
    pub id: i64,
    pub object_id: String,
    pub stripe_index: u32,
    pub shard_index: u8,
    pub generation: u64,
    pub digest: Option<String>,
    pub source: String,
    pub received_at: String,
    pub raw_path: String,
    pub length: usize,
    pub isolated: bool,
}
