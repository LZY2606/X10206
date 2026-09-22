//! Shared data model: manifests, shard rows, and recovery result documents.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Maximum number of candidate combinations enumerated per stripe.
/// Enumeration order is deterministic, so truncation is deterministic too.
pub const MAX_COMBINATIONS: usize = 256;

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(&hasher.finalize())
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

/// Versioned encoding profile registry entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodingProfile {
    pub version: u32,
    pub name: String,
    pub field: String,
    pub matrix: String,
}

pub fn profile_registry(version: u32) -> Option<EncodingProfile> {
    match version {
        1 => Some(EncodingProfile {
            version: 1,
            name: "rs-gf256-vandermonde".to_string(),
            field: "GF(2^8)/0x11d".to_string(),
            matrix: "vandermonde".to_string(),
        }),
        _ => None,
    }
}

/// Object manifest supplied at import time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub name: String,
    pub profile_version: u32,
    pub k: usize,
    pub m: usize,
    pub shard_size: usize,
    pub stripe_count: usize,
    #[serde(default)]
    pub object_digest: Option<String>,
    #[serde(default)]
    pub stripes: Vec<ManifestStripe>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ManifestStripe {
    #[serde(default)]
    pub generation: Option<i64>,
    #[serde(default)]
    pub data_digest: Option<String>,
    /// Expected digest per shard index (index rendered as a string key).
    #[serde(default)]
    pub shards: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ObjectRow {
    pub id: i64,
    pub name: String,
    pub profile_version: u32,
    pub k: usize,
    pub m: usize,
    pub shard_size: usize,
    pub stripe_count: usize,
    pub object_digest: Option<String>,
    pub manifest_json: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ShardRow {
    pub id: i64,
    pub object_id: i64,
    pub stripe: usize,
    pub shard_index: usize,
    pub generation: i64,
    pub source: String,
    pub claimed_digest: String,
    pub actual_digest: String,
    pub length: usize,
    pub quarantined: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct StripeRow {
    pub stripe: usize,
    pub state: String,
    pub result_json: Option<String>,
    pub digest: Option<String>,
    pub committed_at: Option<String>,
}

/// Evidence for a shard candidate that was excluded from every combination.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExcludedEvidence {
    pub shard_id: i64,
    pub shard_index: usize,
    pub generation: i64,
    pub source: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ComboMember {
    pub shard_id: i64,
    pub shard_index: usize,
    pub digest: String,
    pub source: String,
    /// True when this shard fed the decode matrix (first k members).
    pub decode_input: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ShardOutput {
    pub shard_index: usize,
    pub digest: String,
    pub reconstructed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateCombo {
    pub id: usize,
    pub generation: i64,
    pub members: Vec<ComboMember>,
    pub outputs: Vec<ShardOutput>,
    /// Digest of the concatenated reconstructed data shards.
    pub data_digest: String,
    /// Result of checking `data_digest` against the manifest, if provided.
    pub verified: Option<bool>,
    pub matches_manifest_generation: Option<bool>,
    /// Member indices whose stored bytes disagree with the re-encoding.
    pub verification_failures: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Difference {
    pub shard_index: usize,
    /// candidate label (e.g. "C0") -> digest, only for diverging outputs.
    pub digests: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeResult {
    pub stripe: usize,
    pub status: String,
    pub budget_exceeded: bool,
    pub notes: Vec<String>,
    pub candidates: Vec<CandidateCombo>,
    pub excluded: Vec<ExcludedEvidence>,
    pub differences: Vec<Difference>,
}

impl StripeResult {
    pub fn feasible_count(&self) -> usize {
        self.candidates.len()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StripeRunInfo {
    pub stripe: usize,
    /// "computed" | "reused"
    pub action: String,
    pub status: String,
    pub feasible: usize,
    pub budget_exceeded: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecoverReport {
    pub object_id: i64,
    pub stripes: Vec<StripeRunInfo>,
}
