//! On-disk manifest types and database row models.

use serde::{Deserialize, Serialize};

use crate::coding::CodingParams;

/// Top-level manifest file (`manifest.json`) shipped beside the fragments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestFile {
    pub manifest_version: u32,
    #[serde(default)]
    pub object_id: Option<String>,
    pub name: String,
    pub coding: CodingParams,
    /// Total payload length in bytes (stripes trim zero padding).
    pub data_len: u64,
    /// Optional digest over the concatenated payload after padding is trimmed.
    #[serde(default)]
    pub object_digest: Option<String>,
    pub stripes: Vec<StripeSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeSpec {
    pub index: u32,
    /// Fixed shard length used for coding on this stripe.
    pub shard_len: u32,
    /// True payload bytes living on this stripe (<= k * shard_len).
    pub data_len: u32,
    /// Digest over the concatenated, fixed-length rebuilt data shards.
    #[serde(default)]
    pub digest: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ObjectRow {
    pub id: String,
    pub name: String,
    pub coding_version: String,
    pub k: i64,
    pub m: i64,
    pub data_len: i64,
    pub object_digest: Option<String>,
    pub status: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct StripeRow {
    pub id: String,
    pub object_id: String,
    pub stripe_index: i64,
    pub shard_len: i64,
    pub data_len: i64,
    pub expected_digest: Option<String>,
    pub recovered_digest: Option<String>,
    pub status: String,
    pub committed: bool,
    pub commit_id: Option<String>,
    pub ambiguous: bool,
    pub budget_exceeded: bool,
    pub detail: String,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CandidateRow {
    pub id: String,
    pub stripe_id: String,
    pub shard_index: i64,
    pub source: String,
    pub generation: i64,
    pub received_at: i64,
    pub length: i64,
    pub claimed_digest: Option<String>,
    pub recomputed_digest: String,
    pub digest_ok: bool,
    pub length_ok: bool,
    pub usable: bool,
    pub blob_path: String,
}

/// One piece of corruption / exclusion evidence attached to a plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Evidence {
    pub kind: String,
    pub shard_index: Option<i64>,
    pub candidate_id: Option<String>,
    pub source: Option<String>,
    pub generation: Option<i64>,
    pub message: String,
}

/// Serializable description of a participating shard.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Participant {
    pub shard_index: i64,
    pub candidate_id: String,
    pub source: String,
    pub generation: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlanRow {
    pub id: String,
    pub stripe_id: String,
    pub rank: i64,
    pub participants: Vec<Participant>,
    pub output_digest: String,
    pub verifies: bool,
    pub generation_coherent: bool,
    pub selected: bool,
    pub evidence: Vec<Evidence>,
    pub output_blob: String,
}
