use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManifestFile {
    pub schema: String,
    pub object_id: String,
    pub object_size: usize,
    pub generation: i64,
    pub data_shards: usize,
    pub parity_shards: usize,
    pub stripe_size: usize,
    pub object_sha256: String,
    pub stripes: Vec<ManifestStripe>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManifestStripe {
    pub index: usize,
    pub data_len: usize,
    pub sha256: String,
    pub shards: Vec<ManifestShard>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManifestShard {
    pub index: usize,
    pub generation: i64,
    pub length: usize,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ObjectView {
    pub id: i64,
    pub object_id: String,
    pub generation: i64,
    pub source: String,
    pub object_sha256: String,
    pub object_size: usize,
    pub data_shards: usize,
    pub parity_shards: usize,
    pub stripe_size: usize,
    pub stripe_count: usize,
    pub committed_stripes: i64,
    pub healthy_fragments: i64,
    pub excluded_fragments: i64,
    pub status: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct StripeView {
    pub id: i64,
    pub object_id: String,
    pub index: usize,
    pub data_len: usize,
    pub expected_digest: String,
    pub status: String,
    pub committed_at: Option<i64>,
    pub valid_answers: i64,
    pub distinct_outputs: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct FragmentView {
    pub id: i64,
    pub object_id: String,
    pub stripe_index: usize,
    pub shard_index: Option<usize>,
    pub shard_generation: Option<i64>,
    pub received_from: String,
    pub relative_path: String,
    pub raw_path: String,
    pub byte_length: i64,
    pub actual_sha256: String,
    pub claimed_sha256: Option<String>,
    pub expected_sha256: Option<String>,
    pub health: String,
    pub evidence: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct RunView {
    pub id: i64,
    pub object_id: String,
    pub isolated_sources: Vec<String>,
    pub budget: i64,
    pub status: String,
    pub created_at: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReconstructionView {
    pub id: i64,
    pub run_id: i64,
    pub object_id: String,
    pub stripe_index: usize,
    pub ordinal: i64,
    pub valid: bool,
    pub combination_key: String,
    pub participating: serde_json::Value,
    pub excluded_evidence: serde_json::Value,
    pub recomputed_digests: serde_json::Value,
    pub discrepancy: String,
}
