use serde::{Deserialize, Serialize};

use crate::coding::SlotKind;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum StoredShardKind {
    Data,
    Parity,
}

impl From<StoredShardKind> for SlotKind {
    fn from(value: StoredShardKind) -> Self {
        match value {
            StoredShardKind::Data => SlotKind::Data,
            StoredShardKind::Parity => SlotKind::Parity,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestShard {
    pub stripe: usize,
    pub kind: StoredShardKind,
    pub index: usize,
    #[serde(default)]
    pub generation: Option<u64>,
    #[serde(default)]
    pub length: Option<usize>,
    #[serde(default)]
    pub digest: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: String,
    pub code_version: String,
    pub object_id: String,
    #[serde(default)]
    pub object_size: u64,
    #[serde(default)]
    pub object_digest: Option<String>,
    #[serde(default = "default_generation")]
    pub generation: u64,
    pub data_shards: usize,
    pub parity_shards: usize,
    pub shard_size: usize,
    pub stripe_count: usize,
    #[serde(default)]
    pub shards: Vec<ManifestShard>,
}

fn default_generation() -> u64 {
    1
}

#[derive(Debug, Clone, Serialize)]
pub struct FragmentView {
    pub id: i64,
    pub object_id: String,
    pub source: String,
    pub stripe: usize,
    pub kind: StoredShardKind,
    pub index: usize,
    pub generation: u64,
    pub received_digest: Option<String>,
    pub expected_digest: Option<String>,
    pub actual_digest: String,
    pub declared_length: Option<usize>,
    pub actual_length: usize,
    pub raw_path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Participant {
    pub fragment_id: i64,
    pub source: String,
    pub kind: StoredShardKind,
    pub index: usize,
    pub generation: u64,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ShardOutput {
    pub kind: StoredShardKind,
    pub index: usize,
    pub digest: String,
    pub length: usize,
    pub rebuilt: bool,
    pub expected_digest: Option<String>,
    pub trusted: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Evidence {
    pub severity: String,
    pub reason: String,
    pub message: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fragment_ids: Vec<i64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CandidateSolution {
    pub id: String,
    pub generation: u64,
    pub participants: Vec<Participant>,
    pub outputs: Vec<ShardOutput>,
    pub object_digest: Option<String>,
    pub locally_trusted: bool,
    pub object_trusted: bool,
    pub excluded_evidence: Vec<Evidence>,
    pub differences: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CandidateOption {
    pub generation: u64,
    pub digest: String,
    pub sources: Vec<String>,
    pub fragment_ids: Vec<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StripeReport {
    pub stripe: usize,
    pub status: String,
    pub required_for_threshold: usize,
    pub eligible_shard_slots: usize,
    pub candidates: Vec<CandidateOption>,
    pub solutions: Vec<CandidateSolution>,
    pub evidence: Vec<Evidence>,
    pub committed_solution_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunReport {
    pub run_id: i64,
    pub object_id: String,
    pub state: String,
    pub code_version: String,
    pub data_shards: usize,
    pub parity_shards: usize,
    pub stripe_count: usize,
    pub shard_size: usize,
    pub object_digest_expected: Option<String>,
    pub object_digest_recomputed: Option<String>,
    pub isolated_sources: Vec<String>,
    pub stripes: Vec<StripeReport>,
    pub search_budget: usize,
    pub search_attempted: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ObjectStatus {
    pub object_id: String,
    pub manifest: Manifest,
    pub fragments: Vec<FragmentView>,
    pub latest_run: Option<RunReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatusResponse {
    pub objects: Vec<ObjectStatus>,
    pub data_dir: String,
}
