use serde::{Deserialize, Serialize};

pub type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportShard {
    #[serde(default)]
    pub block_index: Option<i64>,
    #[serde(default)]
    pub stripe_index: Option<i64>,
    pub kind: String,
    pub index: i64,
    #[serde(default)]
    pub generation: Option<i64>,
    pub source_id: String,
    #[serde(default)]
    pub data_b64: Option<String>,
    #[serde(default)]
    pub bytes_hex: Option<String>,
    #[serde(default)]
    pub digest: Option<String>,
    #[serde(default)]
    pub shard_len: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportRequest {
    pub source_id: String,
    #[serde(default)]
    pub source_label: Option<String>,
    #[serde(default)]
    pub manifest_b64: Option<String>,
    #[serde(default)]
    pub manifest_json: Option<serde_json::Value>,
    pub object_id: String,
    #[serde(default)]
    pub object_label: Option<String>,
    pub version: String,
    pub k: i64,
    pub m: i64,
    pub stripe_count: i64,
    pub shard_len: i64,
    #[serde(default)]
    pub data_len: Option<i64>,
    #[serde(default)]
    pub object_digest: Option<String>,
    #[serde(default)]
    pub shard_generation: Option<i64>,
    pub shards: Vec<ImportShard>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceView {
    pub source_id: String,
    pub label: String,
    pub isolated: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShardView {
    pub id: i64,
    pub stripe_index: i64,
    pub shard_index: i64,
    pub generation: i64,
    pub source_id: String,
    pub source_label: String,
    pub claimed_digest: String,
    pub actual_digest: String,
    pub actual_len: i64,
    pub digest_ok: bool,
    pub length_ok: bool,
    pub in_range: bool,
    pub isolated: bool,
    pub duplicate_slot: bool,
    pub health: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SolutionView {
    pub id: i64,
    pub digest: String,
    pub witness_ids: Vec<i64>,
    pub witness_indices: Vec<i64>,
    pub generated_indices: Vec<i64>,
    pub excluded_ids: Vec<i64>,
    pub excluded_reasons: Vec<String>,
    pub cross_check_failures: Vec<i64>,
    pub alternative_ids: Vec<i64>,
    pub consistent_ids: Vec<i64>,
    pub search_complete: bool,
    pub trusted: bool,
    pub selected: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StripeView {
    pub object_id: String,
    pub stripe_index: i64,
    pub generation: i64,
    pub state: String,
    pub trust_state: String,
    pub data_digest: String,
    pub candidate_count: i64,
    pub unique_output_count: i64,
    pub solutions: Vec<SolutionView>,
    pub selected_solution_id: Option<i64>,
    pub committed_solution_id: Option<i64>,
    pub search_budget: i64,
    pub output_path: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectView {
    pub object_id: String,
    pub label: String,
    pub version: String,
    pub k: i64,
    pub m: i64,
    pub n: i64,
    pub stripe_count: i64,
    pub shard_len: i64,
    pub data_len: Option<i64>,
    pub object_digest: String,
    pub actual_object_digest: String,
    pub digest_ok: bool,
    pub committed_stripes: i64,
    pub recoverable_stripes: i64,
    pub ambiguous_stripes: i64,
    pub failed_stripes: i64,
    pub progress_percent: f64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DetailResponse {
    pub object: ObjectView,
    pub sources: Vec<SourceView>,
    pub stripes: Vec<StripeView>,
    pub shards: Vec<ShardView>,
}
