use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManifestShardIn {
    pub stripe_no: i64,
    pub shard_index: i64,
    pub generation: i64,
    pub digest: String,
    pub length: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManifestImport {
    pub name: String,
    pub profile_version: i64,
    pub stripe_count: i64,
    pub shard_len: i64,
    #[serde(default)]
    pub object_digest: Option<String>,
    #[serde(default)]
    pub shards: Vec<ManifestShardIn>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShardImport {
    pub stripe_no: i64,
    pub shard_index: i64,
    pub generation: i64,
    pub source: String,
    pub data_hex: String,
    #[serde(default)]
    pub declared_digest: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProfileRow {
    pub version: i64,
    pub k: i64,
    pub m: i64,
    pub field_bits: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ObjectRow {
    pub id: i64,
    pub name: String,
    pub profile_version: i64,
    pub stripe_count: i64,
    pub shard_len: i64,
    pub object_digest: Option<String>,
    pub created_at: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct FragmentRow {
    pub id: i64,
    pub object_id: i64,
    pub stripe_no: i64,
    pub shard_index: i64,
    pub generation: i64,
    pub source: String,
    pub data: Vec<u8>,
    pub digest: String,
    pub declared_digest: Option<String>,
    pub declared_len: Option<i64>,
    pub status: String,
    pub imported_at: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct RunRow {
    pub id: i64,
    pub object_id: i64,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    pub status: String,
    pub note: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SolutionRow {
    pub id: i64,
    pub run_id: i64,
    pub object_id: i64,
    pub stripe_no: i64,
    pub generation: i64,
    pub variant_no: i64,
    pub participants: String,
    pub excluded: String,
    pub output_digest: String,
    pub diff_note: Option<String>,
    pub state: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Participant {
    pub shard_index: i64,
    pub origin: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fragment_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub digest: String,
    pub dup_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Excluded {
    pub fragment_id: i64,
    pub shard_index: i64,
    pub source: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StripeReport {
    pub stripe_no: i64,
    pub status: String,
    pub detail: String,
    pub variants: usize,
    pub budget_exceeded: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunSummary {
    pub run_id: i64,
    pub object_id: i64,
    pub stripes: Vec<StripeReport>,
    pub object_digest_note: Option<String>,
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(data))
}
