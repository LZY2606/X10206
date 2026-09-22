use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncodingParams {
    pub version: u32,
    pub k: usize,
    pub m: usize,
    pub shard_size: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Manifest {
    #[serde(default)]
    pub stripes: Vec<StripeManifest>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StripeManifest {
    /// 长度 k+m；None 表示 manifest 未声明该 shard 摘要。
    #[serde(default)]
    pub shard_digests: Vec<Option<String>>,
}

#[derive(Clone, Debug)]
pub struct ObjectRow {
    pub id: String,
    pub name: String,
    pub params: EncodingParams,
    pub object_len: u64,
    pub stripe_count: usize,
    pub manifest: Manifest,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Fragment {
    pub id: i64,
    pub object_id: String,
    pub stripe_idx: u32,
    pub shard_idx: u32,
    pub generation: u64,
    pub source: String,
    pub declared_digest: String,
    pub computed_digest: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ShardRef {
    pub shard_idx: u32,
    pub generation: u64,
    pub source: String,
    pub digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Evidence {
    pub shard_idx: Option<u32>,
    pub source: String,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum StripeStatus {
    Recovered,
    Ambiguous,
    Unrecoverable,
    Reused,
}

impl StripeStatus {
    pub fn label(&self) -> &'static str {
        match self {
            StripeStatus::Recovered => "已恢复",
            StripeStatus::Ambiguous => "多解存疑",
            StripeStatus::Unrecoverable => "不可恢复",
            StripeStatus::Reused => "复用已提交",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Solution {
    pub id: usize,
    pub generation: u64,
    pub digest: String,
    pub shard_digests: Vec<(u32, String)>,
    pub participating: Vec<ShardRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StripeReport {
    pub stripe_idx: u32,
    pub status: StripeStatus,
    pub participating: Vec<ShardRef>,
    pub excluded: Vec<Evidence>,
    pub solutions: Vec<Solution>,
    pub diffs: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct CreateObject {
    pub id: String,
    pub name: String,
    pub params: EncodingParams,
    pub object_len: u64,
    pub manifest: Manifest,
}
