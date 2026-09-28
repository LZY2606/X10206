use serde::{Deserialize, Serialize};

/// 版本化编码参数清单（manifest）。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub name: String,
    pub codec: String, // 例如 "rs-gf16-v1" / "rs-gf256-v1"
    pub k: usize,
    pub m: usize,
    pub shard_len: usize,
    pub stripe_count: usize,
    pub generation: u64,
    /// 每个 stripe 的 data 区（前 k 个 shard 拼接）摘要；缺失/损坏时为 None。
    #[serde(default)]
    pub stripe_digests: Vec<Option<String>>,
}

#[derive(Clone, Debug)]
pub struct ObjectRow {
    pub id: i64,
    pub manifest: Manifest,
}

#[derive(Clone, Debug)]
pub struct ShardRow {
    pub id: i64,
    pub object_id: i64,
    pub stripe: usize,
    pub idx: usize,
    pub generation: u64,
    pub declared_len: usize,
    pub declared_digest: String,
    pub computed_digest: String,
    pub bytes: Vec<u8>,
    pub source_id: i64,
    pub source_label: String,
    pub quarantined: bool,
}

#[derive(Clone, Debug)]
pub struct SourceRow {
    pub id: i64,
    pub label: String,
    pub quarantined: bool,
}

#[derive(Clone, Debug)]
pub struct CommitRow {
    pub object_id: i64,
    pub stripe: usize,
    pub generation: u64,
    pub digest: String,      // 整条 stripe（k+m shard 拼接）摘要
    pub data_digest: String, // data 区摘要，对应 manifest 约束
    pub shard_digests: Vec<String>,
    pub source_ids: Vec<i64>,
    pub excluded_json: String,
    pub bytes: Vec<u8>, // k+m 个 shard 顺序拼接
    pub committed_at: String,
}
