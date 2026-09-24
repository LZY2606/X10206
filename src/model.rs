//! 恢复报告与候选组合的可序列化模型。

use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Pick {
    pub shard_index: usize,
    pub generation: i64,
    pub source: String,
    pub source_id: i64,
    pub shard_id: i64,
    pub digest: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Combo {
    pub picks: Vec<Pick>,
    /// 重建出的数据区（k 个数据 shard 拼接）的 sha256，用于区分不同输出。
    pub output_digest: String,
    /// 重建后全部 k+m 个 shard 重新计算的摘要。
    pub recomputed: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Evidence {
    pub shard_index: i64,
    pub source: String,
    pub generation: i64,
    pub reason: String,
    pub digest: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct StripeReport {
    pub stripe: usize,
    /// healthy | recovered | reused | unrecoverable | budget_exceeded
    pub status: String,
    pub feasible: Vec<Combo>,
    pub total_feasible: usize,
    pub budget_hit: bool,
    pub chosen: Option<usize>,
    pub evidence: Vec<Evidence>,
    pub differences: Vec<String>,
    pub reused: bool,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ObjectReport {
    pub object_id: String,
    pub run_id: String,
    pub stripes: Vec<StripeReport>,
    pub committed: usize,
    pub reused: usize,
    pub failed: usize,
}
