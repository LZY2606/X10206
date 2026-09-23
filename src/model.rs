//! 导入清单与恢复分析的数据模型。

use crate::coding::CodeParams;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// 导入清单中的单个分片记录。
///
/// 允许同一 `(stripe, index)` 出现多条记录（重复编号 / 多内容候选），
/// 每条记录通过 `file` 指向清单目录中的独立字节文件。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestShard {
    pub index: usize,
    pub generation: u64,
    pub shard_digest: String,
    pub file: String,
    #[serde(default)]
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestStripe {
    pub index: usize,
    /// 该 stripe 每个分片的字节长度。
    pub shard_len: usize,
    /// stripe 原始数据长度（去填充）。
    pub raw_len: usize,
    pub stripe_digest: String,
    pub shards: Vec<ManifestShard>,
}

/// 版本化导入清单。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub manifest_version: u32,
    pub object_id: String,
    pub code: CodeParams,
    pub stripe_count: usize,
    pub total_size: usize,
    pub object_digest: String,
    pub stripes: Vec<ManifestStripe>,
}

/// 排除原因（机读码 + 人读细节同时保留）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExcludedEvidence {
    pub receipt_id: i64,
    pub shard_index: usize,
    pub generation: u64,
    pub source: String,
    pub reason: ExcludeReason,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExcludeReason {
    /// 摘要与清单不符（典型位翻转 / 损坏）。
    BadDigest,
    /// 实际长度与清单不符。
    BadLength,
    /// 编号超出 k+m 范围。
    BadIndex,
    /// generation 低于本可行集合所选 generation。
    OlderGeneration,
    /// generation 相同但内容与重建结果不一致（混代部分写）。
    SameGenerationMismatch,
    /// 好的候选，但本可行集合未选中（仅作展示，不算损坏证据）。
    NotSelected,
    /// 解码结果无法满足该候选（用于秩足但内容矛盾的情形）。
    DecodeMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CandidateView {
    pub receipt_id: i64,
    pub shard_index: usize,
    pub generation: u64,
    pub source: String,
    pub observed_len: usize,
    pub expected_len: usize,
    pub observed_digest: String,
    pub expected_digest: Option<String>,
    pub length_ok: bool,
    pub digest_ok: bool,
    /// good / bad_digest / bad_length / bad_index
    pub health: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Participant {
    pub receipt_id: i64,
    pub shard_index: usize,
    pub generation: u64,
    pub source: String,
}

/// 一个可行重建集合的完整视图：参与分片、排除证据、重算摘要。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SolutionView {
    pub rank: usize,
    pub generation: u64,
    /// 实际进入高斯消元的 k 个分片编号（去重后的编号集合）。
    pub used_indices: Vec<usize>,
    /// 参与计算的分片（含用于一致性校验但未进消元的好分片）。
    pub participants: Vec<Participant>,
    /// 被排除的损坏 / 不适用证据。
    pub excluded: Vec<ExcludedEvidence>,
    /// 被重建出来的分片编号。
    pub rebuilt_indices: Vec<usize>,
    /// 重算的 stripe 摘要（去填充前取 raw_len）。
    pub stripe_digest: String,
    /// stripe 全部 n 个编号的重算分片摘要。
    pub shard_digests: BTreeMap<usize, String>,
    /// 是否与清单 stripe 摘要一致。
    pub matches_manifest: bool,
    /// 去重签名（generation + 参与收据 + 结果摘要）。
    pub signature: String,
    /// 与排名第一的可行解之间的差异（排名第一为空）。
    pub differences: Vec<String>,
}

/// stripe 健康状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StripeStatus {
    /// 原始好分片已覆盖全部编号，无需重建。
    Intact,
    /// 至少存在一个与清单一致的可行重建。
    Recoverable,
    /// 候选不足或所有解码结果均不一致。
    Unrecoverable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeAnalysis {
    pub stripe_index: usize,
    pub shard_len: usize,
    pub raw_len: usize,
    pub manifest_digest: String,
    pub status: StripeStatus,
    pub candidates: Vec<CandidateView>,
    pub solutions: Vec<SolutionView>,
    pub chosen_rank: Option<usize>,
    pub combos_tested: usize,
    pub combos_budget: usize,
    pub budget_hit: bool,
    pub reasons: Vec<String>,
}
