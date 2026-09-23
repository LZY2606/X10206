//! 领域类型：健康/状态枚举、数据库行、导入导出 JSON、API DTO。

use serde::{Deserialize, Serialize};

/// 损坏/排除证据类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// 字节摘要与随附 .digest 声明值不符。
    DigestMismatch,
    /// 同 (generation, shard_index) 存在另一内容候选。
    DuplicateIndex,
    /// 长度与清单声明不一致（短写/截断）。
    LengthMismatch,
    /// 属于旧 generation（版本混杂）。
    StaleGeneration,
    /// 来源被人工隔离。
    SourceIsolated,
    /// 重建结果与对象摘要/分片声明不符。
    RecomputeMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShardHealth {
    /// 有且仅有一个自洽候选（字节摘要通过、长度正确、generation 最新）。
    Unique,
    /// 同一编号存在多个自洽内容候选。
    MultipleCandidates,
    /// 候选字节损坏（摘要不符或长度不符）。
    Corrupt,
    /// 无任何碎片或全部被隔离。
    Missing,
    /// 有碎片但全部来自旧 generation。
    Stale,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StripeStatus {
    /// 尚未计算过。
    Pending,
    /// 存在至少一个可行重建。
    Recoverable,
    /// 可行重建多于一个且对象摘要无法区分。
    Ambiguous,
    /// 已知分片不足 k 或无可行集合。
    Unrecoverable,
    /// 已经原子提交（摘要完整）。
    Committed,
    /// 曾提交，但因来源隔离等原因需要重算。
    NeedsRecompute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Running,
    Interrupted,
    Complete,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Encoding {
    pub k: i64,
    pub m: i64,
    pub shard_len: i64,
}

/// 导入清单（versioned）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestFile {
    pub schema: u32,
    pub object_id: String,
    pub current_generation: u64,
    pub versions: Vec<ManifestVersion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestVersion {
    pub generation: u64,
    pub k: i64,
    pub m: i64,
    pub shard_len: i64,
    pub stripe_count: i64,
    /// 对象数据摘要：SHA-256，按数据分片编号升序拼接。
    pub object_digest: String,
    /// stripe_idx -> shard_idx -> 期望字节摘要（长度统一为 k+m）。
    pub shard_digests: Vec<Vec<String>>,
}

/// 导入的一个接收包（manifest + 碎片 + 来源）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestRequest {
    pub source: String,
    pub received_at: String,
    pub manifest: ManifestFile,
    /// stripe_idx -> shard_idx -> 十六进制字节（缺失键表示未收到）。
    pub shards: Vec<std::collections::BTreeMap<usize, String>>,
    /// 可选：(stripe,shard) -> 随附声明摘要；缺省由清单中的期望摘要充当。
    #[serde(default)]
    pub claimed_digests: std::collections::BTreeMap<String, String>,
}

/// 数据库行：接收来源。
#[derive(Debug, Clone, Serialize)]
pub struct SourceRow {
    pub id: i64,
    pub name: String,
    pub received_at: String,
    pub isolated: bool,
    pub ingest_seq: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ObjectRow {
    pub id: i64,
    pub object_id: String,
    pub current_generation: i64,
    pub shard_health: String,
    pub stripe_status: String,
    pub recovery_pct: i64,
    pub committed_stripes: i64,
    pub total_stripes: i64,
    pub object_digest_ok: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FragmentRow {
    pub id: i64,
    pub object_id: String,
    pub stripe_idx: i64,
    pub shard_idx: i64,
    pub generation: i64,
    pub source_id: i64,
    pub source_name: String,
    pub length: i64,
    pub claimed_digest: String,
    pub actual_digest: String,
    pub expected_digest: Option<String>,
    pub byte_path: String,
    pub receive_order: i64,
    pub excluded: bool,
    pub evidence: Option<String>,
    pub isolated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CandidateMemberDto {
    pub shard_idx: i64,
    pub fragment_ids: Vec<i64>,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CandidateDto {
    pub candidate_id: String,
    pub generation: i64,
    pub members: Vec<CandidateMemberDto>,
    pub missing_shards: Vec<i64>,
    /// 重建出的数据分片 hex：shard_idx -> hex bytes。
    pub rebuilt_data: std::collections::BTreeMap<String, String>,
    /// 重新计算的分片摘要：shard_idx -> sha256 hex。
    pub rebuilt_digests: std::collections::BTreeMap<String, String>,
    pub object_digest: String,
    pub object_digest_ok: bool,
    pub preferred: bool,
    pub differences: Vec<String>,
    pub excluded_evidence: Vec<ExcludedEvidenceDto>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExcludedEvidenceDto {
    pub fragment_id: i64,
    pub shard_idx: i64,
    pub generation: i64,
    pub source_name: String,
    pub kind: String,
    pub detail: String,
    pub claimed_digest: String,
    pub actual_digest: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StripeDto {
    pub stripe_idx: i64,
    pub status: String,
    pub generation: i64,
    pub k: i64,
    pub m: i64,
    pub shard_len: i64,
    pub available: i64,
    pub candidate_count: i64,
    pub committed_generation: Option<i64>,
    pub candidates: Vec<CandidateDto>,
    pub exclusions: Vec<ExcludedEvidenceDto>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunDto {
    pub id: i64,
    pub status: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub total_stripes: i64,
    pub committed_stripes: i64,
    pub failed_stripe: Option<i64>,
    pub error: Option<String>,
}

/// 导出仓 list 文件。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportManifest {
    pub schema: u32,
    pub created_at: String,
    pub objects: Vec<ExportObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportObject {
    pub object_id: String,
    pub generation: i64,
    pub k: i64,
    pub m: i64,
    pub shard_len: i64,
    pub complete: bool,
    pub committed_stripes: i64,
    pub total_stripes: i64,
    pub object_digest: String,
    pub object_digest_ok: bool,
    pub stripes: Vec<ExportStripe>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportStripe {
    pub stripe_idx: i64,
    pub generation: i64,
    pub data_digests: Vec<String>,
    pub object_digest: String,
}
