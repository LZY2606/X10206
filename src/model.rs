//! 领域模型：manifest、fragment 候选、证据、可行解与 stripe 分析结果。

use crate::coding::CodecVersion;
use crate::gf::Field;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// manifest（v1 编码参数）。
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub object_id: String,
    #[serde(default = "default_version")]
    pub codec_version: u32,
    pub field: String,
    pub k: usize,
    pub m: usize,
    pub stripe_length: usize,
    pub stripe_count: usize,
    /// 对象逻辑长度（字节）。None 表示未知/填充长度由 stripe_count*stripe_length*k 决定。
    #[serde(default)]
    pub object_length: Option<usize>,
    /// 整个对象重编码后应匹配的摘要（可选；没有则无法在多解间裁定）。
    #[serde(default)]
    pub object_digest: Option<String>,
}

fn default_version() -> u32 {
    1
}

impl Manifest {
    pub fn field(&self) -> Result<Field, String> {
        Field::from_name(&self.field).ok_or_else(|| format!("未知域: {}", self.field))
    }

    pub fn codec(&self) -> Result<CodecVersion, String> {
        CodecVersion::from_number(self.codec_version)
            .ok_or_else(|| format!("不支持的编码版本: {}", self.codec_version))
    }
}

/// 参与 stripe 的物理碎片（已保存原始字节）。
#[derive(Clone, Debug)]
pub struct FragmentInput {
    pub fragment_id: String,
    pub object_id: String,
    pub stripe: usize,
    pub shard: usize,
    pub generation: u64,
    pub source: String,
    pub bytes: Vec<u8>,
    /// 清单中登记的每块摘要（None = 导入时没有摘要边车）。
    pub claimed_digest: Option<String>,
    pub received_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DigestState {
    /// 重算摘要与登记摘要一致。
    Verified,
    /// 重算摘要与登记摘要不符。
    DigestMismatch,
    /// 导入时没有摘要，无法在本地核对。
    NoDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExcludeReason {
    DigestMismatch,
    LengthMismatch,
    ShardOutOfRange,
    SourceIsolated,
    GenerationMixed,
    RedundantInconsistency,
    SearchBudget,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExcludedEvidence {
    pub fragment_id: String,
    pub shard: usize,
    pub generation: u64,
    pub source: String,
    pub reason: ExcludeReason,
    pub detail: String,
    pub recomputed_digest: String,
    pub claimed_digest: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Participant {
    pub fragment_id: String,
    pub shard: usize,
    pub generation: u64,
    pub source: String,
    pub digest_state: DigestState,
    pub recomputed_digest: String,
}

/// 一个 stripe 的一个可行重建。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StripeSolution {
    /// 内容确定性 id（由 generation 集合与重建字节派生）。
    pub solution_id: String,
    /// 参与计算的碎片（>= k），含作为冗余核对的额外块。
    pub participants: Vec<Participant>,
    /// 本组合被排除的损坏证据。
    pub excluded: Vec<ExcludedEvidence>,
    pub generations: Vec<u64>,
    pub mixed_generation: bool,
    /// 重建出的全部 n 个 shard 字节（按编号）。
    pub shards: Vec<Vec<u8>>,
    /// 每个输出 shard 的重算摘要。
    pub recomputed_shard_digests: Vec<String>,
    /// 生成该解时枚举到的等价格式（不同碎片但字节一致）数量。
    pub equivalent_combos: usize,
    pub truncated_by_budget: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StripeHealth {
    /// 无需重建（k 个以上已验证且彼此一致）。
    Healthy,
    /// 至少一个可行解。
    Recoverable,
    /// 不足 k 或枚举不到可行组合。
    BelowThreshold,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StripeAnalysis {
    pub object_id: String,
    pub stripe: usize,
    pub health: StripeHealth,
    pub solutions: Vec<StripeSolution>,
    /// 与所有组合都无关、但在 stripe 上观察到的全局排除证据。
    pub global_excluded: Vec<ExcludedEvidence>,
    pub present_shards: Vec<usize>,
    pub expected_length: usize,
    pub budget: usize,
}

/// 跨 stripe 组装后的对象结果。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObjectOutcome {
    pub outcome_id: String,
    /// 每个 stripe 选用的 solution_id。
    pub stripe_solutions: Vec<String>,
    pub generations: Vec<u64>,
    pub mixed_generation: bool,
    pub object_digest: String,
    pub digest_matches_manifest: Option<bool>,
    /// 与首个保留结果存在内容差异的 stripe 编号。
    pub diff_stripes_vs_first: Vec<usize>,
    pub bytes: Vec<u8>,
}
