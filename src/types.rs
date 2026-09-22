//! 领域类型：版本化编码参数、清单结构、证据类别与健康度。

use serde::{Deserialize, Serialize};

/// 版本化编码参数。导入时仅按 `version` 查注册表，不允许清单自报 k/m 偷偷变更。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodingParams {
    pub version: String,
    pub k: u8,
    pub m: u8,
    pub poly: u16,
    pub stripe_bytes: usize,
}

/// 编码参数注册表（版本不可变）。新增版本只能追加。
pub fn coding_registry() -> Vec<CodingParams> {
    vec![
        CodingParams { version: "v1".into(), k: 3, m: 2, poly: 0x11d, stripe_bytes: 16 },
        CodingParams { version: "v2".into(), k: 4, m: 3, poly: 0x11d, stripe_bytes: 12 },
    ]
}

pub fn lookup_params(version: &str) -> Option<CodingParams> {
    coding_registry().into_iter().find(|p| p.version == version)
}

/// 导入舱（一个来源目录）的 manifest。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub object_id: String,
    pub object_digest: Option<String>,
    pub coding_version: String,
    /// manifest 声称的总长度；可能与实际不符（审计证据）。
    pub declared_len: Option<u64>,
    /// 清单声称的 stripe 数（允许整 stripe 缺失时仍建出审计行）。
    #[serde(default)]
    pub stripe_count: Option<u32>,
    #[serde(default)]
    pub fragments: Vec<ManifestFragment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestFragment {
    pub shard: u32,
    pub stripe: u32,
    pub generation: u32,
    pub length: u64,
    pub digest: String,
    /// 相对来源目录的路径；缺省按 shards/s{stripe}.sh{shard}.g{generation}.bin 解析，
    /// 同编号重复时用 file 区分。
    #[serde(default)]
    pub file: Option<String>,
}

/// 损坏/排除证据类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// 碎片摘要与重算不符（位翻转/截断/内容替换）。
    DigestMismatch,
    /// manifest 长度与实际字节长度不符。
    LengthMismatch,
    /// manifest 记录的 shard 编号重复。
    DuplicateShard,
    /// 同一 (stripe, shard) 出现两个不同内容候选。
    ConflictingCandidates,
    /// 候选 generation 落后于本 stripe 已知最新代。
    StaleGeneration,
    /// 内容通过摘要，但与 Reed-Solomon 方程矛盾（混代/错编码）。
    CodingInconsistent,
    /// 组合枚举超过搜索预算，未穷尽。
    SearchBudgetExceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FragmentHealth {
    /// 摘要匹配、长度匹配。
    Intact,
    /// 摘要不匹配。
    Corrupt,
    /// manifest 长度与实际不符。
    LengthMismatch,
    /// 被人工隔离。
    Isolated,
    /// 没有清单/摘要可核对。
    Unverified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolutionTier {
    /// 参与块同代 + 编码一致；对象摘要存在时还需对象摘要匹配。
    Trusted,
    /// 方程一致但混代或其它降级因素；仅作保留候选，不自动提交。
    Degraded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StripeStatus {
    Pending,
    Committed,
    Ambiguous,
    Unrecoverable,
    Degraded,
    BudgetLimited,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectStatus {
    Incomplete,
    Trusted,
    Degraded,
    Ambiguous,
    DigestMismatch,
    Unrecoverable,
}

/// 默认组合枚举预算（所有测试共享同一确定值）。
pub const DEFAULT_SEARCH_BUDGET: u64 = 4096;
