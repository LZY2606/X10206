//! Domain enumerations shared by import, recovery and the web layer.

use serde::{Deserialize, Serialize};

/// Why an imported fragment could not participate in a rebuild.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExclusionReason {
    /// Bytes digest does not match the manifest block digest.
    DigestMismatch { expected: String, actual: String },
    /// Stored bytes are not shard_size long.
    LengthMismatch { expected: usize, actual: usize },
    /// Belongs to a different generation than the attempted one.
    GenerationMismatch { attempted: u64, candidate: u64 },
    /// Receipt source has been manually isolated.
    SourceIsolated { source: String },
    /// Another candidate for the same slot was required by this combination.
    NotSelected,
    /// Raw bytes for this receipt are absent from the blob store.
    BlobMissing { hash: String },
}

impl ExclusionReason {
    pub fn label(&self) -> String {
        match self {
            ExclusionReason::DigestMismatch { expected, actual } => format!(
                "摘要不符（期望 {}，实际 {}）",
                short(expected),
                short(actual)
            ),
            ExclusionReason::LengthMismatch { expected, actual } => {
                format!("长度不符（期望 {}，实际 {}）", expected, actual)
            }
            ExclusionReason::GenerationMismatch { attempted, candidate } => {
                format!("generation 不符（尝试 G{}，候选 G{}）", attempted, candidate)
            }
            ExclusionReason::SourceIsolated { source } => format!("来源已隔离：{}", source),
            ExclusionReason::NotSelected => "本组合未选用".to_string(),
            ExclusionReason::BlobMissing { hash } => {
                format!("原始块在存储中缺失：{}", short(hash))
            }
        }
    }
}

pub fn short(d: &str) -> String {
    let d = d.strip_prefix("sha256:").unwrap_or(d);
    if d.len() > 12 {
        format!("{}…", &d[..12])
    } else {
        d.to_string()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FragmentHealth {
    /// Digest matches the manifest.
    Good,
    /// Digest disagrees with the manifest (bit flip / partial write).
    Corrupt,
    /// No manifest digest exists for this coordinate in this generation.
    Unverified,
}

impl FragmentHealth {
    pub fn as_str(&self) -> &'static str {
        match self {
            FragmentHealth::Good => "good",
            FragmentHealth::Corrupt => "corrupt",
            FragmentHealth::Unverified => "unverified",
        }
    }
    pub fn label(&self) -> &'static str {
        match self {
            FragmentHealth::Good => "健康",
            FragmentHealth::Corrupt => "损坏",
            FragmentHealth::Unverified => "无摘要",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StripeStatus {
    NotAttempted,
    /// Exactly one feasible rebuilt stripe.
    Recovered,
    /// Multiple feasible rebuilt stripes, differences recorded.
    Ambiguous,
    /// Not enough shard candidates to reach the recovery threshold.
    BelowThreshold,
    /// Enumeration budget exhausted.
    BudgetExhausted,
    /// A write/IO error aborted the attempt before commit.
    Failed,
}

impl StripeStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            StripeStatus::NotAttempted => "not_attempted",
            StripeStatus::Recovered => "recovered",
            StripeStatus::Ambiguous => "ambiguous",
            StripeStatus::BelowThreshold => "below_threshold",
            StripeStatus::BudgetExhausted => "budget_exhausted",
            StripeStatus::Failed => "failed",
        }
    }
    pub fn label(&self) -> &'static str {
        match self {
            StripeStatus::NotAttempted => "未尝试",
            StripeStatus::Recovered => "已恢复",
            StripeStatus::Ambiguous => "多个可行解",
            StripeStatus::BelowThreshold => "低于恢复下限",
            StripeStatus::BudgetExhausted => "搜索预算耗尽",
            StripeStatus::Failed => "写入失败",
        }
    }
}
