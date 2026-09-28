use serde::{Deserialize, Serialize};

/// Trust level of a concrete reconstruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// Rebuilt bytes match manifest digests for all n rows, current
    /// generation, object length consistent.
    Trusted,
    /// Candidate set is internally consistent (all held-out bytes
    /// verify) but manifest digests disagree.
    Consistent,
    /// Same stripe has >=2 distinct consistent byte answers.
    Ambiguous,
    /// Only k rows available and no manifest digest to verify against.
    Unverified,
}

impl TrustLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            TrustLevel::Trusted => "trusted",
            TrustLevel::Consistent => "consistent",
            TrustLevel::Ambiguous => "ambiguous",
            TrustLevel::Unverified => "unverified",
        }
    }
    pub fn label_zh(&self) -> &'static str {
        match self {
            TrustLevel::Trusted => "可信",
            TrustLevel::Consistent => "自洽未校验",
            TrustLevel::Ambiguous => "多解存疑",
            TrustLevel::Unverified => "未验证",
        }
    }
    pub fn rank(&self) -> u8 {
        match self {
            TrustLevel::Trusted => 3,
            TrustLevel::Consistent => 2,
            TrustLevel::Ambiguous => 1,
            TrustLevel::Unverified => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExcludeReason {
    /// Recomputed received-block digest differs from sidecar digest
    /// (bit flip in transport/storage).
    BlockDigestMismatch,
    /// Sidecar length field differs from stored byte count.
    LengthMismatch,
    /// Sidecar digest missing.
    MissingBlockDigest,
    /// Sidecar claims a different code version/params than manifest.
    SidecarParamMismatch,
    /// Shard has no matching stripe in any known manifest.
    UnknownStripe,
    /// Human operator isolated this source.
    SourceIsolated,
    /// Stripe belongs to another (non-current) generation.
    SupersededGeneration,
}

impl ExcludeReason {
    pub fn label_zh(&self) -> &'static str {
        match self {
            ExcludeReason::BlockDigestMismatch => "块摘要不匹配",
            ExcludeReason::LengthMismatch => "长度不符",
            ExcludeReason::MissingBlockDigest => "缺少块摘要",
            ExcludeReason::SidecarParamMismatch => "侧车参数不符",
            ExcludeReason::UnknownStripe => "无对应条带",
            ExcludeReason::SourceIsolated => "来源已隔离",
            ExcludeReason::SupersededGeneration => "旧 generation",
        }
    }
}

/// A single received block with its provenance.
#[derive(Debug, Clone)]
pub struct ShardRec {
    pub shard_id: String,
    pub object_id: String,
    pub generation: u64,
    pub stripe_idx: usize,
    pub row: usize,
    pub code_version: u32,
    pub size: usize,
    pub sidecar_digest: Option<String>,
    pub computed_digest: String,
    pub blob: String,
    pub source: String,
    pub has_manifest_digest: bool,
    pub manifest_digest_match: Option<bool>,
}
