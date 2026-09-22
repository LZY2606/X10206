//! Persistent domain model and the versioned import manifest schema.

use serde::{Deserialize, Serialize};

use crate::coding::CodingParams;

pub const MANIFEST_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportManifest {
    pub manifest_version: u32,
    pub object: ObjectSpec,
    pub coding: CodingSpec,
    #[serde(default)]
    pub shards: Vec<ShardDecl>,
    #[serde(default)]
    pub fragments: Vec<FragmentSpec>,
    #[serde(default)]
    pub sources: Vec<SourceSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectSpec {
    pub object_id: String,
    pub name: String,
    pub data_len: u64,
    #[serde(default)]
    pub object_digest_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodingSpec {
    pub codec_version: u32,
    pub k: usize,
    pub n: usize,
    pub chunk_size: usize,
}

impl From<CodingSpec> for CodingParams {
    fn from(s: CodingSpec) -> Self {
        CodingParams {
            codec_version: s.codec_version,
            k: s.k,
            n: s.n,
            chunk_size: s.chunk_size,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShardDecl {
    pub stripe_index: usize,
    pub shard_index: usize,
    #[serde(default)]
    pub generation: Option<u64>,
    #[serde(default)]
    pub length: Option<u64>,
    #[serde(default)]
    pub digest_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FragmentSpec {
    pub id: String,
    pub stripe_index: usize,
    pub shard_index: usize,
    pub generation: u64,
    pub source_id: String,
    pub data_file: String,
    #[serde(default)]
    pub digest_sha256: Option<String>,
    #[serde(default)]
    pub received_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceSpec {
    pub source_id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

/// Health flags attached to individual received fragments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FragmentFlag {
    ImportDigestMismatch,
    LengthMismatch,
    WrongGeneration,
    DuplicateIndex,
    DeclaredDigestMissing,
}

impl FragmentFlag {
    pub fn as_str(self) -> &'static str {
        match self {
            FragmentFlag::ImportDigestMismatch => "import_digest_mismatch",
            FragmentFlag::LengthMismatch => "length_mismatch",
            FragmentFlag::WrongGeneration => "wrong_generation",
            FragmentFlag::DuplicateIndex => "duplicate_index",
            FragmentFlag::DeclaredDigestMissing => "declared_digest_missing",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "import_digest_mismatch" => FragmentFlag::ImportDigestMismatch,
            "length_mismatch" => FragmentFlag::LengthMismatch,
            "wrong_generation" => FragmentFlag::WrongGeneration,
            "duplicate_index" => FragmentFlag::DuplicateIndex,
            "declared_digest_missing" => FragmentFlag::DeclaredDigestMissing,
            _ => return None,
        })
    }

    /// A hard flag means the fragment bytes cannot be trusted as input to
    /// reconstruction; the candidate enumerator must exclude them.
    pub fn is_hard(self) -> bool {
        matches!(
            self,
            FragmentFlag::ImportDigestMismatch | FragmentFlag::LengthMismatch
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StripeStatus {
    Pending,
    Committed,
    Ambiguous,
    Infeasible,
}

impl StripeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            StripeStatus::Pending => "pending",
            StripeStatus::Committed => "committed",
            StripeStatus::Ambiguous => "ambiguous",
            StripeStatus::Infeasible => "infeasible",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "committed" => StripeStatus::Committed,
            "ambiguous" => StripeStatus::Ambiguous,
            "infeasible" => StripeStatus::Infeasible,
            _ => StripeStatus::Pending,
        }
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}
