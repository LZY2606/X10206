//! Domain types and the versioned manifest format.

use serde::{Deserialize, Serialize};

/// Versioned object manifest (format `srm-manifest/v1`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestV1 {
    pub manifest_format: String,
    pub object_id: String,
    /// Original (pre-padding) object length in bytes.
    pub data_len: u64,
    /// SHA-256 of the original object bytes.
    pub object_digest: String,
    pub codec: CodecParams,
    /// Per-shard expected digests, keyed by shard index; entries may be absent.
    #[serde(default)]
    pub shard_digests: std::collections::BTreeMap<u32, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodecParams {
    pub version: u32,
    pub data_shards: u32,
    pub parity_shards: u32,
    pub stripe_size: u32,
}

impl CodecParams {
    pub fn k(&self) -> usize {
        self.data_shards as usize
    }
    pub fn n(&self) -> usize {
        (self.data_shards + self.parity_shards) as usize
    }
    pub fn stripe_count(data_len: u64, stripe_size: u32) -> usize {
        let s = stripe_size as u64;
        ((data_len + s - 1) / s) as usize
    }
}

/// Sidecar accompanying one received fragment file.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FragmentMeta {
    pub object_id: String,
    pub shard_index: u32,
    /// Write generation carried by the fragment (partial writes may mix gens).
    #[serde(default)]
    pub generation: u32,
    /// Digest the receiving side recorded for the bytes. May be omitted.
    #[serde(default)]
    pub received_digest: Option<String>,
    /// Free-form provenance label (host / path / operator).
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentStatus {
    /// Eligible for recovery enumeration.
    Eligible,
    /// Length does not match the manifest shard length.
    LengthMismatch,
    /// Sidecar digest disagrees with actual bytes.
    ReceivedDigestMismatch,
    /// Manifest expected digest disagrees with actual bytes.
    ManifestDigestMismatch,
    /// Shard index outside [0, data+parity).
    IndexOutOfRange,
    /// Belongs to a manually isolated source.
    SourceIsolated,
}

impl FragmentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            FragmentStatus::Eligible => "eligible",
            FragmentStatus::LengthMismatch => "length_mismatch",
            FragmentStatus::ReceivedDigestMismatch => "received_digest_mismatch",
            FragmentStatus::ManifestDigestMismatch => "manifest_digest_mismatch",
            FragmentStatus::IndexOutOfRange => "index_out_of_range",
            FragmentStatus::SourceIsolated => "source_isolated",
        }
    }
    pub fn parse(s: &str) -> FragmentStatus {
        match s {
            "length_mismatch" => FragmentStatus::LengthMismatch,
            "received_digest_mismatch" => FragmentStatus::ReceivedDigestMismatch,
            "manifest_digest_mismatch" => FragmentStatus::ManifestDigestMismatch,
            "index_out_of_range" => FragmentStatus::IndexOutOfRange,
            "source_isolated" => FragmentStatus::SourceIsolated,
            _ => FragmentStatus::Eligible,
        }
    }
    pub fn hard_excluded(&self) -> bool {
        !matches!(self, FragmentStatus::Eligible)
    }
}

/// Evidence record explaining why a fragment was excluded from a solution.
#[derive(Debug, Clone, Serialize)]
pub struct ExclusionEvidence {
    pub fragment_id: i64,
    pub shard_index: u32,
    pub source: String,
    pub generation: u32,
    pub reason: String,
    pub detail: String,
}

/// One fragment chosen to participate in a candidate reconstruction.
#[derive(Debug, Clone, Serialize)]
pub struct Participant {
    pub fragment_id: i64,
    pub shard_index: u32,
    pub source: String,
    pub generation: u32,
    pub received_digest: Option<String>,
    pub recomputed_digest: String,
    pub rebuilt: bool,
}

/// A feasible reconstruction of one stripe.
#[derive(Debug, Clone, Serialize)]
pub struct CandidateSolution {
    pub solution_key: String,
    pub generation: u32,
    /// Digest keyed by shard index for every output block of the stripe.
    pub output_digests: Vec<String>,
    pub participants: Vec<Participant>,
    pub excluded: Vec<ExclusionEvidence>,
    /// True when all parity/row checks pass against every selected fragment.
    pub parity_verified: bool,
    /// True when every participant is corroborated by a manifest/received digest.
    pub strongly_corroborated: bool,
    /// Number of blocks rebuilt (not supplied by a fragment).
    pub rebuilt_count: usize,
    /// How many combinations were searched to find this solution.
    pub search_steps: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StripeVerdict {
    /// Unique trusted reconstruction.
    Recoverable,
    /// Multiple feasible reconstructions with different outputs; human review.
    Ambiguous,
    /// Fewer than k usable shard positions; at/below threshold failure.
    Unrecoverable,
    /// Every candidate fragment is corrupt / excluded.
    AllCorrupt,
    /// Deterministic search budget exhausted before a definite answer.
    BudgetExhausted,
}

impl StripeVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            StripeVerdict::Recoverable => "recoverable",
            StripeVerdict::Ambiguous => "ambiguous",
            StripeVerdict::Unrecoverable => "unrecoverable",
            StripeVerdict::AllCorrupt => "all_corrupt",
            StripeVerdict::BudgetExhausted => "budget_exhausted",
        }
    }
    pub fn parse(s: &str) -> Option<StripeVerdict> {
        Some(match s {
            "recoverable" => StripeVerdict::Recoverable,
            "ambiguous" => StripeVerdict::Ambiguous,
            "unrecoverable" => StripeVerdict::Unrecoverable,
            "all_corrupt" => StripeVerdict::AllCorrupt,
            "budget_exhausted" => StripeVerdict::BudgetExhausted,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitState {
    Committed,
    Stale,
}

impl CommitState {
    pub fn as_str(&self) -> &'static str {
        match self {
            CommitState::Committed => "committed",
            CommitState::Stale => "stale",
        }
    }
    pub fn parse(s: &str) -> CommitState {
        match s {
            "stale" => CommitState::Stale,
            _ => CommitState::Committed,
        }
    }
}
