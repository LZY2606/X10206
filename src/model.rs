//! Wire-format and report types shared by the API, import and recovery engine.

use serde::{Deserialize, Serialize};

/// Versioned manifest revision imported for an object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub object_id: String,
    pub version: u64,
    pub generation: u64,
    pub k: u32,
    pub m: u32,
    /// SHA-256 of the fully assembled, unpadded object bytes.
    pub object_digest: String,
    pub stripes: Vec<StripeManifest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeManifest {
    pub index: u32,
    /// True byte length of every shard position (padding included for parity).
    pub shard_len: u64,
    /// True (unpadded) length of the last data shard.
    pub last_data_len: u64,
    /// Expected SHA-256 hex digest keyed by global shard index.
    pub shard_digests: std::collections::BTreeMap<u32, String>,
}

/// One received shard candidate plus its provenance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncomingShard {
    pub shard: u32,
    pub generation: u64,
    /// hex-encoded raw shard bytes (base for the offline import bundle).
    pub data_hex: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ImportBundle {
    pub manifest: Manifest,
    #[serde(default)]
    pub shards: Vec<IncomingShard>,
}

/// Why a received candidate was kept out of the recovery calculation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExclusionReason {
    StaleGeneration { candidate: u64, target: u64 },
    BadDigest { expected: String, actual: String },
    BadLength { expected: u64, actual: u64 },
    OutOfRange,
    IsolatedSource,
    DuplicateShadowed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExcludedEvidence {
    pub reception_id: i64,
    pub source: String,
    pub shard: u32,
    pub generation: u64,
    pub reason: ExclusionReason,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipatingShard {
    pub shard: u32,
    pub reception_id: i64,
    pub source: String,
}

/// One feasible k-shard combination that reconstructs and verifies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeasibleCombo {
    pub rank: usize,
    pub participants: Vec<ParticipatingShard>,
    pub chosen: bool,
    pub reconstructed_shards: Vec<u32>,
    pub recomputed_digests: std::collections::BTreeMap<u32, String>,
    pub divergent_from_chosen: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeReport {
    pub index: u32,
    pub status: String,
    pub target_generation: u64,
    pub eligible_shards: Vec<u32>,
    pub candidates_per_shard: std::collections::BTreeMap<u32, usize>,
    pub combos_tried: usize,
    pub search_budget: usize,
    pub budget_exhausted: bool,
    pub combos: Vec<FeasibleCombo>,
    pub excluded: Vec<ExcludedEvidence>,
    pub missing: Vec<u32>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryReport {
    pub run_id: i64,
    pub object_id: String,
    pub version: u64,
    pub target_generation: u64,
    pub status: String,
    pub stripes_total: usize,
    pub stripes_recovered: usize,
    pub stripes_ambiguous: usize,
    pub stripes_infeasible: usize,
    pub object_digest_expected: String,
    pub object_digest_actual: Option<String>,
    pub object_digest_match: Option<bool>,
    pub reused_committed: Vec<u32>,
    pub stripes: Vec<StripeReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportManifest {
    pub export_id: String,
    pub object_id: String,
    pub run_id: i64,
    pub created_from: String,
    pub object_digest_expected: String,
    pub object_digest_match: bool,
    pub committed: bool,
    pub stripe_files: std::collections::BTreeMap<u32, Vec<u32>>,
}
