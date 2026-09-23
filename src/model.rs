//! Shared data model: manifest format, evidence codes, recovery types.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const CODING_VERSION_V1: &str = "v1";
pub const SHARD_EXT: &str = "bin";
pub const DIGEST_EXT: &str = "digest";

// ---- corruption / exclusion evidence codes -----------------------------
pub const EV_RECEIVED_DIGEST_MISMATCH: &str = "RECEIVED_DIGEST_MISMATCH";
pub const EV_RECEIVED_DIGEST_MISSING: &str = "RECEIVED_DIGEST_MISSING";
pub const EV_LENGTH_MISMATCH: &str = "LENGTH_MISMATCH";
pub const EV_SYMBOL_OUT_OF_RANGE: &str = "SYMBOL_OUT_OF_RANGE";
pub const EV_MANIFEST_DIGEST_MISMATCH: &str = "MANIFEST_DIGEST_MISMATCH";
pub const EV_GENERATION_MISMATCH: &str = "GENERATION_MISMATCH";
pub const EV_SOURCE_ISOLATED: &str = "SOURCE_ISOLATED";
pub const EV_OBJECT_DIGEST_MISMATCH: &str = "OBJECT_DIGEST_MISMATCH";

// ---- rejected-combination reasons --------------------------------------
pub const REJ_BELOW_K: &str = "BELOW_K";
pub const REJ_VERIFY_MISMATCH: &str = "VERIFY_MISMATCH";
pub const REJ_SOURCE_ISOLATED: &str = "SOURCE_ISOLATED";

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

pub fn digest_hex(data: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(data))
}

/// Versioned coding parameters imported from the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub manifest_version: String,
    pub object_id: String,
    pub coding_version: String,
    pub k: usize,
    pub n: usize,
    pub shard_len: usize,
    pub stripes: usize,
    pub generation: u64,
    pub object_digest: String,
    /// `stripes x n` expected per-shard digests.
    pub stripe_shard_digests: Vec<Vec<String>>,
}

impl Manifest {
    pub fn validate(&self) -> Result<(), String> {
        if self.manifest_version != CODING_VERSION_V1 {
            return Err(format!(
                "unsupported manifest_version {}",
                self.manifest_version
            ));
        }
        if self.coding_version != CODING_VERSION_V1 {
            return Err(format!(
                "unknown coding_version {} (only {CODING_VERSION_V1} is supported)",
                self.coding_version
            ));
        }
        if self.k == 0 || self.n < self.k || self.n > 16 {
            return Err(format!("require 0 < k <= n <= 16, got k={} n={}", self.k, self.n));
        }
        if self.stripes == 0 || self.shard_len == 0 {
            return Err("stripes and shard_len must be positive".into());
        }
        if self.stripe_shard_digests.len() != self.stripes {
            return Err(format!(
                "manifest declares {} stripes but lists {} digest rows",
                self.stripes,
                self.stripe_shard_digests.len()
            ));
        }
        for (i, row) in self.stripe_shard_digests.iter().enumerate() {
            if row.len() != self.n {
                return Err(format!("stripe {i} digest row has {} entries, want {}", row.len(), self.n));
            }
        }
        Ok(())
    }

    pub fn expected_digest(&self, stripe: usize, index: usize) -> Option<&str> {
        self.stripe_shard_digests
            .get(stripe)
            .and_then(|row| row.get(index))
            .map(|s| s.as_str())
    }
}

/// One imported raw shard candidate (original bytes preserved verbatim).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fragment {
    pub id: String,
    pub object_id: String,
    pub source: String,
    pub claimed_index: Option<usize>,
    pub claimed_generation: u64,
    pub byte_path: String,
    pub rel_path: String,
    pub length: usize,
    pub received_digest: Option<String>,
    pub content_digest: String,
    pub manifest_digest: Option<String>,
    pub in_range: bool,
}

/// A shard that actually participated in a verified reconstruction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Participant {
    pub fragment_id: String,
    pub index: usize,
    pub source: String,
    pub generation: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RebuiltShard {
    pub index: usize,
    pub digest: String,
}

/// A fragment that did not participate, with the evidence that excluded it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExcludedCandidate {
    pub fragment_id: String,
    pub source: String,
    pub generation: u64,
    pub index: Option<usize>,
    pub evidence: String,
    /// `corrupt` (cannot be trusted), `stale` (older generation),
    /// `isolated` (manual quarantine) or `superseded` (lost the selection).
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CandidateHealth {
    pub fragment_id: String,
    pub index: Option<usize>,
    pub source: String,
    pub generation: u64,
    pub length: usize,
    pub usable: bool,
    pub evidence: Vec<String>,
}

/// One feasible (or attempted) reconstruction of a stripe.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StripeSolution {
    pub id: String,
    pub stripe: usize,
    pub generation: u64,
    pub generation_matches_manifest: bool,
    pub participants: Vec<Participant>,
    pub rebuilt: Vec<RebuiltShard>,
    pub payload_digest: String,
    pub verified: bool,
    pub rejected_reason: Option<String>,
    pub excludes: Vec<ExcludedCandidate>,
    /// Human-readable difference from the best solution, when rank > 0.
    pub diff_vs_best: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct EnumeratedStripe {
    pub stripe: usize,
    pub candidates: Vec<CandidateHealth>,
    pub solutions: Vec<StripeSolution>,
    pub searched_combinations: u64,
    pub truncated: bool,
    pub recoverable: bool,
}

/// One feasible full-object assembly built from one solution per stripe.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Assembly {
    pub id: String,
    pub generation: u64,
    pub stripe_solutions: Vec<String>,
    pub payload_digest: String,
    pub matches_manifest: bool,
    pub rank: usize,
    pub diff_vs_best: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunReport {
    pub run_id: String,
    pub object_id: String,
    pub status: String,
    pub isolated_sources: Vec<String>,
    pub committed: Vec<usize>,
    pub reused: Vec<usize>,
    pub superseded: Vec<usize>,
    pub failed_stripes: Vec<usize>,
    pub truncated_stripes: Vec<usize>,
    pub best_assembly_id: Option<String>,
    pub output_digest: Option<String>,
    pub assemblies: Vec<Assembly>,
}

/// Deterministic enumeration budget.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    pub max_combinations_per_stripe: u64,
    pub max_solutions_per_stripe: usize,
    pub max_assemblies: usize,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            max_combinations_per_stripe: 4096,
            max_solutions_per_stripe: 64,
            max_assemblies: 64,
        }
    }
}
