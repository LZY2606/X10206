//! Domain model: manifests, shards, stripes, recovery evidence.

use crate::rs::EncodingParams;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Object manifest: versioned encoding parameters plus expected digests.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub object_id: String,
    pub encoding: EncodingParams,
    /// Total bytes stored per shard (must equal stripe_size * stripe_count).
    pub shard_bytes: usize,
    /// Original object length in bytes (<= k * shard_bytes).
    pub object_length: usize,
    /// Digest of the full reconstructed object, if the publisher provided one.
    #[serde(default)]
    pub object_digest: Option<String>,
    /// Expected digest per shard index (k+m entries), if provided.
    #[serde(default)]
    pub shard_digests: Option<Vec<String>>,
}

impl Manifest {
    pub fn stripe_count(&self) -> usize {
        self.shard_bytes / self.encoding.stripe_size
    }

    pub fn validate(&self) -> Result<(), String> {
        self.encoding.validate()?;
        if self.shard_bytes == 0 || self.shard_bytes % self.encoding.stripe_size != 0 {
            return Err(format!(
                "manifest 长度不符: shard_bytes={} 不是 stripe_size={} 的整数倍",
                self.shard_bytes, self.encoding.stripe_size
            ));
        }
        if self.object_length > self.encoding.k * self.shard_bytes {
            return Err("manifest 长度不符: object_length 超过 k*shard_bytes".into());
        }
        if let Some(d) = &self.shard_digests {
            if d.len() != self.encoding.total() {
                return Err(format!(
                    "manifest 长度不符: shard_digests 有 {} 项, 期望 {}",
                    d.len(),
                    self.encoding.total()
                ));
            }
        }
        Ok(())
    }
}

/// Health classification of one imported shard copy.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ShardHealth {
    Ok,
    /// Actual byte length disagrees with the manifest.
    LengthMismatch,
    /// Recomputed digest disagrees with the manifest shard digest.
    DigestMismatch,
    /// Source was manually quarantined by an operator.
    Quarantined,
}

impl ShardHealth {
    pub fn as_str(&self) -> &'static str {
        match self {
            ShardHealth::Ok => "ok",
            ShardHealth::LengthMismatch => "length_mismatch",
            ShardHealth::DigestMismatch => "digest_mismatch",
            ShardHealth::Quarantined => "quarantined",
        }
    }
    pub fn from_str(s: &str) -> Self {
        match s {
            "length_mismatch" => ShardHealth::LengthMismatch,
            "digest_mismatch" => ShardHealth::DigestMismatch,
            "quarantined" => ShardHealth::Quarantined,
            _ => ShardHealth::Ok,
        }
    }
}

/// One imported shard copy (duplicates of the same index are all kept).
#[derive(Clone, Debug)]
pub struct ShardRecord {
    pub id: i64,
    pub object_id: String,
    pub idx: usize,
    pub generation: u64,
    pub source: String,
    pub bytes: Vec<u8>,
    pub digest: String,
    pub health: ShardHealth,
}

/// A fragment of one shard candidate within one stripe.
#[derive(Clone, Debug)]
pub struct Fragment {
    pub shard_id: i64,
    pub idx: usize,
    pub generation: u64,
    pub source: String,
    pub data: Vec<u8>,
}

/// Why a candidate was excluded from a reconstruction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExcludedEvidence {
    pub shard_id: i64,
    pub idx: usize,
    pub generation: u64,
    pub source: String,
    pub reason: String,
}

/// One participant in a reconstruction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Participant {
    pub shard_id: i64,
    pub idx: usize,
    pub generation: u64,
    pub source: String,
    pub digest: String,
}

/// One feasible reconstruction of a single stripe.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StripeAlternative {
    /// Recomputed digest of the full recovered stripe row (k+m fragments).
    pub row_digest: String,
    /// Full recovered row, concatenated fragments in index order.
    #[serde(with = "serde_bytes_hex")]
    pub row: Vec<u8>,
    pub participants: Vec<Participant>,
    pub excluded: Vec<ExcludedEvidence>,
    /// True when the set has exactly k shards and cannot be cross-checked.
    pub at_recovery_floor: bool,
    /// Distinct generations among participants ( >1 means mixed generation ).
    pub generations: Vec<u64>,
    /// How many additional feasible selections produce this same row.
    pub equivalent_sets: usize,
}

mod serde_bytes_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}

/// Per-stripe committed state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StripeState {
    pub stripe_no: usize,
    pub status: String, // "pending" | "committed"
    pub committed_digest: Option<String>,
    pub alternatives: Vec<StripeAlternative>,
}

/// One feasible whole-object reconstruction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObjectSolution {
    pub rank: usize,
    pub object_digest: String,
    pub digest_matches_manifest: Option<bool>,
    /// stripe_no -> alternative index chosen.
    pub picks: Vec<(usize, usize)>,
    /// Human-readable difference summary vs. the primary solution.
    pub diff_summary: String,
}
