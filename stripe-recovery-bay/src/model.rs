//! Domain types and the on-disk manifest contract.
//!
//! A manifest is the importer's statement of intent: object layout,
//! versioned encoding parameters, expected generation and per-shard
//! digests. Everything the chamber actually receives is recorded
//! separately, so manifest-vs-reality drift stays visible instead of
//! being silently reconciled.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Sidecar digest file accompanying one received shard block.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShardSidecar {
    pub object_id: String,
    pub stripe_index: u32,
    pub shard_index: u8,
    pub generation: u64,
    /// hex sha256 the sender claims for the block bytes.
    pub sha256: String,
}

/// Manifest description of one stripe.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StripeManifest {
    pub stripe_index: u32,
    /// Fixed block size used by every shard of the stripe.
    pub block_size: u64,
    /// Actual object payload bytes contained in this stripe
    /// (<= k * block_size; only the final stripe is short).
    pub data_length: u64,
    /// Expected generation for a healthy stripe.
    pub generation: u64,
    /// hex sha256 per shard, indexed 0..k+m.
    pub shard_digests: Vec<String>,
}

/// Versioned manifest envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub manifest_version: u8,
    pub object_id: String,
    pub codec_version: u8,
    pub k: u8,
    pub m: u8,
    pub stripe_count: u32,
    /// hex sha256 of the fully assembled object payload.
    pub object_digest: String,
    pub stripes: Vec<StripeManifest>,
}

impl Manifest {
    pub fn total_shards(&self) -> u8 {
        self.k + self.m
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.manifest_version != 1 {
            return Err(format!("unsupported manifest_version {}", self.manifest_version));
        }
        crate::codec::validate_geometry(
            crate::codec::CodecVersion::from_u8(self.codec_version)
                .ok_or_else(|| format!("unknown codec_version {}", self.codec_version))?,
            self.k,
            self.m,
        )?;
        if self.stripes.len() as u32 != self.stripe_count {
            return Err(format!(
                "stripe_count {} but stripes has {} entries",
                self.stripe_count,
                self.stripes.len()
            ));
        }
        let mut expected = 0u32;
        for s in &self.stripes {
            if s.stripe_index != expected {
                return Err(format!("stripes must be ordered 0..n, got {}", s.stripe_index));
            }
            expected += 1;
            if s.shard_digests.len() != self.total_shards() as usize {
                return Err(format!(
                    "stripe {} declares {} digests, expected {}",
                    s.stripe_index,
                    s.shard_digests.len(),
                    self.total_shards()
                ));
            }
            if s.data_length > (self.k as u64) * s.block_size {
                return Err(format!(
                    "stripe {} data_length {} exceeds k*block_size {}",
                    s.stripe_index,
                    s.data_length,
                    (self.k as u64) * s.block_size
                ));
            }
        }
        Ok(())
    }
}

/// sha256 of raw bytes, lower-hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Object digest as stated by the manifest: sha256 over the concatenated
/// data shards, each truncated/padded as the object layout requires.
pub fn object_digest_for(
    k: u8,
    stripes: &[(u64 /*data_length*/, Vec<Vec<u8>> /*all blocks*/)],
) -> String {
    let mut h = Sha256::new();
    for (data_length, blocks) in stripes {
        let mut taken = 0u64;
        for d in 0..k as usize {
            let block = &blocks[d];
            let want = (*data_length - taken).min(block.len() as u64);
            h.update(&block[..want as usize]);
            taken += want;
        }
    }
    hex::encode(h.finalize())
}

/// Health classification of one ingested shard, recorded at import time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ShardHealth {
    /// Sidecar digest matches bytes, generation matches manifest, length matches.
    Healthy = 0,
    /// No sidecar digest was provided; bytes cannot be independently verified.
    Unverified = 1,
    /// Sidecar digest matches bytes but generation is older/newer than manifest.
    WrongGeneration = 2,
    /// Sidecar digest disagrees with the bytes (bit-flip / torn write evidence).
    CorruptDigest = 3,
    /// Bytes length is not the manifest block size.
    LengthMismatch = 4,
}

impl ShardHealth {
    pub fn as_str(self) -> &'static str {
        match self {
            ShardHealth::Healthy => "healthy",
            ShardHealth::Unverified => "unverified",
            ShardHealth::WrongGeneration => "wrong_generation",
            ShardHealth::CorruptDigest => "corrupt_digest",
            ShardHealth::LengthMismatch => "length_mismatch",
        }
    }

    pub fn parse(s: &str) -> Option<ShardHealth> {
        Some(match s {
            "healthy" => ShardHealth::Healthy,
            "unverified" => ShardHealth::Unverified,
            "wrong_generation" => ShardHealth::WrongGeneration,
            "corrupt_digest" => ShardHealth::CorruptDigest,
            "length_mismatch" => ShardHealth::LengthMismatch,
            _ => return None,
        })
    }

    /// Whether the block is structurally usable by the enumerator. A
    /// length-mismatched block can never be decoded; a digest-corrupt
    /// block is deliberately excluded but retained as corruption evidence.
    pub fn structurally_usable(self) -> bool {
        !matches!(self, ShardHealth::LengthMismatch)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunStatus {
    Running,
    Complete,
    Failed,
}

impl RunStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            RunStatus::Running => "running",
            RunStatus::Complete => "complete",
            RunStatus::Failed => "failed",
        }
    }
    pub fn parse(s: &str) -> Option<RunStatus> {
        Some(match s {
            "running" => RunStatus::Running,
            "complete" => RunStatus::Complete,
            "failed" => RunStatus::Failed,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StripeState {
    Pending,
    Recovered,
    Committed,
    Unrecoverable,
    Failed,
}

impl StripeState {
    pub fn as_str(self) -> &'static str {
        match self {
            StripeState::Pending => "pending",
            StripeState::Recovered => "recovered",
            StripeState::Committed => "committed",
            StripeState::Unrecoverable => "unrecoverable",
            StripeState::Failed => "failed",
        }
    }
    pub fn parse(s: &str) -> Option<StripeState> {
        Some(match s {
            "pending" => StripeState::Pending,
            "recovered" => StripeState::Recovered,
            "committed" => StripeState::Committed,
            "unrecoverable" => StripeState::Unrecoverable,
            "failed" => StripeState::Failed,
            _ => return None,
        })
    }
}
