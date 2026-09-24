//! Versioned codec parameters and on-disk JSON models (manifest, fragments).

use serde::{Deserialize, Serialize};

pub const CODEC_V1: &str = "rs-gf256-v1";
pub const MANIFEST_V1: &str = "v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodecParams {
    #[serde(default = "default_codec")]
    pub version: &'static str,
    pub k: usize,
    pub m: usize,
    /// Expected shard length in bytes for this object.
    pub shard_len: usize,
}

fn default_codec() -> &'static str {
    CODEC_V1
}

impl CodecParams {
    pub fn n(&self) -> usize {
        self.k + self.m
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != CODEC_V1 {
            return Err(format!("unsupported codec version: {}", self.version));
        }
        if self.k < 1 {
            return Err("k must be >= 1".into());
        }
        if self.n() + self.k > 256 {
            return Err(format!("k + m + k must fit GF(256): n={}", self.n()));
        }
        if self.shard_len == 0 {
            return Err("shard_len must be > 0".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardDigestEntry {
    pub index: usize,
    #[serde(default)]
    pub length: Option<usize>,
    #[serde(default)]
    pub digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeSpec {
    pub stripe_index: usize,
    #[serde(default)]
    pub generation: Option<u64>,
    pub shards: Vec<ShardDigestEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    #[serde(default = "default_manifest_version")]
    pub manifest_version: String,
    pub object_id: String,
    #[serde(default)]
    pub generation: u64,
    pub codec: CodecParams,
    /// Original object length in bytes (last stripe padding check).
    #[serde(default)]
    pub data_len: Option<usize>,
    #[serde(default)]
    pub object_digest: Option<String>,
    pub stripes: Vec<StripeSpec>,
}

fn default_manifest_version() -> String {
    MANIFEST_V1.into()
}

impl Manifest {
    pub fn validate(&self) -> Result<(), String> {
        if self.manifest_version != MANIFEST_V1 {
            return Err(format!(
                "unsupported manifest version: {}",
                self.manifest_version
            ));
        }
        self.codec.validate()?;
        if self.stripes.is_empty() {
            return Err("manifest has no stripes".into());
        }
        for (i, s) in self.stripes.iter().enumerate() {
            if s.stripe_index != i {
                return Err(format!(
                    "stripes must be contiguous: position {i} has index {}",
                    s.stripe_index
                ));
            }
            if s.shards.len() != self.codec.n() {
                return Err(format!(
                    "stripe {} declares {} shards, expected n={}",
                    i,
                    s.shards.len(),
                    self.codec.n()
                ));
            }
            for (j, entry) in s.shards.iter().enumerate() {
                if entry.index != j {
                    return Err(format!(
                        "stripe {i}: shard entry order mismatch at {j} (index {})",
                        entry.index
                    ));
                }
                if let Some(len) = entry.length {
                    if len != self.codec.shard_len {
                        return Err(format!(
                            "stripe {i} shard {j}: manifest length {len} != codec shard_len {}",
                            self.codec.shard_len
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn stripe_generation(&self, stripe: usize) -> u64 {
        self.stripes[stripe].generation.unwrap_or(self.generation)
    }

    pub fn shard_digest(&self, stripe: usize, shard: usize) -> Option<&str> {
        self.stripes[stripe].shards[shard].digest.as_deref()
    }
}

/// Sidecar metadata stored next to an imported raw fragment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentMeta {
    pub object_id: String,
    pub stripe_index: usize,
    pub shard_index: usize,
    pub generation: u64,
    pub source: String,
    pub length: usize,
    #[serde(default)]
    pub digest: Option<String>,
    pub received_at: i64,
}
