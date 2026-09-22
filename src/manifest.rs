//! On-disk manifest format ("每块摘要" + versioned coding parameters).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const MANIFEST_FORMAT: &str = "stripe-pod-manifest";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub format: String,
    pub manifest_version: u32,
    pub object_id: String,
    pub generation: u64,
    pub codec: String,
    pub data_shards: usize,
    pub parity_shards: usize,
    pub shard_size: usize,
    pub stripe_count: usize,
    pub object_size: usize,
    #[serde(default)]
    pub object_digest: String,
    /// Key: "{stripe_index}:{shard_index}", value: "sha256:..."
    #[serde(default)]
    pub block_digests: BTreeMap<String, String>,
}

impl Manifest {
    pub fn block_digest(&self, stripe: usize, shard: usize) -> Option<&str> {
        self.block_digests
            .get(&format!("{}:{}", stripe, shard))
            .map(|s| s.as_str())
    }

    pub fn validate_shape(&self) -> Result<(), String> {
        if self.format != MANIFEST_FORMAT {
            return Err(format!("unknown manifest format: {}", self.format));
        }
        if self.manifest_version != 1 {
            return Err(format!("unsupported manifest_version: {}", self.manifest_version));
        }
        if self.codec != crate::coding::CODEC_V1 {
            return Err(format!("unknown codec: {}", self.codec));
        }
        if self.data_shards == 0 || self.parity_shards == 0 {
            return Err("data_shards/parity_shards must be positive".into());
        }
        if self.data_shards + self.parity_shards > 256 {
            return Err("data_shards + parity_shards > 256".into());
        }
        if self.shard_size == 0 {
            return Err("shard_size must be positive".into());
        }
        if self.object_size > self.data_shards * self.shard_size * self.stripe_count {
            return Err(format!(
                "object_size {} exceeds encoded capacity {}",
                self.object_size,
                self.data_shards * self.shard_size * self.stripe_count
            ));
        }
        Ok(())
    }
}
