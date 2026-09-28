//! 导入清单 / shard 报文与恢复结果类型。

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct ManifestJson {
    pub object_id: String,
    pub size: u64,
    pub stripe_size: u64,
    pub encoding: EncodingJson,
    #[serde(default)]
    pub stripes: Vec<StripeJson>,
}

#[derive(Debug, Deserialize)]
pub struct EncodingJson {
    #[serde(default = "default_version")]
    pub version: u32,
    pub data_shards: usize,
    pub parity_shards: usize,
}

fn default_version() -> u32 {
    1
}

#[derive(Debug, Deserialize)]
pub struct StripeJson {
    pub index: u32,
    #[serde(default)]
    pub shard_digests: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
pub struct ShardImportJson {
    pub object_id: String,
    pub stripe: u32,
    pub shard_index: u32,
    pub generation: u64,
    pub source: String,
    pub digest: String,
    pub data_b64: String,
}

/// stripe 内每块的期望字节长度（末条带可能更短，块内零填充）。
pub fn shard_len(size: u64, stripe_size: u64, k: usize, stripe: u32) -> usize {
    let start = stripe as u64 * stripe_size;
    if start >= size {
        return 0;
    }
    let data_len = size.min(start + stripe_size) - start;
    ((data_len + k as u64 - 1) / k as u64) as usize
}

pub fn stripe_count(size: u64, stripe_size: u64) -> u32 {
    if size == 0 || stripe_size == 0 {
        return 0;
    }
    ((size + stripe_size - 1) / stripe_size) as u32
}

#[derive(Clone, Debug, Serialize)]
pub struct OutputShard {
    pub shard_index: u32,
    pub bytes: Vec<u8>,
    pub digest: String,
    pub reconstructed: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Evidence {
    pub shard_id: i64,
    pub shard_index: u32,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct VariantResult {
    pub variant_no: usize,
    pub generation: u64,
    pub participants: Vec<i64>,
    pub status: String,
    pub mismatched_indices: Vec<u32>,
    pub diffs: Vec<String>,
    pub outputs: Vec<OutputShard>,
}
