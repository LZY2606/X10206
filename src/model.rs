//! 导入模型、版本化 manifest 与摘要规则。
//!
//! 摘要链：
//! shard_digest   = SHA256(b"SHARD|" || 原始字节)
//! stripe_digest  = SHA256(各 index 顺序拼接的 shard_digest)
//! object_digest  = SHA256(各 stripe 顺序拼接的 stripe_digest)

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MANIFEST_VERSION: &str = "stripe-restore-capsule/1";

pub fn shard_digest(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"SHARD|");
    h.update(data);
    hex::encode(h.finalize())
}

pub fn stripe_digest(shard_digests: &[String]) -> String {
    let mut h = Sha256::new();
    h.update(b"STRIPE|");
    for d in shard_digests {
        h.update(d.as_bytes());
    }
    hex::encode(h.finalize())
}

pub fn object_digest(stripe_digests: &[String]) -> String {
    let mut h = Sha256::new();
    h.update(b"OBJECT|");
    for d in stripe_digests {
        h.update(d.as_bytes());
    }
    hex::encode(h.finalize())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardExpect {
    pub index: usize,
    pub length: usize,
    pub digest_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeSpec {
    pub stripe: usize,
    pub shards: Vec<ShardExpect>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenManifest {
    pub generation: u64,
    pub created_at: String,
    pub k: usize,
    pub m: usize,
    pub stripe_count: usize,
    pub object_digest_hex: String,
    pub stripes: Vec<StripeSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportManifest {
    pub capsule: String,
    pub manifest_id: String,
    pub received_at: String,
    pub object_id: String,
    pub generations: Vec<GenManifest>,
}

/// 每块碎片的随附元数据（字节单独以 .bin 落盘，保证“保存原始字节”）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentMeta {
    pub fragment_id: String,
    pub object_id: String,
    pub generation: u64,
    pub stripe: usize,
    pub shard_index: usize,
    pub source: String,
    pub received_at: String,
    pub length: usize,
    /// 随块附带的每块摘要（可能缺失，也可能与字节/manifest 不一致）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed_digest_hex: Option<String>,
    pub bin_path: String,
}
