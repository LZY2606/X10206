//! SHA-256 helpers and recomputed digests for reconstruction reports.

use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// SHA-256 over the concatenation of fixed-length shards in index order.
pub fn concat_sha256(shards: &[Vec<u8>]) -> String {
    let mut h = Sha256::new();
    for s in shards {
        h.update((s.len() as u64).to_le_bytes());
        h.update(s);
    }
    hex::encode(h.finalize())
}

pub struct ObjectDigestInput<'a> {
    pub shard_length: usize,
    pub data_shards: &'a [Vec<u8>],
}

/// Object digest: SHA-256 over `shard_length || concat(data shards of every
/// stripe)` in stripe order. Length framing prevents cross-stripe ambiguity.
pub fn object_sha256(stripes: &[ObjectDigestInput<'_>]) -> String {
    let mut h = Sha256::new();
    for stripe in stripes {
        h.update((stripe.shard_length as u64).to_le_bytes());
        for s in stripe.data_shards {
            debug_assert_eq!(s.len(), stripe.shard_length);
            h.update(s);
        }
    }
    hex::encode(h.finalize())
}
