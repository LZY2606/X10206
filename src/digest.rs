//! Digest helpers. Every committed block and every exported object is
//! verified by a recomputed sha256 so "success" is never status-only.

use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

pub fn shards_digest(shards: &[Vec<u8>]) -> String {
    let mut h = Sha256::new();
    for s in shards {
        h.update(s);
    }
    hex::encode(h.finalize())
}

/// Object digest: concatenated data shards across stripes in order.
pub fn object_data_digest(stripes: &[Vec<Vec<u8>>], k: usize) -> String {
    let mut h = Sha256::new();
    for stripe in stripes {
        for s in stripe.iter().take(k) {
            h.update(s);
        }
    }
    hex::encode(h.finalize())
}

/// Padded object bytes (data shards concatenated).
pub fn object_bytes(stripes: &[Vec<Vec<u8>>], k: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for stripe in stripes {
        for s in stripe.iter().take(k) {
            out.extend_from_slice(s);
        }
    }
    out
}
