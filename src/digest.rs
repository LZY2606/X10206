use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// 拼接多个 shard 后取摘要（用于 stripe / data 区摘要）。
pub fn sha256_concat(parts: &[Vec<u8>]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    hex::encode(h.finalize())
}
