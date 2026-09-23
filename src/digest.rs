//! SHA-256 摘要工具。

use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// 以条带顺序拼接全部数据块计算对象摘要。
pub fn object_digest(stripes: &[Vec<Vec<u8>>], object_len: usize) -> String {
    let mut hasher = Sha256::new();
    for blocks in stripes {
        for block in blocks {
            hasher.update(block);
        }
    }
    hasher.update(object_len.to_le_bytes());
    hex::encode(hasher.finalize())
}

pub fn short(s: &str) -> String {
    if s.len() <= 12 {
        s.to_string()
    } else {
        format!("{}…", &s[..12])
    }
}
