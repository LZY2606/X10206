use sha2::{Digest, Sha256};

/// 统一的内容摘要：SHA-256 小写十六进制。
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}
