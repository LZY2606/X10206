//! SHA-256 摘要工具：每块摘要与对象级摘要。

use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// 按 stripe 顺序拼接重建字节计算对象摘要（固定块长，尾部按 manifest 声明截断）。
pub fn object_digest(stripe_blocks: &[Vec<u8>], object_len: usize) -> String {
    let mut hasher = Sha256::new();
    let mut remaining = object_len;
    for block in stripe_blocks {
        let take = remaining.min(block.len());
        hasher.update(&block[..take]);
        remaining = remaining.saturating_sub(take);
    }
    let digest = hasher.finalize();
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
