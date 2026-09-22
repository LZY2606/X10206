//! 摘要工具：SHA-256 hex。

use sha2::{Digest, Sha256};

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// 串联多块后的对象摘要（按 stripe 顺序，每块固定 stripe_bytes 后去尾部 padding）。
pub fn sha256_concat(blocks: &[Vec<u8>], total_len: Option<usize>) -> String {
    let mut h = Sha256::new();
    let mut written = 0usize;
    for b in blocks {
        let take = match total_len {
            Some(total) => b.len().min(total.saturating_sub(written)),
            None => b.len(),
        };
        h.update(&b[..take]);
        written += take;
    }
    hex::encode(h.finalize())
}
