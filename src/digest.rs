//! 摘要计算：分片字节 SHA-256；对象摘要为全部数据分片按编号升序拼接后的 SHA-256。

use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

pub fn object_digest(data_shards: &[(usize, &[u8])]) -> String {
    let mut ordered: Vec<(usize, &[u8])> = data_shards.iter().map(|(i, b)| (*i, *b)).collect();
    ordered.sort_unstable_by_key(|(i, _)| *i);
    let mut h = Sha256::new();
    for (i, b) in &ordered {
        h.update(i.to_string().as_bytes());
        h.update([0]);
        h.update(b);
        h.update([0]);
    }
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_is_index_based() {
        let a = object_digest(&[(0, b"A"), (1, b"B")]);
        let b = object_digest(&[(1, b"B"), (0, b"A")]);
        assert_eq!(a, b);
        let c = object_digest(&[(0, b"B"), (1, b"A")]);
        assert_ne!(a, c);
    }
}

/// 跨 stripe 的对象摘要：按 (stripe, shard) 升序拼接数据分片。
pub fn object_digest_stripes(rows: &[(i64, i64, &[u8])]) -> String {
    let mut ordered: Vec<(i64, i64, &[u8])> = rows.to_vec();
    ordered.sort_unstable_by_key(|(s, h, _)| (*s, *h));
    let mut h = Sha256::new();
    for (s, sh, b) in &ordered {
        h.update(s.to_string().as_bytes());
        h.update([0]);
        h.update(sh.to_string().as_bytes());
        h.update([0]);
        h.update(b);
        h.update([0]);
    }
    hex::encode(h.finalize())
}
