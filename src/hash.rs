//! SHA-256 摘要工具。所有摘要均为小写十六进制字符串。

use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// 对可 JSON 序列化结构做确定性摘要（键序由序列化结构决定，字段不可乱序）。
pub fn sha256_json<T: serde::Serialize>(value: &T) -> String {
    let canonical = serde_json::to_vec(value).expect("JSON 序列化失败");
    sha256_hex(&canonical)
}
