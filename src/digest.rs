
//! 版本化摘要。
//!
//! - `sha256`：生产用途的强摘要。
//! - `xor8`：弱摘要（逐字节异或），仅供 fixture 与测试构造“多个可行答案”。

use sha2::{Digest, Sha256};

pub const SHA256: &str = "sha256";
pub const XOR8: &str = "xor8";

pub fn digest(algo: &str, data: &[u8]) -> String {
    match algo {
        SHA256 => {
            let mut h = Sha256::new();
            h.update(data);
            hex::encode(h.finalize())
        }
        XOR8 => {
            let mut acc: u8 = 0;
            for b in data {
                acc ^= *b;
            }
            format!("xor8:{:02x}", acc)
        }
        other => panic!("未知摘要算法版本: {other}"),
    }
}

pub fn is_known(algo: &str) -> bool {
    algo == SHA256 || algo == XOR8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        assert_eq!(
            digest(SHA256, b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn xor8_basic() {
        assert_eq!(digest(XOR8, b""), "xor8:00");
        assert_eq!(digest(XOR8, &[0x01, 0x02, 0x03]), "xor8:00");
        assert_eq!(digest(XOR8, &[0xAB]), "xor8:ab");
    }
}
