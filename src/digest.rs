//! 每块摘要算法：生产用 sha256，测试小有限域 fixture 用弱摘要（便于构造多解）。

use sha2::{Digest, Sha256};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DigestAlg {
    Sha256,
    Sum8,
    Sum16,
}

impl DigestAlg {
    pub fn from_str(s: &str) -> Self {
        match s {
            "sum8" => DigestAlg::Sum8,
            "sum16" => DigestAlg::Sum16,
            _ => DigestAlg::Sha256,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            DigestAlg::Sha256 => "sha256",
            DigestAlg::Sum8 => "sum8",
            DigestAlg::Sum16 => "sum16",
        }
    }

    pub fn digest(&self, bytes: &[u8]) -> String {
        match self {
            DigestAlg::Sha256 => sha256_hex(bytes),
            DigestAlg::Sum8 => {
                let s: u32 = bytes.iter().map(|b| *b as u32).sum();
                format!("{:02x}", s % 256)
            }
            DigestAlg::Sum16 => {
                let s: u32 = bytes.iter().map(|b| *b as u32).sum();
                format!("{:04x}", s % 65536)
            }
        }
    }
}

pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
