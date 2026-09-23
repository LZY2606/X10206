//! Digest helpers. All digests are versioned strings of the form
//! `sha256:<hex>` so a future hash change is distinguishable on import.

use sha2::{Digest, Sha256};

pub const SHA256_PREFIX: &str = "sha256";

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    hex_encode(&out)
}

pub fn of(bytes: &[u8]) -> String {
    format!("{SHA256_PREFIX}:{}", sha256_hex(bytes))
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Split a versioned digest into `(scheme, hex)` and compare against bytes.
pub fn verify(claimed: &str, bytes: &[u8]) -> bool {
    match claimed.split_once(':') {
        Some((SHA256_PREFIX, _)) => of(bytes) == claimed,
        _ => false,
    }
}
