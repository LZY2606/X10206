//! Shared types: import manifest, digests, coding parameters.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

pub fn digest_prefix(hex_digest: &str) -> String {
    format!("sha256:{hex_digest}")
}

pub fn strip_prefix(s: &str) -> &str {
    s.strip_prefix("sha256:").unwrap_or(s)
}

/// Versioned erasure-coding parameters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodecParams {
    pub version: String,
    pub k: usize,
    pub n: usize,
    /// Stripe (shard) size in bytes. Last data shard may be zero-padded.
    pub shard_size: usize,
    /// Original object size before padding, if known.
    pub object_size: Option<usize>,
}

/// A single claimed shard in an import bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardClaim {
    pub stripe: i64,
    pub shard_index: i64,
    pub generation: i64,
    pub source: String,
    /// Claimed digest of `payload_b64`, may be absent.
    pub received_digest: Option<String>,
    /// Manifest-anchored digest for this (stripe, shard_index), may be absent.
    pub manifest_digest: Option<String>,
    pub payload_b64: String,
}

/// Import bundle: versioned manifest plus received fragments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportBundle {
    pub object_id: String,
    pub codec: CodecParams,
    /// Optional object-level digest: sha256 of concatenated data shards,
    /// concatenated over stripes, unpadded to `object_size`.
    pub object_digest: Option<String>,
    pub shards: Vec<ShardClaim>,
}

/// Minimal base64 decoder (standard alphabet, padding optional).
pub fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    let mut table = [255u8; 256];
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (i, &c) in alphabet.iter().enumerate() {
        table[c as usize] = i as u8;
    }
    let clean: Vec<u8> = input
        .bytes()
        .filter(|b| !matches!(b, b' ' | b'\n' | b'\r' | b'\t' | b'='))
        .collect();
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    for chunk in clean.chunks(4) {
        let mut buf = 0u32;
        let mut bits = 0u32;
        for &c in chunk {
            let v = table[c as usize];
            if v == 255 {
                return Err(format!("invalid base64 byte {c:#x}"));
            }
            buf = (buf << 6) | v as u32;
            bits += 6;
        }
        while bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Ok(out)
}

pub fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((triple >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((triple >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(triple & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip() {
        for case in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
            let enc = base64_encode(case);
            assert_eq!(base64_decode(&enc).unwrap(), case);
        }
    }
}
