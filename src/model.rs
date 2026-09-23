//! Domain types exchanged by importer, recovery engine, storage and web.

use serde::{Deserialize, Serialize};

/// Versioned object manifest (metadata only; bytes arrive as receipts).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub object_id: String,
    /// Encoding parameter version: 1 or 2.
    pub codec_version: i64,
    pub k: usize,
    pub m: usize,
    pub stripe_count: usize,
    /// Declared uniform shard length in bytes. Manifest/length mismatch is
    /// recorded as evidence when a receipt disagrees.
    pub shard_len: usize,
    /// Optional global object digest (sha256 of concatenated data stripes).
    #[serde(default)]
    pub object_digest: Option<String>,
    /// Generation the manifest itself was written at.
    #[serde(default = "default_generation")]
    pub generation: i64,
}

fn default_generation() -> i64 {
    1
}

/// One received fragment plus its provenance and per-block digest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptInput {
    pub stripe: usize,
    pub shard: usize,
    pub generation: i64,
    pub source: String,
    /// sha256 hex claimed by the sender for these bytes.
    pub digest: String,
    /// Raw fragment bytes (base64 in on-disk JSON, raw in memory).
    #[serde(with = "base64_bytes")]
    pub bytes: Vec<u8>,
}

/// Bundle accepted by the importer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportBundle {
    pub manifest: Manifest,
    #[serde(default)]
    pub receipts: Vec<ReceiptInput>,
}

/// Why a receipt was excluded from a particular solution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Exclusion {
    DigestMismatch {
        receipt_id: i64,
        source: String,
        claimed: String,
        actual: String,
    },
    LengthMismatch {
        receipt_id: i64,
        source: String,
        expected: usize,
        actual: usize,
    },
    OutOfRange {
        receipt_id: i64,
        source: String,
        stripe: usize,
        shard: usize,
    },
    GenerationConflict {
        receipt_id: i64,
        source: String,
        generation: i64,
        selected_generation: i64,
    },
    DuplicateLoser {
        receipt_id: i64,
        source: String,
        kept_receipt_id: i64,
    },
    IsolatedSource {
        receipt_id: i64,
        source: String,
    },
    NotNeeded {
        receipt_id: i64,
        source: String,
    },
}

/// One verified feasible reconstruction of a stripe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Solution {
    pub codec_version: i64,
    pub generation: i64,
    /// Receipt ids that participated in the k-shard solve.
    pub participant_ids: Vec<i64>,
    /// Receipt ids used only to cross-check the result.
    pub witness_ids: Vec<i64>,
    /// Excluded receipts with the corruption evidence.
    pub exclusions: Vec<Exclusion>,
    /// Fully reconstructed stripe (k+m shards).
    pub shards: Vec<Vec<u8>>,
    /// sha256 hex over the concatenated reconstructed shard bytes.
    pub stripe_digest: String,
    /// sha256 hex over the concatenated data shards only.
    pub data_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StripeStatus {
    Unique,
    Ambiguous,
    Infeasible,
}

/// Result of enumerating feasible sets for one stripe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeReport {
    pub stripe: usize,
    pub status: StripeStatus,
    pub solutions: Vec<Solution>,
    /// Evidence collected for the stripe independent of any one solution
    /// (corrupt / out-of-range / isolated receipts).
    #[serde(default)]
    pub exclusions: Vec<Exclusion>,
    /// True when the search budget was exhausted before enumerating all sets.
    pub truncated: bool,
    pub combos_considered: usize,
    /// True once the global object digest selects one of several feasible
    /// answers. Local status stays `ambiguous` so all evidence is retained.
    #[serde(default)]
    pub resolved: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitStatus {
    Committed,
    Ambiguous,
    Infeasible,
}

/// Per-object run outcome persisted across interruptions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunReport {
    pub run_id: String,
    pub object_id: String,
    pub committed: usize,
    pub ambiguous: usize,
    pub infeasible: usize,
    pub total: usize,
    pub reused: usize,
    pub truncated: bool,
    pub stripes: Vec<StripeReport>,
    pub started_at: String,
    pub finished_at: Option<String>,
}

mod base64_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
            let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
            let n = (b0 << 16) | (b1 << 8) | b2;
            out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
            if chunk.len() > 1 {
                out.push(ALPHABET[((n >> 6) & 63) as usize] as char);
            } else {
                out.push('=');
            }
            if chunk.len() > 2 {
                out.push(ALPHABET[(n & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
        s.serialize_str(&out)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        let mut rev = [255u8; 256];
        for (i, b) in ALPHABET.iter().enumerate() {
            rev[*b as usize] = i as u8;
        }
        let mut out = Vec::new();
        let mut buf: u32 = 0;
        let mut bits = 0u32;
        for c in s.bytes() {
            if c == b'=' || c == b'\n' || c == b'\r' || c == b' ' {
                continue;
            }
            let v = rev[c as usize];
            if v == 255 {
                return Err(serde::de::Error::custom("invalid base64"));
            }
            buf = (buf << 6) | v as u32;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((buf >> bits) as u8);
                buf &= (1 << bits) - 1;
            }
        }
        Ok(out)
    }
}
