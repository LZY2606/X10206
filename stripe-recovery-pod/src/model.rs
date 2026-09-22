//! Domain types and on-disk manifest formats.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Manifest shipped alongside a set of shards. JSON file named `manifest.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub scheme: String,
    pub version: u32,
    pub object_id: String,
    pub object_digest_hex: String,
    pub stripe_count: usize,
    pub shard_len: usize,
    pub data_shards: usize,
    pub parity_shards: usize,
    /// Declared write generation; shards from a partial overwrite can carry
    /// a newer generation for some stripes only.
    pub generation: u64,
    /// Unpadded logical object length in bytes.
    pub data_len: usize,
}

impl Manifest {
    pub fn total_shards(&self) -> usize {
        self.data_shards + self.parity_shards
    }
}

/// Sidecar digest file: `<shard_file>.sha256` containing `"<hex>  <filename>"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sidecar {
    pub digest_hex: String,
    pub filename: Option<String>,
}

/// What one incoming shard file on disk represents.
#[derive(Debug, Clone)]
pub struct IncomingShard {
    pub stripe: usize,
    pub shard_index: usize,
    pub generation: u64,
    pub bytes: Vec<u8>,
    pub filename: String,
    pub sidecar_digest_hex: Option<String>,
}

/// Kinds of evidence recorded while importing or verifying fragments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceKind {
    /// Sidecar digest disagrees with recomputed bytes: bit flip / rot.
    DigestMismatch,
    /// No sidecar digest was provided; digest integrity is unverifiable.
    MissingSidecar,
    /// Shard byte length disagrees with the manifest's shard_len.
    LengthMismatch,
    /// shard_index outside [0, data+parity) or stripe >= stripe_count.
    OutOfRange,
    /// Two fragments with the same (stripe, shard_index) and generation.
    DuplicateIndex,
    /// Two fragments for the same key carry different generation numbers.
    GenerationMix,
    /// Two manifests for the same object disagree on parameters or digest.
    ManifestConflict,
    /// The fragment is excluded because its reception source is human-isolated.
    SourceIsolated,
}

impl EvidenceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            EvidenceKind::DigestMismatch => "digest_mismatch",
            EvidenceKind::MissingSidecar => "missing_sidecar",
            EvidenceKind::LengthMismatch => "length_mismatch",
            EvidenceKind::OutOfRange => "out_of_range",
            EvidenceKind::DuplicateIndex => "duplicate_index",
            EvidenceKind::GenerationMix => "generation_mix",
            EvidenceKind::ManifestConflict => "manifest_conflict",
            EvidenceKind::SourceIsolated => "source_isolated",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "digest_mismatch" => EvidenceKind::DigestMismatch,
            "missing_sidecar" => EvidenceKind::MissingSidecar,
            "length_mismatch" => EvidenceKind::LengthMismatch,
            "out_of_range" => EvidenceKind::OutOfRange,
            "duplicate_index" => EvidenceKind::DuplicateIndex,
            "generation_mix" => EvidenceKind::GenerationMix,
            "manifest_conflict" => EvidenceKind::ManifestConflict,
            "source_isolated" => EvidenceKind::SourceIsolated,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardRef {
    pub stripe: usize,
    pub shard_index: usize,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Parse a sidecar file in the conventional `hex  filename` layout.
pub fn parse_sidecar(text: &str) -> Option<Sidecar> {
    let line = text.lines().next()?.trim();
    let mut parts = line.split_whitespace();
    let digest_hex = parts.next()?.to_string();
    if digest_hex.len() != 64 || !digest_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let filename = parts.next().map(|s| s.trim_start_matches('*').to_string());
    Some(Sidecar { digest_hex, filename })
}

/// Parse the shard file name: `s<stripe>_i<index>_g<generation>.bin`.
pub fn parse_shard_filename(name: &str) -> Option<(usize, usize, u64)> {
    let stem = name.strip_suffix(".bin")?;
    let mut it = stem.split('_');
    let s = it.next()?.strip_prefix('s')?;
    let i = it.next()?.strip_prefix('i')?;
    let g = it.next()?.strip_prefix('g')?;
    Some((s.parse().ok()?, i.parse().ok()?, g.parse().ok()?))
}

/// Assemble logical object bytes from committed stripes, stripping final padding.
pub fn assemble_object(
    stripes: &[Vec<Vec<u8>>],
    data_shards: usize,
    shard_len: usize,
    data_len: usize,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(stripes.len() * data_shards * shard_len);
    for stripe in stripes {
        for d in stripe.iter().take(data_shards) {
            out.extend_from_slice(d);
        }
    }
    out.truncate(data_len);
    out
}
