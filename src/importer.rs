//! Ingest manifests, data shards, parity shards and per-block digests.
//!
//! Two on-disk layouts are accepted:
//! 1. A single JSON bundle (`ImportBundle`, base64 bytes).
//! 2. A directory containing `manifest.json` plus `shards/` files named
//!    `stripe{stripe}.shard{shard}.gen{generation}.src{source}.bin` and a
//!    matching `.sha256` sidecar.
//!
//! Importing never modifies the source fragments; bytes are copied into the
//! pod's own blob store and the claimed digest is kept as received.

use std::fs;
use std::path::{Path, PathBuf};

use crate::digest::sha256_hex;
use crate::model::{ImportBundle, ReceiptInput};
use crate::store::Store;

#[derive(Debug)]
pub enum ImportError {
    Io(String),
    Parse(String),
    Invalid(String),
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportError::Io(s) => write!(f, "io error: {s}"),
            ImportError::Parse(s) => write!(f, "parse error: {s}"),
            ImportError::Invalid(s) => write!(f, "invalid import: {s}"),
        }
    }
}

impl std::error::Error for ImportError {}

impl From<std::io::Error> for ImportError {
    fn from(e: std::io::Error) -> Self {
        ImportError::Io(e.to_string())
    }
}

pub struct ImportOutcome {
    pub object_id: String,
    pub receipts: usize,
}

/// Import a bundle JSON string.
pub fn import_json(store: &Store, json: &str) -> Result<ImportOutcome, ImportError> {
    let bundle: ImportBundle =
        serde_json::from_str(json).map_err(|e| ImportError::Parse(e.to_string()))?;
    import_bundle(store, bundle)
}

/// Import either a `.json` bundle file or a fragment directory.
pub fn import_path(store: &Store, path: &Path) -> Result<ImportOutcome, ImportError> {
    if path.is_dir() {
        import_dir(store, path)
    } else {
        let json = fs::read_to_string(path)?;
        import_json(store, &json)
    }
}

fn validate_bundle(bundle: &ImportBundle) -> Result<(), ImportError> {
    let m = &bundle.manifest;
    if m.object_id.trim().is_empty() {
        return Err(ImportError::Invalid("empty object_id".into()));
    }
    if m.k == 0 {
        return Err(ImportError::Invalid("k must be > 0".into()));
    }
    if m.codec_version != 1 && m.codec_version != 2 {
        return Err(ImportError::Invalid(format!(
            "unsupported codec_version {}",
            m.codec_version
        )));
    }
    if m.stripe_count == 0 {
        return Err(ImportError::Invalid("stripe_count must be > 0".into()));
    }
    for r in &bundle.receipts {
        if r.digest.trim().is_empty() {
            return Err(ImportError::Invalid(format!(
                "receipt stripe={} shard={} is missing a digest",
                r.stripe, r.shard
            )));
        }
        if r.source.trim().is_empty() {
            return Err(ImportError::Invalid(format!(
                "receipt stripe={} shard={} is missing a source",
                r.stripe, r.shard
            )));
        }
    }
    Ok(())
}

pub fn import_bundle(store: &Store, bundle: ImportBundle) -> Result<ImportOutcome, ImportError> {
    validate_bundle(&bundle)?;
    let m = bundle.manifest.clone();
    let object_id = m.object_id.clone();
    store.upsert_manifest(&m).map_err(db_err)?;

    let mut count = 0usize;
    for r in bundle.receipts {
        let actual = sha256_hex(&r.bytes);
        store
            .insert_receipt(
                &object_id,
                r.stripe,
                r.shard,
                r.generation,
                &r.source,
                &r.digest,
                &actual,
                r.bytes.len(),
                &r.bytes,
            )
            .map_err(db_err)?;
        count += 1;
    }
    // Manifest length mismatch evidence is derived at recovery time; we only
    // record the declared length here. Touch the object so lists refresh.
    Ok(ImportOutcome {
        object_id,
        receipts: count,
    })
}

/// Directory layout:
///   manifest.json
///   shards/stripe{S}.shard{H}.gen{G}.src{SOURCE}.bin
///   shards/<same>.sha256  (contents: hex digest, optional whitespace/comments)
pub fn import_dir(store: &Store, dir: &Path) -> Result<ImportOutcome, ImportError> {
    let manifest_path = dir.join("manifest.json");
    let manifest_json = fs::read_to_string(&manifest_path)?;
    let manifest: crate::model::Manifest =
        serde_json::from_str(&manifest_json).map_err(|e| ImportError::Parse(e.to_string()))?;

    let shards_dir = dir.join("shards");
    let mut receipts = Vec::new();
    if shards_dir.is_dir() {
        for entry in fs::read_dir(&shards_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("bin") {
                continue;
            }
            let (stripe, shard, generation, source) = parse_shard_name(&path)?;
            let bytes = fs::read(&path)?;
            let sidecar = PathBuf::from(format!("{}.sha256", path.to_string_lossy()));
            let digest = if sidecar.is_file() {
                let raw = fs::read_to_string(&sidecar)?;
                raw.split_whitespace()
                    .next()
                    .ok_or_else(|| ImportError::Invalid(format!("empty digest sidecar: {sidecar:?}")))?
                    .to_string()
            } else {
                sha256_hex(&bytes)
            };
            receipts.push(ReceiptInput {
                stripe,
                shard,
                generation,
                source,
                digest,
                bytes,
            });
        }
    }
    receipts.sort_by(|a, b| {
        (a.stripe, a.shard, a.generation, &a.source).cmp(&(b.stripe, b.shard, b.generation, &b.source))
    });
    import_bundle(store, ImportBundle { manifest, receipts })
}

fn parse_shard_name(path: &Path) -> Result<(usize, usize, i64, String), ImportError> {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| ImportError::Invalid(format!("bad shard name: {path:?}")))?;
    let mut stripe = None;
    let mut shard = None;
    let mut generation = 1i64;
    let mut source = String::from("unknown");
    for part in stem.split('.') {
        if let Some(v) = part.strip_prefix("stripe") {
            stripe = Some(v.parse().map_err(|_| ImportError::Invalid(stem.into()))?);
        } else if let Some(v) = part.strip_prefix("shard") {
            shard = Some(v.parse().map_err(|_| ImportError::Invalid(stem.into()))?);
        } else if let Some(v) = part.strip_prefix("gen") {
            generation = v.parse().map_err(|_| ImportError::Invalid(stem.into()))?;
        } else if let Some(v) = part.strip_prefix("src") {
            source = v.to_string();
        }
    }
    match (stripe, shard) {
        (Some(s), Some(h)) => Ok((s, h, generation, source)),
        _ => Err(ImportError::Invalid(format!(
            "shard name must include stripeN and shardN: {path:?}"
        ))),
    }
}

fn db_err(e: rusqlite::Error) -> ImportError {
    ImportError::Io(format!("database: {e}"))
}
