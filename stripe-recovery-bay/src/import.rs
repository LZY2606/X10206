//! Ingest a fragment bundle: manifest + per-source shard bytes + sidecars.
//!
//! Expected bundle layout (everything outside the chamber data dir is only
//! read, never modified):
//!
//! ```text
//! bundle/
//!   manifest.json
//!   <source>/s<stripe>/shard<idx>.bin
//!   <source>/s<stripe>/shard<idx>.json   # optional ShardSidecar
//! ```
//!
//! Every received block is copied verbatim into `received/`; the importer
//! never overwrites an existing blob. Classification compares received
//! reality against the manifest rather than trusting either side.

use crate::blockstore::BlobStore;
use crate::db::BayDb;
use crate::model::{sha256_hex, Manifest, ShardHealth, ShardSidecar};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct ImportReport {
    pub object_id: String,
    pub already_present: bool,
    pub shards_ingested: usize,
    pub shards_skipped_identical: usize,
    pub health_counts: std::collections::BTreeMap<String, usize>,
}

pub fn import_bundle(
    db: &BayDb,
    store: &dyn BlobStore,
    bundle: &Path,
) -> Result<ImportReport, String> {
    let manifest_path = bundle.join("manifest.json");
    let manifest_bytes = fs::read(&manifest_path)
        .map_err(|e| format!("read manifest {}: {e}", manifest_path.display()))?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| format!("parse manifest: {e}"))?;
    manifest.validate().map_err(|e| format!("invalid manifest: {e}"))?;

    let already_present = !db.insert_object_if_absent(&manifest).map_err(|e| e.to_string())?;
    db.touch_source("manifest").map_err(|e| e.to_string())?;

    // Preserve the raw manifest bytes as a provenance record too.
    let mdir = store
        .write_received(&manifest.object_id, "_manifest", 0, "manifest.json", &manifest_bytes)
        .map_err(|e| format!("storing manifest bytes: {e}"))?;
    let _ = mdir;

    let mut report = ImportReport {
        object_id: manifest.object_id.clone(),
        already_present,
        shards_ingested: 0,
        shards_skipped_identical: 0,
        health_counts: Default::default(),
    };

    // Each top-level directory of the bundle is one receiving source.
    for entry in fs::read_dir(bundle).map_err(|e| format!("read bundle dir: {e}"))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let src_dir = entry.path();
        if !src_dir.is_dir() {
            continue;
        }
        let source = entry.file_name().to_string_lossy().to_string();
        if source.starts_with('.') {
            continue;
        }
        db.touch_source(&source).map_err(|e| e.to_string())?;
        import_source(db, store, &manifest, &source, &src_dir, &mut report)
            .map_err(|e| format!("source {source}: {e}"))?;
    }

    db.event(
        "import",
        Some(&manifest.object_id),
        &format!(
            "imported {} shards ({} duplicate bytes) from {}",
            report.shards_ingested,
            report.shards_skipped_identical,
            bundle.display()
        ),
    );
    Ok(report)
}

fn import_source(
    db: &BayDb,
    store: &dyn BlobStore,
    manifest: &Manifest,
    source: &str,
    src_dir: &Path,
    report: &mut ImportReport,
) -> Result<(), String> {
    for s in 0..manifest.stripe_count {
        let sdir = src_dir.join(format!("s{s}"));
        if !sdir.is_dir() {
            continue;
        }
        for idx in 0..manifest.total_shards() {
            let bin = sdir.join(format!("shard{idx}.bin"));
            if !bin.is_file() {
                continue;
            }
            let bytes = fs::read(&bin).map_err(|e| format!("read {}: {e}", bin.display()))?;
            let sidecar_path: PathBuf = bin.with_extension("json");
            let sidecar: Option<ShardSidecar> = if sidecar_path.is_file() {
                let sb = fs::read(&sidecar_path)
                    .map_err(|e| format!("read {}: {e}", sidecar_path.display()))?;
                Some(
                    serde_json::from_slice::<ShardSidecar>(&sb)
                        .map_err(|e| format!("parse sidecar {}: {e}", sidecar_path.display()))?,
                )
            } else {
                None
            };

            let stripe_manifest = &manifest.stripes[s as usize];
            let content_digest = sha256_hex(&bytes);

            // Classify against manifest reality.
            let expected_length = stripe_manifest.block_size;
            let expected_digest = &stripe_manifest.shard_digests[idx as usize];
            let expected_generation = stripe_manifest.generation;

            let sidecar_sha = sidecar.as_ref().map(|sc| sc.sha256.clone());
            let claimed_generation = sidecar.as_ref().map(|sc| sc.generation).unwrap_or(expected_generation);

            let mut health = if bytes.len() as u64 != expected_length {
                ShardHealth::LengthMismatch
            } else if let Some(claimed) = &sidecar_sha {
                if claimed.to_lowercase() != content_digest {
                    ShardHealth::CorruptDigest
                } else if claimed_generation != expected_generation {
                    ShardHealth::WrongGeneration
                } else {
                    ShardHealth::Healthy
                }
            } else {
                ShardHealth::Unverified
            };

            // Defensive: sidecar present but refers to a different slot.
            if let Some(sc) = &sidecar {
                if sc.object_id != manifest.object_id
                    || sc.stripe_index != s
                    || sc.shard_index != idx
                {
                    health = ShardHealth::CorruptDigest;
                }
                // Manifest digest disagreement for healthy-looking bytes is
                // recorded as wrong-generation (partial-write mixing) unless
                // already corrupt.
                if matches!(health, ShardHealth::Healthy)
                    && expected_digest.to_lowercase() != content_digest
                {
                    health = ShardHealth::WrongGeneration;
                }
            } else if expected_digest.to_lowercase() != content_digest
                && bytes.len() as u64 == expected_length
            {
                // No sidecar: unverified, but a manifest mismatch hints at a
                // torn write; stay honest and keep it unverified.
            }

            // Duplicate candidates with identical bytes for the same slot are
            // deduped; distinct content is always retained as a candidate.
            let existing = db
                .shards_for_object(&manifest.object_id)
                .map_err(|e| e.to_string())?;
            let dup = existing.iter().any(|r| {
                r.stripe_index == s
                    && r.shard_index == idx
                    && r.source == source
                    && r.content_sha256 == content_digest
            });
            if dup {
                report.shards_skipped_identical += 1;
                continue;
            }

            let name = format!("shard{idx}.{}.bin", &content_digest[..12]);
            let blob = store
                .write_received(&manifest.object_id, source, s, &name, &bytes)
                .map_err(|e| format!("storing received bytes: {e}"))?;
            db.insert_shard(
                &manifest.object_id,
                s,
                idx,
                claimed_generation as i64,
                &content_digest,
                sidecar_sha.as_deref(),
                bytes.len() as i64,
                source,
                health,
                &blob.to_string_lossy(),
            )
            .map_err(|e| e.to_string())?;
            report.shards_ingested += 1;
            *report.health_counts.entry(health.as_str().to_string()).or_default() += 1;
        }
    }
    Ok(())
}
