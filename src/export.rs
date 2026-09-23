//! Atomic export into a fresh directory.
//!
//! Layout:
//!   exports/<object>-NNNN/
//!     stripes/stripe{:06}.bin
//!     manifest.json.new        (staging)
//!     manifest.json            (atomic switch target)
//!
//! The original fragment blobs are never modified. `manifest.json` is the
//! switch point: readers only see an export once that file is renamed into
//! place, and the digest it carries is recomputed from the written bytes.

use std::fs;
use std::path::Path;

use crate::digest::{object_data_digest, sha256_hex};
use crate::engine::{recover_object, RunOptions};
use crate::model::StripeStatus;
use crate::store::{atomic_write, Store};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ExportManifest {
    pub object_id: String,
    pub codec_version: i64,
    pub k: usize,
    pub m: usize,
    pub stripe_count: usize,
    pub shard_len: usize,
    pub generation: i64,
    pub object_digest_claimed: Option<String>,
    pub object_digest_recomputed: String,
    pub stripes: Vec<ExportStripe>,
    pub ambiguous: bool,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ExportStripe {
    pub stripe: usize,
    pub file: String,
    pub sha256: String,
    pub generation: i64,
    pub solution_count: usize,
}

pub struct ExportOutcome {
    pub dir: String,
    pub manifest_path: String,
    pub object_digest: String,
    pub bytes_len: usize,
}

#[derive(Debug)]
pub enum ExportError {
    /// Recovery could not produce a single trustworthy object.
    Unresolved { message: String },
    Other(String),
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExportError::Unresolved { message } => write!(f, "export refused: {message}"),
            ExportError::Other(s) => write!(f, "export failed: {s}"),
        }
    }
}
impl std::error::Error for ExportError {}

fn e_other<E: std::fmt::Display>(e: E) -> ExportError {
    ExportError::Other(e.to_string())
}

/// Recover (resuming committed stripes) then export one object atomically.
pub fn export_object(
    store: &Store,
    object_id: &str,
    options: RunOptions,
) -> Result<ExportOutcome, ExportError> {
    let manifest = store
        .get_manifest(object_id)
        .map_err(e_other)?
        .ok_or_else(|| ExportError::Other(format!("unknown object {object_id}")))?;

    let outcome = recover_object(store, object_id, options).map_err(ExportError::Other)?;

    // Safety first: refuse to publish unresolved stripes or a digest mismatch.
    let infeasible: Vec<usize> = outcome
        .report
        .stripes
        .iter()
        .filter(|r| r.status == StripeStatus::Infeasible)
        .map(|r| r.stripe)
        .collect();
    if !infeasible.is_empty() {
        return Err(ExportError::Unresolved {
            message: format!("infeasible stripes: {infeasible:?}"),
        });
    }
    let unresolved: Vec<usize> = outcome
        .report
        .stripes
        .iter()
        .filter(|r| r.status == StripeStatus::Ambiguous && !r.resolved)
        .map(|r| r.stripe)
        .collect();
    if !unresolved.is_empty() {
        return Err(ExportError::Unresolved {
            message: format!("multiple feasible answers for stripes: {unresolved:?}"),
        });
    }
    let bytes = outcome.object_bytes.ok_or_else(|| ExportError::Unresolved {
        message: "object could not be resolved to a single reconstruction".into(),
    })?;
    let recomputed = object_data_digest(&outcome.committed_shards, manifest.k);
    if let Some(claimed) = &manifest.object_digest {
        if claimed != &recomputed {
            return Err(ExportError::Unresolved {
                message: format!(
                    "object digest mismatch: claimed {claimed}, recomputed {recomputed}"
                ),
            });
        }
    }

    let dir = store.new_export_dir(object_id).map_err(e_other)?;
    let stripes_dir = dir.join("stripes");

    if store.faults().fail_export_write {
        return Err(ExportError::Other("injected export write failure".into()));
    }

    let mut export_stripes = Vec::new();
    for (i, shards) in outcome.committed_shards.iter().enumerate() {
        let mut flat = Vec::new();
        for s in shards {
            flat.extend_from_slice(s);
        }
        let digest = sha256_hex(&flat);
        let fname = format!("stripe{i:06}.bin");
        atomic_write(&stripes_dir.join(&fname), &flat).map_err(e_other)?;
        let generation = outcome.report.stripes[i].solutions[0].generation;
        export_stripes.push(ExportStripe {
            stripe: i,
            file: format!("stripes/{fname}"),
            sha256: digest,
            generation,
            solution_count: outcome.report.stripes[i].solutions.len(),
        });
    }

    let export_manifest = ExportManifest {
        object_id: object_id.to_string(),
        codec_version: manifest.codec_version,
        k: manifest.k,
        m: manifest.m,
        stripe_count: manifest.stripe_count,
        shard_len: manifest.shard_len,
        generation: manifest.generation,
        object_digest_claimed: manifest.object_digest.clone(),
        object_digest_recomputed: recomputed.clone(),
        stripes: export_stripes,
        ambiguous: false,
    };
    let json = serde_json::to_string_pretty(&export_manifest).map_err(e_other)?;

    // Atomic manifest switch: stage then rename inside the new directory.
    let final_path = dir.join("manifest.json");
    let staging = dir.join("manifest.json.new");
    atomic_write(&staging, json.as_bytes()).map_err(e_other)?;
    fs::rename(&staging, &final_path).map_err(e_other)?;

    let dir_display = dir.to_string_lossy().to_string();
    let manifest_display = final_path.to_string_lossy().to_string();
    store
        .record_export(
            object_id,
            &dir_display,
            &manifest_display,
            &recomputed,
            bytes.len(),
            "complete",
        )
        .map_err(e_other)?;

    Ok(ExportOutcome {
        dir: dir_display,
        manifest_path: manifest_display,
        object_digest: recomputed,
        bytes_len: bytes.len(),
    })
}

/// Read an export manifest back (used in tests to verify the switch).
pub fn read_export_manifest(path: &Path) -> serde_json::Result<ExportManifest> {
    serde_json::from_slice(&fs::read(path).unwrap_or_default())
}
