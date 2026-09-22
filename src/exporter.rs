//! Atomic export.
//!
//! Every export lands in a fresh timestamped directory. The manifest is written
//! to a temp name and renamed last, so readers never observe a partial export.
//! `current` is switched via rename (or an atomic symlink replacement).

use crate::db::Db;
use crate::models::{Manifest, FragmentInput};
use crate::recovery::{self, RunReport, StripeSolution};
use rusqlite::params;
use serde::Serialize;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub trait BlobSink {
    fn write_file(&self, path: &Path, bytes: &[u8]) -> io::Result<()>;
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;
}

pub struct FsSink;
impl BlobSink for FsSink {
    fn write_file(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("part");
        fs::write(&tmp, bytes)?;
        fs::rename(&tmp, path)
    }
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        if cfg!(windows) {
            let _ = fs::remove_file(to);
        }
        fs::rename(from, to)
    }
}

/// A sink that fails writes/renames after `succeed_before` successful calls,
/// used to simulate disk write failures during export.
pub struct FailingSink {
    pub succeed_before: usize,
    pub calls: std::sync::Mutex<usize>,
}
impl BlobSink for FailingSink {
    fn write_file(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut calls = self.calls.lock().unwrap();
        *calls += 1;
        if *calls > self.succeed_before {
            return Err(io::Error::new(io::ErrorKind::Other, "simulated disk full"));
        }
        FsSink.write_file(path, bytes)
    }
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        let mut calls = self.calls.lock().unwrap();
        *calls += 1;
        if *calls > self.succeed_before {
            return Err(io::Error::new(io::ErrorKind::Other, "simulated rename failure"));
        }
        FsSink.rename(from, to)
    }
}

#[derive(Debug, Serialize)]
pub struct SolutionRef {
    pub stripe: usize,
    pub key_fragment_ids: Vec<i64>,
    pub selected_rows: Vec<crate::recovery::SelectedShard>,
    pub excluded_evidence: Vec<crate::recovery::ExcludedEvidence>,
    pub verification: String,
    pub recomputed_digest: String,
}

#[derive(Debug, Serialize)]
pub struct ExportManifest {
    pub object_id: String,
    pub version: u32,
    pub n: usize,
    pub k: usize,
    pub stripe_size: usize,
    pub stripe_count: usize,
    pub generation: u64,
    pub object_digest: Option<String>,
    pub status: String,
    pub confidence: String,
    pub stripes: Vec<SolutionRef>,
    /// Present when several feasible reconstructions remain; no single object
    /// file is produced, reviewers must inspect alternatives.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub alternatives: Vec<AlternativeRef>,
    pub exported_at_unix: u64,
}

#[derive(Debug, Serialize)]
pub struct AlternativeRef {
    pub stripe: usize,
    pub digest: String,
    pub blob: String,
    pub key_fragment_ids: Vec<i64>,
    pub verification: String,
}

#[derive(Debug, Serialize)]
pub struct ExportResult {
    pub dir: String,
    pub manifest_path: String,
    pub current_link: String,
    pub status: String,
    pub confidence: String,
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn export_latest(db: &Db, object_id: &str, version: u32) -> anyhow_like::Result<ExportResult, String> {
    export_latest_with_sink(db, object_id, version, &FsSink)
}

fn committed_solution_for(outcome_sol: &StripeSolution) -> bool {
    !outcome_sol.data_digest.is_empty()
}

pub fn export_latest_with_sink(
    db: &Db,
    object_id: &str,
    version: u32,
    sink: &dyn BlobSink,
) -> Result<ExportResult, String> {
    let report: RunReport = recovery::latest_run_report(db, object_id, version)
        .ok_or_else(|| "no completed recovery run for this object version".to_string())?;
    let manifest: Manifest = db
        .load_manifest(object_id, version)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "manifest missing".to_string())?;

    if report.stripes.iter().any(|s| s.status == "pending") {
        return Err("recovery run was interrupted before all stripes were processed".into());
    }

    let stamp = format!(
        "{}-{:03}",
        now_unix(),
        std::process::id() % 1000
    );
    let dir = db
        .data_dir
        .join("exports")
        .join(format!("{}_v{}_{}", object_id, version, stamp));
    let stripes_dir = dir.join("stripes");
    fs::create_dir_all(&stripes_dir).map_err(|e| e.to_string())?;

    let mut refs: Vec<SolutionRef> = Vec::new();
    let mut alternatives: Vec<AlternativeRef> = Vec::new();
    let mut generations = Vec::new();
    let mut ambiguous = false;
    let mut any_infeasible = false;

    for outcome in &report.stripes {
        match outcome.status.as_str() {
            "committed" | "reused" => {
                let sol = &outcome.solutions[0];
                if !committed_solution_for(sol) {
                    any_infeasible = true;
                    continue;
                }
                generations.push(sol.generation);
                let fname = format!("stripe-{}.bin", outcome.stripe_index);
                sink.write_file(&stripes_dir.join(&fname), &sol.data)
                    .map_err(|e| e.to_string())?;
                refs.push(SolutionRef {
                    stripe: outcome.stripe_index,
                    key_fragment_ids: sol.key_tuple.clone(),
                    selected_rows: sol.selected.clone(),
                    excluded_evidence: sol.excluded.clone(),
                    verification: sol.verification.clone(),
                    recomputed_digest: sol.data_digest.clone(),
                });
            }
            "ambiguous" => {
                ambiguous = true;
                for (i, sol) in outcome.solutions.iter().enumerate() {
                    let rel = format!("alternatives/stripe-{}-alt{}.bin", outcome.stripe_index, i);
                    sink.write_file(&dir.join(&rel), &sol.data).map_err(|e| e.to_string())?;
                    alternatives.push(AlternativeRef {
                        stripe: outcome.stripe_index,
                        digest: sol.data_digest.clone(),
                        blob: rel,
                        key_fragment_ids: sol.key_tuple.clone(),
                        verification: sol.verification.clone(),
                    });
                }
            }
            _ => any_infeasible = true,
        }
    }

    if any_infeasible {
        return Err("object has infeasible stripes; refusing to export".into());
    }

    // Rebuild the canonical object only for an unambiguous result.
    let (status, object_digest) = if ambiguous {
        ("ambiguous".to_string(), None)
    } else {
        let blobs: Vec<Vec<u8>> = refs
            .iter()
            .map(|r| fs::read(stripes_dir.join(format!("stripe-{}.bin", r.stripe))).unwrap())
            .collect();
        let digest = crate::models::canonical_object_digest(&manifest, &blobs);
        let path = dir.join("object.bin");
        sink.write_file(&path, &blobs.concat()).map_err(|e| e.to_string())?;
        ("exported".to_string(), Some(digest))
    };

    let export_manifest = ExportManifest {
        object_id: object_id.to_string(),
        version,
        n: manifest.n,
        k: manifest.k,
        stripe_size: manifest.stripe_size,
        stripe_count: manifest.stripe_count,
        generation: *generations.iter().max().unwrap_or(&manifest.generation),
        object_digest,
        status: status.clone(),
        confidence: report.confidence.clone(),
        stripes: refs,
        alternatives,
        exported_at_unix: now_unix(),
    };

    // Manifest is the last thing published: temp name + atomic rename.
    let manifest_tmp = dir.join("export-manifest.json.part");
    let manifest_final = dir.join("export-manifest.json");
    let payload = serde_json::to_vec_pretty(&export_manifest).map_err(|e| e.to_string())?;
    sink.write_file(&manifest_tmp, &payload).map_err(|e| e.to_string())?;
    sink.rename(&manifest_tmp, &manifest_final).map_err(|e| e.to_string())?;

    let current = db.data_dir.join("exports").join("current");
    let current_new = db.data_dir.join("exports").join("current.new");
    let _ = fs::remove_file(&current_new);
    std::os::unix::fs::symlink(&dir, &current_new).map_err(|e| e.to_string())?;
    sink.rename(&current_new, &current).map_err(|e| e.to_string())?;

    {
        let conn = db.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO exports(object_id, version, dir, manifest_path, status, result_json)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                object_id,
                version,
                dir.to_string_lossy(),
                manifest_final.to_string_lossy(),
                status,
                serde_json::to_string(&export_manifest).unwrap()
            ],
        )
        .map_err(|e| e.to_string())?;
    }

    Ok(ExportResult {
        dir: dir.to_string_lossy().to_string(),
        manifest_path: manifest_final.to_string_lossy().to_string(),
        current_link: current.to_string_lossy().to_string(),
        status,
        confidence: report.confidence,
    })
}

/// Convenience used by tests/seed: build FragmentInput records from bytes.
pub fn fragment_input(
    object_id: &str,
    version: u32,
    generation: u64,
    stripe: usize,
    shard: usize,
    source: &str,
    bytes: &[u8],
) -> FragmentInput {
    FragmentInput {
        object_id: object_id.into(),
        version,
        generation,
        stripe_index: stripe,
        shard_index: shard,
        source: source.into(),
        bytes: hex::encode(bytes),
        encoding: "hex".into(),
    }
}

#[allow(non_snake_case)]
mod anyhow_like {
    pub type Result<T, E> = std::result::Result<T, E>;
}

// keep Write trait used in case future sinks are streaming
const _: fn() = || {
    fn _assert<W: Write>(_: W) {}
    _assert(Vec::<u8>::new());
};
