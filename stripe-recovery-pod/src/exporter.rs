//! Atomic export: every export lands in a fresh directory; shard bytes are
//! written first, and the export manifest appears last via an atomic rename.
//! Original imported fragments are never modified.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::db::Store;
use crate::model::sha256_hex;
use crate::db::ObjectRow;
use crate::recovery::load_committed_object;

#[derive(Debug, Serialize)]
pub struct ExportedShard {
    pub stripe: usize,
    pub shard_index: usize,
    pub generation: i64,
    pub file: String,
    pub sha256: String,
    pub participated_sources: Vec<String>,
    pub recomputed_digest: String,
}

#[derive(Debug, Serialize)]
pub struct ExportManifest {
    pub export_kind: String,
    pub object_id: String,
    pub scheme: String,
    pub version: u32,
    pub data_shards: usize,
    pub parity_shards: usize,
    pub stripe_count: usize,
    pub shard_len: usize,
    pub data_len: usize,
    pub object_digest_hex: String,
    pub verified_object_digest_hex: String,
    pub trusted: bool,
    pub exported_at: String,
    pub shards: Vec<ExportedShard>,
    pub notes: Vec<String>,
}

pub fn export_object(store: &Store, obj: &ObjectRow) -> anyhow::Result<PathBuf> {
    let bytes = match load_committed_object(store, obj) {
        Some(b) => b,
        None => anyhow::bail!("object {} is not fully committed; export refused", obj.id),
    };
    let verified = sha256_hex(&bytes);
    if !verified.eq_ignore_ascii_case(&obj.object_digest_hex) {
        anyhow::bail!("object digest mismatch at export; export refused");
    }

    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let dir_name = format!("export-{}-{stamp}", obj.id);
    let dir = store.paths.exports.join(&dir_name);
    if dir.exists() {
        anyhow::bail!("export directory {dir_name} already exists; refusing to overwrite");
    }
    let objects_dir = dir.join("objects").join(&obj.id);
    std::fs::create_dir_all(&objects_dir.join("shards"))?;

    let n = obj.data_shards + obj.parity_shards;
    let mut exported = Vec::new();
    let mut notes = Vec::new();

    for stripe in 0..obj.stripe_count {
        let sc = store
            .get_stripe(&obj.id, stripe)?
            .ok_or_else(|| anyhow::anyhow!("missing commit for stripe {stripe}"))?;
        let sols = store.list_solutions(&obj.id, stripe)?;
        let chosen = sols
            .iter()
            .find(|s| Some(s.id) == sc.chosen_solution_id)
            .or_else(|| sols.first());
        let mut participated: Vec<String> = Vec::new();
        if let Some(sol) = chosen {
            #[derive(serde::Deserialize)]
            struct Combo {
                source: String,
            }
            if let Ok(entries) = serde_json::from_str::<Vec<Combo>>(&sol.combo_json) {
                let mut set: std::collections::BTreeSet<String> =
                    entries.into_iter().map(|c| c.source).collect();
                participated.append(&mut set.into_iter().collect());
            }
        }
        if sols.len() > 1 {
            notes.push(format!(
                "stripe {stripe}: {} feasible reconstructions existed; rank by digest order exported",
                sols.len()
            ));
        }

        for idx in 0..n {
            let (hex, gen) = store
                .committed_shard_hex(&obj.id, stripe, idx)?
                .ok_or_else(|| anyhow::anyhow!("missing committed shard s{stripe} i{idx}"))?;
            let bytes = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap_or(0))
                .collect::<Vec<u8>>();
            let recomputed = sha256_hex(&bytes);
            if recomputed != hex {
                anyhow::bail!("stored shard s{stripe} i{idx} digest inconsistent");
            }
            let file = format!("s{stripe}_i{idx}_g{gen}.bin");
            std::fs::write(objects_dir.join("shards").join(&file), &bytes)?;
            std::fs::write(
                objects_dir.join("shards").join(format!("{file}.sha256")),
                format!("{recomputed}  {file}\n"),
            )?;
            exported.push(ExportedShard {
                stripe,
                shard_index: idx,
                generation: gen,
                file,
                sha256: recomputed.clone(),
                participated_sources: participated.clone(),
                recomputed_digest: recomputed,
            });
        }
    }

    let manifest = ExportManifest {
        export_kind: "stripe-recovery-pod-export-v1".into(),
        object_id: obj.id.clone(),
        scheme: obj.scheme.clone(),
        version: obj.version,
        data_shards: obj.data_shards,
        parity_shards: obj.parity_shards,
        stripe_count: obj.stripe_count,
        shard_len: obj.shard_len,
        data_len: obj.data_len,
        object_digest_hex: obj.object_digest_hex.clone(),
        verified_object_digest_hex: verified,
        trusted: true,
        exported_at: format!("unix:{stamp}"),
        shards: exported,
        notes,
    };

    // Atomic manifest switch: write to a sibling temp name, fsync, rename.
    let tmp = dir.join("manifest.json.tmp");
    let final_path = dir.join("manifest.json");
    let json = serde_json::to_vec_pretty(&manifest)?;
    std::fs::write(&tmp, &json)?;
    if let Ok(f) = std::fs::File::open(&tmp) {
        f.sync_all().ok();
    }
    std::fs::rename(&tmp, &final_path)?;
    store.set_export_dir(&obj.id, Some(dir.to_string_lossy().as_ref()))?;
    Ok(dir)
}

/// Locate an export directory and confirm its manifest switch completed.
pub fn manifest_is_switched(dir: &Path) -> bool {
    dir.join("manifest.json").exists() && !dir.join("manifest.json.tmp").exists()
}
