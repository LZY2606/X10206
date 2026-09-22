//! Atomic export to a NEW directory. Original imported fragments are never
//! modified. Switch strategy:
//!   1. build everything in `<base>.staging-<pid>`;
//!   2. if `<base>` exists, rename it to `<base>.retired-<ts>`;
//!   3. rename staging -> `<base>`;
//!   4. remove the retired directory afterwards.
//! The manifest is written last inside the staging tree (with fsync), so an
//! interrupted export leaves only staging/retired siblings and never a
//! half-switched live directory.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use rusqlite::params;
use serde::Serialize;

use crate::db::{now_ms, Db};
use crate::digest::{sha256_hex, with_prefix};
use crate::store::BlobStore;

#[derive(Debug, Serialize)]
pub struct ExportManifestOut {
    pub format: String,
    pub object_id: String,
    pub generation: u64,
    pub stripe_count: usize,
    pub data_shards: usize,
    pub parity_shards: usize,
    pub shard_size: usize,
    pub object_size: usize,
    pub object_digest: String,
    pub block_digests: BTreeMap<String, String>,
    pub provenance: ExportProvenance,
}

#[derive(Debug, Serialize)]
pub struct ExportProvenance {
    pub exported_at_ms: i64,
    pub active_outcome_ids: Vec<i64>,
    pub ambiguous_stripes: Vec<usize>,
    pub recovery_id: i64,
}

#[derive(Debug)]
pub struct ExportResult {
    pub target_dir: PathBuf,
    pub generation: u64,
    pub stripe_count: usize,
}

pub fn export_object(
    db: &Db,
    store: &BlobStore,
    export_root: &Path,
    object_id: &str,
) -> std::io::Result<ExportResult> {
    fs::create_dir_all(export_root)?;

    // Snapshot active stripes and their generation from SQLite.
    let conn = db.conn.lock().unwrap();
    let gen_row: (i64, usize, usize, usize, usize, String) = {
        conn.query_row(
            "SELECT g.generation, g.data_shards, g.parity_shards, g.shard_size,
                    g.stripe_count, g.object_digest
             FROM stripes s
             JOIN outcomes o ON o.id = s.active_outcome_id
             JOIN generations g
               ON g.object_id = o.object_id AND g.generation = o.generation
             WHERE s.object_id=?1
             GROUP BY g.generation
             ORDER BY g.generation DESC LIMIT 1",
            params![object_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        )
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other,
            format!("无法导出：对象尚未有可一致导出的 stripe（{}）", e)))?
    };
    let generation = gen_row.0 as u64;
    let k = gen_row.1;
    let m = gen_row.2;
    let shard_size = gen_row.3;
    let stripe_count = gen_row.4;
    let object_digest = gen_row.5;

    let mut active: BTreeMap<usize, (i64, i64)> = BTreeMap::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT s.stripe_index, s.active_outcome_id, o.recovery_id
                 FROM stripes s JOIN outcomes o ON o.id = s.active_outcome_id
                 WHERE s.object_id=?1 AND o.generation=?2
                 ORDER BY s.stripe_index",
            )
            .unwrap();
        let rows = stmt
            .query_map(params![object_id, generation as i64], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))
            })
            .unwrap();
        for r in rows {
            let (si, oid, rid) = r.unwrap();
            active.insert(si as usize, (oid, rid));
        }
    }

    if active.len() != stripe_count {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "无法导出：只有 {}/{} 个 stripe 在 G{} 上有已提交结果",
                active.len(),
                stripe_count,
                generation
            ),
        ));
    }

    let recovery_id = active.values().map(|(_, rid)| *rid).max().unwrap_or(0);
    let mut ambiguous_stripes = Vec::new();
    for (si, (oid, _)) in &active {
        let ambiguous: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM outcomes
                 WHERE recovery_id=(SELECT recovery_id FROM outcomes WHERE id=?1)
                   AND stripe_index=?2 AND feasible=1",
                params![oid, *si as i64],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if ambiguous > 1 {
            ambiguous_stripes.push(*si);
        }
    }
    // Build block digest map + remember blob hashes per stripe.
    let mut block_digests: BTreeMap<String, String> = BTreeMap::new();
    let mut blobs_to_copy: BTreeMap<usize, Vec<(usize, String)>> = BTreeMap::new();
    let mut object_bytes: Vec<u8> = Vec::new();
    let mut outcome_ids = Vec::new();
    for si in 0..stripe_count {
        let (oid, _) = active[&si];
        outcome_ids.push(oid);
        let mut stmt = conn
            .prepare(
                "SELECT shard_index, blob_hash, recomputed_digest
                 FROM outcome_blocks WHERE outcome_id=?1 ORDER BY shard_index",
            )
            .unwrap();
        let rows = stmt
            .query_map(params![oid], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))
            })
            .unwrap();
        let mut entries = Vec::new();
        for r in rows {
            let (shard, hash, digest) = r.unwrap();
            block_digests.insert(format!("{}:{}", si, shard), digest);
            entries.push((shard as usize, hash));
        }
        blobs_to_copy.insert(si, entries);
    }

    // Object size from generation row.
    let object_size: usize = conn
        .query_row(
            "SELECT object_size FROM generations
             WHERE object_id=?1 AND generation=?2",
            params![object_id, generation as i64],
            |r| r.get(0),
        )
        .unwrap_or(k * shard_size * stripe_count);
    drop(conn);

    // Assemble object bytes for digest double-check.
    for si in 0..stripe_count {
        for shard in 0..k {
            let hash = &blobs_to_copy[&si]
                .iter()
                .find(|(s, _)| *s == shard)
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::Other, format!("stripe {} 缺 data shard {}", si, shard))
                })?
                .1;
            let bytes = store.read(hash)?;
            object_bytes.extend_from_slice(&bytes);
        }
    }
    object_bytes.truncate(object_size);
    let actual_object_digest = with_prefix(&sha256_hex(&object_bytes));
    if !object_digest.is_empty() && actual_object_digest != object_digest {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "导出前校验失败：对象摘要不一致（期望 {}，实际 {}）",
                object_digest, actual_object_digest
            ),
        ));
    }

    // Stage directory.
    let ts = now_ms();
    let safe_name = object_id.replace(['/', '\\'], "_");
    let base = export_root.join(format!("export-{}-g{}", safe_name, generation));
    let staging = export_root.join(format!(
        ".export-{}-g{}.staging-{}-{}",
        safe_name,
        generation,
        std::process::id(),
        ts
    ));
    fs::create_dir_all(staging.join("shards"))?;

    // Copy every block (read-only on sources).
    for (si, entries) in &blobs_to_copy {
        for (shard, hash) in entries {
            let bytes = store.read(hash)?;
            let path = staging.join("shards").join(format!("s{}-{}.bin", si, shard));
            let mut f = fs::File::create(&path)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
    }

    let manifest = ExportManifestOut {
        format: crate::manifest::MANIFEST_FORMAT.to_string(),
        object_id: object_id.to_string(),
        generation,
        stripe_count,
        data_shards: k,
        parity_shards: m,
        shard_size,
        object_size,
        object_digest: if object_digest.is_empty() { actual_object_digest } else { object_digest },
        block_digests,
        provenance: ExportProvenance {
            exported_at_ms: ts,
            active_outcome_ids: outcome_ids,
            ambiguous_stripes: ambiguous_stripes.clone(),
            recovery_id,
        },
    };
    let json = serde_json::to_vec_pretty(&manifest).unwrap();
    let manifest_path = staging.join("manifest.json");
    let mut f = fs::File::create(&manifest_path)?;
    f.write_all(&json)?;
    f.sync_all()?;
    drop(f);

    // Atomic switch.
    let retired = export_root.join(format!(
        ".export-{}-g{}.retired-{}",
        safe_name, generation, ts
    ));
    if base.exists() {
        fs::rename(&base, &retired)?;
    }
    fs::rename(&staging, &base)?;
    if retired.exists() {
        let _ = fs::remove_dir_all(&retired);
    }

    {
        let conn = db.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO export_records
             (object_id, target_dir, status, generation, stripe_count,
              manifest_path, created_at)
             VALUES (?1,?2,'active',?3,?4,?5,?6)",
            params![
                object_id,
                base.to_string_lossy(),
                generation as i64,
                stripe_count as i64,
                base.join("manifest.json").to_string_lossy(),
                ts
            ],
        )
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    }

    Ok(ExportResult {
        target_dir: base,
        generation,
        stripe_count,
    })
}

