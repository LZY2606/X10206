//! Offline import: reads a source directory containing manifests and shard
//! files, stores raw bytes in the content-addressed blob store, and records
//! every receipt (a duplicate shard number with different bytes yields a
//! distinct fragment plus receipt, never first-come-first-served overwrites).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use rusqlite::params;

use crate::db::{now_ms, Db};
use crate::digest::{sha256_hex, with_prefix};
use crate::manifest::Manifest;
use crate::store::BlobStore;

#[derive(Debug, Default)]
pub struct ImportReport {
    pub object_id: String,
    pub manifests: usize,
    pub fragments_new: usize,
    pub receipts: usize,
    pub duplicates_seen: usize,
    pub warnings: Vec<String>,
}

/// Recursively collect regular files.
fn walk(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(p) = stack.pop() {
        for entry in fs::read_dir(&p)? {
            let entry = entry?;
            let path = entry.path();
            let ft = entry.file_type()?;
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file() {
                out.push(path);
            }
        }
    }
    Ok(out)
}

/// Parse the file name of a shard: `s{stripe}-{shard}[gN][-tag].bin`
///
/// The optional `gN` suffix on the shard number provides a generation hint;
/// any additional `-tag` suffix (`-dup`, `-mirror`, ...) is allowed so that
/// duplicate shard numbers from several receipts are never silently dropped.
fn parse_shard_name(name: &str) -> Option<(usize, usize, Option<u64>)> {
    let stem = name.strip_suffix(".bin")?;
    let rest = stem.strip_prefix('s')?;
    let mut parts = rest.split('-');
    let stripe: usize = parts.next()?.parse().ok()?;
    let shard_field = parts.next()?;
    let mut gen: Option<u64> = None;
    let shard: usize = shard_field.parse().ok()?;
    // Generation hint may be attached to the shard field (`1g2`) or appear as
    // a separate segment (`-g2`); tags like `-dup` are simply ignored.
    for seg in parts {
        if let Some(n) = seg.strip_prefix('g') {
            if let Ok(v) = n.parse::<u64>() {
                gen = Some(v);
            }
        }
    }
    Some((stripe, shard, gen))
}

pub fn import_dir(db: &Db, store: &BlobStore, dir: &Path) -> std::io::Result<ImportReport> {
    let source = dir
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| dir.to_string_lossy().to_string());
    let files = walk(dir)?;

    // 1. Parse all manifests first, keyed by generation.
    let mut manifests: BTreeMap<u64, (Manifest, PathBuf)> = BTreeMap::new();
    for path in &files {
        let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let looks_manifest = name.ends_with(".json");
        if !looks_manifest {
            continue;
        }
        let bytes = fs::read(path)?;
        match serde_json::from_slice::<Manifest>(&bytes) {
            Ok(m) => match m.validate_shape() {
                Ok(()) => {
                    if m.format != crate::manifest::MANIFEST_FORMAT {
                        continue;
                    }
                    manifests.insert(m.generation, (m, path.clone()));
                }
                Err(e) => {
                    let bad = m;
                    let _ = bad.validate_shape();
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("manifest {} is invalid: {}", name, e),
                    ));
                }
            },
Err(e) => { eprintln!("MANIFEST PARSE FAIL {}: {}", name, e); continue }
        }
    }

    // A source directory may carry only shard files (e.g. a mirror / recovery
    // medium). In that case we must attach its receipts to an existing object;
    // exactly one known object is required for an unambiguous join.
    let object_id = if let Some((_, (m, _))) = manifests.iter().next() {
        m.object_id.clone()
    } else {
        let conn = db.conn.lock().unwrap();
        let ids: Vec<String> = {
            let mut stmt = conn.prepare("SELECT object_id FROM objects ORDER BY object_id").unwrap();
            stmt.query_map([], |r| r.get::<_, String>(0))
                .unwrap()
                .map(|r| r.unwrap())
                .collect()
        };
        drop(conn);
        match ids.len() {
            0 => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "no stripe-pod manifest found and no known object to attach fragments to",
                ));
            }
            1 => ids.into_iter().next().unwrap(),
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "source directory has no manifest and multiple objects are known;                      add a manifest to disambiguate",
                ));
            }
        }
    };
    let mut report = ImportReport { object_id: object_id.clone(), ..Default::default() };

    // Object/generation rows + manifest-vs-actual length checks are done per
    // shard import; ensure object exists.
    let conn = db.conn.lock().unwrap();
    let ts = now_ms();
    conn.execute(
        "INSERT OR IGNORE INTO objects(object_id, created_at) VALUES (?1, ?2)",
        params![object_id, ts],
    )
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    for (gen, (m, mpath)) in &manifests {
        let rel_manifest = mpath.strip_prefix(dir).unwrap_or(mpath).to_string_lossy().to_string();
        conn.execute(
            "INSERT OR IGNORE INTO generations
             (object_id, generation, codec, data_shards, parity_shards, shard_size,
              stripe_count, object_size, object_digest, manifest_source)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                object_id,
                gen,
                m.codec,
                m.data_shards,
                m.parity_shards,
                m.shard_size,
                m.stripe_count,
                m.object_size,
                m.object_digest,
                rel_manifest,
            ],
        )
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        report.manifests += 1;
        for (key, digest) in &m.block_digests {
            let (stripe, shard) = key.split_once(':').ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("bad block_digests key {} in manifest G{}", key, gen),
                )
            })?;
            let stripe: i64 = stripe.parse().map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("bad block_digests key in manifest G{}", gen),
                )
            })?;
            let shard: i64 = shard.parse().map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("bad block_digests key in manifest G{}", gen),
                )
            })?;
            conn.execute(
                "INSERT OR REPLACE INTO block_digests
                 (object_id, generation, stripe_index, shard_index, digest)
                 VALUES (?1,?2,?3,?4,?5)",
                params![object_id, gen, stripe, shard, digest],
            )
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        }
    }
    drop(conn);

    // Generation parameters for shard attribution: prefer manifests present
    // in this directory; otherwise fall back to already-imported generations.
    #[derive(Clone)]
    struct GenShape {
        data_shards: usize,
        parity_shards: usize,
        shard_size: usize,
        stripe_count: usize,
    }
    let mut gen_shapes: BTreeMap<u64, GenShape> = BTreeMap::new();
    for (gen, (m, _)) in &manifests {
        gen_shapes.insert(
            *gen,
            GenShape {
                data_shards: m.data_shards,
                parity_shards: m.parity_shards,
                shard_size: m.shard_size,
                stripe_count: m.stripe_count,
            },
        );
    }
    if gen_shapes.is_empty() {
        let conn = db.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT generation, data_shards, parity_shards, shard_size, stripe_count
                 FROM generations WHERE object_id=?1 ORDER BY generation",
            )
            .unwrap();
        let rows = stmt
            .query_map(params![&object_id], |r| {
                Ok((
                    r.get::<_, i64>(0)? as u64,
                    r.get::<_, i64>(1)? as usize,
                    r.get::<_, i64>(2)? as usize,
                    r.get::<_, i64>(3)? as usize,
                    r.get::<_, i64>(4)? as usize,
                ))
            })
            .unwrap();
        for r in rows {
            let (gen, d, p, sz, sc) = r.unwrap();
            gen_shapes.insert(gen, GenShape { data_shards: d, parity_shards: p, shard_size: sz, stripe_count: sc });
        }
    }

    // 2. Import every shard file, attributing it to each generation whose
    //    stripe range covers it and whose generation hint (if any) matches.
    for path in &files {
        let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let Some((stripe, shard, gen_hint)) = parse_shard_name(&name) else {
            if !name.ends_with(".json") {
                report.warnings.push(format!("忽略无法识别的文件：{}", name));
            }
            continue;
        };
        let bytes = fs::read(path)?;
        let rel_path = path.strip_prefix(dir).unwrap_or(path).to_string_lossy().to_string();
        let actual_len = bytes.len();
        let hash_hex = sha256_hex(&bytes);
        let digest = with_prefix(&hash_hex);

        let staged = store.stage(&bytes).map_err(|e| {
            std::io::Error::new(e.kind(), format!("stage {}: {}", rel_path, e))
        })?;
        store.promote(&staged).map_err(|e| {
            std::io::Error::new(e.kind(), format!("promote {}: {}", rel_path, e))
        })?;

        let conn = db.conn.lock().unwrap();
        for (gen, shape) in &gen_shapes {
            if let Some(hint) = gen_hint {
                if hint != *gen {
                    continue;
                }
            }
            let n = shape.data_shards + shape.parity_shards;
            if stripe >= shape.stripe_count || shard >= n {
                report.warnings.push(format!(
                    "{}：坐标 s{}-{} 超出 G{} 范围（{} stripes × {} shards）",
                    name, stripe, shard, gen, shape.stripe_count, n
                ));
                continue;
            }
            // Manifest-vs-actual length check.
            if actual_len != shape.shard_size {
                report.warnings.push(format!(
                    "manifest 与实际长度不符：{} 声明 shard_size={}，实际 {} 字节",
                    name, shape.shard_size, actual_len
                ));
            }

            let ts = now_ms();
            let inserted = conn
                .execute(
                    "INSERT OR IGNORE INTO fragments
                     (object_id, generation, stripe_index, shard_index, blob_hash,
                      byte_length, created_at)
                     VALUES (?1,?2,?3,?4,?5,?6,?7)",
                    params![object_id, gen, stripe, shard, hash_hex, actual_len, ts],
                )
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
            if inserted > 0 {
                report.fragments_new += 1;
            } else {
                report.duplicates_seen += 1;
            }

            let fragment_id: i64 = conn
                .query_row(
                    "SELECT id FROM fragments
                     WHERE object_id=?1 AND generation=?2 AND stripe_index=?3
                       AND shard_index=?4 AND blob_hash=?5",
                    params![object_id, gen, stripe, shard, hash_hex],
                    |r| r.get(0),
                )
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

            let receipt_added = conn
                .execute(
                    "INSERT OR IGNORE INTO fragment_receipts
                     (fragment_id, source, rel_path, received_at)
                     VALUES (?1,?2,?3,?4)",
                    params![fragment_id, source, rel_path, ts],
                )
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
            if receipt_added > 0 {
                report.receipts += 1;
            }

            // Explicit check against manifest digest if provided.
            let expected_dig: Option<String> = conn
                .query_row(
                    "SELECT digest FROM block_digests
                     WHERE object_id=?1 AND generation=?2 AND stripe_index=?3 AND shard_index=?4",
                    params![object_id, gen, stripe, shard],
                    |r| r.get(0),
                )
                .ok();
            if let Some(expected) = expected_dig {
                if expected != digest {
                    report.warnings.push(format!(
                        "{} 与摘要不符（G{}）：期望 {}，实际 {}",
                        name,
                        gen,
                        crate::model::short(&expected),
                        crate::model::short(&digest)
                    ));
                }
            }
        }
        drop(conn);
    }

    // 3. Cross-check: manifest declares digests for coordinates with no receipt.
    for (gen, shape) in &gen_shapes {
        for stripe in 0..shape.stripe_count {
            for shard in 0..(shape.data_shards + shape.parity_shards) {
                let conn = db.conn.lock().unwrap();
                let has_digest: i64 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM block_digests
                         WHERE object_id=?1 AND generation=?2 AND stripe_index=?3 AND shard_index=?4",
                        params![object_id, gen, stripe, shard],
                        |r| r.get(0),
                    )
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                if has_digest == 0 {
                    drop(conn);
                    continue;
                }
                let count: i64 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM fragments
                         WHERE object_id=?1 AND generation=?2 AND stripe_index=?3 AND shard_index=?4",
                        params![object_id, gen, stripe, shard],
                        |r| r.get(0),
                    )
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                drop(conn);
                if count == 0 {
                    report.warnings.push(format!(
                        "G{} s{}-{}：manifest 有摘要但未收到任何候选（缺失块）",
                        gen, stripe, shard
                    ));
                }
            }
        }
    }

    Ok(report)
}
