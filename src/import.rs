//! 离线导入：manifest、data shard、parity shard、每块摘要。
//! 保存原始字节（vault，不改动源文件）与接收来源。

use crate::commit::sha256_hex;
use crate::db::{safe_seg, Store};
use crate::model::{ObjectManifestV1, ShardHealth, ShardSidecarV1};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ImportedShard {
    pub object_id: String,
    pub stripe_idx: usize,
    pub shard_idx: usize,
    pub generation: u64,
    pub source: String,
    pub actual_len: usize,
    pub claimed_len: usize,
    pub claimed_digest: Option<String>,
    pub actual_digest: String,
    pub health: ShardHealth,
    pub bytes_path: PathBuf,
}

pub struct ImportReport {
    pub objects: Vec<String>,
    pub shards: usize,
    pub skipped_duplicates: usize,
}

fn find_manifest(path: &Path) -> std::io::Result<Option<PathBuf>> {
    let direct = path.join("manifest.json");
    if direct.is_file() {
        return Ok(Some(direct));
    }
    if !path.is_dir() {
        return Ok(None);
    }
    let mut found = None;
    for e in std::fs::read_dir(path)? {
        let e = e?;
        if e.file_type()?.is_dir() && e.path().join("manifest.json").is_file() {
            found = Some(e.path().join("manifest.json"));
            break;
        }
    }
    Ok(found)
}

fn parse_shard_name(name: &str) -> Option<(usize, usize)> {
    let cap = name.strip_suffix(".bin")?;
    // shard-<stripe>-<shard>[-g<gen>][-<source>].bin
    let body = cap.strip_prefix("shard-")?;
    let mut it = body.split(['-', '_']);
    let stripe: usize = it.next()?.parse().ok()?;
    let shard: usize = it.next()?.parse().ok()?;
    Some((stripe, shard))
}

pub fn import_path(store: &Store, input: &Path) -> std::io::Result<ImportReport> {
    let manifest_path = find_manifest(input)?
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "目录中找不到 manifest.json"))?;
    import_manifest(store, &manifest_path)
}

pub fn import_manifest(store: &Store, manifest_path: &Path) -> std::io::Result<ImportReport> {
    let dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let manifest: ObjectManifestV1 = serde_json::from_slice(&std::fs::read(manifest_path)?)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("manifest 解析失败: {e}")))?;

    // sidecar 索引：相对于 manifest 目录，key = 数据文件名。
    let mut sidecars: HashMap<String, ShardSidecarV1> = HashMap::new();
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        let fname = e.file_name().to_string_lossy().to_string();
        if fname.ends_with(".sidecar.json") {
            if let Ok(sc) = serde_json::from_slice::<ShardSidecarV1>(&std::fs::read(e.path())?) {
                let base = fname.strip_suffix(".sidecar.json").unwrap();
                sidecars.insert(base.to_string(), sc);
            }
        }
    }

    let mut imported = Vec::new();
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        if !e.file_type()?.is_file() {
            continue;
        }
        let fname = e.file_name().to_string_lossy().to_string();
        if !fname.ends_with(".bin") {
            continue;
        }
        let bytes = std::fs::read(e.path())?;
        let actual_digest = sha256_hex(&bytes);
        let (parsed_stripe, parsed_shard) = match parse_shard_name(&fname) {
            Some(v) => v,
            None => continue,
        };
        let sidecar = sidecars.get(&fname).cloned();
        let stripe_idx = sidecar.as_ref().map(|s| s.stripe_idx).unwrap_or(parsed_stripe);
        let shard_idx = sidecar.as_ref().map(|s| s.shard_idx).unwrap_or(parsed_shard);
        let generation = sidecar.as_ref().map(|s| s.generation).unwrap_or(0);
        let source = sidecar
            .as_ref()
            .map(|s| if s.source.is_empty() { "unknown".to_string() } else { s.source.clone() })
            .unwrap_or_else(|| "unknown".to_string());
        let claimed_digest = sidecar.as_ref().and_then(|s| s.sha256.clone());

        if stripe_idx >= manifest.stripe_count {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{fname} 的 stripe 编号 {stripe_idx} 超出 manifest 声明"),
            ));
        }
        if shard_idx >= manifest.params.n() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{fname} 的 shard 编号 {shard_idx} 超出 manifest 声明"),
            ));
        }

        let claimed_len = manifest.stripe_len;
        let health = if bytes.len() != claimed_len {
            ShardHealth::LengthMismatch
        } else if let Some(claim) = &claimed_digest {
            if claim.eq_ignore_ascii_case(&actual_digest) {
                ShardHealth::Verified
            } else {
                ShardHealth::DigestMismatch
            }
        } else {
            ShardHealth::Unverified
        };

        // 原始字节原样入 vault（内容寻址，相同字节只存一份），源文件不改动。
        let rel = format!(
            "{}/s{:06}-i{:02}-{}.bin",
            safe_seg(&manifest.object_id),
            stripe_idx,
            shard_idx,
            &actual_digest[..16]
        );
        let dest = store.vault_shard_path(&rel);
        if !dest.exists() {
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&dest, &bytes)?;
        }

        imported.push(ImportedShard {
            object_id: manifest.object_id.clone(),
            stripe_idx,
            shard_idx,
            generation,
            source,
            actual_len: bytes.len(),
            claimed_len,
            claimed_digest,
            actual_digest,
            health,
            bytes_path: dest,
        });
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut skipped = 0usize;
    let conn = store.conn.lock().unwrap();
    let tx = conn.unchecked_transaction().map_err(io_other)?;
    tx.execute(
        "INSERT OR IGNORE INTO objects(object_id, params_json, stripe_len, stripe_count, object_digest, imported_at)
         VALUES (?1,?2,?3,?4,?5,?6)",
        rusqlite::params![
            manifest.object_id,
            serde_json::to_string(&manifest.params).unwrap(),
            manifest.stripe_len as i64,
            manifest.stripe_count as i64,
            manifest.object_digest,
            now
        ],
    )
    .map_err(io_other)?;
    for (stripe, digest) in &manifest.stripe_digests {
        tx.execute(
            "INSERT OR IGNORE INTO stripe_expected(object_id, stripe_idx, digest) VALUES (?1,?2,?3)",
            rusqlite::params![manifest.object_id, *stripe as i64, digest],
        )
        .map_err(io_other)?;
    }
    for s in &imported {
        let affected = tx
            .execute(
                "INSERT OR IGNORE INTO shards
                 (object_id, stripe_idx, shard_idx, generation, source, claimed_len, actual_len,
                  claimed_digest, actual_digest, health, bytes_path, received_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                rusqlite::params![
                    s.object_id,
                    s.stripe_idx as i64,
                    s.shard_idx as i64,
                    s.generation as i64,
                    s.source,
                    s.claimed_len as i64,
                    s.actual_len as i64,
                    s.claimed_digest,
                    s.actual_digest,
                    s.health as u8,
                    s.bytes_path.to_string_lossy(),
                    now
                ],
            )
            .map_err(io_other)?;
        if affected == 0 {
            skipped += 1;
        }
    }
    tx.commit().map_err(io_other)?;
    Ok(ImportReport {
        objects: vec![manifest.object_id],
        shards: imported.len(),
        skipped_duplicates: skipped,
    })
}

fn io_other<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
}
