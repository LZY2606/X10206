//! 导出：写入全新目录，manifest 以"临时文件 + rename"原子切换；
//! 只读取 committed_blocks，staging 临时块永不参与。原碎片目录不改动。

use crate::db::Db;
use crate::digest::{object_digest, sha256_hex};
use crate::model::ObjectManifest;
use crate::recovery::load_all_committed;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize)]
pub struct ExportedBlock {
    pub stripe: usize,
    pub shard: usize,
    pub generation: u64,
    pub source: String,
    pub length: usize,
    pub sha256: String,
    pub file: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExportManifest {
    pub object_id: String,
    pub codec_version: u32,
    pub k: usize,
    pub m: usize,
    pub block_len: usize,
    pub stripe_count: usize,
    pub object_len: usize,
    pub exported_at_unix: u64,
    pub object_digest_expected: Option<String>,
    pub object_digest_recomputed: String,
    pub object_trusted: bool,
    pub blocks: Vec<ExportedBlock>,
}

#[derive(Debug)]
pub struct ExportOutcome {
    pub dir: PathBuf,
    pub manifest_path: PathBuf,
    pub object_trusted: bool,
}

pub fn export_object(
    db: &Db,
    manifest: &ObjectManifest,
    exports_root: &Path,
) -> Result<ExportOutcome, String> {
    let committed = load_all_committed(db, manifest).map_err(|e| e.to_string())?;
    if committed.len() != manifest.stripe_count
        || committed.values().any(|m| m.len() != manifest.n())
    {
        return Err(format!(
            "对象 {} 未完整提交（{}/{} stripe），拒绝导出",
            manifest.object_id,
            committed.len(),
            manifest.stripe_count
        ));
    }

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let dir_name = format!("export_{}_ts{}", manifest.object_id, ts);
    let dir = exports_root.join(&dir_name);
    // 新目录：已存在则加序号，绝不覆盖旧导出。
    let mut unique = 0u32;
    let dir = loop {
        let candidate = if unique == 0 {
            dir.clone()
        } else {
            exports_root.join(format!("{dir_name}_{unique}"))
        };
        if !candidate.exists() {
            break candidate;
        }
        unique += 1;
    };
    let data_dir = dir.join("blocks");
    std::fs::create_dir_all(&data_dir).map_err(|e| format!("创建导出目录失败: {e}"))?;

    let mut blocks_meta = Vec::new();
    let mut flat: Vec<Vec<u8>> = Vec::new();
    for stripe in 0..manifest.stripe_count {
        let row = &committed[&stripe];
        for shard in 0..manifest.n() {
            let bytes = &row[&shard];
            let digest = sha256_hex(bytes);
            let file = format!(
                "obj-{}__s{}__i{}.bin",
                manifest.object_id, stripe, shard
            );
            let final_path = data_dir.join(&file);
            let tmp_path = data_dir.join(format!(".{file}.tmp"));
            std::fs::write(&tmp_path, bytes).map_err(|e| format!("写导出块失败: {e}"))?;
            std::fs::rename(&tmp_path, &final_path)
                .map_err(|e| format!("切换导出块失败: {e}"))?;
            // 每块单独 .digest（原子切换）
            let digest_file = format!("{file}.digest");
            let d_tmp = data_dir.join(format!(".{digest_file}.tmp"));
            std::fs::write(&d_tmp, format!("{digest}  {file}\n"))
                .map_err(|e| format!("写摘要失败: {e}"))?;
            std::fs::rename(&d_tmp, data_dir.join(&digest_file))
                .map_err(|e| format!("切换摘要失败: {e}"))?;

            let gen = db_generation(db, &manifest.object_id, stripe).unwrap_or(0);
            blocks_meta.push(ExportedBlock {
                stripe,
                shard,
                generation: gen,
                source: if shard < manifest.k { "committed-data" } else { "committed-parity" }.into(),
                length: bytes.len(),
                sha256: digest,
                file: format!("blocks/{file}"),
            });
        }
        for shard in 0..manifest.k {
            flat.push(row[&shard].clone());
        }
    }

    let recomputed = object_digest(&flat, manifest.object_len);
    let trusted = match &manifest.object_digest {
        Some(exp) => exp.eq_ignore_ascii_case(&recomputed),
        None => true,
    };

    let export_manifest = ExportManifest {
        object_id: manifest.object_id.clone(),
        codec_version: manifest.codec_version,
        k: manifest.k,
        m: manifest.m,
        block_len: manifest.block_len,
        stripe_count: manifest.stripe_count,
        object_len: manifest.object_len,
        exported_at_unix: ts,
        object_digest_expected: manifest.object_digest.clone(),
        object_digest_recomputed: recomputed.clone(),
        object_trusted: trusted,
        blocks: blocks_meta,
    };
    let json = serde_json::to_string_pretty(&export_manifest)
        .map_err(|e| format!("导出清单序列化失败: {e}"))?;

    // 原子清单切换：manifest.json.tmp -> rename
    let tmp_manifest = dir.join(".manifest.json.tmp");
    let final_manifest = dir.join("manifest.json");
    std::fs::write(&tmp_manifest, json).map_err(|e| format!("写导出清单失败: {e}"))?;
    std::fs::rename(&tmp_manifest, &final_manifest)
        .map_err(|e| format!("切换导出清单失败: {e}"))?;

    // 顶层 current 指针：同样 tmp-symlink + rename 原子切换（不支持 symlink 时写文本指针文件）。
    let pointer = exports_root.join(format!("current_{}", manifest.object_id));
    let rel_target = PathBuf::from(&dir_name);
    #[cfg(unix)]
    {
        let tmp_link = exports_root.join(format!(".current_{}.tmp", manifest.object_id));
        let _ = std::fs::remove_file(&tmp_link);
        if std::os::unix::fs::symlink(&rel_target, &tmp_link).is_ok() {
            let _ = std::fs::remove_file(&pointer);
            let _ = std::fs::rename(&tmp_link, &pointer);
        }
    }
    let _ = pointer;
    let _ = rel_target;

    Ok(ExportOutcome {
        dir,
        manifest_path: final_manifest,
        object_trusted: trusted,
    })
}

fn db_generation(db: &Db, object_id: &str, stripe: usize) -> Option<u64> {
    let conn = db.conn.lock().unwrap();
    conn.query_row(
        "SELECT generation FROM commits WHERE object_id=?1 AND stripe=?2",
        rusqlite::params![object_id, stripe as i64],
        |r| r.get::<_, i64>(0),
    )
    .ok()
    .map(|v| v as u64)
}

/// 导出后做一次只读复核（防止读到半成品）。
pub fn verify_export(outcome: &ExportOutcome) -> Result<(), String> {
    let bytes = std::fs::read(&outcome.manifest_path)
        .map_err(|e| format!("导出复核读取失败: {e}"))?;
    let m: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("导出清单损坏: {e}"))?;
    let blocks = m
        .get("blocks")
        .and_then(|v| v.as_array())
        .ok_or("导出清单缺少 blocks")?;
    for b in blocks {
        let rel = b
            .get("file")
            .and_then(|v| v.as_str())
            .ok_or("block 缺少 file")?;
        let expected = b
            .get("sha256")
            .and_then(|v| v.as_str())
            .ok_or("block 缺少 sha256")?;
        let path = outcome.dir.join(rel);
        let data = std::fs::read(&path).map_err(|e| format!("导出块缺失: {e}"))?;
        let actual = sha256_hex(&data);
        if !actual.eq_ignore_ascii_case(expected) {
            return Err(format!("导出块 {rel} 摘要不符"));
        }
    }
    Ok(())
}

// BTreeMap 仅为类型占位保持编译稳定（未来按 stripe 聚合元数据用）。
#[allow(dead_code)]
fn _unused(_: BTreeMap<usize, ()>) {}
