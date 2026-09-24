//! 从 inbox 导入 manifest、data/parity shard 与每块摘要。
//! 原始字节按内容寻址保存，接收来源记录为父目录名（或 inbox 根标记为 `inbox`）。

use crate::db::Db;
use crate::model::{Manifest, MANIFEST_KIND, MANIFEST_VERSION};
use crate::store::BlockStore;
use anyhow::{bail, Context, Result};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub fn inbox_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("inbox")
}

/// 解析碎片文件名：`<object>__g<gen>_s<stripe>_i<index>__<sha256>.frag[.bin]`。
/// object 允许包含下划线；`__` 作为元数据分隔符。
fn parse_fragment_name(name: &str) -> Option<(String, u64, u64, usize, Option<String>)> {
    let stem = name.strip_suffix(".bin").unwrap_or(name);
    let stem = stem.strip_suffix(".frag").unwrap_or(stem);
    let (object, rest) = stem.split_once("__")?;
    let (meta, digest) = match rest.split_once("__") {
        Some((m, d)) => (m, Some(d.to_string())),
        None => (rest, None),
    };
    let parts: Vec<&str> = meta.split('_').collect();
    if parts.len() != 3 {
        return None;
    }
    let gen = parts[0].strip_prefix('g')?.parse().ok()?;
    let stripe = parts[1].strip_prefix('s')?.parse().ok()?;
    let index = parts[2].strip_prefix('i')?.parse().ok()?;
    Some((object.to_string(), gen, stripe, index, digest))
}

fn source_for(path: &Path, inbox: &Path) -> String {
    path.parent()
        .and_then(|p| if p == inbox { None } else { p.file_name() })
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "inbox".to_string())
}

/// 读取 sidecar 摘要：`<file>.sha256` 文件内首个空白分隔 token。
fn read_sidecar(path: &Path) -> Option<String> {
    let sidecar = path.with_extension("frag.sha256");
    let candidates = [
        path.with_file_name(format!("{}.sha256", path.file_name()?.to_string_lossy())),
        sidecar,
    ];
    for cand in candidates {
        if let Ok(text) = std::fs::read_to_string(&cand) {
            if let Some(token) = text.split_whitespace().next() {
                return Some(token.to_lowercase());
            }
        }
    }
    None
}

#[derive(Debug, Default)]
pub struct ImportReport {
    pub manifests: usize,
    pub fragments: usize,
    pub skipped: Vec<String>,
}

pub fn import_inbox(engine_db: &Db, store: &BlockStore, data_dir: &Path) -> Result<ImportReport> {
    let inbox = inbox_dir(data_dir);
    std::fs::create_dir_all(&inbox)?;
    let mut report = ImportReport::default();
    let mut manifest_files = Vec::new();
    let mut fragment_files = Vec::new();

    for entry in walkdir(&inbox) {
        if !entry.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if name.ends_with(".manifest.json") {
            manifest_files.push(entry);
        } else if name.ends_with(".frag") || name.ends_with(".frag.bin") {
            fragment_files.push(entry);
        }
    }

    for path in manifest_files {
        import_manifest(engine_db, store, &path, &inbox, &mut report)?;
    }
    for path in fragment_files {
        import_fragment(engine_db, store, &path, &inbox, &mut report)?;
    }
    Ok(report)
}

fn import_manifest(
    db: &Db,
    store: &BlockStore,
    path: &Path,
    inbox: &Path,
    report: &mut ImportReport,
) -> Result<()> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let manifest: Manifest = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse manifest {}", path.display()))?;
    if manifest.manifest_kind != MANIFEST_KIND {
        bail!("bad manifest kind: {}", manifest.manifest_kind);
    }
    if manifest.manifest_version != MANIFEST_VERSION {
        bail!("unsupported manifest version: {}", manifest.manifest_version);
    }
    if db.manifest_for_object(&manifest.object_id)?.is_some() {
        report.skipped.push(format!(
            "manifest for {} already imported (partial-write generation kept)",
            manifest.object_id
        ));
        return Ok(());
    }
    let (_digest, blob) = store.save_original(&bytes)?;
    let saved = store.save_manifest_bytes(&manifest.object_id, &bytes)?;
    let _ = blob;
    db.insert_manifest(
        &manifest.object_id,
        manifest.current_generation as i64,
        &saved.to_string_lossy(),
        &source_for(path, inbox),
    )?;
    report.manifests += 1;
    Ok(())
}

fn import_fragment(
    db: &Db,
    store: &BlockStore,
    path: &Path,
    inbox: &Path,
    report: &mut ImportReport,
) -> Result<()> {
    let name = path.file_name().unwrap().to_string_lossy().to_string();
    let Some((object_id, generation, stripe, index, name_digest)) = parse_fragment_name(&name)
    else {
        report
            .skipped
            .push(format!("无法解析碎片文件名：{name}"));
        return Ok(());
    };
    let Some((_, manifest)) = db.manifest_for_object(&object_id)? else {
        report.skipped.push(format!(
            "{name}：对象 {object_id} 的 manifest 尚未导入，暂存待关联"
        ));
        return Ok(());
    };
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let (content_digest, blob_path) = store.save_original(&bytes)?;

    let mut claimed = name_digest;
    if claimed.is_none() {
        claimed = read_sidecar(path);
    }
    if let Some(d) = claimed.as_mut() {
        *d = d.to_lowercase();
    }

    // 同内容碎片可能从多个来源重复送达：来源全部记录，但块只存一份。
    let source = source_for(path, inbox);
    db.upsert_fragment(
        &object_id,
        stripe as i64,
        index as i64,
        generation as i64,
        &content_digest,
        claimed.as_deref(),
        bytes.len() as i64,
        &blob_path.to_string_lossy(),
        &source,
    )?;
    let _ = manifest;
    report.fragments += 1;
    Ok(())
}

fn walkdir(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
        paths.sort();
        for p in paths {
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push(p);
            }
        }
    }
    out
}

pub fn all_received_sources(db: &Db) -> Result<Vec<String>> {
    let mut set: HashSet<String> = HashSet::new();
    for (_, manifest) in db.list_manifests()? {
        set.insert(manifest.received_from);
        for (_, sources) in db.fragments_for_object(&manifest.object_id)? {
            set.extend(sources);
        }
    }
    let mut v: Vec<String> = set.into_iter().collect();
    v.sort();
    Ok(v)
}
