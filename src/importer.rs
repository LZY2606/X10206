//! 导入 manifest、data/parity shard 与每块摘要；原始字节原样保存，不改原文件。
//!
//! 碎片文件命名：`obj-<object_id>__s<stripe>__i<shard>__g<generation>__src-<source>.bin`
//! 同目录（或 digest/ 子目录）下 `<同名>.digest` 提供随附摘要（hex，单行）。

use crate::db::Db;
use crate::digest::sha256_hex;
use crate::model::{ObjectManifest, ReceivedBlock};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ImportOutcome {
    pub manifests: usize,
    pub blocks: usize,
    pub warnings: usize,
}

/// 扫描目录：查找 manifest.json（根目录或子目录）与全部 .bin 碎片。
pub fn import_dir(db: &Db, root: &Path) -> Result<ImportOutcome, String> {
    let mut manifests = 0usize;
    let mut blocks = 0usize;
    let mut warnings = 0usize;

    let mut manifest_paths: Vec<PathBuf> = Vec::new();
    let mut bin_paths: Vec<PathBuf> = Vec::new();
    walk(root, root, &mut manifest_paths, &mut bin_paths)
        .map_err(|e| format!("扫描 {} 失败: {e}", root.display()))?;

    // object_id -> manifest
    let mut manifest_by_object: BTreeMap<String, ObjectManifest> = BTreeMap::new();

    for mp in &manifest_paths {
        match read_manifest(mp) {
            Ok((json, m)) => {
                if let Err(e) = m.validate() {
                    let _ = db.insert_warning(
                        Some(&m.object_id),
                        "object",
                        "invalid_manifest",
                        &e,
                        &mp.display().to_string(),
                    );
                    warnings += 1;
                    continue;
                }
                db.upsert_object(&json, &m)
                    .map_err(|e| format!("写入清单失败: {e}"))?;
                manifest_by_object.insert(m.object_id.clone(), m);
                manifests += 1;
            }
            Err(e) => {
                let _ = db.insert_warning(None, "global", "bad_manifest", &e, &mp.display().to_string());
                warnings += 1;
            }
        }
    }

    for bp in &bin_paths {
        let fname = bp.file_name().and_then(|s| s.to_str()).unwrap_or_default();
        let parsed = match parse_block_filename(fname) {
            Some(p) => p,
            None => {
                let _ = db.insert_warning(
                    None,
                    "global",
                    "bad_filename",
                    &format!("无法解析碎片文件名: {fname}"),
                    &bp.display().to_string(),
                );
                warnings += 1;
                continue;
            }
        };
        let manifest = match manifest_by_object.get(&parsed.object_id) {
            Some(m) => m.clone(),
            None => {
                // 也允许清单此前已导入（增量导入）。
                let json = db
                    .get_manifest_json(&parsed.object_id)
                    .map_err(|e| e.to_string())?;
                match json {
                    Some(json) => match serde_json::from_str::<ObjectManifest>(&json) {
                        Ok(m) => {
                            manifest_by_object.insert(m.object_id.clone(), m.clone());
                            m
                        }
                        Err(e) => {
                            let _ = db.insert_warning(
                                Some(&parsed.object_id),
                                "object",
                                "bad_manifest",
                                &e.to_string(),
                                &bp.display().to_string(),
                            );
                            warnings += 1;
                            continue;
                        }
                    },
                    None => {
                        let _ = db.insert_warning(
                            Some(&parsed.object_id),
                            "object",
                            "unknown_object",
                            "碎片引用了未导入 manifest 的对象",
                            &bp.display().to_string(),
                        );
                        warnings += 1;
                        continue;
                    }
                }
            }
        };

        if parsed.stripe >= manifest.stripe_count {
            let _ = db.insert_warning(
                Some(&parsed.object_id),
                "object",
                "stripe_out_of_range",
                &format!("stripe {} >= {}", parsed.stripe, manifest.stripe_count),
                &bp.display().to_string(),
            );
            warnings += 1;
            continue;
        }
        let kind = match manifest.shard_kind(parsed.shard) {
            Some(k) => k,
            None => {
                let _ = db.insert_warning(
                    Some(&parsed.object_id),
                    "object",
                    "shard_out_of_range",
                    &format!("shard {} >= n={}", parsed.shard, manifest.n()),
                    &bp.display().to_string(),
                );
                warnings += 1;
                continue;
            }
        };

        let bytes = std::fs::read(bp)
            .map_err(|e| format!("读取 {} 失败: {e}", bp.display()))?;
        let attached = read_attached_digest(bp);
        let recalculated = sha256_hex(&bytes);

        // manifest 与实际长度不符：记录证据，但仍保存原始字节（标记由分析层排除）。
        let mut len_ok = true;
        if bytes.len() != manifest.block_len {
            len_ok = false;
            let _ = db.insert_warning(
                Some(&parsed.object_id),
                "object",
                "length_mismatch",
                &format!(
                    "stripe={} shard={} gen={} source={}: 实际长度 {} != block_len {}",
                    parsed.stripe, parsed.shard, parsed.generation, parsed.source,
                    bytes.len(), manifest.block_len
                ),
                &bp.display().to_string(),
            );
            warnings += 1;
        }
        let _ = len_ok;

        // 同一编号重复/候选：UNIQUE 约束会去重完全相同记录；不同内容/代数/来源各自保留。
        let rb = ReceivedBlock {
            object_id: parsed.object_id.clone(),
            stripe: parsed.stripe,
            shard: parsed.shard,
            generation: parsed.generation,
            source: parsed.source.clone(),
            bytes,
            attached_digest: attached,
            origin_path: bp.display().to_string(),
        };
        db.insert_raw_block(&rb, kind.as_str(), &recalculated)
            .map_err(|e| format!("写入碎片失败: {e}"))?;
        blocks += 1;
    }

    Ok(ImportOutcome {
        manifests,
        blocks,
        warnings,
    })
}

fn walk(
    base: &Path,
    dir: &Path,
    manifests: &mut Vec<PathBuf>,
    bins: &mut Vec<PathBuf>,
) -> std::io::Result<()> {
    if base != dir && is_hidden_dir(dir) {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            if !is_hidden_dir(&path) {
                walk(base, &path, manifests, bins)?;
            }
        } else if ft.is_file() {
            if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                if name == "manifest.json" {
                    manifests.push(path);
                } else if name.ends_with(".bin") {
                    bins.push(path);
                }
            }
        }
    }
    Ok(())
}

fn is_hidden_dir(p: &Path) -> bool {
    p.file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.starts_with('.') || s == "exports" || s == "staging")
        .unwrap_or(false)
}

fn read_manifest(path: &Path) -> Result<(String, ObjectManifest), String> {
    let json = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let m: ObjectManifest = serde_json::from_str(&json).map_err(|e| format!("manifest 解析失败: {e}"))?;
    Ok((json, m))
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParsedName {
    pub object_id: String,
    pub stripe: usize,
    pub shard: usize,
    pub generation: u64,
    pub source: String,
}

/// `obj-<id>__s<stripe>__i<shard>__g<gen>__src-<source>.bin`
pub fn parse_block_filename(name: &str) -> Option<ParsedName> {
    let stem = name.strip_suffix(".bin")?;
    let mut object_id: Option<String> = None;
    let mut stripe = None;
    let mut shard = None;
    let mut generation = 0u64;
    let mut source = String::from("unknown");
    for part in stem.split("__") {
        if let Some(v) = part.strip_prefix("obj-") {
            object_id = Some(v.to_string());
        } else if let Some(v) = part.strip_prefix("src-") {
            source = v.to_string();
        } else if let Some(rest) = part.strip_prefix("g") {
            // 必须放在 s/i 泛前缀判断之前精确排除
            generation = rest.parse().ok()?;
        } else if let Some(rest) = part.strip_prefix('s') {
            if !part.starts_with("src-") {
                stripe = rest.parse().ok();
            }
        } else if let Some(rest) = part.strip_prefix('i') {
            shard = rest.parse().ok();
        }
    }
    Some(ParsedName {
        object_id: object_id?,
        stripe: stripe?,
        shard: shard?,
        generation,
        source,
    })
}

pub fn block_filename(object_id: &str, stripe: usize, shard: usize, generation: u64, source: &str) -> String {
    format!("obj-{object_id}__s{stripe}__i{shard}__g{generation}__src-{source}.bin")
}

fn read_attached_digest(bin_path: &Path) -> Option<String> {
    let sibling = bin_path.with_extension("bin.digest");
    let direct = bin_path.with_extension("digest");
    for candidate in [sibling, direct] {
        if let Ok(text) = std::fs::read_to_string(&candidate) {
            let v = text.trim().split_whitespace().next().unwrap_or("").to_string();
            if v.len() == 64 && v.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(v);
            }
        }
    }
    None
}

#[cfg(test)]
mod name_tests {
    use super::*;
    #[test]
    fn parse_demo_name() {
        let p = parse_block_filename(
            "obj-obj-demo-trusted__s2__i0__g1__src-node-b.bin",
        )
        .unwrap();
        assert_eq!(p.object_id, "obj-demo-trusted");
        assert_eq!(p.stripe, 2);
        assert_eq!(p.shard, 0);
        assert_eq!(p.generation, 1);
        assert_eq!(p.source, "node-b");
    }
}
