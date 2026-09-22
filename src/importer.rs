//! 导入"条带复原舱"bundle：manifest + data/parity shard + 每块摘要边车。
//! 原始字节按原样保存，不做任何修改；重复 shard 编号作为多个候选保留。

use crate::model::{FragmentInput, Manifest};
use crate::store::Store;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub struct ImportReport {
    pub object_id: String,
    pub fragment_count: usize,
    pub sources: BTreeSet<String>,
    pub warnings: Vec<String>,
}

/// bundle 结构：
///   manifest.json
///   shards/<name>.bin          原始碎片
///   shards/<name>.digest       可选，单行 hex sha256
/// 文件名：s<stripe>_sh<shard>_g<generation>.bin（允许其它后缀内容去重）。
/// 或同目录放 <name>.meta.json：{"source":"nodeA"}（不填则用文件名来源）。
pub fn import_bundle(store: &Store, dir: &Path) -> Result<ImportReport, String> {
    let manifest_path = dir.join("manifest.json");
    let manifest: Manifest = serde_json::from_slice(
        &std::fs::read(&manifest_path).map_err(|e| format!("读取 manifest.json 失败: {e}"))?,
    )
    .map_err(|e| format!("解析 manifest.json 失败: {e}"))?;
    manifest.field().map_err(|e| e)?;
    manifest.codec().map_err(|e| e)?;
    if manifest.k == 0 || manifest.m == 0 || manifest.stripe_length == 0 {
        return Err("manifest 中 k、m、stripe_length 必须大于 0".into());
    }
    store.upsert_manifest(&manifest)?;

    let shards_dir = dir.join("shards");
    let mut warnings = Vec::new();
    let mut sources = BTreeSet::new();
    let mut count = 0usize;

    let mut bin_files: Vec<std::path::PathBuf> = Vec::new();
    if shards_dir.exists() {
        for entry in std::fs::read_dir(&shards_dir).map_err(|e| e.to_string())? {
            let p = entry.map_err(|e| e.to_string())?.path();
            if p.extension().and_then(|s| s.to_str()) == Some("bin") {
                bin_files.push(p);
            }
        }
    }
    bin_files.sort();

    let mut seen: BTreeMap<(usize, usize, String), String> = BTreeMap::new();

    for path in bin_files {
        let file_stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| format!("非法文件名: {}", path.display()))?
            .to_string();
        let parsed = parse_shard_name(&file_stem);
        let (stripe, shard, generation) = match parsed {
            Some(v) => v,
            None => {
                warnings.push(format!("{} 文件名无法解析，已跳过", path.display()));
                continue;
            }
        };
        let meta_path = path.with_file_name(format!("{}.meta.json", file_stem));
        let source = if meta_path.exists() {
            #[derive(serde::Deserialize)]
            struct Meta {
                #[serde(default)]
                source: Option<String>,
            }
            let meta: Meta = serde_json::from_slice(
                &std::fs::read(&meta_path).map_err(|e| e.to_string())?,
            )
            .map_err(|e| format!("解析 {} 失败: {e}", meta_path.display()))?;
            meta.source.unwrap_or_else(|| file_stem.clone())
        } else {
            file_stem.clone()
        };
        sources.insert(source.clone());

        let digest_path = path.with_extension("digest");
        let claimed_digest = if digest_path.exists() {
            let raw = std::fs::read_to_string(&digest_path).map_err(|e| e.to_string())?;
            Some(raw.trim().to_string())
        } else {
            None
        };

        let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
        let recomputed = hex::encode(Sha256::digest(&bytes));

        if stripe >= manifest.stripe_count {
            warnings.push(format!(
                "{file_stem}: stripe {stripe} 超出 stripe_count {}，仍保存并标记为越界证据",
                manifest.stripe_count
            ));
        }
        if shard >= manifest.k + manifest.m {
            warnings.push(format!(
                "{file_stem}: shard {shard} 超出 k+m {}，仍保存并标记为越界证据",
                manifest.k + manifest.m
            ));
        }
        if bytes.len() != manifest.stripe_length {
            warnings.push(format!(
                "{file_stem}: 长度 {} 与 stripe_length {} 不符",
                bytes.len(),
                manifest.stripe_length
            ));
        }
        if let Some(claimed) = &claimed_digest {
            if !claimed.eq_ignore_ascii_case(&recomputed) {
                warnings.push(format!(
                    "{file_stem}: 摘要边车与实际字节不符（损坏证据，重建时排除）"
                ));
            }
        }

        let key = (stripe, shard, recomputed.clone());
        let fragment_id = match seen.get(&key) {
            Some(existing) => existing.clone(),
            None => {
                let mut hasher = Sha256::new();
                hasher.update(manifest.object_id.as_bytes());
                hasher.update(stripe.to_le_bytes());
                hasher.update(shard.to_le_bytes());
                hasher.update(generation.to_le_bytes());
                hasher.update(source.as_bytes());
                hasher.update(recomputed.as_bytes());
                let id = format!("frag_{}", &hex::encode(hasher.finalize())[..20]);
                seen.insert(key, id.clone());
                id
            }
        };

        let input = FragmentInput {
            fragment_id: fragment_id.clone(),
            object_id: manifest.object_id.clone(),
            stripe,
            shard,
            generation,
            source,
            bytes,
            claimed_digest,
            received_at: now_iso(),
        };
        store.save_fragment(&input)?;
        count += 1;
    }

    if count == 0 {
        return Err("bundle 中没有任何 shard".into());
    }
    Ok(ImportReport {
        object_id: manifest.object_id,
        fragment_count: count,
        sources,
        warnings,
    })
}

fn parse_shard_name(stem: &str) -> Option<(usize, usize, u64)> {
    // 形如 s01_sh03_g2
    let mut stripe = None;
    let mut shard = None;
    let mut generation = 0u64;
    for part in stem.split('_') {
        if let Some(v) = part.strip_prefix("sh") {
            if let Ok(n) = v.parse::<usize>() {
                shard = Some(n);
                continue;
            }
        }
        if let Some(v) = part.strip_prefix('g') {
            let num: String = v.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(n) = num.parse::<u64>() {
                generation = n;
                continue;
            }
        }
        if let Some(v) = part.strip_prefix('s') {
            // 去掉可能的后缀（如 g1-alt 中的 -alt）
            let num: String = v.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(n) = num.parse::<usize>() {
                stripe = Some(n);
            }
        }
    }
    Some((stripe?, shard?, generation))
}

fn now_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("unix:{}", secs)
}
