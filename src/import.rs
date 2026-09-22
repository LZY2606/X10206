//! 导入一个"来源舱"目录：读取 manifest，逐块保存原始字节、接收来源与审计证据。
//! 导入过程只读来源目录，绝不修改其中任何文件。

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::db::Storage;
use crate::hashutil::sha256_hex;
use crate::types::{
    lookup_params, FragmentHealth, Manifest, ManifestFragment, EvidenceKind,
};

#[derive(Debug)]
pub enum ImportError {
    Io(String),
    Parse(String),
    UnsupportedVersion(String),
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportError::Io(e) => write!(f, "读取来源目录失败: {e}"),
            ImportError::Parse(e) => write!(f, "manifest 解析失败: {e}"),
            ImportError::UnsupportedVersion(v) => write!(f, "不支持的编码版本: {v}"),
        }
    }
}

fn fragment_path(root: &Path, mf: &ManifestFragment) -> PathBuf {
    match &mf.file {
        Some(rel) if !rel.is_empty() => root.join(rel),
        _ => root.join(format!(
            "shards/s{}.sh{}.g{}.bin",
            mf.stripe, mf.shard, mf.generation
        )),
    }
}

fn kind_str(k: EvidenceKind) -> &'static str {
    match k {
        EvidenceKind::DigestMismatch => "digest_mismatch",
        EvidenceKind::LengthMismatch => "length_mismatch",
        EvidenceKind::DuplicateShard => "duplicate_shard",
        EvidenceKind::ConflictingCandidates => "conflicting_candidates",
        EvidenceKind::StaleGeneration => "stale_generation",
        EvidenceKind::CodingInconsistent => "coding_inconsistent",
        EvidenceKind::SearchBudgetExceeded => "search_budget_exceeded",
    }
}

pub fn import_bundle(storage: &mut Storage, dir: &Path) -> Result<String, ImportError> {
    let manifest_path = dir.join("manifest.json");
    let raw = fs::read_to_string(&manifest_path)
        .map_err(|e| ImportError::Io(format!("{}: {e}", manifest_path.display())))?;
    let manifest: Manifest =
        serde_json::from_str(&raw).map_err(|e| ImportError::Parse(e.to_string()))?;

    let params = lookup_params(&manifest.coding_version)
        .ok_or_else(|| ImportError::UnsupportedVersion(manifest.coding_version.clone()))?;
    if (params.k as u32) > 255 - params.m as u32 {
        return Err(ImportError::Parse("k+m 超出有限域容量".into()));
    }

    let source_name = dir
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "source".into());
    let source_id = storage
        .upsert_source(&source_name, &dir.to_string_lossy())
        .map_err(|e| ImportError::Io(e.to_string()))?;

    let stripe_count = manifest
        .stripe_count
        .unwrap_or_else(|| manifest.fragments.iter().map(|f| f.stripe).max().unwrap_or(0) + 1)
        as i64;
    let object_id = storage
        .upsert_object(
            &manifest.object_id,
            &manifest.coding_version,
            manifest.object_digest.as_deref(),
            manifest.declared_len.map(|v| v as i64),
            stripe_count,
        )
        .map_err(|e| ImportError::Io(e.to_string()))?;

    // 同一 manifest 内 (stripe, shard) 编号重复检测（即使内容相同）。
    let mut seen: HashSet<(u32, u32)> = HashSet::new();
    // (stripe, shard, generation) -> 首个摘要，用于识别同编号两个内容候选。
    let mut content_by_key: HashMap<(u32, u32, u32), String> = HashMap::new();

    // 预扫：确保 stripe 行存在，长度以 params.stripe_bytes 为准。
    for s in 0..stripe_count {
        storage
            .ensure_stripe(object_id, s, params.stripe_bytes as i64)
            .map_err(|e| ImportError::Io(e.to_string()))?;
    }

    let mut imported = 0usize;
    for mf in &manifest.fragments {
        let path = fragment_path(dir, mf);
        let bytes = fs::read(&path)
            .map_err(|e| ImportError::Io(format!("{}: {e}", path.display())))?;
        let actual_len = bytes.len() as i64;
        let actual_digest = sha256_hex(&bytes);

        let stripe_row_id = storage
            .ensure_stripe(object_id, mf.stripe as i64, params.stripe_bytes as i64)
            .map_err(|e| ImportError::Io(e.to_string()))?;

        let duplicate = !seen.insert((mf.stripe, mf.shard));
        if duplicate {
            storage
                .add_evidence(
                    Some(stripe_row_id),
                    Some(object_id),
                    None,
                    None,
                    kind_str(EvidenceKind::DuplicateShard),
                    &format!("来源 {source_name} manifest 中 stripe {} shard {} 编号重复", mf.stripe, mf.shard),
                )
                .map_err(|e| ImportError::Io(e.to_string()))?;
        }

        let length_mismatch = actual_len != mf.length as i64;
        let digest_match = actual_digest.eq_ignore_ascii_case(&mf.digest);

        let health = if !digest_match {
            FragmentHealth::Corrupt
        } else if length_mismatch {
            FragmentHealth::LengthMismatch
        } else {
            FragmentHealth::Intact
        };

        let frag_id = storage
            .insert_fragment(
                object_id,
                source_id,
                mf.stripe as i64,
                mf.shard as i64,
                mf.generation as i64,
                mf.length as i64,
                actual_len,
                &mf.digest,
                &actual_digest,
                match health {
                    FragmentHealth::Intact => "intact",
                    FragmentHealth::Corrupt => "corrupt",
                    FragmentHealth::LengthMismatch => "length_mismatch",
                    FragmentHealth::Isolated => "isolated",
                    FragmentHealth::Unverified => "unverified",
                },
                &bytes,
            )
            .map_err(|e| ImportError::Io(e.to_string()))?;

        if length_mismatch {
            storage
                .add_evidence(
                    Some(stripe_row_id),
                    Some(object_id),
                    Some(frag_id),
                    None,
                    kind_str(EvidenceKind::LengthMismatch),
                    &format!(
                        "manifest 长度 {} 与实际长度 {} 不符 (frag #{frag_id})",
                        mf.length, actual_len
                    ),
                )
                .map_err(|e| ImportError::Io(e.to_string()))?;
        }
        if !digest_match {
            storage
                .add_evidence(
                    Some(stripe_row_id),
                    Some(object_id),
                    Some(frag_id),
                    None,
                    kind_str(EvidenceKind::DigestMismatch),
                    &format!(
                        "位翻转/内容篡改：重算摘要 {actual_digest} 与 manifest 声明 {} 不符 (frag #{frag_id})",
                        mf.digest
                    ),
                )
                .map_err(|e| ImportError::Io(e.to_string()))?;
        }

        let key = (mf.stripe, mf.shard, mf.generation);
        if let Some(first) = content_by_key.get(&key) {
            if first != &actual_digest {
                storage
                    .add_evidence(
                        Some(stripe_row_id),
                        Some(object_id),
                        Some(frag_id),
                        None,
                        kind_str(EvidenceKind::ConflictingCandidates),
                        &format!(
                            "stripe {} shard {} gen {} 存在两个不同内容候选：{first} 与 {actual_digest}",
                            mf.stripe, mf.shard, mf.generation
                        ),
                    )
                    .map_err(|e| ImportError::Io(e.to_string()))?;
            }
        } else {
            content_by_key.insert(key, actual_digest);
        }
        imported += 1;
    }

    Ok(format!("来源 {source_name} 导入 {imported} 块，对象 {}", manifest.object_id))
}
