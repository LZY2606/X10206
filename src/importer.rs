//! 导入 manifest、data/parity shard 与每块摘要；保存原始字节与接收来源。

use crate::db::{Database, FragmentRow, ObjectRow};
use crate::model::{ManifestFile, MANIFEST_FORMAT_VERSION};
use crate::store::FileStore;
use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct ImportReport {
    pub object_id: String,
    pub fragments_imported: u32,
    pub fragments_skipped: Vec<SkippedFragment>,
    pub stripe_count: u32,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SkippedFragment {
    pub stripe_index: u32,
    pub shard_index: u32,
    pub file: String,
    pub reason: String,
}

/// 从离线目录导入：读取 manifest.json 与其引用的碎片文件。
/// 原始字节写入 raw 区（内容寻址），manifest 声明只进数据库，不做信任假设。
pub fn import_dir(db: &Database, store: &FileStore, dir: &Path) -> Result<ImportReport> {
    let manifest_path = dir.join("manifest.json");
    let text = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("读取 manifest 失败: {}", manifest_path.display()))?;
    let manifest: ManifestFile =
        serde_json::from_str(&text).with_context(|| "manifest.json 解析失败")?;
    import_manifest(db, store, &manifest, &mut |file| {
        let p = dir.join(file);
        std::fs::read(&p).with_context(|| format!("读取碎片失败: {}", p.display()))
    })
}

/// 直接以 manifest 结构导入（测试与程序化导入）。
pub fn import_manifest(
    db: &Database,
    store: &FileStore,
    manifest: &ManifestFile,
    read_file: &mut dyn FnMut(&str) -> Result<Vec<u8>>,
) -> Result<ImportReport> {
    if manifest.format_version != MANIFEST_FORMAT_VERSION {
        bail!(
            "不支持的 manifest 格式版本: {}（当前支持 {}）",
            manifest.format_version,
            MANIFEST_FORMAT_VERSION
        );
    }
    manifest.coding.validate()?;
    let object_id = manifest.object_id.clone();
    let stripe_count = manifest.stripes.len() as u32;
    let expected_len = manifest
        .coding
        .stripe_size as u64
        * manifest.coding.data_shards as u64
        * stripe_count as u64;
    let mut warnings = Vec::new();
    if manifest.object_len > expected_len {
        bail!(
            "manifest 对象长度 {} 超出条带容量 {}",
            manifest.object_len,
            expected_len
        );
    }

    db.upsert_object(&ObjectRow {
        object_id: object_id.clone(),
        object_len: manifest.object_len,
        object_digest: manifest.object_digest.clone(),
        coding_version: manifest.coding.version,
        data_shards: manifest.coding.data_shards,
        parity_shards: manifest.coding.parity_shards,
        stripe_size: manifest.coding.stripe_size,
        stripe_count,
        imported_at: crate::db::now(),
    })?;

    let mut imported = 0u32;
    let mut skipped = Vec::new();
    for stripe in &manifest.stripes {
        db.ensure_stripe(&object_id, stripe.stripe_index)?;
        for shard in &stripe.shards {
            db.insert_source_if_absent(&object_id, &shard.source)?;
            if shard.shard_index >= manifest.coding.total_shards() {
                skipped.push(SkippedFragment {
                    stripe_index: stripe.stripe_index,
                    shard_index: shard.shard_index,
                    file: shard.file.clone(),
                    reason: format!(
                        "shard 编号越界（编码参数共 {} 块）",
                        manifest.coding.total_shards()
                    ),
                });
                continue;
            }
            let bytes = match read_file(&shard.file) {
                Ok(b) => b,
                Err(e) => {
                    skipped.push(SkippedFragment {
                        stripe_index: stripe.stripe_index,
                        shard_index: shard.shard_index,
                        file: shard.file.clone(),
                        reason: format!("读取失败: {e:#}"),
                    });
                    continue;
                }
            };
            let digest = store.save_raw(&bytes)?;
            db.insert_fragment(&FragmentRow {
                id: 0,
                object_id: object_id.clone(),
                stripe_index: stripe.stripe_index,
                shard_index: shard.shard_index,
                generation: shard.generation,
                source: shard.source.clone(),
                file_path: shard.file.clone(),
                declared_len: shard.declared_len,
                declared_digest: shard.declared_digest.clone(),
                artifact_digest: digest,
                len: bytes.len() as u64,
            })?;
            imported += 1;
            if let Some(dl) = shard.declared_len {
                if dl != bytes.len() as u64 {
                    warnings.push(format!(
                        "stripe {} shard {}: manifest 声明长度 {} 与实际 {} 不符",
                        stripe.stripe_index,
                        shard.shard_index,
                        dl,
                        bytes.len()
                    ));
                }
            }
        }
    }
    Ok(ImportReport {
        object_id,
        fragments_imported: imported,
        fragments_skipped: skipped,
        stripe_count,
        warnings,
    })
}
