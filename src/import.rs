//! 导入：把一批 manifest + shard 文件收入 inbox。
//! 原始字节逐位复制保存，不做任何修改；所有异常只记录证据，不阻断其他碎片。

use std::collections::BTreeMap;
use std::path::Path;

use crate::manifest::ImportManifest;
use crate::model::{sha256_hex, EvidenceKind};
use crate::store::Store;

#[derive(Debug, Default)]
pub struct ImportReport {
    pub batch_id: String,
    pub object_id: String,
    pub shards_imported: usize,
    pub evidence: usize,
}

pub fn import_batch(store: &Store, dir: &Path) -> std::io::Result<ImportReport> {
    let manifest_path = dir.join("manifest.json");
    let manifest_bytes = std::fs::read(&manifest_path)?;
    let manifest: ImportManifest = match ImportManifest::parse(&manifest_bytes) {
        Ok(m) => m,
        Err(e) => {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e));
        }
    };
    let params = manifest.coding.params().map_err(std::io::Error::other)?;
    let field = params.field();
    let batch_id = dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("batch")
        .to_string();
    let object_pk = store.ensure_object(
        &manifest.object_id,
        &params,
        manifest.stripes,
        manifest.object_digest.as_ref().map(|d| d.value.as_str()),
    )?;

    // 原样保存 manifest。
    store.atomic_write(&store.inbox_path(&batch_id, "manifest.json"), &manifest_bytes)?;

    let mut report = ImportReport {
        batch_id: batch_id.clone(),
        object_id: manifest.object_id.clone(),
        ..Default::default()
    };

    // 同一 (stripe,slot) 的到达次数与不同内容数，用于重复编号证据。
    let mut seen: BTreeMap<(usize, usize), (usize, std::collections::BTreeSet<String>)> =
        BTreeMap::new();

    for entry in &manifest.shards {
        let src_path = dir.join(&entry.file);
        let bytes = match std::fs::read(&src_path) {
            Ok(b) => b,
            Err(e) => {
                store.add_evidence(
                    object_pk,
                    entry.stripe,
                    Some(entry.slot),
                    None,
                    EvidenceKind::LengthMismatch,
                    &format!("{}: 无法读取 ({e})", entry.file),
                    "import",
                )?;
                report.evidence += 1;
                continue;
            }
        };
        let actual = sha256_hex(&bytes);
        let inbox_rel = format!(
            "inbox/{batch_id}/s{}-slot{}-gen{}-{}.bin",
            entry.stripe,
            entry.slot,
            entry.generation,
            &actual[..10]
        );
        let inbox_full = store.root.join(&inbox_rel);
        store.atomic_write(&inbox_full, &bytes)?;
        let rid = store.insert_replica(
            object_pk,
            entry.stripe,
            entry.slot,
            entry.generation,
            &entry.source,
            entry.digest.as_ref().map(|d| d.value.as_str()),
            &bytes,
            &inbox_rel,
        )?;
        report.shards_imported += 1;

        if bytes.len() != params.shard_size {
            store.add_evidence(
                object_pk,
                entry.stripe,
                Some(entry.slot),
                Some(rid),
                EvidenceKind::LengthMismatch,
                &format!(
                    "manifest 声明 {} 字节，实际 {} 字节",
                    params.shard_size,
                    bytes.len()
                ),
                "import",
            )?;
            report.evidence += 1;
        }
        if !field.check_symbols(&bytes) {
            store.add_evidence(
                object_pk,
                entry.stripe,
                Some(entry.slot),
                Some(rid),
                EvidenceKind::OutOfField,
                &format!("出现 GF(2^{}) 域外符号", params.field_bits),
                "import",
            )?;
            report.evidence += 1;
        }
        if let Some(d) = &entry.digest {
            if d.alg != "sha256" {
                store.add_evidence(
                    object_pk,
                    entry.stripe,
                    Some(entry.slot),
                    Some(rid),
                    EvidenceKind::DigestMismatch,
                    &format!("不支持的摘要算法 {}", d.alg),
                    "import",
                )?;
                report.evidence += 1;
            } else if !d.value.eq_ignore_ascii_case(&actual) {
                store.add_evidence(
                    object_pk,
                    entry.stripe,
                    Some(entry.slot),
                    Some(rid),
                    EvidenceKind::DigestMismatch,
                    &format!("提供 {} ，重算 {actual}", d.value),
                    "import",
                )?;
                report.evidence += 1;
            }
        }
        let e = seen.entry((entry.stripe, entry.slot)).or_default();
        e.0 += 1;
        e.1.insert(actual);
    }

    for ((stripe, slot), (count, contents)) in &seen {
        if *count > 1 {
            let kind = if contents.len() > 1 {
                EvidenceKind::DuplicateSlot
            } else {
                EvidenceKind::DuplicateSlot
            };
            store.add_evidence(
                object_pk,
                *stripe,
                Some(*slot),
                None,
                kind,
                &format!(
                    "slot {slot} 收到 {count} 个副本、{} 种不同内容候选（不先到先得，全部纳入枚举）",
                    contents.len()
                ),
                "import",
            )?;
            report.evidence += 1;
        }
    }

    Ok(report)
}
