//! Export into a fresh directory with an atomic manifest pointer switch.
//! Imported fragments in SQLite are never modified.

use crate::recover::{sha256_hex, shard_path};
use crate::runner::{object_out_dir, run_recovery};
use crate::store::Store;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, serde::Serialize)]
pub struct ExportResult {
    pub dir: String,
    pub file: String,
    pub digest: String,
    pub size: u64,
}

pub fn exports_root(data_dir: &Path) -> PathBuf {
    data_dir.join("exports")
}

pub fn export_object(
    store: &Store,
    object_id: i64,
    data_dir: &Path,
) -> Result<ExportResult, String> {
    let object = store
        .get_object(object_id)
        .ok_or_else(|| "对象不存在".to_string())?;
    let out_dir = object_out_dir(data_dir, object_id);

    // Make sure recovery is complete first.
    run_recovery(store, object_id, &out_dir, None);
    let stripe_total = store.stripe_count(&object);
    let commits = store.list_commits(object_id);
    if commits.len() != stripe_total {
        return Err(format!(
            "仅 {}/{} 个 stripe 已提交, 无法导出",
            commits.len(),
            stripe_total
        ));
    }

    let k = object.params.k;
    let shard_size = object.params.shard_size;
    let mut bytes: Vec<u8> = Vec::new();
    let mut stripe_digests = Vec::new();
    for stripe in 0..stripe_total {
        let commit = commits.iter().find(|c| c.stripe == stripe).unwrap();
        let mut stripe_bytes = Vec::new();
        for idx in 0..k {
            let p = shard_path(&out_dir, stripe, idx);
            let b = std::fs::read(&p)
                .map_err(err_str)?;
            if b.len() != shard_size {
                return Err(format!("stripe {} 编号 {} 长度异常", stripe, idx));
            }
            stripe_bytes.extend_from_slice(&b);
        }
        if sha256_hex(&stripe_bytes) != commit.digest {
            return Err(format!("stripe {} 提交摘要校验失败", stripe));
        }
        stripe_digests.push(commit.digest.clone());
        bytes.extend_from_slice(&stripe_bytes);
    }
    bytes.truncate(object.total_len as usize);
    let digest = sha256_hex(&bytes);

    // Object-level constraint from the manifest: the assembled object must
    // match the declared digest, otherwise the chosen combos are not
    // trustworthy as a whole even if each stripe looked feasible.
    if !object.object_digest.is_empty() && digest != object.object_digest {
        return Err(format!(
            "对象摘要校验失败: manifest 声明 {}..., 重建结果 {}...",
            &object.object_digest[..12.min(object.object_digest.len())],
            &digest[..12]
        ));
    }

    // Fresh directory for every export.
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let export_dir = exports_root(data_dir).join(format!("export_{:020}", ts));
    std::fs::create_dir_all(&export_dir).map_err(err_str)?;

    let file_name = format!("{}.bin", object.name);
    let tmp_file = export_dir.join(format!("{}.tmp", file_name));
    std::fs::write(&tmp_file, &bytes).map_err(err_str)?;
    std::fs::rename(&tmp_file, export_dir.join(&file_name)).map_err(err_str)?;

    let manifest = serde_json::json!({
        "object_id": object_id,
        "name": object.name,
        "total_len": object.total_len,
        "sha256": digest,
        "manifest_object_digest": object.object_digest,
        "coding": object.params,
        "stripe_digests": stripe_digests,
    });
    let manifest_str = serde_json::to_string_pretty(&manifest).unwrap();
    let m_tmp = export_dir.join("manifest.json.tmp");
    std::fs::write(&m_tmp, manifest_str).map_err(err_str)?;
    std::fs::rename(&m_tmp, export_dir.join("manifest.json")).map_err(err_str)?;

    // Atomic pointer switch: CURRENT.tmp -> CURRENT (rename is atomic).
    let root = exports_root(data_dir);
    let cur_tmp = root.join("CURRENT.tmp");
    std::fs::write(&cur_tmp, export_dir.to_string_lossy().as_bytes()).map_err(err_str)?;
    std::fs::rename(&cur_tmp, root.join("CURRENT")).map_err(err_str)?;

    Ok(ExportResult {
        dir: export_dir.to_string_lossy().to_string(),
        file: file_name,
        digest,
        size: bytes.len() as u64,
    })
}

fn err_str<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}
