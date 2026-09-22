//! 导出：每次使用全新目录，清单以 `.pending` -> 正式名原子切换。
//! 只读取已提交且摘要完整的 stripe；原始碎片永不修改。

use crate::commit::{read_committed, sha256_hex, stripe_digest, CommitManifestV1};
use crate::db::Store;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

#[derive(Debug, Serialize)]
pub struct ExportManifestV1 {
    pub version: String,
    pub export_id: String,
    pub object_id: String,
    pub stripe_count: usize,
    pub stripes: Vec<ExportedStripe>,
    pub object_digest: String,
}

#[derive(Debug, Serialize)]
pub struct ExportedStripe {
    pub stripe_idx: usize,
    pub dir: String,
    pub stripe_digest: String,
}

pub struct ExportResult {
    pub export_id: String,
    pub dir: PathBuf,
    pub manifest_digest: String,
}

pub fn export_object(store: &Store, object_id: &str, stripe_count: usize) -> std::io::Result<ExportResult> {
    let export_id = format!(
        "{}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        &crate::commit::sha256_hex(object_id.as_bytes())[..8]
    );
    let dir = store.exports_dir().join(&export_id);
    std::fs::create_dir_all(&dir.join("stripes"))?;

    let mut stripes = Vec::new();
    let mut object_hasher = Sha256::new();
    for idx in 0..stripe_count {
        let src = store
            .commits_dir(object_id)
            .join(format!("stripe-{:06}", idx));
        let (manifest, blocks): (CommitManifestV1, Vec<Vec<u8>>) = read_committed(&src)?;
        let digest = stripe_digest(&blocks);
        let out_rel = format!("stripes/stripe-{:06}", idx);
        let out = dir.join(&out_rel);
        std::fs::create_dir_all(&out)?;
        for (j, bytes) in blocks.iter().enumerate() {
            std::fs::write(out.join(format!("shard-{:03}.bin", j)), bytes)?;
        }
        let copied_manifest = serde_json::to_vec_pretty(&manifest).map_err(io_other)?;
        std::fs::write(out.join("commit-manifest.json"), copied_manifest)?;
        Digest::update(&mut object_hasher, (idx as u64).to_be_bytes());
        Digest::update(&mut object_hasher, digest.as_bytes());
        stripes.push(ExportedStripe {
            stripe_idx: idx,
            dir: out_rel,
            stripe_digest: digest,
        });
    }

    let export_manifest = ExportManifestV1 {
        version: "export-manifest/v1".into(),
        export_id: export_id.clone(),
        object_id: object_id.into(),
        stripe_count,
        stripes,
        object_digest: hex::encode(object_hasher.finalize()),
    };
    let bytes = serde_json::to_vec_pretty(&export_manifest).map_err(io_other)?;
    let manifest_digest = sha256_hex(&bytes);

    if store.faults.fail_export_promote() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "injected failure before manifest atomic switch",
        ));
    }

    // 原子清单切换：先写 pending，再 rename 为正式清单。
    let pending = dir.join("export-manifest.json.pending");
    let final_m = dir.join("export-manifest.json");
    std::fs::write(&pending, bytes)?;
    std::fs::rename(&pending, &final_m)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    {
        let conn = store.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO exports(export_id, object_id, dir, manifest_digest, created_at)
             VALUES (?1,?2,?3,?4,?5)",
            rusqlite::params![export_id, object_id, dir.to_string_lossy(), manifest_digest, now],
        )
        .map_err(io_other)?;
    }
    Ok(ExportResult {
        export_id,
        dir,
        manifest_digest,
    })
}

fn io_other<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
}
