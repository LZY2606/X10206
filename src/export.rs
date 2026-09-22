//! 导出：写入全新目录，清单通过 tmp + rename 原子切换；原始碎片不改动。

use crate::store::Store;
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

pub struct ExportOutcome {
    pub dir: PathBuf,
    pub files: Vec<String>,
}

fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    let tmp = dir.join(format!("{name}.tmp"));
    let dst = dir.join(name);
    fs::write(&tmp, bytes).map_err(|e| format!("写入临时块 {} 失败：{e}", tmp.display()))?;
    fs::rename(&tmp, &dst).map_err(|e| format!("原子切换 {} 失败：{e}", dst.display()))
}

pub fn export_object(store: &Store, object_id: &str, base: &Path) -> Result<ExportOutcome, String> {
    let obj = store
        .get_object(object_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("对象 {object_id} 不存在"))?;
    let total = obj.params.k + obj.params.m;

    // 仅导出摘要完整校验通过的已提交 stripe；临时块绝不作为最终读取来源。
    for stripe in 0..obj.stripe_count as u32 {
        if !store
            .verify_committed(object_id, stripe, total)
            .map_err(|e| e.to_string())?
        {
            return Err(format!("stripe {stripe} 未提交或摘要不完整，拒绝导出"));
        }
    }

    let dir = base.join(format!("{}.new", obj.id));
    if dir.exists() {
        fs::remove_dir_all(&dir).map_err(|e| format!("清理旧导出目录失败：{e}"))?;
    }
    fs::create_dir_all(&dir).map_err(|e| format!("创建导出目录 {} 失败：{e}", dir.display()))?;

    let mut files = Vec::new();
    let mut object_bytes: Vec<u8> = Vec::new();
    let mut manifest_stripes = Vec::new();

    for stripe in 0..obj.stripe_count as u32 {
        let (generation, solution_digest) = store
            .committed_stripe(object_id, stripe)
            .map_err(|e| e.to_string())?
            .unwrap();
        let shards = store
            .committed_shards(object_id, stripe)
            .map_err(|e| e.to_string())?;
        let mut shard_entries = Vec::new();
        for (idx, digest, bytes) in &shards {
            let name = format!("shard-{stripe}-{idx}.bin");
            write_atomic(&dir, &name, bytes)?;
            files.push(name.clone());
            if (*idx as usize) < obj.params.k {
                object_bytes.extend_from_slice(bytes);
            }
            shard_entries.push(json!({"shard_idx": idx, "digest": digest, "file": name}));
        }
        manifest_stripes.push(json!({
            "stripe_idx": stripe,
            "generation": generation,
            "solution_digest": solution_digest,
            "shards": shard_entries,
        }));
    }

    object_bytes.truncate(obj.object_len as usize);
    write_atomic(&dir, "object.bin", &object_bytes)?;
    files.push("object.bin".into());

    let manifest = json!({
        "object_id": obj.id,
        "name": obj.name,
        "encoding": {
            "version": obj.params.version,
            "k": obj.params.k,
            "m": obj.params.m,
            "shard_size": obj.params.shard_size,
        },
        "object_len": obj.object_len,
        "stripes": manifest_stripes,
    });
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?;
    // 原子清单切换：先写临时文件，再 rename 生效。
    write_atomic(&dir, "manifest.json", &manifest_bytes)?;
    files.push("manifest.json".into());

    Ok(ExportOutcome { dir, files })
}
