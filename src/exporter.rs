//! 导出恢复结果到全新目录：对象字节 + 逐 stripe/shard 重建块 + 参与计算说明，
//! 最后原子切换 manifest.ready；不改动任何原始碎片。

use crate::model::*;
use crate::recovery::load_manifest;
use crate::store::Store;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{}", secs)
}

pub struct ExportResult {
    pub export_id: String,
    pub dir: PathBuf,
    pub outcome_id: String,
}

pub fn export_outcome(
    store: &Store,
    object_id: &str,
    outcome_id: Option<&str>,
) -> Result<ExportResult, String> {
    let manifest = load_manifest(store, object_id)?;
    let rows = store.list_outcomes(object_id)?;
    if rows.is_empty() {
        return Err("对象尚未成功恢复，无可导出结果".into());
    }
    let mut metas: Vec<serde_json::Value> = rows
        .iter()
        .map(|j| serde_json::from_str(j).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    let chosen_index = match outcome_id {
        Some(id) => metas
            .iter()
            .position(|m| m["outcome_id"] == id)
            .ok_or_else(|| format!("结果 {id} 不存在"))?,
        None => 0,
    };
    let meta = metas[chosen_index].clone();
    let chosen_id = meta["outcome_id"].as_str().unwrap().to_string();
    let stripe_solutions: Vec<String> =
        serde_json::from_value(meta["stripe_solutions"].clone()).map_err(|e| e.to_string())?;

    let export_id = format!("export_{}_{}", now(), &chosen_id[..8]);
    let rel_dir = format!("exports/{}", export_id);
    let dir = store.exports_dir().join(&export_id);
    let staging = store.exports_dir().join(format!(".staging-{}", export_id));
    if staging.exists() {
        std::fs::remove_dir_all(&staging).map_err(|e| e.to_string())?;
    }
    std::fs::create_dir_all(staging.join("stripes")).map_err(|e| e.to_string())?;

    // 只从已提交的最终块读取；若任何块缺失则拒绝导出。
    let mut object_bytes: Vec<u8> = Vec::new();
    let mut stripe_manifests = Vec::new();
    for (s, sid) in stripe_solutions.iter().enumerate() {
        let (_, analysis_json) = store
            .get_stripe_commit(object_id, s)
            .ok_or_else(|| format!("stripe {s} 尚未提交，禁止导出"))?;
        let analysis: StripeAnalysis =
            serde_json::from_str(&analysis_json).map_err(|e| e.to_string())?;
        let sol = analysis
            .solutions
            .iter()
            .find(|x| &x.solution_id == sid)
            .ok_or_else(|| format!("stripe {s} 的已提交解 {sid} 不在最新分析中"))?;

        let sdir = staging.join("stripes").join(format!("stripe-{:04}", s));
        std::fs::create_dir_all(&sdir).map_err(|e| e.to_string())?;
        for (sh, digest) in sol.recomputed_shard_digests.iter().enumerate() {
            if !store.block_exists(digest) {
                return Err(format!("stripe {s} shard {sh} 最终块缺失（禁止读取临时块）"));
            }
            let bytes = store.read_block(digest)?;
            if sha256_hex(&bytes) != *digest {
                return Err(format!("stripe {s} shard {sh} 最终块摘要损坏"));
            }
            let fname = format!("shard-{:02}.bin", sh);
            store.write_export_file(&sdir.join(&fname), &bytes)?;
            if sh < manifest.k {
                object_bytes.extend_from_slice(&bytes);
            }
        }

        let provenance = serde_json::json!({
            "stripe": s,
            "solution_id": sid,
            "participants": sol.participants,
            "excluded": sol.excluded,
            "generations": sol.generations,
            "mixed_generation": sol.mixed_generation,
            "recomputed_shard_digests": sol.recomputed_shard_digests,
            "equivalent_combos": sol.equivalent_combos,
            "health": analysis.health,
            "global_excluded": analysis.global_excluded,
        });
        store.write_export_file(
            &sdir.join("provenance.json"),
            serde_json::to_vec_pretty(&provenance).unwrap().as_slice(),
        )?;
        stripe_manifests.push(serde_json::json!({
            "stripe": s,
            "solution_id": sid,
            "digests": sol.recomputed_shard_digests,
        }));
    }

    if let Some(limit) = manifest.object_length {
        object_bytes.truncate(limit);
    }
    let object_digest = sha256_hex(&object_bytes);
    if object_digest != chosen_id {
        return Err(format!(
            "导出对象摘要 {object_digest} 与结果 id {chosen_id} 不一致"
        ));
    }
    store.write_export_file(&staging.join("object.bin"), &object_bytes)?;

    // 多结果差异说明。
    metas.sort_by_key(|m| m["outcome_id"].as_str().unwrap_or("").to_string());
    let ready_manifest = serde_json::json!({
        "export_id": export_id,
        "object_id": object_id,
        "manifest": manifest,
        "outcome_id": chosen_id,
        "object_digest": object_digest,
        "object_length": object_bytes.len(),
        "digest_matches_manifest": meta["digest_matches_manifest"],
        "generations": meta["generations"],
        "mixed_generation": meta["mixed_generation"],
        "stripes": stripe_manifests,
        "all_outcomes": metas,
    });
    let ready_bytes = serde_json::to_vec_pretty(&ready_manifest).unwrap();
    // 先写临时清单，再原子改名为 manifest.json（清单切换）。
    let tmp_manifest = staging.join("manifest.json.tmp");
    store.write_export_file(&tmp_manifest, &ready_bytes)?;
    let final_manifest = staging.join("manifest.json");
    std::fs::rename(&tmp_manifest, &final_manifest).map_err(|e| e.to_string())?;

    // staging -> 正式新目录（同文件系统 rename，原子）。
    if dir.exists() {
        std::fs::remove_dir_all(&dir).map_err(|e| e.to_string())?;
    }
    store.export_rename(&staging, &dir)?;
    store.record_export(&export_id, object_id, &chosen_id, &rel_dir, "ready", &now())?;

    let _ = metas;
    Ok(ExportResult {
        export_id,
        dir,
        outcome_id: chosen_id,
    })
}
