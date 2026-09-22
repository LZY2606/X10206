//! 导出：每次写入全新的时间戳目录，manifest 先落临时文件再原子 rename，
//! 原始碎片目录（sources 导入路径）完全不改动。

use std::fs;
use std::path::{Path, PathBuf};

use crate::db::Storage;
use crate::hashutil::sha256_hex;
use crate::recovery::OutputSink;
use serde::Serialize;

#[derive(Debug, Serialize)]
struct ExportManifest {
    exported_at_ms: i64,
    object_id: String,
    coding_version: String,
    object_digest_declared: Option<String>,
    object_digest_recomputed: String,
    status: String,
    declared_len: Option<i64>,
    stripes: Vec<ExportStripe>,
}

#[derive(Debug, Serialize)]
struct ExportStripe {
    stripe_idx: i64,
    tier: String,
    generation: i64,
    participants: Vec<i64>,
    excluded_corrupt_evidence: Vec<i64>,
    digest_recomputed: String,
    output_len: i64,
}

pub fn export_object(
    storage: &mut Storage,
    sink: &dyn OutputSink,
    data_root: &Path,
    object_db_id: i64,
) -> std::io::Result<PathBuf> {
    let object = storage
        .get_object(object_db_id)
        .map_err(ioerr)?
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "object missing"))?;
    if object.status != "trusted" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("对象状态为 {}，仅 trusted 对象允许导出", object.status),
        ));
    }
    let params = crate::types::lookup_params(&object.coding_version)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "unknown coding"))?;

    let export_root = data_root.join("exports");
    fs::create_dir_all(&export_root)?;
    let stamp = crate::db::now_ms();
    let dir = export_root.join(format!("export-{}-{stamp}", object.object_id));
    // 新目录：若撞名（同一毫秒），加序号，绝不覆盖。
    let dir = unique_dir(&dir);
    let data_dir = dir.join("data");
    fs::create_dir_all(&data_dir)?;

    let stripes = storage.list_stripes(object_db_id).map_err(ioerr)?;
    let mut manifest_stripes = Vec::new();
    let mut blocks: Vec<Vec<u8>> = Vec::new();

    for s in &stripes {
        let output = storage
            .committed_solution_output(s.id)
            .map_err(ioerr)?
            .ok_or_else(|| std::io::Error::other("committed stripe missing output"))?;
        let sol_rows = storage.list_solutions(s.id).map_err(ioerr)?;
        let committed_sol = sol_rows
            .iter()
            .find(|sol| sol.output_digest == s.output_digest.clone().unwrap_or_default())
            .ok_or_else(|| std::io::Error::other("committed solution row missing"))?;
        let participants: Vec<i64> =
            serde_json::from_str(&committed_sol.chosen_subset).unwrap_or_default();
        let evidence = storage.evidence_for_stripe(s.id).map_err(ioerr)?;
        let excluded: Vec<i64> = evidence
            .iter()
            .filter(|e| e.kind == "coding_inconsistent")
            .filter_map(|e| e.fragment_id)
            .collect();

        let stripe_dir = data_dir.join(format!("s{}", s.stripe_idx));
        fs::create_dir_all(&stripe_dir)?;
        for shard in 0..output.len() / params.stripe_bytes {
            let chunk =
                output[shard * params.stripe_bytes..(shard + 1) * params.stripe_bytes].to_vec();
            let rel = format!("{}/s{}/d{}.bin", object.object_id, s.stripe_idx, shard);
            let bytes = sink.read(&rel)?;
            if sha256_hex(&bytes) != sha256_hex(&chunk) {
                return Err(std::io::Error::other("export read-back digest mismatch"));
            }
            fs::write(stripe_dir.join(format!("d{shard}.bin")), &chunk)?;
            blocks.push(chunk);
        }

        manifest_stripes.push(ExportStripe {
            stripe_idx: s.stripe_idx,
            tier: committed_sol.tier.clone(),
            generation: committed_sol.generation,
            participants,
            excluded_corrupt_evidence: excluded,
            digest_recomputed: committed_sol.output_digest.clone(),
            output_len: output.len() as i64,
        });
    }

    let total_len = object.declared_len.map(|v| v as usize);
    let object_digest_recomputed = crate::hashutil::sha256_concat(&blocks, total_len);

    let manifest = ExportManifest {
        exported_at_ms: stamp,
        object_id: object.object_id.clone(),
        coding_version: object.coding_version.clone(),
        object_digest_declared: object.object_digest.clone(),
        object_digest_recomputed: object_digest_recomputed.clone(),
        status: object.status.clone(),
        declared_len: object.declared_len,
        stripes: manifest_stripes,
    };
    let json = serde_json::to_string_pretty(&manifest).map_err(|e| std::io::Error::other(e.to_string()))?;

    // 原子清单切换：manifest.json.tmp -> manifest.json。
    let manifest_tmp = dir.join("manifest.json.tmp");
    let manifest_final = dir.join("manifest.json");
    fs::write(&manifest_tmp, json)?;
    fs::rename(&manifest_tmp, &manifest_final)?;

    Ok(dir)
}

fn unique_dir(base: &Path) -> PathBuf {
    if !base.exists() {
        return base.to_path_buf();
    }
    for i in 1..10_000 {
        let candidate = PathBuf::from(format!("{}-{i}", base.display()));
        if !candidate.exists() {
            return candidate;
        }
    }
    panic!("cannot allocate unique export dir");
}

fn ioerr(e: rusqlite::Error) -> std::io::Error {
    std::io::Error::other(e.to_string())
}
