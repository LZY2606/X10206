//! Export: writes the recovered object into a fresh directory and switches
//! the manifest in atomically. Original fragments are never modified.

use crate::model::*;
use crate::recover;
use crate::store::Store;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, serde::Serialize)]
pub struct ExportManifest {
    pub object_id: String,
    pub object_length: usize,
    pub object_digest: String,
    pub solution_rank: usize,
    pub stripes: usize,
    pub participants: Vec<Participant>,
    pub excluded: Vec<ExcludedEvidence>,
    pub exported_at: String,
}

/// Export one solution of an object into `dest_root/<object_id>/`.
/// The manifest is written to a temp file and atomically renamed into place.
pub fn export_object(
    store: &Store,
    object_id: &str,
    solution_rank: usize,
    dest_root: &Path,
) -> Result<PathBuf, String> {
    let m = store
        .get_manifest(object_id)
        .map_err(|e| e.to_string())?
        .ok_or("对象不存在")?;
    let stripes = store
        .stripe_states(object_id, m.stripe_count())
        .map_err(|e| e.to_string())?;
    let (solutions, _) = recover::assemble_solutions(&m, &stripes, 4096);
    let solution = solutions
        .iter()
        .find(|s| s.rank == solution_rank)
        .ok_or_else(|| format!("没有 rank={} 的可行解", solution_rank))?;
    let bytes = recover::object_bytes(&m, &stripes, solution)?;

    let out_dir = dest_root.join(object_id);
    let tmp_dir = dest_root.join(format!(".{}.tmp", object_id));
    if tmp_dir.exists() {
        std::fs::remove_dir_all(&tmp_dir).map_err(|e| e.to_string())?;
    }
    std::fs::create_dir_all(&tmp_dir).map_err(|e| format!("创建导出目录失败: {}", e))?;

    let result = (|| -> Result<PathBuf, String> {
        std::fs::write(tmp_dir.join("data"), &bytes).map_err(|e| format!("写入数据失败: {}", e))?;
        let mut participants = Vec::new();
        let mut excluded = Vec::new();
        for (no, alt) in &solution.picks {
            let st = stripes.iter().find(|s| s.stripe_no == *no).unwrap();
            let a = &st.alternatives[*alt];
            participants.extend(a.participants.iter().cloned());
            excluded.extend(a.excluded.iter().cloned());
        }
        let manifest = ExportManifest {
            object_id: object_id.to_string(),
            object_length: bytes.len(),
            object_digest: sha256_hex(&bytes),
            solution_rank,
            stripes: stripes.len(),
            participants,
            excluded,
            exported_at: chrono_now(),
        };
        let json = serde_json::to_string_pretty(&manifest).unwrap();
        let tmp_manifest = tmp_dir.join("manifest.json.tmp");
        std::fs::write(&tmp_manifest, json).map_err(|e| format!("写入清单失败: {}", e))?;
        // Atomic manifest switch inside the new directory.
        std::fs::rename(&tmp_manifest, tmp_dir.join("manifest.json"))
            .map_err(|e| format!("清单原子切换失败: {}", e))?;
        // Atomic directory switch: build new dir, then swap.
        if out_dir.exists() {
            std::fs::remove_dir_all(&out_dir).map_err(|e| e.to_string())?;
        }
        std::fs::rename(&tmp_dir, &out_dir).map_err(|e| format!("目录切换失败: {}", e))?;
        Ok(out_dir)
    })();
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
    result
}

fn chrono_now() -> String {
    // Avoid a chrono dependency; epoch seconds are enough for an audit trail.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{}s since epoch", secs)
}
