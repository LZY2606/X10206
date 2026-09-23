//! 导出：把对象的所有 stripe 重组为新目录，原 inbox 碎片不改动。
//!
//! 原子切换：先写 `tmp-<export_id>/`（含数据块、校验块与 MANIFEST.json），
//! 全部摘要校验通过后改名为正式目录，再把 `LATEST` 指针原子指向它。

use serde::Serialize;

use crate::model::object_digest_hex;
use crate::store::{Provenance, Store};

pub const EXPORT_MANIFEST_VERSION: &str = "stripe-bay/export/v1";

#[derive(Serialize)]
pub struct ExportShard {
    pub stripe: usize,
    pub slot: usize,
    pub file: String,
    pub digest: String,
    pub generation: i64,
}

#[derive(Serialize)]
pub struct ExportManifest {
    pub manifest_version: String,
    pub object_id: String,
    pub field_bits: u32,
    pub k: usize,
    pub m: usize,
    pub shard_size: usize,
    pub stripes: usize,
    pub object_digest: String,
    pub per_stripe: Vec<Vec<ExportShard>>,
    pub provenance: Vec<Provenance>,
}

#[derive(Debug)]
pub struct ExportReport {
    pub export_id: String,
    pub path: std::path::PathBuf,
    pub object_digest: String,
}

pub fn export_object(store: &Store, object_id: &str) -> std::io::Result<ExportReport> {
    let obj = store
        .get_object(object_id)?
        .ok_or_else(|| std::io::Error::other("未知对象"))?;
    let total = obj.stripes as usize;
    let mut provs: Vec<Provenance> = Vec::new();
    for stripe in 0..total {
        if store.committed_solution(obj.id, stripe)?.is_none() {
            return Err(std::io::Error::other(format!(
                "stripe {stripe} 尚未提交，拒绝导出"
            )));
        }
        // load_committed 会逐块核对摘要与长度。
        provs.push(store.load_committed(&obj, stripe)?);
    }

    let export_id = format!(
        "export-{}-{}",
        obj.object_id.replace('/', "_"),
        crate::store::store_run_ts()
    );
    let exports_root = store.root.join("exports");
    std::fs::create_dir_all(&exports_root)?;
    let tmp = exports_root.join(format!("tmp-{export_id}"));
    let final_dir = exports_root.join(&export_id);
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp)?;

    let mut grid: Vec<Vec<Vec<u8>>> = Vec::new();
    let mut per_stripe: Vec<Vec<ExportShard>> = Vec::new();
    for (stripe, prov) in provs.iter().enumerate() {
        let mut stripe_grid = vec![Vec::new(); obj.k as usize + obj.m as usize];
        let mut rows = Vec::new();
        for sh in &prov.shards {
            let data = std::fs::read(store.committed_dir(&obj.object_id, stripe).join(&sh.file))?;
            // 导出前再核一次。
            if crate::model::sha256_hex(&data) != sh.digest {
                return Err(std::io::Error::other("已提交块摘要在导出时不符"));
            }
            let fname = format!("stripe-{stripe:04}-slot-{:03}.bin", sh.slot);
            store.atomic_write(&tmp.join(&fname), &data)?;
            stripe_grid[sh.slot] = data;
            rows.push(ExportShard {
                stripe,
                slot: sh.slot,
                file: fname,
                digest: sh.digest.clone(),
                generation: prov.generation,
            });
        }
        grid.push(stripe_grid);
        per_stripe.push(rows);
    }
    let object_digest = object_digest_hex(&grid);
    if let Some(expected) = &obj.object_digest {
        if !expected.eq_ignore_ascii_case(&object_digest) {
            return Err(std::io::Error::other(
                "导出对象摘要与 manifest 不符，拒绝切换清单",
            ));
        }
    }

    let manifest = ExportManifest {
        manifest_version: EXPORT_MANIFEST_VERSION.into(),
        object_id: obj.object_id.clone(),
        field_bits: obj.field_bits as u32,
        k: obj.k as usize,
        m: obj.m as usize,
        shard_size: obj.shard_size as usize,
        stripes: total,
        object_digest: object_digest.clone(),
        per_stripe,
        provenance: provs,
    };
    let json = serde_json::to_vec_pretty(&manifest).unwrap();
    store.atomic_write(&tmp.join("MANIFEST.json"), &json)?;
    store.atomic_write(&tmp.join("MANIFEST.commit.json"), &json)?;

    std::fs::rename(&tmp, &final_dir)?;
    // 原子指针切换。
    let pointer = exports_root.join(format!("{}.LATEST.part", obj.object_id));
    std::fs::write(&pointer, &export_id)?;
    std::fs::rename(
        &pointer,
        exports_root.join(format!("{}.LATEST", obj.object_id)),
    )?;
    Ok(ExportReport { export_id, path: final_dir, object_digest })
}
