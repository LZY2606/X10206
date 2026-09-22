use crate::store::{sha256_hex, timestamp, Store};
use serde_json::json;
use std::fs;

pub fn export_object(store: &Store, object_id: &str, generation: Option<i64>) -> std::io::Result<String> {
    let objects = store.find_object(object_id, generation).map_err(|e| std::io::Error::other(e.to_string()))?;
    let object = objects.into_iter().next().ok_or_else(|| std::io::Error::other("object not found"))?;
    let stripes = store.list_stripes(object.pk).map_err(|e| std::io::Error::other(e.to_string()))?;
    if stripes.is_empty() || stripes.iter().any(|stripe| stripe.status != "committed") {
        return Err(std::io::Error::other("object has uncommitted stripes"));
    }
    let mut payload = Vec::new();
    let mut stripe_reports = Vec::new();
    for stripe in &stripes {
        if !store.verify_committed_stripe(&object.object_id, object.generation, stripe.index, &stripe.expected_digest) {
            return Err(std::io::Error::other("committed stripe digest is incomplete"));
        }
        let bytes = store.committed_bytes(&object, stripe.index)?;
        if sha256_hex(&bytes) != stripe.expected_digest {
            return Err(std::io::Error::other("recomputed stripe digest mismatch"));
        }
        payload.extend_from_slice(&bytes);
        stripe_reports.push(json!({
            "stripe": stripe.index,
            "data_len": stripe.data_len,
            "sha256": stripe.expected_digest
        }));
    }
    payload.truncate(object.object_size);
    let object_digest = sha256_hex(&payload);
    if object_digest != object.object_sha256 {
        return Err(std::io::Error::other(format!("object digest mismatch: recomputed {object_digest}")));
    }
    let export_id = timestamp();
    let dir_name = format!("{}-g{}-{}", object.object_id, object.generation, export_id);
    let export_dir = store.data_dir.join("exports").join(dir_name);
    fs::create_dir_all(&export_dir)?;
    let object_tmp = export_dir.join(format!("{}.part", object.object_id));
    let manifest_tmp = export_dir.join("MANIFEST.json.part");
    fs::write(&object_tmp, &payload)?;
    let report = json!({
        "schema": "stripes-recovery-pod-export/v1",
        "object_id": object.object_id,
        "generation": object.generation,
        "object_size": object.object_size,
        "object_sha256": object_digest,
        "coding": {
            "data_shards": object.data_shards,
            "parity_shards": object.parity_shards,
            "stripe_size": object.stripe_size
        },
        "stripes": stripe_reports,
        "original_fragments_modified": false
    });
    fs::write(&manifest_tmp, serde_json::to_vec_pretty(&report).unwrap())?;
    fs::rename(&object_tmp, export_dir.join(format!("{}.bin", object.object_id)))?;
    let manifest_path = export_dir.join("MANIFEST.json");
    fs::rename(&manifest_tmp, &manifest_path)?;
    let link_tmp = store.data_dir.join("exports").join(format!("CURRENT.tmp.{export_id}"));
    let link_final = store.data_dir.join("exports").join("CURRENT");
    if link_final.exists() || link_final.is_symlink() {
        fs::remove_file(&link_final)?;
    }
    std::os::unix::fs::symlink(&export_dir, &link_tmp)?;
    fs::rename(&link_tmp, &link_final)?;
    {
        let mut conn = store.conn.lock().unwrap();
        conn.execute("INSERT INTO exports(object_pk, directory, manifest_path, created_at) VALUES(?1,?2,?3,?4)", rusqlite::params![object.pk, export_dir.to_string_lossy(), manifest_path.to_string_lossy(), export_id]).ok();
    }
    Ok(export_dir.to_string_lossy().to_string())
}
