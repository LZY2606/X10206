use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::model::Manifest;
use crate::store::{Storage, digest_hex, digest_hex_path, kind_name};

pub fn export_object(storage: &Storage, manifest: &Manifest) -> std::io::Result<PathBuf> {
    let mut missing = Vec::new();
    for stripe in 0..manifest.stripe_count {
        let shards = storage.committed_shards(&manifest.object_id, stripe)?;
        if shards.len() != manifest.data_shards + manifest.parity_shards {
            missing.push(stripe.to_string());
        }
    }
    if !missing.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("refusing partial export; uncommitted stripes: {}", missing.join(", ")),
        ));
    }

    let export_root = storage.root().join("exports");
    std::fs::create_dir_all(&export_root)?;
    let name = format!(
        "{}-{}",
        sanitize(&manifest.object_id),
        chrono_like_timestamp()
    );
    let target_dir = export_root.join(&name);
    std::fs::create_dir_all(&target_dir)?;

    let mut object_bytes = Vec::new();
    let mut export_manifest = manifest.clone();
    export_manifest.shards.clear();

    for stripe in 0..manifest.stripe_count {
        let committed = storage.committed_shards(&manifest.object_id, stripe)?;
        let stripe_dir = target_dir.join(format!("stripe-{stripe}"));
        std::fs::create_dir_all(&stripe_dir)?;

        let mut by_kind: BTreeMap<_, Vec<_>> = BTreeMap::new();
        for shard in committed {
            let bytes = std::fs::read(&shard.path)?;
            if digest_hex(&bytes) != shard.digest {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("committed shard digest failed for stripe {stripe}"),
                ));
            }
            let filename = format!("{}.bin", shard.path.file_name().unwrap().to_string_lossy());
            std::fs::write(stripe_dir.join(&filename), &bytes)?;
            if shard.kind == crate::model::StoredShardKind::Data {
                object_bytes.extend(bytes);
            }
            by_kind.entry(shard.kind).or_default().push((shard, digest_hex(&bytes), filename));
        }

        for (kind, entries) in by_kind {
            for (shard, digest, _) in entries {
                export_manifest.shards.push(crate::model::ManifestShard {
                    stripe,
                    kind,
                    index: shard.index,
                    generation: Some(shard.generation),
                    length: Some(manifest.shard_size),
                    digest: Some(digest),
                });
            }
        }
    }

    export_manifest.object_digest = Some(digest_hex(&object_bytes));
    let temporary_manifest = target_dir.join("manifest.json.tmp");
    let final_manifest = target_dir.join("manifest.json");
    let json = serde_json::to_vec_pretty(&export_manifest)?;
    let mut file = std::fs::File::create(&temporary_manifest)?;
    std::io::Write::write_all(&mut file, &json)?;
    file.sync_all()?;
    std::fs::rename(&temporary_manifest, &final_manifest)?;

    let switch = export_root.join(format!("{}.latest", sanitize(&manifest.object_id)));
    let switch_tmp = export_root.join(format!("{}.latest.tmp", sanitize(&manifest.object_id)));
    std::fs::write(&switch_tmp, target_dir.to_string_lossy().as_bytes())?;
    std::fs::rename(&switch_tmp, &switch)?;
    Ok(target_dir)
}

fn sanitize(value: &str) -> String {
    value.chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '-' | '_') { c } else { '_' }).collect()
}

fn chrono_like_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let millis = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
    format!("{millis:016}")
}
