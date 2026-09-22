use std::path::{Path, PathBuf};

use crate::model::{Manifest, ManifestShard, StoredShardKind};
use crate::store::{RawFragment, Storage, kind_name, parse_kind};

#[derive(Debug, Clone)]
pub struct ImportedObject {
    pub object_id: String,
    pub fragment_count: usize,
}

pub fn read_manifest(path: impl AsRef<Path>) -> std::io::Result<Manifest> {
    let bytes = std::fs::read(path)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

pub fn import_directory(storage: &Storage, dir: impl AsRef<Path>, source_prefix: &str) -> std::io::Result<Vec<ImportedObject>> {
    let dir = dir.as_ref();
    let manifest_paths: Vec<PathBuf> = if dir.is_file() {
        vec![dir.to_path_buf()]
    } else {
        let mut paths = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_file() && path.file_name().map_or(false, |name| name == "manifest.json") {
                paths.push(path);
            }
        }
        paths.sort();
        paths
    };

    let mut imported = Vec::new();
    for manifest_path in manifest_paths {
        let manifest = read_manifest(&manifest_path)?;
        crate::engine::validate_manifest(&manifest)
            .map_err(|message| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{}: {}", manifest_path.display(), message)))?;
        let base = manifest_path.parent().unwrap_or(Path::new("."));
        let mut fragment_count = 0;

        for shard in &manifest.shards {
            for source_file in resolve_shard_paths(base, shard)? {
                let bytes = std::fs::read(&source_file)?;
                let sidecar = sidecar_path(&source_file);
                let received_digest = if sidecar.exists() {
                    Some(normalize_hex(std::fs::read_to_string(sidecar)?))
                } else {
                    None
                };
                let source = format!(
                    "{}:{}",
                    source_prefix.trim_end_matches(':'),
                    source_file.file_name().unwrap().to_string_lossy()
                );
                storage.import_fragment(&RawFragment {
                    manifest: manifest.clone(),
                    stripe: shard.stripe,
                    kind: shard.kind,
                    index: shard.index,
                    generation: shard.generation.unwrap_or(manifest.generation),
                    declared_length: shard.length,
                    received_digest,
                    expected_digest: shard.digest.clone(),
                    source,
                    bytes,
                })?;
                fragment_count += 1;
            }
        }
        imported.push(ImportedObject {
            object_id: manifest.object_id,
            fragment_count,
        });
    }
    Ok(imported)
}

fn resolve_shard_paths(base: &Path, shard: &ManifestShard) -> std::io::Result<Vec<PathBuf>> {
    let exact = base
        .join(format!("stripe-{}", shard.stripe))
        .join(format!("{}.bin", shard_file_stem(shard)));
    if exact.exists() {
        return Ok(vec![exact]);
    }

    let mut matches = Vec::new();
    let stripe_dir = base.join(format!("stripe-{}", shard.stripe));
    if stripe_dir.exists() {
        let prefix = format!("{}.", shard_file_stem(shard));
        for entry in std::fs::read_dir(&stripe_dir)? {
            let path = entry?.path();
            if !path.is_file() || path.extension().and_then(|value| value.to_str()) != Some("bin") {
                continue;
            }
            if path.file_stem().and_then(|value| value.to_str()).map_or(false, |name| name.starts_with(&prefix)) {
                matches.push(path);
            }
        }
    }
    matches.sort();
    if matches.is_empty() {
        return Ok(Vec::new());
    }
    Ok(matches)
}

fn shard_file_stem(shard: &ManifestShard) -> String {
    format!(
        "{}_i{:04}_g{:020}",
        kind_name(shard.kind),
        shard.index,
        shard.generation.unwrap_or(1)
    )
}

fn sidecar_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap().to_os_string();
    name.push(".digest");
    path.with_file_name(name)
}

fn normalize_hex(value: String) -> String {
    value.trim().to_ascii_lowercase()
}

pub fn parse_shard_kind(value: StoredShardKind) -> &'static str {
    kind_name(value)
}

pub fn shard_kind_from_name(value: &str) -> StoredShardKind {
    parse_kind(value)
}
