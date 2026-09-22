use crate::model::{ManifestFile, ManifestShard};
use crate::store::{sha256_hex, Store};
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Default)]
pub struct IngestReport {
    pub sources_scanned: usize,
    pub manifests_accepted: usize,
    pub manifests_rejected: usize,
    pub fragments_received: usize,
    pub fragments_healthy: usize,
    pub fragments_generation_mixed: usize,
    pub fragments_excluded: usize,
    pub messages: Vec<String>,
}

pub fn ingest_inbox(store: &Store) -> std::io::Result<IngestReport> {
    let inbox = store.data_dir.join("inbox");
    let mut report = IngestReport::default();
    if !inbox.exists() {
        return Ok(report);
    }
    let mut sources: Vec<PathBuf> = fs::read_dir(&inbox)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    sources.sort();
    for source_dir in sources {
        report.sources_scanned += 1;
        let received_from = source_dir.file_name().and_then(|name| name.to_str()).unwrap_or("unknown").to_string();
        ingest_source(store, &source_dir, &received_from, &mut report)?;
    }
    Ok(report)
}

fn ingest_source(store: &Store, source_dir: &Path, received_from: &str, report: &mut IngestReport) -> std::io::Result<()> {
    let mut manifest_files: Vec<PathBuf> = Vec::new();
    let mut shard_files: Vec<PathBuf> = Vec::new();
    for entry in walkdir(source_dir)? {
        if !entry.is_file() {
            continue;
        }
        let name = entry.file_name().map(|name| name.to_string_lossy().to_string()).unwrap_or_default();
        if name.ends_with(".manifest.json") {
            manifest_files.push(entry);
        } else if is_shard_name(&name) {
            shard_files.push(entry);
        }
    }
    manifest_files.sort();
    shard_files.sort();

    let mut manifests = Vec::new();
    for manifest_path in manifest_files {
        let bytes = fs::read(&manifest_path)?;
        let relative = manifest_path.strip_prefix(&store.data_dir).unwrap_or(&manifest_path).to_string_lossy().to_string();
        let raw_path = store.raw_path("__manifest__", 0, received_from, &manifest_path.file_name().unwrap().to_string_lossy());
        store.copy_raw_atomic(&manifest_path, &raw_path)?;
        match parse_and_validate_manifest(&bytes) {
            Ok(manifest) => {
                let object_id = manifest.object_id.clone();
                let generation = manifest.generation;
                let digest = manifest.object_sha256.clone();
                store.upsert_object(&manifest, received_from, &relative).map_err(io_err)?;
                let pk = store.object_pk(&object_id, generation, &digest).map_err(io_err)?.expect("object inserted");
                manifests.push((manifest, pk));
                report.manifests_accepted += 1;
            }
            Err(message) => {
                report.manifests_rejected += 1;
                report.messages.push(format!("{received_from}/{}: {message}", manifest_path.display()));
            }
        }
    }

    for shard_path in shard_files {
        if let Some(message) = ingest_shard(store, shard_path, source_dir, received_from, &manifests, report)? {
            report.messages.push(message);
        }
    }
    Ok(())
}

fn ingest_shard(
    store: &Store,
    shard_path: PathBuf,
    source_dir: &Path,
    received_from: &str,
    manifests: &[(ManifestFile, i64)],
    report: &mut IngestReport,
) -> std::io::Result<Option<String>> {
    let name = shard_path.file_name().unwrap().to_string_lossy().to_string();
    let Some(parsed) = parse_shard_name(&name) else {
        return Ok(Some(format!("{received_from}/{name}: unrecognized shard file name")));
    };
    let bytes = fs::read(&shard_path)?;
    let actual = sha256_hex(&bytes);
    let claimed = read_sidecar(&shard_path, &actual);
    let rel = shard_path.strip_prefix(source_dir).unwrap_or(&shard_path).to_string_lossy().to_string();
    let raw_target = store.raw_path(&parsed.object_id, parsed.generation, received_from, &name);
    store.copy_raw_atomic(&shard_path, &raw_target)?;
    if let Some((side_path, claimed_digest)) = &claimed {
        let side_target = store.raw_path(&parsed.object_id, parsed.generation, received_from, &side_path.file_name().unwrap().to_string_lossy());
        store.copy_raw_atomic(side_path, &side_target)?;
        let _ = claimed_digest;
    }
    report.fragments_received += 1;

    let candidates: Vec<&(ManifestFile, i64)> = manifests
        .iter()
        .filter(|(manifest, _)| manifest.object_id == parsed.object_id)
        .collect();
    if candidates.is_empty() {
        return Ok(Some(format!("{received_from}/{name}: no accepted manifest for object")));
    }

    for (manifest, object_pk) in candidates {
        let Some(stripe) = manifest.stripes.iter().find(|stripe| stripe.index == parsed.stripe) else {
            continue;
        };
        let specs: Vec<&ManifestShard> = stripe.shards.iter().filter(|shard| shard.index == parsed.shard).collect();
        if specs.len() > 1 {
            return Ok(Some(format!("{received_from}/{name}: manifest repeats shard index {}", parsed.shard)));
        }
        let Some(spec) = specs.first().copied() else {
            store.upsert_fragment(*object_pk, parsed.stripe, Some(parsed.shard), Some(parsed.generation), received_from, &rel, raw_target.to_string_lossy().as_ref(), bytes.len() as i64, &actual, claimed.as_ref().map(|(_, digest)| digest.as_str()), None, "excluded", "shard index not present in manifest version").map_err(io_err)?;
            report.fragments_excluded += 1;
            continue;
        };
        let sidecar_ok = match &claimed {
            None => false,
            Some((_, digest)) => digest == &actual,
        };
        let expected_match = actual == spec.sha256;
        let length_match = bytes.len() == spec.length;
        let manifest_generation_match = parsed.generation == spec.generation;
        let (health, evidence) = if !sidecar_ok {
            ("excluded", "sidecar missing or digest does not match received bytes")
        } else if !length_match {
            ("excluded", "received byte length differs from manifest")
        } else if !expected_match {
            ("corrupt", "sidecar is internally complete, but digest differs from manifest expectation")
        } else if manifest_generation_match {
            ("healthy", "digest, length, and generation match manifest")
        } else if parsed.generation == manifest.generation {
            ("generation_mixed_eligible", "content matches current object generation, but shard header carries another generation")
        } else {
            ("corrupt", "content matches shard digest but header belongs to an unrelated generation")
        };
        if health == "healthy" {
            report.fragments_healthy += 1;
        } else if health == "generation_mixed_eligible" {
            report.fragments_generation_mixed += 1;
        } else {
            report.fragments_excluded += 1;
        }
        store.upsert_fragment(
            *object_pk,
            parsed.stripe,
            Some(parsed.shard),
            Some(parsed.generation),
            received_from,
            &rel,
            raw_target.to_string_lossy().as_ref(),
            bytes.len() as i64,
            &actual,
            Some(&spec.sha256),
            Some(&spec.sha256),
            health,
            evidence,
        ).map_err(io_err)?;
    }
    Ok(None)
}

#[derive(Debug)]
struct ShardFileName {
    object_id: String,
    generation: i64,
    stripe: usize,
    shard: usize,
}

fn is_shard_name(name: &str) -> bool {
    parse_shard_name(name).is_some()
}

fn parse_shard_name(name: &str) -> Option<ShardFileName> {
    let body = name.strip_suffix(".bin")?;
    let mut parts = body.split('-');
    if parts.next()? != "shard" {
        return None;
    }
    let object_id = parts.next()?.to_string();
    let generation = parts.next()?.parse().ok()?;
    let stripe = parts.next()?.parse().ok()?;
    let shard = parts.next()?.parse().ok()?;
    if parts.next().is_some() || object_id.is_empty() {
        return None;
    }
    Some(ShardFileName { object_id, generation, stripe, shard })
}

fn read_sidecar(shard_path: &Path, actual: &str) -> Option<(PathBuf, String)> {
    let side = PathBuf::from(format!("{}.sha256", shard_path.display()));
    let text = fs::read_to_string(&side).ok()?;
    let claimed = text.split_whitespace().next()?.to_string();
    if claimed.len() == 64 && claimed.chars().all(|c| c.is_ascii_hexdigit()) && claimed == actual {
        Some((side, claimed))
    } else {
        Some((side, claimed))
    }
}

fn parse_and_validate_manifest(bytes: &[u8]) -> serde_json::Result<ManifestFile> {
    let manifest: ManifestFile = serde_json::from_slice(bytes)?;
    if manifest.schema != "stripes-recovery-pod/v1" {
        return Err(serde::de::Error::custom("unsupported schema"));
    }
    if manifest.data_shards == 0 || manifest.parity_shards == 0 || manifest.stripe_size == 0 {
        return Err(serde::de::Error::custom("coding parameters must be non-zero"));
    }
    if manifest.data_shards + manifest.parity_shards > 255 {
        return Err(serde::de::Error::custom("too many shards for GF(256)"));
    }
    let mut stripe_indices = HashSet::new();
    for stripe in &manifest.stripes {
        if !stripe_indices.insert(stripe.index) {
            return Err(serde::de::Error::custom("duplicate stripe index"));
        }
        if stripe.data_len > manifest.stripe_size * manifest.data_shards || stripe.sha256.len() != 64 {
            return Err(serde::de::Error::custom("invalid stripe length or digest"));
        }
        let mut shard_indices = HashSet::new();
        for shard in &stripe.shards {
            if !shard_indices.insert(shard.index) || shard.index >= manifest.data_shards + manifest.parity_shards {
                return Err(serde::de::Error::custom("duplicate or out-of-range shard index"));
            }
            if shard.length != manifest.stripe_size || shard.sha256.len() != 64 {
                return Err(serde::de::Error::custom("manifest and actual shard length specification disagree"));
            }
        }
        if shard_indices.len() != manifest.data_shards + manifest.parity_shards {
            return Err(serde::de::Error::custom("manifest does not list every shard number"));
        }
    }
    let _ = BTreeMap::<(), ()>::new();
    Ok(manifest)
}

fn walkdir(root: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut results = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                stack.push(path);
            } else {
                results.push(path);
            }
        }
    }
    results.sort();
    Ok(results)
}

fn io_err(error: rusqlite::Error) -> std::io::Error {
    std::io::Error::other(error.to_string())
}
