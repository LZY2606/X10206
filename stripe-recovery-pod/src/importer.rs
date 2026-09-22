//! Import pod: reads `incoming/<source>/` delivery bundles, stores untouched
//! fragment bytes under `fragments/` and records provenance + evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::db::{FragmentRow, ObjectRow, Store};
use crate::model::{
    parse_shard_filename, parse_sidecar, sha256_hex, EvidenceKind, IncomingShard, Manifest,
};

/// Result of importing one delivery source directory.
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct ImportReport {
    pub source: String,
    pub manifests: usize,
    pub shards: usize,
    pub evidence: usize,
    pub warnings: Vec<String>,
}

pub fn scan_and_import_all(store: &Store) -> anyhow::Result<Vec<ImportReport>> {
    let mut reports = Vec::new();
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&store.paths.incoming)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    entries.sort();
    for dir in entries {
        reports.push(import_source(store, &dir)?);
    }
    Ok(reports)
}

pub fn import_source(store: &Store, source_dir: &Path) -> anyhow::Result<ImportReport> {
    let source = source_dir
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".into());
    store.upsert_source(&source)?;
    let mut report = ImportReport { source: source.clone(), ..Default::default() };

    let mut files: Vec<PathBuf> = std::fs::read_dir(source_dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    files.sort();

    // First pass: manifests (they define the authoritative parameters per object).
    let mut manifests: BTreeMap<String, Manifest> = BTreeMap::new();
    for path in &files {
        if path.file_name().and_then(|n| n.to_str()) == Some("manifest.json") {
            match import_manifest(store, &source, path, &mut report) {
                Ok(m) => {
                    manifests.insert(m.object_id.clone(), m);
                    report.manifests += 1;
                }
                Err(e) => report.warnings.push(format!("manifest.json: {e}")),
            }
        }
    }

    // Second pass: shards + sidecars.
    let mut sidecars: BTreeMap<String, String> = BTreeMap::new();
    let mut shard_files: Vec<PathBuf> = Vec::new();
    for path in &files {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_string();
        if let Some(base) = name.strip_suffix(".sha256") {
            match std::fs::read_to_string(path) {
                Ok(text) => {
                    if let Some(sc) = parse_sidecar(&text) {
                        sidecars.insert(base.to_string(), sc.digest_hex);
                    } else {
                        report.warnings.push(format!("{name}: unparsable digest sidecar"));
                    }
                }
                Err(e) => report.warnings.push(format!("{name}: {e}")),
            }
        } else if name.ends_with(".bin") {
            shard_files.push(path.clone());
        }
    }

    for path in &shard_files {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_string();
        let parsed = parse_shard_filename(&name);
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                report.warnings.push(format!("{name}: {e}"));
                continue;
            }
        };
        let (stripe, shard_index, file_gen) = match parsed {
            Some(v) => v,
            None => {
                report.warnings.push(format!("{name}: filename does not match sS_iI_gG.bin"));
                continue;
            }
        };

        // A shard without a discoverable object cannot be anchored; record and skip.
        if manifests.is_empty() {
            store.add_evidence(
                "unanchored",
                Some(stripe),
                Some(shard_index),
                None,
                Some(&source),
                EvidenceKind::ManifestConflict,
                &format!("{name}: no manifest.json present in this source"),
            )?;
            report.evidence += 1;
            continue;
        }
        for (object_id, manifest) in &manifests {
            import_shard(
                store,
                object_id,
                manifest,
                &source,
                IncomingShard {
                    stripe,
                    shard_index,
                    generation: file_gen,
                    bytes: bytes.clone(),
                    filename: name.clone(),
                    sidecar_digest_hex: sidecars.get(&name).cloned(),
                },
                &mut report,
            )?;
        }
    }
    Ok(report)
}

fn import_manifest(
    store: &Store,
    source: &str,
    path: &Path,
    report: &mut ImportReport,
) -> anyhow::Result<Manifest> {
    let manifest: Manifest = serde_json::from_slice(&std::fs::read(path)?)?;
    if manifest.scheme != crate::coding::CODING_SCHEME {
        anyhow::bail!("unknown scheme {}", manifest.scheme);
    }
    let params = crate::coding::CodingParams {
        version: manifest.version,
        k: manifest.data_shards,
        n: manifest.total_shards(),
        shard_len: manifest.shard_len,
    };
    if let Err(e) = params.validate() {
        anyhow::bail!("invalid parameters: {e}");
    }
    let row = ObjectRow {
        id: manifest.object_id.clone(),
        scheme: manifest.scheme.clone(),
        version: manifest.version,
        stripe_count: manifest.stripe_count,
        shard_len: manifest.shard_len,
        data_shards: manifest.data_shards,
        parity_shards: manifest.parity_shards,
        generation: manifest.generation,
        data_len: manifest.data_len,
        object_digest_hex: manifest.object_digest_hex.clone(),
        run_status: "new".into(),
        run_detail: String::new(),
        search_budget: 256,
        export_dir: None,
    };
    let existed = store.upsert_object(&row)?;
    if let Some(prior) = store.get_object(&row.id)? {
        if existed
            && (prior.version != row.version
                || prior.stripe_count != row.stripe_count
                || prior.shard_len != row.shard_len
                || prior.data_shards != row.data_shards
                || prior.parity_shards != row.parity_shards
                || prior.data_len != row.data_len
                || prior.object_digest_hex != row.object_digest_hex)
        {
            store.add_evidence(
                &row.id,
                None,
                None,
                None,
                Some(source),
                EvidenceKind::ManifestConflict,
                &format!(
                    "manifest from {source}: params/digest differ from first-seen \
                     (v{} {}/{} len={} digest {} vs v{} {}/{} len={} digest {})",
                    manifest.version,
                    manifest.data_shards,
                    manifest.parity_shards,
                    manifest.data_len,
                    &manifest.object_digest_hex[..8],
                    prior.version,
                    prior.data_shards,
                    prior.parity_shards,
                    prior.data_len,
                    &prior.object_digest_hex[..8],
                ),
            )?;
            report.evidence += 1;
        }
    }
    Ok(manifest)
}

#[allow(clippy::too_many_arguments)]
fn import_shard(
    store: &Store,
    object_id: &str,
    manifest: &Manifest,
    source: &str,
    sh: IncomingShard,
    report: &mut ImportReport,
) -> anyhow::Result<()> {
    let n = manifest.total_shards();
    let content_digest = sha256_hex(&sh.bytes);

    // Out-of-range shards are stored as evidence only and never enter candidates.
    if sh.stripe >= manifest.stripe_count || sh.shard_index >= n {
        store.add_evidence(
            object_id,
            Some(sh.stripe),
            Some(sh.shard_index),
            None,
            Some(source),
            EvidenceKind::OutOfRange,
            &format!(
                "{}: stripe/index outside manifest bounds (stripes={}, n={})",
                sh.filename, manifest.stripe_count, n
            ),
        )?;
        report.evidence += 1;
        return Ok(());
    }

    let mut problems: Vec<(EvidenceKind, String)> = Vec::new();

    if sh.bytes.len() != manifest.shard_len {
        problems.push((
            EvidenceKind::LengthMismatch,
            format!(
                "{}: length {} != manifest shard_len {}",
                sh.filename,
                sh.bytes.len(),
                manifest.shard_len
            ),
        ));
    }
    let digest_verified = match &sh.sidecar_digest_hex {
        None => {
            problems.push((
                EvidenceKind::MissingSidecar,
                format!("{}: no .sha256 sidecar, integrity unverifiable", sh.filename),
            ));
            false
        }
        Some(declared) => {
            if declared.eq_ignore_ascii_case(&content_digest) {
                true
            } else {
                problems.push((
                    EvidenceKind::DigestMismatch,
                    format!(
                        "{}: recomputed {} but sidecar declares {}",
                        sh.filename,
                        &content_digest[..12],
                        &declared[..declared.len().min(12)]
                    ),
                ));
                false
            }
        }
    };

    // Duplicate index / generation mix detection against what is already stored
    // or already seen inside this same import batch.
    let existing = store.fragments_for_stripe(object_id, sh.stripe)?;
    let same_key: Vec<_> = existing
        .iter()
        .filter(|f| f.shard_index == sh.shard_index)
        .collect();
    let mut gens: BTreeSet<u64> = same_key.iter().map(|f| f.generation).collect();
    gens.insert(sh.generation);
    if gens.len() > 1 {
        problems.push((
            EvidenceKind::GenerationMix,
            format!(
                "{}: index {} seen with generations {:?} (partial write)",
                sh.filename,
                sh.shard_index,
                gens.iter().copied().collect::<Vec<_>>()
            ),
        ));
    }
    let distinct_contents: BTreeSet<String> = same_key.iter().map(|f| f.content_digest.clone()).collect();
    let duplicate_index = !same_key.is_empty()
        && (distinct_contents.contains(&content_digest)
            || same_key.iter().any(|f| f.generation == sh.generation));

    // Persist the raw, untouched bytes for provenance.
    let rel_dir = std::path::Path::new("fragments")
        .join(object_id)
        .join(source);
    let abs_dir = store.paths.root.join(&rel_dir);
    std::fs::create_dir_all(&abs_dir)?;
    let rel_path = rel_dir.join(&sh.filename);
    let abs_path = store.paths.root.join(&rel_path);
    if !abs_path.exists() {
        std::fs::write(&abs_path, &sh.bytes)?;
    }

    let row = FragmentRow {
        id: 0,
        object_id: object_id.to_string(),
        source: source.to_string(),
        stripe: sh.stripe,
        shard_index: sh.shard_index,
        generation: sh.generation,
        content_digest: content_digest.clone(),
        declared_digest: sh.sidecar_digest_hex.clone(),
        length: sh.bytes.len(),
        file_path: rel_path.to_string_lossy().to_string(),
        digest_verified: digest_verified as i64,
    };
    let fragment_id = store.insert_fragment(&row)?;

    if duplicate_index {
        // Distinguish identical-content duplicate (benign corroboration) from
        // two content candidates for the same key+generation.
        let conflicting: BTreeSet<_> = same_key
            .iter()
            .filter(|f| f.generation == sh.generation && f.content_digest != content_digest)
            .map(|f| f.source.clone())
            .collect();
        if conflicting.is_empty() {
            problems.push((
                EvidenceKind::DuplicateIndex,
                format!(
                    "{}: identical shard index {} generation {} delivered again by {}",
                    sh.filename, sh.shard_index, sh.generation, source
                ),
            ));
        } else {
            problems.push((
                EvidenceKind::DuplicateIndex,
                format!(
                    "{}: two content candidates for index {} generation {} (also from {:?})",
                    sh.filename, sh.shard_index, sh.generation, conflicting
                ),
            ));
        }
    }

    for (kind, detail) in problems {
        store.add_evidence(
            object_id,
            Some(sh.stripe),
            Some(sh.shard_index),
            Some(fragment_id),
            Some(source),
            kind,
            &detail,
        )?;
        report.evidence += 1;
    }
    report.shards += 1;
    Ok(())
}

/// Convenience for tests and the demo seeder: write a delivery bundle.
pub fn write_bundle(
    incoming_root: &Path,
    source: &str,
    manifest: &Manifest,
    shards: &[(usize, usize, u64, Vec<u8>)],
    sidecars: &BTreeMap<(usize, usize, u64), String>,
) -> anyhow::Result<()> {
    let dir = incoming_root.join(source);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("manifest.json"), serde_json::to_vec_pretty(manifest)?)?;
    for (stripe, idx, gen, bytes) in shards {
        let name = format!("s{stripe}_i{idx}_g{gen}.bin");
        std::fs::write(dir.join(&name), bytes)?;
        if let Some(digest) = sidecars.get(&(*stripe, *idx, *gen)) {
            std::fs::write(dir.join(format!("{name}.sha256")), format!("{digest}  {name}\n"))?;
        }
    }
    Ok(())
}
