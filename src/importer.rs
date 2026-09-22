//! Manifest and fragment import. Original fragment bytes are preserved
//! verbatim together with the receiving source; nothing is mutated.

use crate::db::Db;
use crate::models::{FragmentInput, ImportAnomaly, Manifest};

fn decode_base64(s: &str) -> Result<Vec<u8>, String> {
    let table = |c: u8| -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            _ => None,
        }
    };
    let clean: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let mut out = Vec::new();
    let mut chunk: u32 = 0;
    let mut bits = 0u32;
    let mut padding = 0usize;
    for b in clean {
        if b == b'=' {
            padding += 1;
            continue;
        }
        let v = table(b).ok_or_else(|| format!("invalid base64 byte 0x{b:02x}"))?;
        chunk = (chunk << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((chunk >> bits) as u8);
            chunk &= (1 << bits) - 1;
        }
    }
    if padding > 2 {
        return Err("too many padding characters".into());
    }
    Ok(out)
}

pub fn decode_fragment_bytes(input: &FragmentInput) -> Result<Vec<u8>, String> {
    match input.encoding.as_str() {
        "" | "hex" => hex::decode(input.bytes.trim()).map_err(|e| format!("invalid hex: {e}")),
        "base64" => decode_base64(&input.bytes),
        other => Err(format!("unsupported fragment encoding '{other}'")),
    }
}

#[derive(Debug, Clone)]
pub struct ImportResult {
    pub manifest_stored: bool,
    pub imported: usize,
    pub duplicate: usize,
    pub anomalies: Vec<ImportAnomaly>,
}

pub fn import_manifest(db: &Db, manifest: &Manifest) -> Result<ImportResult, String> {
    manifest.valid()?;
    db.upsert_manifest(manifest).map_err(|e| e.to_string())?;
    Ok(ImportResult {
        manifest_stored: true,
        imported: 0,
        duplicate: 0,
        anomalies: Vec::new(),
    })
}

/// Import a batch of fragments. Returns per-record anomalies; valid records
/// are still stored so reviewers can inspect competing evidence.
pub fn import_fragments(db: &Db, inputs: &[FragmentInput]) -> ImportResult {
    let mut result = ImportResult {
        manifest_stored: false,
        imported: 0,
        duplicate: 0,
        anomalies: Vec::new(),
    };

    for input in inputs {
        let manifest = match db.load_manifest(&input.object_id, input.version) {
            Ok(Some(m)) => m,
            Ok(None) => {
                result.anomalies.push(ImportAnomaly {
                    code: "NO_MANIFEST".into(),
                    detail: format!("object {} v{} has no manifest", input.object_id, input.version),
                });
                continue;
            }
            Err(e) => {
                result.anomalies.push(ImportAnomaly {
                    code: "DB_ERROR".into(),
                    detail: e.to_string(),
                });
                continue;
            }
        };

        let bytes = match decode_fragment_bytes(input) {
            Ok(b) => b,
            Err(detail) => {
                result.anomalies.push(ImportAnomaly {
                    code: "BAD_ENCODING".into(),
                    detail: format!(
                        "{} v{} stripe {} shard {}: {detail}",
                        input.object_id, input.version, input.stripe_index, input.shard_index
                    ),
                });
                continue;
            }
        };

        let mut reasons: Vec<String> = Vec::new();
        if input.shard_index >= manifest.n {
            reasons.push(format!("shard_index {} out of range n={}", input.shard_index, manifest.n));
        }
        if input.stripe_index >= manifest.stripe_count {
            reasons.push(format!(
                "stripe_index {} out of range stripe_count={}",
                input.stripe_index, manifest.stripe_count
            ));
        }
        if bytes.len() != manifest.stripe_size {
            reasons.push(format!(
                "length {} disagrees with manifest stripe_size {}",
                bytes.len(),
                manifest.stripe_size
            ));
        }

        let actual = crate::models::sha256_hex(&bytes);
        let expected = manifest.expected_shard_digest(input.stripe_index, input.shard_index);
        let digest_ok = match expected {
            Some(want) => want.eq_ignore_ascii_case(&actual),
            None => true,
        };
        if let Some(want) = expected {
            if !digest_ok {
                reasons.push(format!("digest mismatch: actual {actual} != expected {want}"));
            }
        }

        // Duplicate detection: identical (identity coordinates + content digest).
        let existing = db
            .list_fragments(&input.object_id, input.version)
            .unwrap_or_default()
            .into_iter()
            .any(|f| {
                f.generation == input.generation
                    && f.stripe_index == input.stripe_index
                    && f.shard_index == input.shard_index
                    && f.source == input.source
                    && f.actual_digest == actual
            });
        if existing {
            result.duplicate += 1;
            continue;
        }

        let state = if reasons.is_empty() { "eligible" } else { "excluded" };
        let excluded_reason = if reasons.is_empty() { None } else { Some(reasons.join("; ")) };
        match db.insert_fragment(
            &input.object_id,
            input.version,
            input.generation,
            input.stripe_index,
            input.shard_index,
            &input.source,
            &bytes,
            expected,
            digest_ok,
            state,
            excluded_reason.as_deref(),
        ) {
            Ok(_) => {
                result.imported += 1;
                for r in reasons {
                    result.anomalies.push(ImportAnomaly {
                        code: "FRAGMENT_EXCLUDED".into(),
                        detail: format!(
                            "{} v{} g{} s{}:{} from {}: {r}",
                            input.object_id,
                            input.version,
                            input.generation,
                            input.stripe_index,
                            input.shard_index,
                            input.source
                        ),
                    });
                }
            }
            Err(e) => result.anomalies.push(ImportAnomaly {
                code: "DB_ERROR".into(),
                detail: e.to_string(),
            }),
        }
    }

    result
}

/// Import an offline directory containing `manifest.json`, `fragments.json`
/// (a JSON array of FragmentInput) and optional `digests.txt` lines
/// `stripe:shard  sha256hex`. Original files are never modified.
pub fn import_directory(db: &Db, dir: &std::path::Path) -> Result<ImportResult, String> {
    let manifest_path = dir.join("manifest.json");
    let manifest: Manifest = serde_json::from_str(
        &std::fs::read_to_string(&manifest_path)
            .map_err(|e| format!("read {}: {e}", manifest_path.display()))?,
    )
    .map_err(|e| format!("parse manifest: {e}"))?;
    let mut result = import_manifest(db, &manifest)?;

    let mut manifest = manifest;
    let digests_path = dir.join("digests.txt");
    if digests_path.exists() {
        let mut map = std::collections::HashMap::new();
        for line in std::fs::read_to_string(&digests_path).map_err(|e| e.to_string())?.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            if let (Some(key), Some(digest)) = (parts.next(), parts.next()) {
                map.insert(key.to_string(), digest.to_string());
            }
        }
        manifest.shard_digests = Some(map);
        db.upsert_manifest(&manifest).map_err(|e| e.to_string())?;
    }

    let fragments_path = dir.join("fragments.json");
    if fragments_path.exists() {
        let inputs: Vec<FragmentInput> =
            serde_json::from_str(&std::fs::read_to_string(&fragments_path).map_err(|e| e.to_string())?)
                .map_err(|e| format!("parse fragments: {e}"))?;
        let fr = import_fragments(db, &inputs);
        result.imported += fr.imported;
        result.duplicate += fr.duplicate;
        result.anomalies.extend(fr.anomalies);
    }
    Ok(result)
}
