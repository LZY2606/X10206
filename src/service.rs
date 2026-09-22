use base64::Engine;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::coding::{cauchy_coefficient, mul, Witness};
use crate::db::{atomic_write, now_millis, sha256_hex, normalize_digest, Store};
use crate::models::*;

#[derive(Clone, Debug)]
pub struct RecoveryConfig {
    pub search_budget: usize,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self { search_budget: 1024 }
    }
}

pub trait OutputStorage {
    fn write(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()>;
    fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()>;
    fn remove_dir_all(&self, path: &Path) -> std::io::Result<()>;
}

pub struct DiskStorage;

impl OutputStorage for DiskStorage {
    fn write(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, bytes)
    }
    fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        std::fs::rename(from, to)
    }
    fn remove_dir_all(&self, path: &Path) -> std::io::Result<()> {
        std::fs::remove_dir_all(path)
    }
}

#[derive(Default)]
pub struct FailOnceAtCommit {
    pub calls: std::cell::RefCell<usize>,
    pub fail_data_write: bool,
    pub fail_manifest_write: bool,
    pub fail_rename: bool,
}

impl OutputStorage for FailOnceAtCommit {
    fn write(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        let is_data = path.extension().and_then(|v| v.to_str()) == Some("data");
        let is_manifest = path.extension().and_then(|v| v.to_str()) == Some("json");
        let mut calls = self.calls.borrow_mut();
        *calls += 1;
        if *calls == 1 && ((is_data && self.fail_data_write) || (is_manifest && self.fail_manifest_write)) {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "injected write failure"));
        }
        DiskStorage.write(path, bytes)
    }
    fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        let mut calls = self.calls.borrow_mut();
        *calls += 1;
        if *calls == 1 && self.fail_rename {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "injected rename failure"));
        }
        drop(calls);
        DiskStorage.rename(from, to)
    }
    fn remove_dir_all(&self, path: &Path) -> std::io::Result<()> {
        DiskStorage.remove_dir_all(path)
    }
}

#[derive(Clone, Debug)]
struct ShardRow {
    id: i64,
    stripe_index: i64,
    shard_index: i64,
    generation: i64,
    source_id: String,
    actual_digest: String,
    actual_len: i64,
    claimed_digest: Option<String>,
    digest_ok: bool,
    length_ok: bool,
    in_range: bool,
    source_isolated: bool,
}

#[derive(Clone, Debug)]
struct CandidateSet {
    generation: i64,
    shards: Vec<ShardRow>,
}

#[derive(Clone, Debug)]
struct Reconstruction {
    full: Vec<Vec<u8>>,
    witnesses: Vec<ShardRow>,
    generated: Vec<i64>,
    cross_failures: Vec<i64>,
    excluded: Vec<(i64, String)>,
    digest: String,
    trusted: bool,
}

fn b64_decode(value: &str) -> Result<Vec<u8>> {
    let clean = value.replace(['\n', '\r', ' ', '\t'], "");
    base64::engine::general_purpose::STANDARD.decode(clean).map_err(|e| e.to_string())
}

fn decode_import_shard(shard: &ImportShard) -> Result<(Vec<u8>, Option<String>)> {
    if let Some(value) = &shard.data_b64 {
        return Ok((b64_decode(value)?, shard.digest.clone()));
    }
    if let Some(value) = &shard.bytes_hex {
        let clean = value.replace(['\n', '\r', ' ', '\t'], "");
        return Ok((hex::decode(clean).map_err(|e| e.to_string())?, shard.digest.clone()));
    }
    Err("shard requires dataB64 or bytesHex".into())
}

impl Store {
    pub fn import(&self, request: ImportRequest) -> Result<i64> {
        validate_request(&request)?;
        let manifest_bytes = if let Some(b64) = &request.manifest_b64 {
            b64_decode(b64)?
        } else {
            serde_json::to_vec_pretty(&request.manifest_json.clone().unwrap_or(serde_json::json!({
                "objectId": request.object_id,
                "version": request.version,
                "k": request.k,
                "m": request.m,
                "stripeCount": request.stripe_count,
                "shardLen": request.shard_len,
                "dataLen": request.data_len,
                "objectDigest": request.object_digest,
                "generation": request.shard_generation,
            }))).map_err(|e| e.to_string())?
        };
        let manifest_path = self.save_manifest(&request.object_id, &manifest_bytes)?;
        self.ensure_object(&request, manifest_path)?;
        self.ensure_source(&request.source_id, request.source_label.as_deref().unwrap_or(&request.source_id))?;

        let mut imported = 0;
        for incoming in &request.shards {
            let (bytes, claimed) = decode_import_shard(incoming)?;
            let actual_digest = self.save_content_addressed(&bytes)?;
            let claimed = claimed.or_else(|| incoming.digest.clone()).map(|v| normalize_digest(&v));
            let digest_ok = claimed.as_ref().map_or(true, |expected| expected == &actual_digest);
            let stripe_index = incoming.stripe_index.unwrap_or(incoming.block_index.unwrap_or(0));
            let shard_index = incoming.index;
            let in_range = stripe_index >= 0
                && stripe_index < request.stripe_count
                && shard_index >= 0
                && shard_index < request.k + request.m;
            let expected_len = incoming.shard_len.unwrap_or(request.shard_len);
            let length_ok = bytes.len() as i64 == expected_len;
            let generation = incoming.generation.or(request.shard_generation).unwrap_or(0);
            self.insert_shard(
                &request.object_id,
                &request.source_id,
                stripe_index,
                shard_index,
                generation,
                &incoming.kind,
                &actual_digest,
                claimed,
                bytes.len() as i64,
                digest_ok,
                length_ok,
                in_range,
            )?;
            imported += 1;
        }
        Ok(imported)
    }

    pub fn set_source_isolated(&self, source_id: &str, isolated: bool) -> Result<()> {
        let affected = self.lock()
            .execute("UPDATE sources SET isolated=?1 WHERE source_id=?2", params![isolated, source_id])
            .map_err(|e| e.to_string())?;
        if affected == 0 {
            return Err("source not found".into());
        }
        Ok(())
    }
}

fn validate_request(request: &ImportRequest) -> Result<()> {
    if request.object_id.trim().is_empty() || request.source_id.trim().is_empty() {
        return Err("objectId and sourceId are required".into());
    }
    if request.k < 1 || request.m < 1 || request.k + request.m > 256 {
        return Err("k must be positive, m positive and k+m <= 256".into());
    }
    if request.stripe_count < 1 || request.shard_len < 1 {
        return Err("stripeCount and shardLen must be positive".into());
    }
    if request.shards.is_empty() {
        return Err("import requires at least one shard".into());
    }
    Ok(())
}

fn millis() -> i64 {
    UNIX_EPOCH.elapsed().map(|v| v.as_millis() as i64).unwrap_or(0)
}

#[derive(Clone, Debug)]
struct ObjectParams {
    object_id: String,
    k: i64,
    m: i64,
    stripe_count: i64,
    shard_len: i64,
    data_len: Option<i64>,
    object_digest: String,
}

fn object_params(conn: &Connection, object_id: &str) -> Result<ObjectParams> {
    conn.query_row(
        "SELECT object_id,k,m,stripe_count,shard_len,data_len,object_digest FROM objects WHERE object_id=?1",
        params![object_id],
        |row| Ok(ObjectParams {
            object_id: row.get(0)?,
            k: row.get(1)?,
            m: row.get(2)?,
            stripe_count: row.get(3)?,
            shard_len: row.get(4)?,
            data_len: row.get(5)?,
            object_digest: row.get(6)?,
        }),
    ).map_err(|e| e.to_string())
}

fn load_shards(conn: &Connection, object_id: &str) -> Result<Vec<ShardRow>> {
    let mut stmt = conn.prepare(
        "SELECT sh.id, sh.stripe_index, sh.shard_index, sh.generation, sh.source_id,
                sh.actual_digest, sh.actual_len, sh.claimed_digest,
                sh.digest_ok, sh.length_ok, sh.in_range, COALESCE(s.isolated,0)
         FROM shards sh JOIN sources s ON s.source_id=sh.source_id
         WHERE sh.object_id=?1
         ORDER BY sh.stripe_index, sh.generation, sh.shard_index, sh.id",
    ).map_err(|e| e.to_string())?;
    let rows = stmt.query_map(params![object_id], |row| Ok(ShardRow {
        id: row.get(0)?,
        stripe_index: row.get(1)?,
        shard_index: row.get(2)?,
        generation: row.get(3)?,
        source_id: row.get(4)?,
        actual_digest: row.get(5)?,
        actual_len: row.get(6)?,
        claimed_digest: row.get(7)?,
        digest_ok: row.get::<_, i64>(8)? != 0,
        length_ok: row.get::<_, i64>(9)? != 0,
        in_range: row.get::<_, i64>(10)? != 0,
        source_isolated: row.get::<_, i64>(11)? != 0,
    })).map_err(|e| e.to_string())?;
    rows.collect::<std::result::Result<Vec<_>, _>>().map_err(|e| e.to_string())
}

fn exclusion_reason(shard: &ShardRow) -> Option<String> {
    if !shard.in_range {
        return Some("outside manifest stripe/shard range".into());
    }
    if shard.source_isolated {
        return Some(format!("source {} manually isolated", shard.source_id));
    }
    if !shard.digest_ok {
        return Some(format!(
            "digest mismatch: claimed {}, recomputed {}",
            shard.claimed_digest.clone().unwrap_or_else(|| "-".into()),
            shard.actual_digest
        ));
    }
    if !shard.length_ok {
        return Some(format!("length mismatch: recomputed {} bytes", shard.actual_len));
    }
    None
}

fn generation_candidates(shards: &[ShardRow], stripe: i64) -> Vec<CandidateSet> {
    let mut grouped: BTreeMap<i64, Vec<ShardRow>> = BTreeMap::new();
    for shard in shards.iter().filter(|s| s.stripe_index == stripe) {
        grouped.entry(shard.generation).or_default().push(shard.clone());
    }
    grouped.into_iter().map(|(generation, mut rows)| {
        rows.sort_by_key(|s| (s.shard_index, s.id, s.actual_digest.clone()));
        let mut unique = Vec::new();
        for row in rows {
            if exclusion_reason(&row).is_some() {
                continue;
            }
            let duplicate = unique.iter().any(|existing: &ShardRow| {
                existing.shard_index == row.shard_index && existing.actual_digest == row.actual_digest
            });
            if !duplicate {
                unique.push(row);
            }
        }
        CandidateSet { generation, shards: unique }
    }).collect()
}

fn all_excluded(shards: &[ShardRow]) -> Vec<(i64, String)> {
    let mut excluded = Vec::new();
    for shard in shards {
        if let Some(reason) = exclusion_reason(shard) {
            excluded.push((shard.id, reason));
        }
    }
    excluded.sort();
    excluded.dedup_by_key(|(id, _)| *id);
    excluded
}

fn enumerate_witness_sets(candidates: &[ShardRow], k: usize, budget: usize) -> (Vec<Vec<ShardRow>>, bool) {
    let mut output = Vec::new();
    let mut complete = true;
    fn walk(
        start: usize,
        candidates: &[ShardRow],
        k: usize,
        budget: usize,
        chosen: &mut Vec<ShardRow>,
        used_slots: &mut BTreeSet<i64>,
        output: &mut Vec<Vec<ShardRow>>,
        complete: &mut bool,
    ) {
        if chosen.len() == k {
            if output.len() < budget {
                output.push(chosen.clone());
            } else {
                *complete = false;
            }
            return;
        }
        let remaining = k - chosen.len();
        for index in start..=candidates.len().saturating_sub(remaining) {
            if output.len() >= budget {
                *complete = false;
                return;
            }
            let candidate = &candidates[index];
            if used_slots.contains(&candidate.shard_index) {
                continue;
            }
            chosen.push(candidate.clone());
            used_slots.insert(candidate.shard_index);
            walk(index + 1, candidates, k, budget, chosen, used_slots, output, complete);
            used_slots.remove(&candidate.shard_index);
            chosen.pop();
        }
    }
    let mut chosen = Vec::new();
    let mut used = BTreeSet::new();
    walk(0, candidates, k, budget, &mut chosen, &mut used, &mut output, &mut complete);
    (output, complete)
}

fn try_reconstruction(
    store: &Store,
    params: &ObjectParams,
    group: &CandidateSet,
    witnesses: &[ShardRow],
    excluded: &[(i64, String)],
) -> Result<Option<Reconstruction>> {
    let k = params.k as usize;
    let n = (params.k + params.m) as usize;
    let shard_len = params.shard_len as usize;
    let witness_input: Vec<Witness> = witnesses.iter().map(|s| Witness {
        index: s.shard_index as usize,
        bytes: read_shard_bytes(store, s)?,
    }).collect();
    let full = match crate::coding::reconstruct_missing(k, n, shard_len, &witness_input) {
        Ok(full) => full,
        Err(_) => return Ok(None),
    };
    let witness_ids: BTreeSet<i64> = witnesses.iter().map(|s| s.id).collect();
    let witness_slots: BTreeSet<i64> = witnesses.iter().map(|s| s.shard_index).collect();
    let mut cross_failures = Vec::new();
    for candidate in &group.shards {
        if witness_ids.contains(&candidate.id) {
            continue;
        }
        let bytes = read_shard_bytes(store, candidate)?;
        if full[candidate.shard_index as usize] != bytes {
            cross_failures.push(candidate.id);
        }
    }
    let mut data = Vec::with_capacity(k * shard_len);
    for shard in full.iter().take(k) {
        data.extend_from_slice(shard);
    }
    let digest = sha256_hex(&data);
    let generated = (0..n as i64).filter(|index| !witness_slots.contains(index)).collect();
    let mut all_excluded = excluded.to_vec();
    for id in &cross_failures {
        all_excluded.push((*id, "candidate byte comparison disagrees with this reconstruction".into()));
    }
    all_excluded.sort();
    all_excluded.dedup_by_key(|(id, _)| *id);
    Ok(Some(Reconstruction {
        full,
        witnesses: witnesses.to_vec(),
        generated,
        cross_failures,
        excluded: all_excluded,
        digest,
        trusted: false,
    }))
}

fn read_shard_bytes(store: &Store, shard: &ShardRow) -> Result<Vec<u8>> {
    store.read_raw(&shard.actual_digest)
        .map_err(|e| format!("raw shard {} unavailable: {e}", shard.actual_digest))
}
