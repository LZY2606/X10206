//! Stripe recovery engine.
//!
//! Candidates are never first-come-first-served. For every stripe the engine
//! enumerates feasible (generation, k distinct rows, one content per row)
//! combinations in a deterministic order, decodes them, keeps every distinct
//! feasible output, records why competing evidence was excluded, and only
//! commits a stripe when the result is unique (or cryptographically expected).

use crate::coding;
use crate::db::Db;
use crate::models::{self, FragmentRecord, Manifest};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

pub const DEFAULT_BUDGET: usize = 4096;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Failpoints {
    /// Fail Nth stripe's atomic blob commit (1-based), simulating disk write failure.
    #[serde(default)]
    pub fail_commit_nth: usize,
    /// Stop after writing the temp blob but before commit, simulating a crash.
    #[serde(default)]
    pub crash_before_commit_nth: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectedShard {
    pub fragment_id: i64,
    pub row: usize,
    pub generation: u64,
    pub source: String,
    pub actual_digest: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExcludedEvidence {
    pub fragment_id: i64,
    pub row: usize,
    pub generation: u64,
    pub source: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StripeSolution {
    pub stripe_index: usize,
    pub generation: u64,
    pub key_tuple: Vec<i64>,
    pub verification: String, // "expected" | "verified" | "threshold-only"
    pub data: Vec<u8>,
    pub data_digest: String,
    pub selected: Vec<SelectedShard>,
    pub excluded: Vec<ExcludedEvidence>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StripeOutcome {
    pub stripe_index: usize,
    pub status: String, // committed | ambiguous | infeasible | reused | length-mismatch
    pub generation: Option<u64>,
    pub data_digest: Option<String>,
    pub solutions: Vec<StripeSolution>,
    pub detail: String,
    /// Rows with no eligible candidate at the target generation.
    pub missing_rows: Vec<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GlobalCombo {
    pub selections: Vec<usize>,
    pub object_digest: String,
    pub matches_manifest: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunReport {
    pub object_id: String,
    pub version: u32,
    pub budget: usize,
    pub combos_considered: usize,
    pub budget_exhausted: bool,
    pub stripes: Vec<StripeOutcome>,
    pub global_combos: Vec<GlobalCombo>,
    pub object_digest: Option<String>,
    pub object_digest_matches: Option<bool>,
    pub recoverable: bool,
    pub confidence: String, // trusted | threshold-only | ambiguous | unrecoverable
    pub failpoint: Option<String>,
    pub interrupted: bool,
}

struct Candidate {
    frag: FragmentRecord,
    bytes: Vec<u8>,
}

fn load_candidates(db: &Db, object_id: &str, version: u32, stripe: usize) -> Vec<Candidate> {
    let frags = db.list_fragments(object_id, version).unwrap_or_default();
    let mut out = Vec::new();
    for frag in frags.into_iter().filter(|f| f.stripe_index == stripe) {
        if let Ok(bytes) = db.fragment_bytes(frag.id) {
            out.push(Candidate { frag, bytes });
        }
    }
    out
}

fn expected_length(m: &Manifest) -> usize {
    // data rows carry exactly stripe_size bytes; parity rows the same length.
    m.stripe_size
}

/// Enumerate feasible solutions for one stripe within the combination budget.
#[allow(clippy::too_many_arguments)]
fn enumerate_stripe(
    m: &Manifest,
    stripe: usize,
    candidates: &[Candidate],
    isolated: &BTreeSet<String>,
    budget: &mut usize,
) -> (Vec<StripeSolution>, Vec<ExcludedEvidence>, Vec<usize>, String) {
    let k = m.k;
    let n = m.n;
    let want_len = expected_length(m);
    let mut excluded: Vec<ExcludedEvidence> = Vec::new();

    let mut available: Vec<&Candidate> = Vec::new();
    let mut length_bad = false;
    for c in candidates {
        let f = &c.frag;
        if isolated.contains(&f.source) {
            excluded.push(ExcludedEvidence {
                fragment_id: f.id,
                row: f.shard_index,
                generation: f.generation,
                source: f.source.clone(),
                reason: "source isolated by operator".into(),
            });
            continue;
        }
        if f.shard_index >= n {
            excluded.push(ExcludedEvidence {
                fragment_id: f.id,
                row: f.shard_index,
                generation: f.generation,
                source: f.source.clone(),
                reason: format!("shard index {} outside n={}", f.shard_index, n),
            });
            continue;
        }
        if c.bytes.len() != want_len {
            length_bad = true;
            excluded.push(ExcludedEvidence {
                fragment_id: f.id,
                row: f.shard_index,
                generation: f.generation,
                source: f.source.clone(),
                reason: format!("length {} != manifest stripe length {}", c.bytes.len(), want_len),
            });
            continue;
        }
        if !f.digest_ok {
            excluded.push(ExcludedEvidence {
                fragment_id: f.id,
                row: f.shard_index,
                generation: f.generation,
                source: f.source.clone(),
                reason: format!("digest mismatch: actual {} != expected {}", f.actual_digest,
                    f.expected_digest.clone().unwrap_or_else(|| "?".into())),
            });
            continue;
        }
        available.push(c);
    }

    if available.is_empty() {
        let detail = if length_bad {
            "no digest-valid fragments with manifest-declared length".to_string()
        } else {
            "no eligible fragments (all excluded or missing)".to_string()
        };
        return (Vec::new(), excluded, (0..n).collect(), detail);
    }

    // Enumerate from the highest generation downwards. The first generation
    // that yields feasible sets is the partial-write generation to trust;
    // older generations stay on record as stale evidence only.
    let gens: BTreeSet<u64> = available.iter().map(|c| c.frag.generation).collect();
    let mut missing_rows: Vec<usize> = Vec::new();
    for gen in gens.into_iter().rev() {
        let same_gen: Vec<&Candidate> = available.iter().copied().filter(|c| c.frag.generation == gen).collect();
        for c in &available {
            if c.frag.generation != gen {
                excluded.push(ExcludedEvidence {
                    fragment_id: c.frag.id,
                    row: c.frag.shard_index,
                    generation: c.frag.generation,
                    source: c.frag.source.clone(),
                    reason: format!(
                        "generation {} != enumerated generation {} (mixed partial write)",
                        c.frag.generation, gen
                    ),
                });
            }
        }

        // Group by row; order candidates deterministically by (digest, source, id).
        let mut by_row: BTreeMap<usize, Vec<&Candidate>> = BTreeMap::new();
        for c in same_gen {
            by_row.entry(c.frag.shard_index).or_default().push(c);
        }
        for v in by_row.values_mut() {
            v.sort_by(|a, b| {
                a.frag
                    .actual_digest
                    .cmp(&b.frag.actual_digest)
                    .then_with(|| a.frag.source.cmp(&b.frag.source))
                    .then_with(|| a.frag.id.cmp(&b.frag.id))
            });
            v.dedup_by(|a, b| a.frag.actual_digest == b.frag.actual_digest);
        }
        let present: BTreeSet<usize> = by_row.keys().copied().collect();
        missing_rows = (0..n).filter(|r| !present.contains(r)).collect();
        if present.len() < k {
            continue; // try an older generation
        }

        let row_list: Vec<usize> = present.into_iter().collect();
        let mut solutions: Vec<StripeSolution> = Vec::new();
        let mut row_combos: Vec<Vec<usize>> = Vec::new();
        row_combinations(&row_list, k, &mut Vec::new(), &mut row_combos);
        // Deterministic: lower row tuples first.
        row_combos.sort();

        'combo: for rows in row_combos {
            let mut pick: Vec<usize> = vec![0; rows.len()];
            loop {
                if *budget == 0 {
                    return (
                        solutions,
                        excluded,
                        missing_rows,
                        format!("search budget exhausted at generation {gen}"),
                    );
                }
                *budget -= 1;

                let selected: Vec<&Candidate> = rows
                    .iter()
                    .enumerate()
                    .map(|(i, row)| by_row[row][pick[i]])
                    .collect();
                let avail: Vec<(usize, Vec<u8>)> =
                    selected.iter().map(|c| (c.frag.shard_index, c.bytes.clone())).collect();
                if let Some(decoded) = coding::reconstruct(&avail, n, k) {
                    // Cross-check every same-generation eligible fragment against
                    // the decoded stripe; conflicts are corrupt evidence even
                    // though their own digest block had no recorded expected digest.
                    let mut conflicts = 0usize;
                    for c in &same_gen {
                        let used = selected.iter().any(|s| s.frag.id == c.frag.id);
                        if used {
                            continue;
                        }
                        if !coding::matches_linear(c.frag.shard_index, &c.bytes, &decoded[..k], n, k) {
                            conflicts += 1;
                            excluded.push(ExcludedEvidence {
                                fragment_id: c.frag.id,
                                row: c.frag.shard_index,
                                generation: c.frag.generation,
                                source: c.frag.source.clone(),
                                reason: "content conflicts with a feasible k-of-n solution".into(),
                            });
                        }
                    }

                    let mut verification = if selected.len() + same_gen.len() - selected.len() >= k + 1
                        && same_gen.iter().all(|c| {
                            selected.iter().any(|s| s.frag.id == c.frag.id)
                                || coding::matches_linear(c.frag.shard_index, &c.bytes, &decoded[..k], n, k)
                        }) {
                        "verified"
                    } else {
                        "threshold-only"
                    };

                    // Cryptographic expectations pin the exact row contents.
                    let mut expected_ok = true;
                    for row in 0..n {
                        if let Some(want) = m.expected_shard_digest(stripe, row) {
                            if models::sha256_hex(&decoded[row]) != want {
                                expected_ok = false;
                            }
                        }
                    }
                    if expected_ok && m.shard_digests.is_some() {
                        verification = "expected";
                    }

                    let data = decoded[..k].concat();
                    let data_digest = models::sha256_hex(&data);
                    let key_tuple: Vec<i64> = selected.iter().map(|c| c.frag.id).collect();
                    let sol = StripeSolution {
                        stripe_index: stripe,
                        generation: gen,
                        key_tuple,
                        verification: verification.to_string(),
                        data,
                        data_digest,
                        selected: selected
                            .iter()
                            .map(|c| SelectedShard {
                                fragment_id: c.frag.id,
                                row: c.frag.shard_index,
                                generation: c.frag.generation,
                                source: c.frag.source.clone(),
                                actual_digest: c.frag.actual_digest.clone(),
                            })
                            .collect(),
                        excluded: Vec::new(),
                    };
                    if !expected_ok {
                        // Decoded output violates recorded per-shard digests.
                        for row in 0..n {
                            if let Some(want) = m.expected_shard_digest(stripe, row) {
                                if models::sha256_hex(&decoded[row]) != want {
                                    excluded.push(ExcludedEvidence {
                                        fragment_id: -1,
                                        row,
                                        generation: gen,
                                        source: "-".into(),
                                        reason: format!("reconstructed shard digest != manifest expected {want}"),
                                    });
                                }
                            }
                        }
                    }
                    let _ = conflicts;
                    let dup = solutions.iter().any(|s| s.data_digest == sol.data_digest);
                    if !dup {
                        solutions.push(sol);
                    }
                }

                // advance multi-base pick counters
                let mut idx = 0usize;
                loop {
                    pick[idx] += 1;
                    if pick[idx] < by_row[&rows[idx]].len() {
                        break;
                    }
                    pick[idx] = 0;
                    idx += 1;
                    if idx == rows.len() {
                        break 'combo;
                    }
                }
            }
        }

        if !solutions.is_empty() {
            // Sort solutions deterministically and attach the full evidence set.
            solutions.sort_by(|a, b| {
                a.key_tuple
                    .cmp(&b.key_tuple)
            });
            for s in solutions.iter_mut() {
                s.excluded = excluded.clone();
            }
            return (solutions, excluded, missing_rows, String::new());
        }
    }

    (
        Vec::new(),
        excluded,
        missing_rows,
        "no k rows yield a consistent solution at any generation".to_string(),
    )
}

fn row_combinations(rows: &[usize], k: usize, prefix: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
    if prefix.len() == k {
        out.push(prefix.clone());
        return;
    }
    let need = k - prefix.len();
    for (i, &r) in rows.iter().enumerate() {
        if rows.len() - i < need {
            break;
        }
        prefix.push(r);
        row_combinations(&rows[i + 1..], k, prefix, out);
        prefix.pop();
    }
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

fn dedup_excluded(v: &mut Vec<ExcludedEvidence>) {
    let mut seen = BTreeSet::new();
    v.retain(|e| seen.insert((e.fragment_id, e.row, e.reason.clone())));
    v.sort_by(|a, b| a.row.cmp(&b.row).then(a.fragment_id.cmp(&b.fragment_id)));
}

pub struct RecoveryError(pub String);
impl std::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl From<rusqlite::Error> for RecoveryError {
    fn from(e: rusqlite::Error) -> Self {
        RecoveryError(e.to_string())
    }
}
impl From<std::io::Error> for RecoveryError {
    fn from(e: std::io::Error) -> Self {
        RecoveryError(e.to_string())
    }
}

fn committed_blob_path(db: &Db, object_id: &str, version: u32, stripe: usize, digest: &str) -> PathBuf {
    let name = format!("{}_v{}_s{}_{}.bin", sanitize(object_id), version, stripe, &digest[..12]);
    db.data_dir.join("committed").join(name)
}

fn alternatives_dir(db: &Db, run_id: i64) -> PathBuf {
    db.data_dir.join("alternatives").join(format!("run-{run_id}"))
}

pub fn list_committed_stripes(db: &Db, object_id: &str, version: u32) -> Vec<(usize, String, PathBuf)> {
    let conn = db.conn.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT stripe_index, data_digest, blob_path FROM stripe_states
             WHERE object_id=?1 AND version=?2 AND status='committed' ORDER BY stripe_index",
        )
        .expect("prepare");
    let rows = stmt
        .query_map(params![object_id, version], |r| {
            Ok((r.get::<_, i64>(0)? as usize, r.get::<_, String>(1)?, r.get::<_, String>(2)?))
        })
        .expect("query");
    let mut out = Vec::new();
    for r in rows {
        let (s, d, p) = r.unwrap();
        let path = PathBuf::from(&p);
        if path.exists() {
            if let Ok(bytes) = fs::read(&path) {
                if models::sha256_hex(&bytes) == d {
                    out.push((s, d, path));
                    continue;
                }
            }
        }
    }
    out
}

/// Run recovery for one object version. Commits stripes independently so an
/// interruption never loses completed work; only digest-intact committed
/// stripes are reused, never temp blocks.
pub fn run_recovery(
    db: &Db,
    object_id: &str,
    version: u32,
    budget_total: usize,
    failpoints: &Failpoints,
) -> Result<RunReport, RecoveryError> {
    let manifest = db
        .load_manifest(object_id, version)?
        .ok_or_else(|| RecoveryError(format!("no manifest for {object_id} v{version}")))?;
    manifest.valid().map_err(RecoveryError)?;

    let isolated: BTreeSet<String> = db.isolated_sources()?.into_iter().collect();

    // Any leftover temp block is from an interrupted run; it is never read,
    // only cleaned up.
    if let Ok(entries) = fs::read_dir(db.tmp_dir()) {
        for e in entries.flatten() {
            let p = e.path();
            if p.to_string_lossy().starts_with(&db.tmp_dir().join("commit-").to_string_lossy()) {
                fs::remove_file(&p).ok();
            }
        }
    }

    let run_id = {
        let conn = db.conn.lock().unwrap();
        let fp = if failpoints.fail_commit_nth != 0 || failpoints.crash_before_commit_nth != 0 {
            Some(serde_json::to_string(failpoints).unwrap())
        } else {
            None
        };
        conn.execute(
            "INSERT INTO runs(object_id, version, budget, status, failpoint) VALUES (?1,?2,?3,'running',?4)",
            params![object_id, version, budget_total as i64, fp],
        )?;
        conn.last_insert_rowid()
    };

    let mut remaining = budget_total;
    let mut outcomes: Vec<StripeOutcome> = Vec::new();
    let mut commits_this_run = 0usize;
    let mut interrupted = false;
    let mut failpoint_hit: Option<String> = None;

    for stripe in 0..manifest.stripe_count {
        // Reuse only a fully committed, digest-intact stripe.
        let committed: Vec<(usize, String, PathBuf)> = list_committed_stripes(db, object_id, version)
            .into_iter()
            .filter(|(s, _, _)| *s == stripe)
            .collect();
        if let Some((_, digest, path)) = committed.into_iter().next() {
            let bytes = fs::read(&path)?;
            let gen = {
                let conn = db.conn.lock().unwrap();
                conn.query_row(
                    "SELECT generation FROM stripe_states WHERE object_id=?1 AND version=?2 AND stripe_index=?3",
                    params![object_id, version, stripe as i64],
                    |r| r.get::<_, Option<i64>>(0),
                )?
            };
            outcomes.push(StripeOutcome {
                stripe_index: stripe,
                status: "reused".into(),
                generation: gen.map(|g| g as u64),
                data_digest: Some(digest.clone()),
                solutions: vec![StripeSolution {
                    stripe_index: stripe,
                    generation: gen.unwrap_or(0) as u64,
                    key_tuple: vec![],
                    verification: "committed".into(),
                    data: bytes,
                    data_digest: digest,
                    selected: vec![],
                    excluded: vec![],
                }],
                detail: "reused digest-intact committed stripe after interruption".into(),
                missing_rows: vec![],
            });
            continue;
        }

        let candidates = load_candidates(db, object_id, version, stripe);
        let (mut solutions, mut excluded, missing_rows, budget_detail) =
            enumerate_stripe(&manifest, stripe, &candidates, &isolated, &mut remaining);
        dedup_excluded(&mut excluded);

        if budget_detail.contains("budget exhausted") {
            // partial solutions may exist; record the cap and stop trusting them
            outcomes.push(StripeOutcome {
                stripe_index: stripe,
                status: "infeasible".into(),
                generation: None,
                data_digest: None,
                solutions: vec![],
                detail: budget_detail,
                missing_rows,
            });
            interrupted = true;
            break;
        }

        if solutions.is_empty() {
            let status = "infeasible";
            persist_no_solution(db, run_id, object_id, version, stripe, status, &excluded, &budget_detail)?;
            outcomes.push(StripeOutcome {
                stripe_index: stripe,
                status: status.into(),
                generation: None,
                data_digest: None,
                solutions: vec![],
                detail: if budget_detail.is_empty() {
                    format!(
                        "{} missing rows {:?}; no consistent k-of-{} set",
                        missing_rows.len(),
                        missing_rows,
                        manifest.k
                    )
                } else {
                    budget_detail
                },
                missing_rows,
            });
            continue;
        }

        // Persist every distinct feasible solution (uncommitted alternatives keep
        // their bytes outside the tmp area so reviewers can inspect them).
        fs::create_dir_all(alternatives_dir(db, run_id).join(format!("stripe-{stripe}"))).ok();
        for (idx, sol) in solutions.iter().enumerate() {
            let blob = alternatives_dir(db, run_id)
                .join(format!("stripe-{stripe}"))
                .join(format!("sol-{idx}-{}.bin", &sol.data_digest[..12]));
            fs::write(&blob, &sol.data)?;
            let conn = db.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO solutions(run_id, stripe_index, generation, key_tuple, verification,
                    data_digest, blob_path, selected_rows_json, evidence_json, excluded_json, committed)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,0)",
                params![
                    run_id,
                    stripe as i64,
                    sol.generation as i64,
                    serde_json::to_string(&sol.key_tuple).unwrap(),
                    sol.verification,
                    sol.data_digest,
                    blob.to_string_lossy().to_string(),
                    serde_json::to_string(&sol.selected).unwrap(),
                    serde_json::to_string(&sol.excluded).unwrap(),
                    serde_json::to_string(&excluded).unwrap(),
                ],
            )?;
        }

        let unique_digests: BTreeSet<String> = solutions.iter().map(|s| s.data_digest.clone()).collect();
        if unique_digests.len() > 1 {
            let detail = format!(
                "{} distinct feasible reconstructions retained (divergent)",
                unique_digests.len()
            );
            {
                let conn = db.conn.lock().unwrap();
                conn.execute(
                    "INSERT INTO stripe_states(object_id, version, stripe_index, status, generation,
                        data_digest, blob_path, evidence_json, detail, updated_run)
                     VALUES (?1,?2,?3,'ambiguous',NULL,NULL,NULL,?4,?5,?6)
                     ON CONFLICT(object_id, version, stripe_index) DO UPDATE SET
                        status='ambiguous', generation=NULL, data_digest=NULL, blob_path=NULL,
                        evidence_json=excluded.evidence_json, detail=excluded.detail, updated_run=excluded.updated_run",
                    params![
                        object_id,
                        version,
                        stripe as i64,
                        serde_json::to_string(&excluded).unwrap(),
                        detail,
                        run_id
                    ],
                )?;
            }
            for s in solutions.iter_mut() {
                s.excluded = excluded.clone();
            }
            outcomes.push(StripeOutcome {
                stripe_index: stripe,
                status: "ambiguous".into(),
                generation: Some(solutions[0].generation),
                data_digest: None,
                solutions,
                detail,
                missing_rows,
            });
            continue;
        }

        // Unique feasible output: commit atomically (temp file -> rename).
        commits_this_run += 1;
        let committed_key_tuple = solutions[0].key_tuple.clone();
        let sol = solutions.remove(0);
        let blob = committed_blob_path(db, object_id, version, stripe, &sol.data_digest);
        let tmp = db
            .tmp_dir()
            .join(format!("commit-run{run_id}-stripe{stripe}.tmp"));
        fs::write(&tmp, &sol.data)?;

        if failpoints.crash_before_commit_nth == commits_this_run {
            failpoint_hit = Some(format!("crash-before-commit on stripe {stripe}"));
            interrupted = true;
            break; // temp file deliberately remains; it must never be read
        }
        if failpoints.fail_commit_nth == commits_this_run {
            fs::remove_file(&tmp).ok();
            let _ = run_id;
            {
                let conn = db.conn.lock().unwrap();
                conn.execute("UPDATE runs SET status='failed' WHERE id=?1", params![run_id])?;
            }
            return Err(RecoveryError(format!(
                "simulated disk write failure while committing stripe {stripe}"
            )));
        }

        fs::rename(&tmp, &blob)?;
        {
            let conn = db.conn.lock().unwrap();
            conn.execute(
                "UPDATE solutions SET committed=1, blob_path=?4 WHERE run_id=?1 AND stripe_index=?2 AND data_digest=?3",
                params![run_id, stripe as i64, sol.data_digest, blob.to_string_lossy()],
            )?;
            conn.execute(
                "INSERT INTO stripe_states(object_id, version, stripe_index, status, generation,
                    data_digest, blob_path, evidence_json, detail, updated_run)
                 VALUES (?1,?2,?3,'committed',?4,?5,?6,?7,?8,?9)
                 ON CONFLICT(object_id, version, stripe_index) DO UPDATE SET
                    status='committed', generation=excluded.generation, data_digest=excluded.data_digest,
                    blob_path=excluded.blob_path, evidence_json=excluded.evidence_json,
                    detail=excluded.detail, updated_run=excluded.updated_run",
                params![
                    object_id,
                    version,
                    stripe as i64,
                    sol.generation as i64,
                    sol.data_digest,
                    blob.to_string_lossy(),
                    serde_json::to_string(&sol.excluded).unwrap(),
                    format!("committed via fragments {:?} ({})", sol.key_tuple, sol.verification),
                    run_id
                ],
            )?;
        }
        outcomes.push(StripeOutcome {
            stripe_index: stripe,
            status: "committed".into(),
            generation: Some(sol.generation),
            data_digest: Some(sol.data_digest.clone()),
            solutions: vec![StripeSolution {
                excluded: excluded.clone(),
                ..sol
            }],
            detail: format!("committed via fragments {:?}", committed_key_tuple),
            missing_rows,
        });
    }

    let report = finalize_report(db, run_id, object_id, version, &manifest, budget_total, remaining, outcomes, failpoint_hit, interrupted)?;
    Ok(report)
}

fn persist_no_solution(
    db: &Db,
    run_id: i64,
    object_id: &str,
    version: u32,
    stripe: usize,
    status: &str,
    excluded: &[ExcludedEvidence],
    detail: &str,
) -> Result<(), RecoveryError> {
    let conn = db.conn.lock().unwrap();
    conn.execute(
        "INSERT INTO stripe_states(object_id, version, stripe_index, status, generation,
            data_digest, blob_path, evidence_json, detail, updated_run)
         VALUES (?1,?2,?3,?4,NULL,NULL,NULL,?5,?6,?7)
         ON CONFLICT(object_id, version, stripe_index) DO UPDATE SET status=excluded.status,
            generation=NULL, data_digest=NULL, blob_path=NULL,
            evidence_json=excluded.evidence_json, detail=excluded.detail, updated_run=excluded.updated_run",
        params![
            object_id,
            version,
            stripe as i64,
            status,
            serde_json::to_string(excluded).unwrap(),
            detail,
            run_id
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn finalize_report(
    db: &Db,
    run_id: i64,
    object_id: &str,
    version: u32,
    manifest: &Manifest,
    budget_total: usize,
    remaining: usize,
    mut outcomes: Vec<StripeOutcome>,
    failpoint_hit: Option<String>,
    interrupted: bool,
) -> Result<RunReport, RecoveryError> {
    // Stripes never reached in an interrupted run are reported as pending and
    // remain without committed state.
    let seen: BTreeSet<usize> = outcomes.iter().map(|o| o.stripe_index).collect();
    for stripe in 0..manifest.stripe_count {
        if !seen.contains(&stripe) {
            outcomes.push(StripeOutcome {
                stripe_index: stripe,
                status: "pending".into(),
                generation: None,
                data_digest: None,
                solutions: vec![],
                detail: "not processed (run interrupted or budget exhausted)".into(),
                missing_rows: vec![],
            });
        }
    }
    outcomes.sort_by_key(|o| o.stripe_index);

    let stripe_combos_used = budget_total - remaining;
    let mut combos_considered = 0usize;
    let mut budget_exhausted = false;
    let mut global_combos: Vec<GlobalCombo> = Vec::new();

    let all_have_solutions = outcomes
        .iter()
        .all(|o| matches!(o.status.as_str(), "committed" | "reused") && !o.solutions.is_empty());
    let ambiguous_present = outcomes.iter().any(|o| o.status == "ambiguous");
    let infeasible_present = outcomes.iter().any(|o| matches!(o.status.as_str(), "infeasible" | "pending" | "length-mismatch"));

    if all_have_solutions && !infeasible_present {
        // Cartesian product over per-stripe alternatives, deterministic order.
        let per_stripe: Vec<&StripeOutcome> = outcomes.iter().collect();
        let mut indices = vec![0usize; per_stripe.len()];
        loop {
            if combos_considered >= budget_total {
                budget_exhausted = true;
                break;
            }
            combos_considered += 1;
            let mut blobs: Vec<Vec<u8>> = Vec::with_capacity(per_stripe.len());
            for (i, outcome) in per_stripe.iter().enumerate() {
                blobs.push(outcome.solutions[indices[i]].data.clone());
            }
            let digest = models::canonical_object_digest(manifest, &blobs);
            let matches_manifest = manifest.object_digest.as_ref().map(|want| {
                want.eq_ignore_ascii_case(&digest)
            });
            global_combos.push(GlobalCombo {
                selections: indices.clone(),
                object_digest: digest,
                matches_manifest,
            });

            let mut carry = 0usize;
            loop {
                indices[carry] += 1;
                if indices[carry] < per_stripe[carry].solutions.len() {
                    break;
                }
                indices[carry] = 0;
                carry += 1;
                if carry == indices.len() {
                    break;
                }
            }
            if carry == indices.len() {
                break;
            }
        }
    }

    let distinct_digests: BTreeSet<String> =
        global_combos.iter().map(|c| c.object_digest.clone()).collect();
    let matches: Vec<&GlobalCombo> = global_combos.iter().filter(|c| c.matches_manifest == Some(true)).collect();

    let (object_digest, object_digest_matches, confidence) = if let Some(want) = &manifest.object_digest {
        if matches.len() == 1 {
            (Some(matches[0].object_digest.clone()), Some(true), "trusted".to_string())
        } else if !global_combos.is_empty() {
            (Some(global_combos[0].object_digest.clone()), Some(false), "untrusted".to_string())
        } else {
            (None, Some(false), "unrecoverable".to_string())
        }
    } else if distinct_digests.len() == 1 && global_combos.len() == 1 {
        let all_strong = outcomes.iter().all(|o| {
            o.solutions
                .iter()
                .any(|s| matches!(s.verification.as_str(), "expected" | "verified" | "committed"))
        });
        let conf = if all_strong { "trusted" } else { "threshold-only" }.to_string();
        (Some(distinct_digests.into_iter().next().unwrap()), None, conf)
    } else if distinct_digests.len() > 1 || ambiguous_present {
        (None, None, "ambiguous".to_string())
    } else {
        (None, None, "unrecoverable".to_string())
    };

    let recoverable = !global_combos.is_empty()
        && !infeasible_present
        && (!ambiguous_present || manifest.object_digest.is_some() && matches.len() == 1);

    let report = RunReport {
        object_id: object_id.to_string(),
        version,
        budget: budget_total,
        combos_considered: stripe_combos_used + combos_considered,
        budget_exhausted,
        stripes: outcomes,
        global_combos,
        object_digest,
        object_digest_matches,
        recoverable,
        confidence,
        failpoint: failpoint_hit,
        interrupted,
    };

    {
        let conn = db.conn.lock().unwrap();
        let status = if interrupted {
            "interrupted"
        } else if report.recoverable {
            "complete"
        } else {
            "incomplete"
        };
        conn.execute(
            "UPDATE runs SET status=?1, report_json=?2 WHERE id=?3",
            params![status, serde_json::to_string(&report).unwrap(), run_id],
        )?;
    }
    Ok(report)
}

/// Last completed/incomplete run report for an object version, if any.
pub fn latest_run_report(db: &Db, object_id: &str, version: u32) -> Option<RunReport> {
    let conn = db.conn.lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT report_json FROM runs WHERE object_id=?1 AND version=?2 AND report_json IS NOT NULL ORDER BY id DESC LIMIT 1")
        .ok()?;
    let json: String = stmt
        .query_row(params![object_id, version], |r| r.get(0))
        .ok()?;
    serde_json::from_str(&json).ok()
}
