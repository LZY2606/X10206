//! Stripe recovery engine.
//!
//! Candidate selection is never first-come-first-served: for every stripe we
//! enumerate feasible slot/candidate combinations under deterministic order
//! and a fixed search budget, rebuild with Cauchy Reed-Solomon, and verify
//! against every known per-block digest. Distinct feasible stripes are ALL
//! retained with participating shards, excluded-corruption evidence and
//! 重新计算的摘要 recorded per outcome.
//!
//! Commits are per stripe: rebuilt blobs are staged -> promoted -> SQLite rows
//! inserted in one transaction. On restart only fully committed outcomes whose
//! blobs exist and digests still match are reused; staged leftovers are swept.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::params;
use serde::Serialize;

use crate::coding::{self, CodingParams};
use crate::db::{now_ms, Db};
use crate::digest::{sha256_hex, with_prefix};
use crate::model::{ExclusionReason, StripeStatus};
use crate::store::BlobStore;

/// Maximum combinations examined per stripe before the search is capped.
pub const SEARCH_BUDGET: usize = 1000;

#[derive(Clone, Debug)]
struct GenInfo {
    generation: u64,
    data_shards: usize,
    parity_shards: usize,
    shard_size: usize,
    stripe_count: usize,
    object_size: usize,
    object_digest: String,
}

#[derive(Clone, Debug)]
struct Candidate {
    fragment_id: i64,
    shard_index: usize,
    blob_hash: String,
    byte_length: usize,
    sources: Vec<String>,
    expected_digest: Option<String>,
    isolated_source: Option<String>,
}

#[derive(Debug)]
struct FeasibleOutcome {
    generation: u64,
    chosen: BTreeMap<usize, Candidate>,
    rebuilt: BTreeMap<usize, (String, Vec<u8>)>,
    stripe_digest: String,
    all_digests_match: bool,
    differences: Vec<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct RunReport {
    pub object_id: String,
    pub recovery_id: i64,
    pub reused: usize,
    pub recovered: usize,
    pub ambiguous: usize,
    pub below_threshold: usize,
    pub budget_exhausted: usize,
    pub failed: usize,
    pub total_stripes: usize,
    pub object_checks: Vec<ObjectCheckSummary>,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ObjectCheckSummary {
    pub generation: u64,
    pub status: String,
    pub matching_stripes: usize,
    pub stripe_count: usize,
    pub object_digest_expected: String,
    pub object_digest_actual: String,
    pub note: String,
}

fn isolated_set(db: &Db, object_id: &str) -> BTreeSet<String> {
    let conn = db.conn.lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT source FROM isolated_sources WHERE object_id=?1 ORDER BY source")
        .unwrap();
    stmt.query_map(params![object_id], |r| r.get::<_, String>(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
}

fn isolated_signature(isolated: &BTreeSet<String>) -> String {
    serde_json::to_string(isolated).unwrap_or_else(|_| "[]".into())
}

fn load_generations(db: &Db, object_id: &str) -> Vec<GenInfo> {
    let conn = db.conn.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT generation, data_shards, parity_shards, shard_size, stripe_count,
                    object_size, object_digest
             FROM generations WHERE object_id=?1 ORDER BY generation ASC",
        )
        .unwrap();
    stmt.query_map(params![object_id], |r| {
        Ok(GenInfo {
            generation: r.get(0)?,
            data_shards: r.get(1)?,
            parity_shards: r.get(2)?,
            shard_size: r.get(3)?,
            stripe_count: r.get(4)?,
            object_size: r.get(5)?,
            object_digest: r.get(6)?,
        })
    })
    .unwrap()
    .map(|r| r.unwrap())
    .collect()
}

fn expected_digest(db: &Db, object_id: &str, gen: u64, stripe: usize, shard: usize) -> Option<String> {
    let conn = db.conn.lock().unwrap();
    conn.query_row(
        "SELECT digest FROM block_digests
         WHERE object_id=?1 AND generation=?2 AND stripe_index=?3 AND shard_index=?4",
        params![object_id, gen, stripe, shard],
        |r| r.get::<_, String>(0),
    )
    .ok()
}

fn load_candidates(
    db: &Db,
    object_id: &str,
    g: &GenInfo,
    stripe: usize,
    isolated: &BTreeSet<String>,
) -> Vec<Candidate> {
    let conn = db.conn.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, shard_index, blob_hash, byte_length FROM fragments
             WHERE object_id=?1 AND generation=?2 AND stripe_index=?3
             ORDER BY shard_index ASC, id ASC",
        )
        .unwrap();
    let base: Vec<(i64, usize, String, usize)> = stmt
        .query_map(params![object_id, g.generation, stripe], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    drop(stmt);

    let mut out = Vec::new();
    for (fragment_id, shard_index, blob_hash, byte_length) in base {
        let mut src_stmt = conn
            .prepare("SELECT source FROM fragment_receipts WHERE fragment_id=?1 ORDER BY id")
            .unwrap();
        let sources: Vec<String> = src_stmt
            .query_map(params![fragment_id], |r| r.get::<_, String>(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        drop(src_stmt);
        let isolated_source = sources.iter().find(|s| isolated.contains(*s)).cloned();
        let exp: Option<String> = conn
            .query_row(
                "SELECT digest FROM block_digests
                 WHERE object_id=?1 AND generation=?2 AND stripe_index=?3 AND shard_index=?4",
                params![object_id, g.generation, stripe, shard_index],
                |r| r.get::<_, String>(0),
            )
            .ok();
        let _ = (&blob_hash, &exp);
        out.push(Candidate {
            fragment_id,
            shard_index,
            blob_hash,
            byte_length,
            sources,
            expected_digest: exp,
            isolated_source,
        });
    }
    out
}

fn usable(c: &Candidate, shard_size: usize) -> Result<(), ExclusionReason> {
    if let Some(src) = &c.isolated_source {
        return Err(ExclusionReason::SourceIsolated { source: src.clone() });
    }
    if c.byte_length != shard_size {
        return Err(ExclusionReason::LengthMismatch {
            expected: shard_size,
            actual: c.byte_length,
        });
    }
    if let Some(expected) = &c.expected_digest {
        let actual = with_prefix(&c.blob_hash);
        if actual != *expected {
            return Err(ExclusionReason::DigestMismatch {
                expected: expected.clone(),
                actual,
            });
        }
    }
    Ok(())
}

/// Enumerate k-subsets choosing one candidate per slot.
///
/// Each element is `(slot, candidate_index)`. Iteration order is lexicographic
/// by (chosen shard indices ascending, then candidate ids ascending via the
/// pre-sorted candidate lists) — fully deterministic.
fn enumerate_selections(
    slots: &[usize],
    per_slot: &BTreeMap<usize, Vec<usize>>,
    budget: usize,
) -> (Vec<Vec<usize>>, bool) {
    let mut combos: Vec<Vec<usize>> = Vec::new();
    let mut capped = false;
    fn rec(
        pos: usize,
        slots: &[usize],
        per_slot: &BTreeMap<usize, Vec<usize>>,
        current: &mut Vec<usize>,
        combos: &mut Vec<Vec<usize>>,
        budget: usize,
        capped: &mut bool,
    ) {
        if *capped {
            return;
        }
        if pos == slots.len() {
            if combos.len() >= budget {
                *capped = true;
                return;
            }
            combos.push(current.clone());
            return;
        }
        for &ci in &per_slot[&slots[pos]] {
            current.push(ci);
            rec(pos + 1, slots, per_slot, current, combos, budget, capped);
            current.pop();
            if *capped {
                return;
            }
        }
    }
    let mut current = Vec::new();
    rec(0, slots, per_slot, &mut current, &mut combos, budget, &mut capped);
    (combos, capped)
}

struct GenerationAttempt {
    gen: u64,
    n: usize,
    feasible: Vec<FeasibleOutcome>,
    capped: bool,
    /// (candidate, reason) for receipts that could not participate.
    unusable: Vec<(Candidate, ExclusionReason)>,
    /// All healthy/usable candidate ids in this generation's slots, for
    /// "participated but not selected" evidence.
    usable: Vec<Candidate>,
    below_threshold: bool,
}

fn attempt_generation(
    db: &Db,
    store: &BlobStore,
    object_id: &str,
    g: &GenInfo,
    stripe: usize,
    isolated: &BTreeSet<String>,
) -> Result<GenerationAttempt, String> {
    let params = CodingParams {
        data_shards: g.data_shards,
        parity_shards: g.parity_shards,
        shard_size: g.shard_size,
    };
    let n = g.data_shards + g.parity_shards;
    let candidates = load_candidates(db, object_id, g, stripe, isolated);

    // Group by slot; record unusable evidence.
    let mut by_slot: BTreeMap<usize, Vec<Candidate>> = BTreeMap::new();
    let mut unusable: Vec<(Candidate, ExclusionReason)> = Vec::new();
    for c in candidates {
        match usable(&c, g.shard_size) {
            Ok(()) => by_slot.entry(c.shard_index).or_default().push(c),
            Err(reason) => unusable.push((c, reason)),
        }
    }

    let slots: Vec<usize> = by_slot.keys().copied().collect();
    let mut feasible: Vec<FeasibleOutcome> = Vec::new();
    let mut seen_keys: BTreeSet<String> = BTreeSet::new();

    let below_threshold = slots.len() < g.data_shards;
    let usable_all: Vec<Candidate> = by_slot.values().flatten().cloned().collect();
    if below_threshold {
        return Ok(GenerationAttempt {
            gen: g.generation,
            n,
            feasible: Vec::new(),
            capped: false,
            unusable,
            usable: usable_all,
            below_threshold: true,
        });
    }

    // Choose which k slots to use: lexicographic k-subsets of slot indices.
    let mut slot_combos: Vec<Vec<usize>> = Vec::new();
    {
        fn gen_subsets(
            start: usize,
            need: usize,
            slots: &[usize],
            current: &mut Vec<usize>,
            out: &mut Vec<Vec<usize>>,
        ) {
            if need == 0 {
                out.push(current.clone());
                return;
            }
            for i in start..=(slots.len() - need) {
                current.push(slots[i]);
                gen_subsets(i + 1, need - 1, slots, current, out);
                current.pop();
            }
        }
        let mut current = Vec::new();
        gen_subsets(0, g.data_shards, &slots, &mut current, &mut slot_combos);
    }

    let mut budget_left = SEARCH_BUDGET;
    let mut cap_hit = false;

    for chosen_slots in slot_combos {
        if budget_left == 0 {
            cap_hit = true;
            break;
        }
        let mut per_slot: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for s in &chosen_slots {
            let v: Vec<usize> = (0..by_slot[s].len()).collect();
            per_slot.insert(*s, v);
        }
        let (picks, capped) = enumerate_selections(&chosen_slots, &per_slot, budget_left);
        if capped {
            cap_hit = true;
        }
        budget_left = budget_left.saturating_sub(picks.len());

        for pick in picks {
            let mut available: Vec<(usize, Vec<u8>)> = Vec::new();
            let mut chosen: BTreeMap<usize, Candidate> = BTreeMap::new();
            for (slot, ci) in chosen_slots.iter().zip(pick.iter()) {
                let cand = by_slot[slot][*ci].clone();
                let bytes = match store.read(&cand.blob_hash) {
                    Ok(b) => b,
                    Err(_) => {
                        let hash = cand.blob_hash.clone();
                        unusable.push((cand, ExclusionReason::BlobMissing { hash }));
                        continue;
                    }
                };
                available.push((cand.shard_index, bytes));
                chosen.insert(cand.shard_index, cand);
            }
            if available.len() != g.data_shards {
                continue;
            }
            let rebuilt_all = match coding::reconstruct(&available, params) {
                Ok(r) => r,
                Err(_) => continue,
            };

            // Verify every shard position against known digests.
            let mut all_match = true;
            let mut rebuilt = BTreeMap::new();
            for shard in 0..n {
                let bytes = rebuilt_all[shard].clone();
                let recomputed = with_prefix(&sha256_hex(&bytes));
                let expected = expected_digest(db, object_id, g.generation, stripe, shard);
                if let Some(e) = &expected {
                    if *e != recomputed {
                        all_match = false;
                    }
                }
                if !chosen.contains_key(&shard) {
                    rebuilt.insert(shard, (sha256_hex(&bytes), bytes));
                }
            }
            let stripe_digest = sha256_hex(&rebuilt_all.concat());
            if !seen_keys.insert(stripe_digest.clone()) {
                continue;
            }

            // Differences vs manifest expectations (per shard digest lines).
            let mut differences = Vec::new();
            for shard in 0..n {
                let recomputed = with_prefix(&sha256_hex(&rebuilt_all[shard]));
                if let Some(e) = expected_digest(db, object_id, g.generation, stripe, shard) {
                    if e != recomputed {
                        differences.push(format!(
                            "shard {} 摘要不一致：期望 {}，重建 {}",
                            shard,
                            crate::model::short(&e),
                            crate::model::short(&recomputed)
                        ));
                    }
                }
            }
            feasible.push(FeasibleOutcome {
                generation: g.generation,
                chosen,
                rebuilt,
                stripe_digest,
                all_digests_match: all_match,
                differences,
            });
        }
    }

    Ok(GenerationAttempt {
        gen: g.generation,
        n,
        feasible,
        capped: cap_hit,
        unusable,
        usable: usable_all,
        below_threshold: false,
    })
}

/// Outcome chosen for the stripe pointer.
#[derive(Debug)]
struct CommittedStripe {
    generation: u64,
    outcome_id: i64,
    ambiguous: bool,
}

/// Persist one stripe attempt. Promotes staged rebuilt blobs first; all DB
/// writes for the stripe happen in a single transaction.
fn commit_stripe(
    db: &Db,
    store: &BlobStore,
    recovery_id: i64,
    object_id: &str,
    stripe: usize,
    attempts: &[GenerationAttempt],
    status: StripeStatus,
    note: &str,
    isolated_sig: &str,
) -> std::io::Result<Option<CommittedStripe>> {
    // Flatten and rank feasible outcomes: higher generation first, then
    // deterministic stripe digest. Feasible outcomes from every generation
    // are retained.
    let mut ranked: Vec<(usize, &FeasibleOutcome)> = attempts
        .iter()
        .enumerate()
        .flat_map(|(gi, a)| a.feasible.iter().map(move |f| (gi, f)))
        .collect();
    ranked.sort_by(|(gi_a, a), (gi_b, b)| {
        let ga = attempts[*gi_a].gen;
        let gb = attempts[*gi_b].gen;
        gb.cmp(&ga)
            .then_with(|| a.stripe_digest.cmp(&b.stripe_digest))
    });
    let ambiguous = ranked.len() > 1;

    // Stage + promote all rebuilt blobs up front so the transaction never has
    // to perform IO that could be injected-failure mid-commit.
    let mut promoted: BTreeMap<String, String> = BTreeMap::new();
    for (_, outcome) in &ranked {
        for (_, (hash, bytes)) in &outcome.rebuilt {
            if promoted.contains_key(hash) || store.contains(hash) {
                promoted.insert(hash.clone(), hash.clone());
                continue;
            }
            let staged = store.stage(bytes)?;
            store.promote(&staged)?;
            promoted.insert(hash.clone(), hash.clone());
        }
    }

    let ts = now_ms();
    let mut committed: Option<CommittedStripe> = None;
    let mut tx = db.conn.lock().unwrap();
    let txn = tx.transaction().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    if ranked.is_empty() {
        // Infeasible: keep one non-feasible outcome row PER attempted
        // generation so corruption evidence from every candidate set is
        // visible (e.g. G0 below threshold while G1 has a partial write).
        for att in attempts.iter() {
            txn.execute(
                "INSERT INTO outcomes
                 (recovery_id, object_id, stripe_index, generation, rank, feasible,
                  outcome_key, stripe_digest, all_digests_match, differences_json, error)
                 VALUES (?1,?2,?3,?4,-1,0,'','',0,'[]',?5)",
                params![recovery_id, object_id, stripe as i64, att.gen as i64, note],
            )
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
            let oid = txn.last_insert_rowid();
            write_evidence(&txn, oid, att, None)?;
        }
        txn.execute(
            "INSERT INTO stripes
             (object_id, stripe_index, active_recovery_id, active_outcome_id,
              generation, isolated_signature, status, ambiguous, note, updated_at)
             VALUES (?1,?2,NULL,NULL,NULL,?3,?4,0,?5,?6)
             ON CONFLICT(object_id, stripe_index) DO UPDATE SET
               active_recovery_id=NULL, active_outcome_id=NULL, generation=NULL,
               isolated_signature=excluded.isolated_signature,
               status=excluded.status, ambiguous=0, note=excluded.note,
               updated_at=excluded.updated_at",
            params![
                object_id,
                stripe as i64,
                isolated_sig,
                status.as_str(),
                note,
                ts
            ],
        )
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        txn.commit().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        return Ok(None);
    }

    for (rank, (gi, outcome)) in ranked.iter().enumerate() {
        let att = &attempts[*gi];
        txn.execute(
            "INSERT INTO outcomes
             (recovery_id, object_id, stripe_index, generation, rank, feasible,
              outcome_key, stripe_digest, all_digests_match, differences_json)
             VALUES (?1,?2,?3,?4,?5,1,?6,?7,?8,?9)",
            params![
                recovery_id,
                object_id,
                stripe as i64,
                outcome.generation as i64,
                rank as i64,
                outcome.stripe_digest,
                outcome.stripe_digest,
                outcome.all_digests_match as i64,
                serde_json::to_string(&outcome.differences).unwrap_or_else(|_| "[]".into()),
            ],
        )
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        let oid = txn.last_insert_rowid();

        // Blocks + recomputed digests for every position.
        let chosen_ids: BTreeSet<i64> = outcome.chosen.values().map(|c| c.fragment_id).collect();
        for shard in 0..(att.n) {
            let recomputed = if let Some((hash, bytes)) = outcome.rebuilt.get(&shard) {
                let _ = hash;
                with_prefix(&sha256_hex(bytes))
            } else if let Some(cand) = outcome.chosen.get(&shard) {
                with_prefix(&cand.blob_hash)
            } else {
                continue;
            };
            let expected: String = txn
                .query_row(
                    "SELECT COALESCE(digest,'') FROM block_digests
                     WHERE object_id=?1 AND generation=?2 AND stripe_index=?3 AND shard_index=?4",
                    params![object_id, outcome.generation, stripe, shard],
                    |r| r.get(0),
                )
                .unwrap_or_default();
            let matches_expected = expected.is_empty() || expected == recomputed;
            let fragment_id = outcome.chosen.get(&shard).map(|c| c.fragment_id);
            let hash = if let Some(cand) = outcome.chosen.get(&shard) {
                cand.blob_hash.clone()
            } else {
                outcome.rebuilt[&shard].0.clone()
            };
            txn.execute(
                "INSERT INTO outcome_blocks
                 (outcome_id, shard_index, fragment_id, blob_hash, recomputed_digest,
                  expected_digest, matches_expected, rebuilt)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    oid,
                    shard as i64,
                    fragment_id,
                    hash,
                    recomputed,
                    expected,
                    matches_expected as i64,
                    fragment_id.is_none() as i64
                ],
            )
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        }

        // Evidence: participating shards, rebuilt gaps, excluded corruption.
        for c in outcome.chosen.values() {
            txn.execute(
                "INSERT INTO outcome_evidence
                 (outcome_id, shard_index, fragment_id, receipt_source, role, reason)
                 VALUES (?1,?2,?3,?4,'participant','')",
                params![
                    oid,
                    c.shard_index as i64,
                    c.fragment_id,
                    c.sources.join(",")
                ],
            )
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        }
        for shard in outcome.rebuilt.keys() {
            txn.execute(
                "INSERT INTO outcome_evidence
                 (outcome_id, shard_index, fragment_id, receipt_source, role, reason)
                 VALUES (?1,?2,NULL,'','rebuilt','')",
                params![oid, *shard as i64],
            )
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        }
        write_evidence(&txn, oid, att, Some(&chosen_ids))?;

        if rank == 0 {
            committed = Some(CommittedStripe {
                generation: outcome.generation,
                outcome_id: oid,
                ambiguous,
            });
        }
    }

    let active = committed.as_ref().unwrap();
    txn.execute(
        "INSERT INTO stripes
         (object_id, stripe_index, active_recovery_id, active_outcome_id,
          generation, isolated_signature, status, ambiguous, note, updated_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
         ON CONFLICT(object_id, stripe_index) DO UPDATE SET
           active_recovery_id=excluded.active_recovery_id,
           active_outcome_id=excluded.active_outcome_id,
           generation=excluded.generation,
           isolated_signature=excluded.isolated_signature,
           status=excluded.status,
           ambiguous=excluded.ambiguous,
           note=excluded.note,
           updated_at=excluded.updated_at",
        params![
            object_id,
            stripe as i64,
            recovery_id,
            active.outcome_id,
            active.generation as i64,
            isolated_sig,
            status.as_str(),
            active.ambiguous as i64,
            note,
            ts
        ],
    )
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    txn.commit().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    Ok(committed)
}



/// Write corruption / exclusion evidence. `selected_ids` (Some) adds
/// `excluded_unselected` rows for healthy candidates not used; None records
/// all unusable reasons (below-threshold case).
fn write_evidence(
    txn: &rusqlite::Transaction,
    oid: i64,
    att: &GenerationAttempt,
    selected_ids: Option<&BTreeSet<i64>>,
) -> std::io::Result<()> {
    for (cand, reason) in &att.unusable {
        let reason_json = serde_json::to_string(reason).unwrap_or_default();
        txn.execute(
            "INSERT INTO outcome_evidence
             (outcome_id, shard_index, fragment_id, receipt_source, role, reason)
             VALUES (?1,?2,?3,?4,'excluded_corrupt',?5)",
            params![
                oid,
                cand.shard_index as i64,
                cand.fragment_id,
                cand.sources.join(","),
                reason_json
            ],
        )
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    }
    if let Some(sel) = selected_ids {
        for cand in &att.usable {
            if !sel.contains(&cand.fragment_id) {
                let reason = ExclusionReason::NotSelected;
                txn.execute(
                    "INSERT INTO outcome_evidence
                     (outcome_id, shard_index, fragment_id, receipt_source, role, reason)
                     VALUES (?1,?2,?3,?4,'excluded_unselected',?5)",
                    params![
                        oid,
                        cand.shard_index as i64,
                        cand.fragment_id,
                        cand.sources.join(","),
                        serde_json::to_string(&reason).unwrap_or_default()
                    ],
                )
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
            }
        }
    }
    Ok(())
}

/// Verify a previously committed outcome is still fully usable: every block
/// blob exists, and every expected digest still matches.
fn committed_outcome_valid(
    db: &Db,
    store: &BlobStore,
    _object_id: &str,
    outcome_id: i64,
) -> bool {
    let conn = db.conn.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT blob_hash, recomputed_digest, expected_digest, matches_expected
             FROM outcome_blocks WHERE outcome_id=?1 ORDER BY shard_index",
        )
        .unwrap();
    let rows: Vec<(String, String, String, i64)> = stmt
        .query_map(params![outcome_id], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    drop(stmt);
    let gen: u64 = conn
        .query_row("SELECT generation FROM outcomes WHERE id=?1", params![outcome_id], |r| {
            r.get::<_, i64>(0)
        })
        .map(|v| v as u64)
        .unwrap_or(0);
    drop(conn);

    if rows.is_empty() {
        return false;
    }
    for (hash, recomputed, expected, matches) in rows {
        if !store.contains(&hash) {
            return false;
        }
        let bytes = match store.read(&hash) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let actual = with_prefix(&sha256_hex(&bytes));
        if actual != recomputed {
            return false;
        }
        if !expected.is_empty() && (expected != actual || matches == 0) {
            return false;
        }
    }
    let _ = gen;
    true
}

/// Read active blocks of one stripe in shard order: (shard_index, generation, bytes).
fn read_active_stripe(
    db: &Db,
    store: &BlobStore,
    object_id: &str,
    stripe: usize,
) -> Option<(i64, Vec<(usize, Vec<u8>)>)> {
    let conn = db.conn.lock().unwrap();
    let (outcome_id, gen): (i64, i64) = conn
        .query_row(
            "SELECT s.active_outcome_id, o.generation
             FROM stripes s JOIN outcomes o ON o.id = s.active_outcome_id
             WHERE s.object_id=?1 AND s.stripe_index=?2 AND s.active_outcome_id IS NOT NULL",
            params![object_id, stripe as i64],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok()?;
    let mut stmt = conn
        .prepare(
            "SELECT shard_index, blob_hash FROM outcome_blocks
             WHERE outcome_id=?1 ORDER BY shard_index",
        )
        .unwrap();
    let rows: Vec<(i64, String)> = stmt
        .query_map(params![outcome_id], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    drop(stmt);
    drop(conn);
    let mut out = Vec::new();
    for (shard, hash) in rows {
        match store.read(&hash) {
            Ok(b) => out.push((shard as usize, b)),
            Err(_) => return None,
        }
    }
    Some((gen, out))
}

pub struct RecoveryOptions {
    pub trigger: String,
    pub force: bool,
}

pub fn run_recovery(
    db: &Db,
    store: &BlobStore,
    object_id: &str,
    opts: RecoveryOptions,
) -> RunReport {
    let gens = load_generations(db, object_id);
    let total_stripes = gens.iter().map(|g| g.stripe_count).max().unwrap_or(0);
    let isolated = isolated_set(db, object_id);
    let sig = isolated_signature(&isolated);

    let mut report = RunReport {
        object_id: object_id.to_string(),
        total_stripes,
        ..Default::default()
    };

    let ts = now_ms();
    let recovery_id = {
        let conn = db.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO recoveries
             (object_id, started_at, forced, trigger, isolated_signature)
             VALUES (?1,?2,?3,?4,?5)",
            params![object_id, ts, opts.force as i64, opts.trigger, sig],
        )
        .unwrap();
        conn.last_insert_rowid()
    };
    report.recovery_id = recovery_id;

    for stripe in 0..total_stripes {
        // Reuse only when not forced, isolation signature matches, and the
        // committed outcome survives full re-verification.
        let mut reuse = None;
        if !opts.force {
            let conn = db.conn.lock().unwrap();
            let prior: Option<(i64, String, i64)> = conn
                .query_row(
                    "SELECT active_outcome_id, isolated_signature, ambiguous FROM stripes
                     WHERE object_id=?1 AND stripe_index=?2 AND active_outcome_id IS NOT NULL",
                    params![object_id, stripe as i64],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .ok();
            drop(conn);
            if let Some((oid, prior_sig, ambiguous)) = prior {
                if prior_sig == sig && committed_outcome_valid(db, store, object_id, oid) {
                    reuse = Some((oid, ambiguous != 0));
                }
            }
        }
        if let Some((_, ambiguous)) = reuse {
            report.reused += 1;
            if ambiguous {
                report.ambiguous += 1;
            }
            continue;
        }

        let mut attempts = Vec::new();
        let mut any_capped = false;
        let mut attempted_any_gen = false;
        for g in &gens {
            attempted_any_gen = true;
            if stripe >= g.stripe_count {
                // Partial write: this generation does not even cover the
                // stripe. Record a synthetic below-threshold attempt so its
                // absence is visible as evidence rather than silently ignored.
                attempts.push(GenerationAttempt {
                    gen: g.generation,
                    n: g.data_shards + g.parity_shards,
                    feasible: Vec::new(),
                    capped: false,
                    unusable: Vec::new(),
                    usable: Vec::new(),
                    below_threshold: true,
                });
                continue;
            }
            match attempt_generation(db, store, object_id, g, stripe, &isolated) {
                Ok(att) => {
                    any_capped |= att.capped;
                    attempts.push(att);
                }
                Err(e) => {
                    report.errors.push(format!("stripe {}: {}", stripe, e));
                }
            }
        }

        let any_feasible = attempts.iter().any(|a| !a.feasible.is_empty());
        let all_below = !attempts.is_empty()
            && attempts.iter().all(|a| a.below_threshold && a.feasible.is_empty());
        let (status, note) = if any_feasible {
            let ranked_count: usize = attempts.iter().map(|a| a.feasible.len()).sum();
            if ranked_count > 1 {
                (StripeStatus::Ambiguous, "存在多个可行重建，已保留全部".to_string())
            } else {
                (StripeStatus::Recovered, String::new())
            }
        } else if any_capped {
            (StripeStatus::BudgetExhausted, format!("搜索预算 {} 耗尽", SEARCH_BUDGET))
        } else if all_below || attempted_any_gen {
            (
                StripeStatus::BelowThreshold,
                format!("可用 shard 少于恢复下限 k（搜索预算 {}）", SEARCH_BUDGET),
            )
        } else {
            (StripeStatus::Failed, "无可用 generation".to_string())
        };

        match commit_stripe(db, store, recovery_id, object_id, stripe, &attempts, status, &note, &sig)
        {
            Ok(_committed) => match status {
                StripeStatus::Recovered => report.recovered += 1,
                StripeStatus::Ambiguous => {
                    report.ambiguous += 1;
                    report.recovered += 1;
                }
                StripeStatus::BelowThreshold => report.below_threshold += 1,
                StripeStatus::BudgetExhausted => report.budget_exhausted += 1,
                StripeStatus::Failed => report.failed += 1,
                StripeStatus::NotAttempted => {}
            },
            Err(e) => {
                report.failed += 1;
                report.errors.push(format!("stripe {} 提交失败：{}", stripe, e));
                let conn = db.conn.lock().unwrap();
                conn.execute(
                    "INSERT INTO stripes
                     (object_id, stripe_index, active_recovery_id, active_outcome_id,
                      generation, isolated_signature, status, ambiguous, note, updated_at)
                     VALUES (?1,?2,NULL,NULL,NULL,?3,'failed',0,?4,?5)
                     ON CONFLICT(object_id, stripe_index) DO UPDATE SET
                       active_recovery_id=NULL, active_outcome_id=NULL, generation=NULL,
                       isolated_signature=excluded.isolated_signature,
                       status='failed', ambiguous=0, note=excluded.note,
                       updated_at=excluded.updated_at",
                    params![object_id, stripe as i64, sig, e.to_string(), now_ms()],
                )
                .unwrap();
            }
        }
    }

    // Object-level verification per generation.
    report.object_checks = verify_object(db, store, object_id, recovery_id, &gens);

    {
        let conn = db.conn.lock().unwrap();
        conn.execute(
            "UPDATE recoveries SET finished_at=?1 WHERE id=?2",
            params![now_ms(), recovery_id],
        )
        .unwrap();
    }
    report
}

fn verify_object(
    db: &Db,
    store: &BlobStore,
    object_id: &str,
    recovery_id: i64,
    gens: &[GenInfo],
) -> Vec<ObjectCheckSummary> {
    // Active stripe outcomes by stripe index.
    let mut active: BTreeMap<usize, (i64, Vec<(usize, Vec<u8>)>)> = BTreeMap::new();
    for stripe in 0..gens.iter().map(|g| g.stripe_count).max().unwrap_or(0) {
        if let Some(v) = read_active_stripe(db, store, object_id, stripe) {
            active.insert(stripe, v);
        }
    }

    let mut summaries = Vec::new();
    for g in gens {
        let k = g.data_shards;
        let shard_size = g.shard_size;
        let mut matching = 0usize;
        let mut assembled: Vec<u8> = Vec::with_capacity(g.object_size);
        let mut ok = true;

        for stripe in 0..g.stripe_count {
            let Some((gen_id, blocks)) = active.get(&stripe) else {
                ok = false;
                continue;
            };
            if *gen_id as u64 != g.generation {
                ok = false; // generation mixing across stripes
                continue;
            }
            // Data shards 0..k in order.
            let mut stripe_bytes = vec![0u8; k * shard_size];
            let mut complete = true;
            for (shard, bytes) in blocks {
                if *shard < k {
                    if bytes.len() != shard_size {
                        complete = false;
                        break;
                    }
                    stripe_bytes[*shard * shard_size..(*shard + 1) * shard_size]
                        .copy_from_slice(bytes);
                }
            }
            if !complete {
                ok = false;
                continue;
            }
            assembled.extend_from_slice(&stripe_bytes);
            // Compare this stripe's data against expected data-shard digests.
            let mut stripe_ok = true;
            for shard in 0..k {
                let Some(expected) = expected_digest(db, object_id, g.generation, stripe, shard)
                else {
                    continue;
                };
                let actual = with_prefix(&sha256_hex(
                    &stripe_bytes[shard * shard_size..(shard + 1) * shard_size],
                ));
                if actual != expected {
                    stripe_ok = false;
                }
            }
            if stripe_ok {
                matching += 1;
            } else {
                ok = false;
            }
        }

        assembled.truncate(g.object_size);
        let actual_digest = with_prefix(&sha256_hex(&assembled));
        let expected_digest = g.object_digest.clone();
        let digest_ok = expected_digest.is_empty() || actual_digest == expected_digest;
        if !digest_ok {
            ok = false;
        }

        let status = if ok && matching == g.stripe_count {
            "verified"
        } else if matching == 0 {
            "unrecoverable"
        } else {
            "partial"
        };
        let note = if ok {
            String::new()
        } else if !digest_ok {
            format!("对象摘要不一致：期望 {}，实际 {}", crate::model::short(&expected_digest), crate::model::short(&actual_digest))
        } else {
            format!("{}/{} 个 stripe 属于该 generation 且摘要一致", matching, g.stripe_count)
        };

        let summary = ObjectCheckSummary {
            generation: g.generation,
            status: status.to_string(),
            matching_stripes: matching,
            stripe_count: g.stripe_count,
            object_digest_expected: expected_digest,
            object_digest_actual: actual_digest,
            note,
        };
        {
            let conn = db.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO object_checks
                 (recovery_id, object_id, generation, stripe_count, matching_stripes,
                  status, object_digest_expected, object_digest_actual, note)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    recovery_id,
                    object_id,
                    g.generation as i64,
                    g.stripe_count as i64,
                    matching as i64,
                    status,
                    summary.object_digest_expected,
                    summary.object_digest_actual,
                    summary.note
                ],
            )
            .unwrap();
        }
        summaries.push(summary);
    }
    summaries
}
