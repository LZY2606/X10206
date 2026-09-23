//! Recovery orchestration: per-stripe commit, crash-safe resume and atomic
//! export. Reconstruction bytes live only in memory until a stripe commits;
//! `work/` staging is never read as a final result.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::digest::{object_bytes, object_data_digest};
use crate::gf256::Gf256;
use crate::model::{RunReport, StripeReport, StripeStatus};
use crate::recovery::{classify, enumerate_stripe, Ambiguity, SEARCH_BUDGET};
use crate::store::Store;

static RUN_SEQ: AtomicU64 = AtomicU64::new(0);

pub struct RunOptions {
    pub run_id: Option<String>,
    /// Resume an interrupted run: reuse verified committed stripes.
    pub resume: bool,
}

impl Default for RunOptions {
    fn default() -> Self {
        RunOptions {
            run_id: None,
            resume: true,
        }
    }
}

fn new_run_id(object_id: &str) -> String {
    let seq = RUN_SEQ.fetch_add(1, Ordering::Relaxed);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("run-{}-{}-{}", sanitize(object_id), ts, seq)
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

/// Result summary returned by [`recover_object`].
pub struct RecoveryOutcome {
    pub report: RunReport,
    pub ambiguities: Vec<Ambiguity>,
    /// Object bytes when every stripe committed as unique (or ambiguity was
    /// resolved by the object digest); `None` otherwise.
    pub object_bytes: Option<Vec<u8>>,
    pub committed_shards: Vec<Vec<Vec<u8>>>,
}

/// Run recovery for one object, committing stripe by stripe.
pub fn recover_object(
    store: &Store,
    object_id: &str,
    options: RunOptions,
) -> Result<RecoveryOutcome, String> {
    let manifest = store
        .get_manifest(object_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("unknown object {object_id}"))?;
    let gf = Gf256::new();

    let run_id = options
        .run_id
        .clone()
        .unwrap_or_else(|| new_run_id(object_id));
    let started_at = crate::store::store_atomic_ts();

    // Resume: only committed stripes whose bytes re-verify are reusable.
    let reusable: std::collections::HashSet<i64> = if options.resume {
        store
            .verify_committed(
                object_id,
                manifest.shard_len,
                manifest.k,
                manifest.m,
            )
            .into_iter()
            .collect()
    } else {
        std::collections::HashSet::new()
    };

    // Reuse the prior in-memory reports for committed stripes if present so
    // participants/exclusions survive a resume; otherwise synthesize them
    // from the committed row.
    let prior: Option<RunReport> = store
        .last_run(object_id)
        .ok()
        .flatten()
        .and_then(|(_, json)| serde_json::from_str(&json).ok());

    let groups = classify(store, &manifest);
    let mut stripes: Vec<StripeReport> = Vec::new();
    let mut reused = 0usize;

    for group in groups {
        let stripe_idx = group.stripe;
        if reusable.contains(&(stripe_idx as i64)) {
            reused += 1;
            let report = prior
                .as_ref()
                .and_then(|p| p.stripes.iter().find(|r| r.stripe == stripe_idx))
                .cloned()
                .unwrap_or_else(|| committed_placeholder_report(store, object_id, stripe_idx));
            stripes.push(report);
            continue;
        }

        let report = enumerate_stripe(
            &gf,
            &manifest,
            group.stripe,
            &group.healthy,
            &group.exclusions,
        );

        // Commit per stripe immediately so an interruption preserves work.
        commit_report(store, object_id, &manifest, &run_id, &report)?;
        stripes.push(report);
    }

    // Global object-digest resolution of multiple feasible answers.
    let mut committed_shards: Vec<Vec<Vec<u8>>> = Vec::new();
    let mut ambiguities = Vec::new();
    let mut unique_count = 0usize;
    let mut ambiguous_unresolved = 0usize;
    let mut infeasible_count = 0usize;
    let mut truncated = false;

    for report in &stripes {
        truncated |= report.truncated;
        if report.status == StripeStatus::Infeasible {
            infeasible_count += 1;
        }
    }

    // Returns a per-stripe chosen solution index. Ambiguous stripes are
    // `Some(idx)` only when the global object digest selects them.
    let selections = resolve_with_object_digest(&manifest, &stripes);
    let mut stripes = stripes;
    for (i, sel) in selections.iter().enumerate() {
        if stripes[i].status == StripeStatus::Ambiguous {
            if sel.is_some() {
                stripes[i].resolved = true;
            } else {
                ambiguous_unresolved += 1;
            }
        }
        if stripes[i].status == StripeStatus::Unique {
            unique_count += 1;
        }
    }
    let ambiguous_total = stripes
        .iter()
        .filter(|r| r.status == StripeStatus::Ambiguous)
        .count();

    for report in &stripes {
        if report.status == StripeStatus::Ambiguous {
            let chosen = selections[report.stripe].unwrap_or(0);
            let diff = if report.solutions.len() >= 2 {
                crate::recovery::solution_diff(&report.solutions[0], &report.solutions[1])
            } else {
                Vec::new()
            };
            ambiguities.push(Ambiguity {
                stripe: report.stripe,
                answer_count: report.solutions.len(),
                generations: report.solutions.iter().map(|s| s.generation).collect(),
                differing_shards: diff,
            });
            committed_shards.push(report.solutions[chosen].shards.clone());
        } else if report.status == StripeStatus::Unique {
            committed_shards.push(report.solutions[0].shards.clone());
        } else {
            committed_shards.push(Vec::new());
        }
    }

    let fully_resolved =
        infeasible_count == 0 && ambiguous_unresolved == 0 && !truncated;

    // Two-phase stripe commit: enumeration committed every stripe eagerly;
    // now upgrade ambiguous stripes that the global object digest selected,
    // writing the chosen reconstruction as the committed block.
    if infeasible_count == 0 {
        for report in &stripes {
            if report.status == StripeStatus::Ambiguous {
                if let Some(chosen) = selections[report.stripe] {
                    commit_solution(
                        store, object_id, &manifest, &run_id, report, chosen, true,
                    )?;
                }
            }
        }
    }

    let object_bytes_opt = if fully_resolved {
        Some(object_bytes(&committed_shards, manifest.k))
    } else {
        None
    };

    let mut run_report = RunReport {
        run_id: run_id.clone(),
        object_id: object_id.to_string(),
        committed: unique_count,
        ambiguous: ambiguous_total,
        infeasible: infeasible_count,
        total: stripes.len(),
        reused,
        truncated,
        stripes,
        started_at,
        finished_at: None,
    };

    store
        .start_run(&run_id, object_id, &serde_json::to_string(&run_report).unwrap())
        .map_err(|e| e.to_string())?;
    run_report.finished_at = Some(crate::store::store_atomic_ts());
    store
        .finish_run(
            &run_id,
            if fully_resolved { "complete" } else { "blocked" },
            &serde_json::to_string(&run_report).unwrap(),
        )
        .map_err(|e| e.to_string())?;

    Ok(RecoveryOutcome {
        report: run_report,
        ambiguities,
        object_bytes: object_bytes_opt,
        committed_shards,
    })
}

fn commit_report(
    store: &Store,
    object_id: &str,
    manifest: &crate::model::Manifest,
    run_id: &str,
    report: &StripeReport,
) -> Result<(), String> {
    if report.status == StripeStatus::Infeasible {
        let conn = store.db_lock();
        conn.execute(
            "DELETE FROM committed_stripes WHERE object_id=?1 AND stripe=?2",
            rusqlite::params![object_id, report.stripe as i64],
        )
        .map_err(|e| e.to_string())?;
        drop(conn);
        return Ok(());
    }
    commit_solution(store, object_id, manifest, run_id, report, 0, report.resolved)
}

fn commit_solution(
    store: &Store,
    object_id: &str,
    _manifest: &crate::model::Manifest,
    run_id: &str,
    report: &StripeReport,
    solution_index: usize,
    resolved: bool,
) -> Result<(), String> {
    let sol = &report.solutions[solution_index];
    let status = match report.status {
        StripeStatus::Unique => "committed",
        StripeStatus::Ambiguous => {
            if resolved {
                "committed"
            } else {
                "ambiguous"
            }
        }
        StripeStatus::Infeasible => "infeasible",
    };
    store
        .commit_stripe(
            object_id,
            report.stripe,
            sol.codec_version,
            sol.generation,
            status,
            resolved,
            report.solutions.len(),
            &sol.participant_ids,
            &sol.witness_ids,
            &serde_json::to_string(&sol.exclusions).unwrap(),
            &sol.stripe_digest,
            &sol.data_digest,
            &sol.shards,
            run_id,
        )
        .map_err(|e| format!("commit write failed for stripe {}: {e}", report.stripe))
}

fn committed_placeholder_report(
    store: &Store,
    object_id: &str,
    stripe: usize,
) -> StripeReport {
    use crate::model::{Exclusion, Solution};
    let rows = store.committed_stripes(object_id).unwrap_or_default();
    let row = rows.into_iter().find(|r| r.stripe as usize == stripe);
    match row {
        Some(row) => {
            let exclusions: Vec<Exclusion> =
                serde_json::from_str(&row.exclusions_json).unwrap_or_default();
            let participant_ids: Vec<i64> =
                serde_json::from_str(&row.participant_ids).unwrap_or_default();
            let witness_ids: Vec<i64> =
                serde_json::from_str(&row.witness_ids).unwrap_or_default();
            let status = match row.status.as_str() {
                "ambiguous" => StripeStatus::Ambiguous,
                _ => StripeStatus::Unique,
            };
            // On resume the committed bytes are re-verified; reflect them as a
            // single solution without re-reading shards (UI uses blob digest).
            let manifest = store.get_manifest(object_id).ok().flatten();
            let shards = if let Some(m) = manifest {
                let flat = store
                    .read_blob(&row.blob_path)
                    .unwrap_or_default();
                flat.chunks(m.shard_len).map(|c| c.to_vec()).collect()
            } else {
                Vec::new()
            };
            StripeReport {
                stripe,
                status,
                exclusions: Vec::new(),
                truncated: false,
                combos_considered: 0,
                solutions: vec![Solution {
                    codec_version: row.codec_version,
                    generation: row.generation,
                    participant_ids,
                    witness_ids,
                    exclusions,
                    shards,
                    stripe_digest: row.stripe_digest,
                    data_digest: row.data_digest,
                }],
                resolved: false,
            }
        }
        None => StripeReport {
            stripe,
            status: StripeStatus::Infeasible,
            solutions: vec![],
            exclusions: vec![],
            truncated: false,
            combos_considered: 0,
            resolved: false,
        },
    }
}

/// For each stripe, choose the solution index consistent with the global
/// object digest. Unique stripes resolve to 0; ambiguous stripes return
/// `None` when no choice matches. Without a digest, ambiguous stripes stay
/// unresolved.
fn resolve_with_object_digest(
    manifest: &crate::model::Manifest,
    stripes: &[StripeReport],
) -> Vec<Option<usize>> {
    let target = match &manifest.object_digest {
        Some(d) => d.clone(),
        None => {
            // No global digest: ambiguous stripes cannot be adjudicated.
            return stripes
                .iter()
                .map(|r| match r.status {
                    StripeStatus::Unique => Some(0),
                    _ => None,
                })
                .collect();
        }
    };

    // Build per-stripe option lists (unique stripes have one option).
    let options: Vec<Vec<&crate::model::Solution>> = stripes
        .iter()
        .map(|r| {
            if r.status == StripeStatus::Infeasible {
                Vec::new()
            } else {
                r.solutions.iter().collect()
            }
        })
        .collect();

    // Deterministic backtracking with a bounded product search.
    let mut chosen = vec![0usize; stripes.len()];
    let found = choose(&options, 0, &mut chosen, &target, manifest.k, 0, SEARCH_BUDGET).is_some();
    if !found {
        // No combination matches the claimed object digest.
        return stripes
            .iter()
            .map(|r| if r.status == StripeStatus::Infeasible { None } else { None })
            .collect();
    }
    stripes
        .iter()
        .enumerate()
        .map(|(i, r)| {
            if r.status == StripeStatus::Infeasible {
                None
            } else {
                Some(chosen[i])
            }
        })
        .collect()
}

fn choose<'a>(
    options: &[Vec<&'a crate::model::Solution>],
    i: usize,
    chosen: &mut [usize],
    target: &str,
    k: usize,
    mut visited: usize,
    budget: usize,
) -> Option<usize> {
    if i == options.len() {
        return Some(visited);
    }
    for (idx, _sol) in options[i].iter().enumerate() {
        if visited >= budget {
            return None;
        }
        visited += 1;
        chosen[i] = idx;
        // Prune: incremental digest isn't possible across stripes cheaply, so
        // only evaluate at the leaf; budget keeps it bounded.
        if i + 1 == options.len() {
            let assembled: Vec<Vec<Vec<u8>>> = options
                .iter()
                .enumerate()
                .map(|(j, opts)| opts[chosen[j]].shards.clone())
                .collect();
            if object_data_digest(&assembled, k) == target {
                return Some(visited);
            }
        } else if let Some(v) = choose(options, i + 1, chosen, target, k, visited, budget) {
            return Some(v);
        }
        visited += 1;
    }
    None
}
