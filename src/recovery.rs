//! Enumerate feasible candidate sets and reconstruct stripes.
//!
//! Candidate selection is deliberately *not* first-come-first-served. For
//! every stripe we:
//!   1. mark corrupt evidence (digest/length/range/isolation),
//!   2. group digest-healthy receipts by generation, never mixing generations,
//!   3. expand duplicate-numbered content candidates into candidate sets,
//!   4. choose every deterministic k-subset up to SEARCH_BUDGET,
//!   5. reconstruct on GF(256) and cross-check every unused healthy shard,
//!   6. keep every distinct answer and report where they differ.
//!
//! Exactly-k receipts (the recovery threshold) is a first-class case: there
//! are no witness shards, so the answer is accepted but labelled ambiguous
//! unless the global object digest disambiguates it.

use std::collections::BTreeMap;

use crate::digest::shards_digest;
use crate::gf256::Gf256;
use crate::model::{Exclusion, Manifest, Solution, StripeReport, StripeStatus};
use crate::rs::{reconstruct, CodecVersion};
use crate::store::{ReceiptRow, Store};

/// Deterministic search budget for candidate combinations per stripe.
pub const SEARCH_BUDGET: usize = 4096;

/// A digest-healthy receipt carrying its raw bytes.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub receipt: ReceiptRow,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct EnumStripe {
    pub stripe: usize,
    /// digest-healthy, in-range, right-length, non-isolated
    pub healthy: Vec<Candidate>,
    pub exclusions: Vec<Exclusion>,
}

/// Load and classify receipts for an object into per-stripe groups.
pub fn classify(store: &Store, manifest: &Manifest) -> Vec<EnumStripe> {
    let receipts = store.list_receipts(&manifest.object_id).unwrap_or_default();
    let isolated = store.isolated_sources(&manifest.object_id).unwrap_or_default();
    let k = manifest.k;
    let m = manifest.m;
    let total = k + m;

    let mut groups: BTreeMap<usize, EnumStripe> = BTreeMap::new();
    for s in 0..manifest.stripe_count {
        groups.insert(
            s,
            EnumStripe {
                stripe: s,
                healthy: Vec::new(),
                exclusions: Vec::new(),
            },
        );
    }

    for r in receipts {
        let target = groups.entry(r.stripe as usize).or_insert(EnumStripe {
            stripe: r.stripe as usize,
            healthy: Vec::new(),
            exclusions: Vec::new(),
        });

        if isolated.iter().any(|s| s == &r.source) {
            target.exclusions.push(Exclusion::IsolatedSource {
                receipt_id: r.id,
                source: r.source.clone(),
            });
            continue;
        }
        if r.stripe < 0
            || (r.stripe as usize) >= manifest.stripe_count
            || r.shard < 0
            || (r.shard as usize) >= total
        {
            target.exclusions.push(Exclusion::OutOfRange {
                receipt_id: r.id,
                source: r.source.clone(),
                stripe: r.stripe as usize,
                shard: r.shard as usize,
            });
            continue;
        }
        // Corruption evidence: the recomputed digest disagrees with the claim.
        if r.claimed_digest != r.actual_digest {
            target.exclusions.push(Exclusion::DigestMismatch {
                receipt_id: r.id,
                source: r.source.clone(),
                claimed: r.claimed_digest.clone(),
                actual: r.actual_digest.clone(),
            });
            continue;
        }
        // Manifest/actual length mismatch evidence.
        if (r.length as usize) != manifest.shard_len {
            target.exclusions.push(Exclusion::LengthMismatch {
                receipt_id: r.id,
                source: r.source.clone(),
                expected: manifest.shard_len,
                actual: r.length as usize,
            });
            continue;
        }
        let bytes = match store.read_blob(&r.blob_path) {
            Ok(b) => b,
            Err(_) => {
                target.exclusions.push(Exclusion::DigestMismatch {
                    receipt_id: r.id,
                    source: r.source.clone(),
                    claimed: r.claimed_digest.clone(),
                    actual: "<unreadable>".to_string(),
                });
                continue;
            }
        };
        target.healthy.push(Candidate { receipt: r, bytes });
    }

    groups.into_values().collect()
}


/// Enumerate every feasible reconstruction for one stripe (bounded budget).
pub fn enumerate_stripe(
    gf: &Gf256,
    manifest: &Manifest,
    stripe: usize,
    healthy: &[Candidate],
    base_exclusions: &[Exclusion],
) -> StripeReport {
    let mut report = StripeReport {
        stripe,
        status: StripeStatus::Infeasible,
        solutions: Vec::new(),
        exclusions: base_exclusions.to_vec(),
        truncated: false,
        combos_considered: 0,
        resolved: false,
    };

    let version = match CodecVersion::from_i64(manifest.codec_version) {
        Some(v) => v,
        None => return report,
    };
    let k = manifest.k;
    let m = manifest.m;

    // Partial writes: group by generation and never mix within one solution.
    let mut by_generation: BTreeMap<i64, Vec<&Candidate>> = BTreeMap::new();
    for c in healthy {
        by_generation.entry(c.receipt.generation).or_default().push(c);
    }
    // Newest generation first, but older generations are still enumerated.
    let generations: Vec<i64> = by_generation.keys().copied().rev().collect();

    for (gi, &generation) in generations.iter().enumerate() {
        let pool = by_generation[&generation].clone();

        // Same shard number with different content candidates: bucket them.
        let mut buckets: BTreeMap<usize, Vec<&Candidate>> = BTreeMap::new();
        for c in &pool {
            buckets.entry(c.receipt.shard as usize).or_default().push(*c);
        }
        let distinct_shards: Vec<usize> = buckets.keys().copied().collect();
        if distinct_shards.len() < k {
            // Recovery threshold cannot be met from distinct shard numbers.
            for (j, &other_gen) in generations.iter().enumerate() {
                if j == gi {
                    continue;
                }
                for c in &by_generation[&other_gen] {
                    report.exclusions.push(Exclusion::GenerationConflict {
                        receipt_id: c.receipt.id,
                        source: c.receipt.source.clone(),
                        generation: c.receipt.generation,
                        selected_generation: generation,
                    });
                }
            }
            continue;
        }

        // Expand duplicate-number candidates into concrete assignments.
        for assignment in cartesian_assignments(&buckets) {
            let assigned_indices: Vec<usize> = assignment.keys().copied().collect();
            for combo in combinations(&assigned_indices, k) {
                if report.combos_considered >= SEARCH_BUDGET {
                    report.truncated = true;
                    break;
                }
                report.combos_considered += 1;

                let present: Vec<(usize, Vec<u8>)> = combo
                    .iter()
                    .map(|idx| (**idx, assignment[idx].bytes.clone()))
                    .collect();
                let participant_ids: Vec<i64> = combo
                    .iter()
                    .map(|idx| assignment[idx].receipt.id)
                    .collect();

                let full = match reconstruct(gf, version, k, m, &present) {
                    Some(f) => f,
                    None => continue,
                };

                // Cross-check healthy receipts at *other* shard indices.
                // Candidates at a participant shard index are alternatives,
                // not witnesses: they cannot agree with a different solve.
                let chosen_indices: Vec<usize> =
                    combo.iter().map(|idx| **idx).collect();
                let mut witness_ids = Vec::new();
                let mut conflict = false;
                for c in &pool {
                    if participant_ids.contains(&c.receipt.id) {
                        continue;
                    }
                    let shard_idx = c.receipt.shard as usize;
                    if chosen_indices.contains(&shard_idx) {
                        continue;
                    }
                    witness_ids.push(c.receipt.id);
                    if full[shard_idx] != c.bytes {
                        conflict = true;
                    }
                }
                if conflict {
                    continue;
                }

                let mut exclusions = base_exclusions.to_vec();
                // Other generations are evidence relative to this solution.
                for (j, &other_gen) in generations.iter().enumerate() {
                    if j == gi {
                        continue;
                    }
                    for c in &by_generation[&other_gen] {
                        exclusions.push(Exclusion::GenerationConflict {
                            receipt_id: c.receipt.id,
                            source: c.receipt.source.clone(),
                            generation: c.receipt.generation,
                            selected_generation: generation,
                        });
                    }
                }
                // Duplicate-numbered candidates not used in the solve but
                // agreeing with the result are recorded as excluded losers.
                for idx in &distinct_shards {
                    let chosen_id = assignment[idx].receipt.id;
                    for c in &buckets[idx] {
                        if c.receipt.id != chosen_id {
                            exclusions.push(Exclusion::DuplicateLoser {
                                receipt_id: c.receipt.id,
                                source: c.receipt.source.clone(),
                                kept_receipt_id: chosen_id,
                            });
                        }
                    }
                }
                // Classify remaining healthy receipts:
                //  - same shard index as a participant, unchosen candidate:
                //    duplicate loser;
                //  - different shard index: a witness (already cross-checked).
                for c in &pool {
                    if participant_ids.contains(&c.receipt.id) {
                        continue;
                    }
                    let shard_idx = c.receipt.shard as usize;
                    if chosen_indices.contains(&shard_idx) {
                        exclusions.push(Exclusion::DuplicateLoser {
                            receipt_id: c.receipt.id,
                            source: c.receipt.source.clone(),
                            kept_receipt_id: assignment[&shard_idx].receipt.id,
                        });
                    }
                    // Witnesses are recorded on the solution, not excluded.
                }

                witness_ids.sort_unstable();
                let solution = Solution {
                    codec_version: manifest.codec_version,
                    generation,
                    participant_ids,
                    witness_ids,
                    exclusions,
                    stripe_digest: shards_digest(&full),
                    data_digest: shards_digest(&full[..k]),
                    shards: full,
                };
                dedupe_insert(&mut report.solutions, solution);
            }
            if report.truncated {
                break;
            }
        }
    }

    // Deterministic order: newer generation, then stable digest/participants.
    report.solutions.sort_by(|a, b| {
        b.generation
            .cmp(&a.generation)
            .then(a.stripe_digest.cmp(&b.stripe_digest))
            .then(a.participant_ids.cmp(&b.participant_ids))
    });
    report.status = match report.solutions.len() {
        0 => StripeStatus::Infeasible,
        1 => StripeStatus::Unique,
        _ => StripeStatus::Ambiguous,
    };
    report
}

/// Deterministic k-combinations of item references, lexicographic order.
pub fn combinations<T>(items: &[T], k: usize) -> Vec<Vec<&T>> {
    let n = items.len();
    if k > n || k == 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut idx: Vec<usize> = (0..k).collect();
    loop {
        out.push(idx.iter().map(|&i| &items[i]).collect());
        // Find the rightmost position that can be incremented.
        let mut i = k - 1;
        loop {
            if idx[i] < n - k + i {
                break;
            }
            if i == 0 {
                return out;
            }
            i -= 1;
        }
        idx[i] += 1;
        for j in i + 1..k {
            idx[j] = idx[j - 1] + 1;
        }
    }
}

/// Expand duplicate-number buckets into assignments shard-index -> candidate.
fn cartesian_assignments<'a>(
    buckets: &'a BTreeMap<usize, Vec<&'a Candidate>>,
) -> Vec<BTreeMap<usize, &'a Candidate>> {
    let keys: Vec<usize> = buckets.keys().copied().collect();
    let mut results: Vec<BTreeMap<usize, &Candidate>> = vec![BTreeMap::new()];
    for key in keys {
        let mut next = Vec::new();
        for assignment in &results {
            for candidate in &buckets[&key] {
                let mut a = assignment.clone();
                a.insert(key, *candidate);
                next.push(a);
            }
        }
        results = next;
    }
    results
}

fn dedupe_insert(answers: &mut Vec<Solution>, solution: Solution) {
    if answers.iter().any(|a| a.stripe_digest == solution.stripe_digest) {
        return;
    }
    answers.push(solution);
}

/// Difference between two stripe answers: list shard indices whose bytes differ.
pub fn solution_diff(a: &Solution, b: &Solution) -> Vec<usize> {
    a.shards
        .iter()
        .zip(b.shards.iter())
        .enumerate()
        .filter_map(|(i, (x, y))| if x != y { Some(i) } else { None })
        .collect()
}

/// Per-object result of a recovery run for the UI and API.
pub use crate::model::RunReport;

/// Difference summary for ambiguous stripes across the whole object.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Ambiguity {
    pub stripe: usize,
    pub answer_count: usize,
    pub generations: Vec<i64>,
    pub differing_shards: Vec<usize>,
}
