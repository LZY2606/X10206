//! Recovery engine.
//!
//! Candidate selection never trusts arrival order. For every shard index the
//! engine builds deterministic, generation-scoped candidate groups; it
//! enumerates feasible k-shard combinations under a fixed search budget,
//! reconstructs each combination, and cross-validates it against (a) every
//! other clean candidate in the same stripe and (b) the manifest object
//! digest. Every feasible reconstruction is retained with the participating
//! shards, excluded corruption evidence and recomputed digests.
//!
//! Commit is per stripe: reconstructed bytes are staged into pending rows and
//! promoted in one transaction. Pending data is never used for final output and
//! is wiped on startup, so an interrupted run only reuses fully committed
//! stripes.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::coding::{reconstruct, CodingParams};
use crate::db::{StagedShard, StagedSolution, StagedStripe, Store};
use crate::gf::Gf256;
use crate::db::ObjectRow;
use crate::model::{assemble_object, sha256_hex, EvidenceKind};
use rusqlite::params;

/// Deterministic cap on the number of combinations tried per stripe.
pub const STRIPE_SEARCH_BUDGET: usize = 256;
/// Deterministic cap on cross-stripe object assemblies tried.
pub const OBJECT_SEARCH_BUDGET: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashPoint {
    None,
    /// Roll back the commit transaction after staging stripe index == value.
    BeforeCommit(usize),
    /// Simulate a disk write failure while staging stripe index == value.
    StagingWriteFail(usize),
}

/// One clean candidate fragment for a shard index.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub fragment_id: i64,
    pub source: String,
    pub generation: u64,
    pub content_digest: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComboEntry {
    pub shard_index: usize,
    pub fragment_id: i64,
    pub source: String,
    pub generation: u64,
    pub content_digest: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExcludedEntry {
    pub fragment_id: i64,
    pub shard_index: usize,
    pub source: String,
    pub generation: u64,
    pub reasons: Vec<String>,
}

/// One feasible, fully cross-validated reconstruction of a stripe.
#[derive(Debug, Clone)]
pub struct StripeSolution {
    pub generation: i64,
    pub combo: Vec<ComboEntry>,
    pub excluded: Vec<ExcludedEntry>,
    /// All n reconstructed shards, ordered by index.
    pub shards: Vec<Vec<u8>>,
    pub stripe_data_digest: String,
    pub object_digest: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StripeResult {
    pub stripe: usize,
    pub status: String,
    pub generation: Option<i64>,
    pub detail: String,
    pub solutions: Vec<StripeSolution>,
    /// Candidates observed but never usable (length/range/digest failures).
    pub excluded: Vec<ExcludedEntry>,
    pub reused: bool,
}

#[derive(Debug, Clone, Default)]
pub struct RunReport {
    pub object_id: String,
    pub status: String,
    pub detail: String,
    pub stripes: Vec<StripeResult>,
    pub committed: usize,
    pub reused: usize,
    pub failed: Vec<usize>,
    pub assembled_object_digest: Option<String>,
}

fn load_bytes(store: &Store, file_path: &str) -> Vec<u8> {
    let p = store.paths.root.join(file_path);
    std::fs::read(&p).unwrap_or_default()
}

/// All reasons a fragment is excluded from candidacy.
fn exclusion_reasons(
    obj: &ObjectRow,
    isolated: &BTreeSet<String>,
    f: &crate::db::FragmentRow,
) -> Vec<String> {
    let mut reasons = Vec::new();
    let n = obj.data_shards + obj.parity_shards;
    if isolated.contains(&f.source) {
        reasons.push(EvidenceKind::SourceIsolated.as_str().into());
    }
    if f.stripe >= obj.stripe_count || f.shard_index >= n {
        reasons.push(EvidenceKind::OutOfRange.as_str().into());
    }
    if f.length != obj.shard_len {
        reasons.push(EvidenceKind::LengthMismatch.as_str().into());
    }
    if f.digest_verified == 0 {
        if f.declared_digest.is_some() {
            reasons.push(EvidenceKind::DigestMismatch.as_str().into());
        } else {
            reasons.push(EvidenceKind::MissingSidecar.as_str().into());
        }
    }
    reasons
}

/// Deterministically build candidate groups for one stripe.
///
/// Returns `(groups, excluded)` where groups maps shard_index -> candidates
/// ordered by (generation DESC, content_digest, source, fragment_id). Only
/// digest-verified, correct-length, non-isolated fragments are candidates.
pub fn build_candidates(
    store: &Store,
    obj: &ObjectRow,
    stripe: usize,
) -> (BTreeMap<usize, Vec<Candidate>>, Vec<ExcludedEntry>) {
    let isolated: BTreeSet<String> = store
        .list_sources()
        .unwrap_or_default()
        .into_iter()
        .filter(|(_, iso, _)| *iso)
        .map(|(name, _, _)| name)
        .collect();

    let mut groups: BTreeMap<usize, Vec<Candidate>> = BTreeMap::new();
    let mut excluded: Vec<ExcludedEntry> = Vec::new();

    for f in store.fragments_for_stripe(&obj.id, stripe).unwrap_or_default() {
        let reasons = exclusion_reasons(obj, &isolated, &f);
        if !reasons.is_empty() {
            excluded.push(ExcludedEntry {
                fragment_id: f.id,
                shard_index: f.shard_index,
                source: f.source,
                generation: f.generation,
                reasons,
            });
            continue;
        }
        groups.entry(f.shard_index).or_default().push(Candidate {
            fragment_id: f.id,
            source: f.source.clone(),
            generation: f.generation,
            content_digest: f.content_digest.clone(),
            bytes: load_bytes(store, &f.file_path),
        });
    }

    for candidates in groups.values_mut() {
        // Stable, total ordering: newest generation first, then content, then
        // provenance. Never first-come-first-served.
        candidates.sort_by(|a, b| {
            b.generation
                .cmp(&a.generation)
                .then_with(|| a.content_digest.cmp(&b.content_digest))
                .then_with(|| a.source.cmp(&b.source))
                .then_with(|| a.fragment_id.cmp(&b.fragment_id))
        });
        candidates.dedup_by(|a, b| a.content_digest == b.content_digest);
    }
    excluded.sort_by(|a, b| {
        a.shard_index
            .cmp(&b.shard_index)
            .then_with(|| a.fragment_id.cmp(&b.fragment_id))
    });
    excluded.dedup_by_key(|e| e.fragment_id);
    (groups, excluded)
}

/// Enumerate index tuples of exactly k distinct shard indices, deterministically.
fn index_tuples(indices: &[usize], k: usize) -> Vec<Vec<usize>> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    fn rec(
        indices: &[usize],
        k: usize,
        start: usize,
        cur: &mut Vec<usize>,
        out: &mut Vec<Vec<usize>>,
    ) {
        if cur.len() == k {
            out.push(cur.clone());
            return;
        }
        for i in start..indices.len() {
            cur.push(indices[i]);
            rec(indices, k, i + 1, cur, out);
            cur.pop();
        }
    }
    rec(indices, k, 0, &mut cur, &mut out);
    out
}

/// Solve a single stripe: enumerate generation-consistent k-combinations,
/// reconstruct and cross-validate. Solutions are deduplicated by reconstructed
/// content; every distinct feasible answer is retained.
pub fn solve_stripe(
    gf: &Gf256,
    params: CodingParams,
    groups: &BTreeMap<usize, Vec<Candidate>>,
    excluded: Vec<ExcludedEntry>,
) -> StripeResult {
    let stripe_index = 0usize; // stripe number is filled by caller context via detail
    let k = params.k;
    let n = params.n;

    if groups.len() < k {
        return StripeResult {
            stripe: stripe_index,
            status: "unrecoverable".into(),
            generation: None,
            detail: format!(
                "only {} distinct clean shard indices, recovery floor is {}",
                groups.len(),
                k
            ),
            solutions: vec![],
            excluded,
            reused: false,
        };
    }

    let indices: Vec<usize> = groups.keys().copied().collect();
    let tuples = index_tuples(&indices, k);

    // Try each generation in descending order.
    let mut generations: BTreeSet<u64> = BTreeSet::new();
    for cands in groups.values() {
        if let Some(c) = cands.first() {
            generations.insert(c.generation);
        }
    }
    let mut generations: Vec<u64> = generations.into_iter().collect();
    generations.sort_unstable_by(|a, b| b.cmp(a));

    let mut solutions: Vec<StripeSolution> = Vec::new();
    let mut tried = 0usize;
    let mut first_gen_error: Option<String> = None;

    for gen in &generations {
        if tried >= STRIPE_SEARCH_BUDGET {
            break;
        }
        let mut feasible_this_gen = false;
        for tuple in &tuples {
            if tried >= STRIPE_SEARCH_BUDGET {
                break;
            }
            // Pick the deterministic best candidate for each index at this gen.
            let mut combo: Vec<ComboEntry> = Vec::new();
            let mut avail: Vec<(usize, Vec<u8>)> = Vec::new();
            let mut ok = true;
            for &idx in tuple {
                let cand = groups
                    .get(&idx)
                    .and_then(|cands| cands.iter().find(|c| c.generation == *gen));
                match cand {
                    Some(c) => {
                        combo.push(ComboEntry {
                            shard_index: idx,
                            fragment_id: c.fragment_id,
                            source: c.source.clone(),
                            generation: c.generation,
                            content_digest: c.content_digest.clone(),
                        });
                        avail.push((idx, c.bytes.clone()));
                    }
                    None => ok = false,
                }
            }
            if !ok {
                continue;
            }
            tried += 1;
            let rec = match reconstruct(gf, params, &avail) {
                Ok(r) => r,
                Err(e) => {
                    if first_gen_error.is_none() {
                        first_gen_error = Some(e);
                    }
                    continue;
                }
            };

            // Cross-validate against every clean candidate in this stripe:
            // any candidate whose bytes disagree with reconstruction is
            // corruption evidence and must be excluded.
            let mut corroborated = true;
            let mut combo_ids: BTreeSet<i64> = combo.iter().map(|c| c.fragment_id).collect();
            let mut extra_excluded: Vec<ExcludedEntry> = Vec::new();
            for (&idx, cands) in groups {
                for c in cands {
                    if c.generation != *gen {
                        continue;
                    }
                    if combo_ids.contains(&c.fragment_id) {
                        continue;
                    }
                    if c.bytes == rec[idx] {
                        // Benign duplicate delivery corroborates the answer.
                        combo_ids.insert(c.fragment_id);
                    } else {
                        corroborated = false;
                        extra_excluded.push(ExcludedEntry {
                            fragment_id: c.fragment_id,
                            shard_index: idx,
                            source: c.source.clone(),
                            generation: c.generation,
                            reasons: vec![
                                "corroboration_failed".into(),
                                EvidenceKind::DigestMismatch.as_str().into(),
                            ],
                        });
                    }
                }
            }
            if !corroborated {
                continue;
            }

            let data_digest = {
                let mut data = Vec::with_capacity(k * params.shard_len);
                for d in rec.iter().take(k) {
                    data.extend_from_slice(d);
                }
                sha256_hex(&data)
            };

            // Multiple combos may yield the identical reconstruction; dedupe.
            let all_excluded: BTreeSet<i64> = excluded.iter().map(|e| e.fragment_id).collect();
            let mut merged = excluded.clone();
            for e in extra_excluded {
                merged.push(e);
            }
            merged.sort_by_key(|e| (e.shard_index, e.fragment_id));
            merged.dedup_by_key(|e| e.fragment_id);
            let _ = all_excluded;

            let digest_of_all: String = {
                let mut all = Vec::with_capacity(n * params.shard_len);
                for s in &rec {
                    all.extend_from_slice(s);
                }
                sha256_hex(&all)
            };
            if solutions.iter().any(|s| s.stripe_data_digest == data_digest && {
                let mut a = Vec::new();
                for sh in &s.shards {
                    a.extend_from_slice(sh);
                }
                sha256_hex(&a) == digest_of_all
            }) {
                feasible_this_gen = true;
                continue;
            }
            solutions.push(StripeSolution {
                generation: *gen as i64,
                combo,
                excluded: merged,
                shards: rec,
                stripe_data_digest: data_digest,
                object_digest: None,
            });
            feasible_this_gen = true;
        }
        if feasible_this_gen {
            // Higher generation is authoritative; do not mix generations.
            break;
        }
    }

    if solutions.is_empty() {
        let detail = match first_gen_error {
            Some(e) => format!("no k-combination cross-validated (last decode error: {e})"),
            None => format!(
                "no generation-consistent cross-validated combination among {} tried",
                tried
            ),
        };
        StripeResult {
            stripe: stripe_index,
            status: "unrecoverable".into(),
            generation: None,
            detail,
            solutions: vec![],
            excluded,
            reused: false,
        }
    } else {
        // Order solutions deterministically by reconstructed content.
        solutions.sort_by(|a, b| {
            let ah: String = {
                let mut x = Vec::new();
                for s in &a.shards {
                    x.extend_from_slice(s);
                }
                sha256_hex(&x)
            };
            let bh: String = {
                let mut x = Vec::new();
                for s in &b.shards {
                    x.extend_from_slice(s);
                }
                sha256_hex(&x)
            };
            ah.cmp(&bh)
        });
        let detail = format!(
            "{} distinct feasible reconstruction(s) from {} combination(s) tried; \
             solution 0 chosen deterministically",
            solutions.len(),
            tried
        );
        StripeResult {
            stripe: stripe_index,
            status: "feasible".into(),
            generation: Some(solutions[0].generation),
            detail,
            solutions,
            excluded,
            reused: false,
        }
    }
}

/// All fragment combinations of size k with distinct shard indices at one
/// generation. Deterministic order: index tuple (ascending), then candidate
/// rank inside each group. Capped by `STRIPE_SEARCH_BUDGET`.
fn enumerate_combos(
    groups: &BTreeMap<usize, Vec<Candidate>>,
    gen: u64,
    k: usize,
) -> Vec<Vec<(usize, Candidate)>> {
    let groups: Vec<(usize, Vec<Candidate>)> = groups
        .iter()
        .map(|(idx, c)| (*idx, c.iter().filter(|c| c.generation == gen).cloned().collect::<Vec<_>>()))
        .filter(|(_, c)| !c.is_empty())
        .collect();
    let mut out = Vec::new();
    let mut cur: Vec<(usize, Candidate)> = Vec::new();
    fn rec(
        groups: &[(usize, Vec<Candidate>)],
        k: usize,
        start: usize,
        cur: &mut Vec<(usize, Candidate)>,
        out: &mut Vec<Vec<(usize, Candidate)>>,
        budget_left: &mut usize,
    ) {
        if *budget_left == 0 {
            return;
        }
        if cur.len() == k {
            out.push(cur.clone());
            *budget_left -= 1;
            return;
        }
        // Reserve enough distinct indices to complete the combo.
        for gi in start..groups.len() {
            if groups.len() - gi < k - cur.len() {
                break;
            }
            for cand in &groups[gi].1 {
                cur.push((groups[gi].0, cand.clone()));
                rec(groups, k, gi + 1, cur, out, budget_left);
                cur.pop();
                if *budget_left == 0 {
                    return;
                }
            }
        }
    }
    let mut budget = STRIPE_SEARCH_BUDGET;
    rec(&groups, k, 0, &mut cur, &mut out, &mut budget);
    out
}

/// Solve a stripe with full candidate-alternative enumeration. This is the
/// engine used by the run loop; the exported `solve_stripe` wraps it with the
/// caller's stripe number.
pub fn solve_numbered(
    gf: &Gf256,
    params: CodingParams,
    stripe_num: usize,
    groups: BTreeMap<usize, Vec<Candidate>>,
    excluded: Vec<ExcludedEntry>,
) -> StripeResult {
    let k = params.k;
    let n = params.n;

    if groups.len() < k {
        return StripeResult {
            stripe: stripe_num,
            status: "unrecoverable".into(),
            generation: None,
            detail: format!(
                "only {} distinct clean shard indices, recovery floor is {}",
                groups.len(), k
            ),
            solutions: vec![],
            excluded,
            reused: false,
        };
    }

    let mut generations: Vec<u64> = groups
        .values()
        .flat_map(|c| c.iter().map(|c| c.generation))
        .collect::<BTreeSet<u64>>()
        .into_iter()
        .collect();
    generations.sort_unstable_by(|a, b| b.cmp(a));

    let mut solutions: Vec<StripeSolution> = Vec::new();
    let mut tried = 0usize;
    for gen in generations {
        let combos = enumerate_combos(&groups, gen, k);
        let mut feasible = false;
        for combo_frags in combos {
            tried += 1;
            let avail: Vec<(usize, Vec<u8>)> =
                combo_frags.iter().map(|(i, c)| (*i, c.bytes.clone())).collect();
            let rec = match reconstruct(gf, params, &avail) {
                Ok(r) => r,
                Err(_) => continue,
            };

            // A combo is retained as a feasible reconstruction whenever the k
            // shards decode consistently. Other same-generation clean
            // candidates that DISAGREE with it do not invalidate the combo —
            // they are competing content candidates (possibly corrupt with a
            // forged per-shard digest) and are recorded as excluded evidence;
            // the object-level digest assembly decides which feasible answer is
            // trustworthy. Candidate selection is therefore not first-come and
            // not majority-vote: every self-consistent answer survives.
            let chosen_ids: BTreeSet<i64> = combo_frags.iter().map(|(_, c)| c.fragment_id).collect();
            let mut merge = excluded.clone();
            for (&idx, cands) in &groups {
                for c in cands {
                    if c.generation != gen || chosen_ids.contains(&c.fragment_id) {
                        continue;
                    }
                    if c.bytes == rec[idx] {
                        continue;
                    }
                    merge.push(ExcludedEntry {
                        fragment_id: c.fragment_id,
                        shard_index: idx,
                        source: c.source.clone(),
                        generation: c.generation,
                        reasons: vec![
                            "competing_candidate_disagrees".into(),
                            EvidenceKind::DigestMismatch.as_str().into(),
                        ],
                    });
                }
            }
            merge.sort_by_key(|e| (e.shard_index, e.fragment_id));
            merge.dedup_by_key(|e| e.fragment_id);

            let mut all = Vec::with_capacity(n * params.shard_len);
            for s in &rec {
                all.extend_from_slice(s);
            }
            let reconstructed_digest = sha256_hex(&all);
            if solutions.iter().any(|s| {
                let mut a = Vec::new();
                for sh in &s.shards {
                    a.extend_from_slice(sh);
                }
                sha256_hex(&a) == reconstructed_digest
            }) {
                feasible = true;
                continue;
            }
            let mut data = Vec::with_capacity(k * params.shard_len);
            for d in rec.iter().take(k) {
                data.extend_from_slice(d);
            }
            solutions.push(StripeSolution {
                generation: gen as i64,
                combo: combo_frags
                    .iter()
                    .map(|(i, c)| ComboEntry {
                        shard_index: *i,
                        fragment_id: c.fragment_id,
                        source: c.source.clone(),
                        generation: c.generation,
                        content_digest: c.content_digest.clone(),
                    })
                    .collect(),
                excluded: merge,
                shards: rec,
                stripe_data_digest: sha256_hex(&data),
                object_digest: None,
            });
            feasible = true;
        }
        if feasible {
            break;
        }
    }

    solutions.sort_by(|a, b| {
        let h = |s: &StripeSolution| {
            let mut x = Vec::new();
            for sh in &s.shards {
                x.extend_from_slice(sh);
            }
            sha256_hex(&x)
        };
        h(a).cmp(&h(b))
    });

    if solutions.is_empty() {
        StripeResult {
            stripe: stripe_num,
            status: "unrecoverable".into(),
            generation: None,
            detail: format!("no cross-validated combination among {tried} tried (budget {STRIPE_SEARCH_BUDGET})"),
            solutions: vec![],
            excluded,
            reused: false,
        }
    } else {
        StripeResult {
            stripe: stripe_num,
            status: "feasible".into(),
            generation: Some(solutions[0].generation),
            detail: format!(
                "{} distinct feasible reconstruction(s) from {tried} combination(s); \
                 differences retained as separate solutions, rank 0 chosen by digest order",
                solutions.len()
            ),
            solutions,
            excluded,
            reused: false,
        }
    }
}

fn decode_committed_stripes(
    store: &Store,
    obj: &ObjectRow,
) -> BTreeMap<usize, (i64, Vec<Vec<u8>>)> {
    let n = obj.data_shards + obj.parity_shards;
    let mut map = BTreeMap::new();
    for sc in store.list_stripes(&obj.id).unwrap_or_default() {
        if sc.status != "committed" || sc.chosen_solution_id.is_none() {
            continue;
        }
        let mut shards = vec![Vec::new(); n];
        let mut ok = true;
        for idx in 0..n {
            match store.committed_shard_hex(&obj.id, sc.stripe, idx) {
                Ok(Some((hex, _gen))) => {
                    let bytes = decode_hex(&hex);
                    if bytes.len() != obj.shard_len {
                        ok = false;
                        break;
                    }
                    shards[idx] = bytes;
                }
                _ => {
                    ok = false;
                    break;
                }
            }
        }
        if !ok {
            continue;
        }
        let rank = store
            .list_solutions(&obj.id, sc.stripe)
            .ok()
            .and_then(|sols| {
                sols.into_iter()
                    .find(|s| Some(s.id) == sc.chosen_solution_id)
                    .map(|s| s.rank_order)
            })
            .unwrap_or(0);
        map.insert(sc.stripe, (rank, shards));
    }
    map
}

fn decode_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or(0))
        .collect()
}

pub fn encode_hex(b: &[u8]) -> String {
    hex::encode(b)
}

/// Cross-stripe enumeration: find assemblies whose object digest matches the
/// manifest. Returns the deterministically smallest trusted per-stripe rank
/// selection, the number of distinct trusted object digests found, and how
/// many assemblies were examined under the budget.
fn find_trusted_assembly(
    obj: &ObjectRow,
    stripe_solutions: &BTreeMap<usize, &StripeResult>,
    committed: &BTreeMap<usize, (i64, Vec<Vec<u8>>)>,
) -> Option<(BTreeMap<usize, i64>, usize, usize)> {
    fn walk<'a>(
        stripe: usize,
        obj: &'a ObjectRow,
        solved: &'a BTreeMap<usize, &'a StripeResult>,
        committed: &'a BTreeMap<usize, (i64, Vec<Vec<u8>>)>,
        cur: &mut Vec<&'a [Vec<u8>]>,
        ranks: &mut Vec<i64>,
        examined: &mut usize,
        trusted: &mut Vec<Vec<i64>>,
        found_digests: &mut BTreeSet<String>,
        budget: usize,
    ) {
        if *examined >= budget {
            return;
        }
        if stripe == obj.stripe_count {
            *examined += 1;
            let mut data = Vec::new();
            for shards in cur.iter() {
                for d in shards.iter().take(obj.data_shards) {
                    data.extend_from_slice(d);
                }
            }
            data.truncate(obj.data_len);
            let digest = sha256_hex(&data);
            if digest.eq_ignore_ascii_case(&obj.object_digest_hex)
                && found_digests.insert(digest)
            {
                trusted.push(ranks.clone());
            }
            return;
        }
        if let Some((rank, bytes)) = committed.get(&stripe) {
            cur.push(bytes);
            ranks.push(*rank);
            walk(stripe + 1, obj, solved, committed, cur, ranks, examined, trusted, found_digests, budget);
            ranks.pop();
            cur.pop();
            return;
        }
        if let Some(result) = solved.get(&stripe) {
            for (rank, sol) in result.solutions.iter().enumerate() {
                cur.push(&sol.shards);
                ranks.push(rank as i64);
                walk(stripe + 1, obj, solved, committed, cur, ranks, examined, trusted, found_digests, budget);
                ranks.pop();
                cur.pop();
                if *examined >= budget {
                    return;
                }
            }
        }
    }

    let solved: BTreeMap<usize, &StripeResult> =
        stripe_solutions.iter().map(|(k, v)| (*k, *v)).collect();
    let mut cur: Vec<&[Vec<u8>]> = Vec::new();
    let mut ranks: Vec<i64> = Vec::new();
    let mut trusted: Vec<Vec<i64>> = Vec::new();
    let mut found: BTreeSet<String> = BTreeSet::new();
    let mut examined = 0usize;
    walk(
        0, obj, &solved, committed, &mut cur, &mut ranks, &mut examined, &mut trusted, &mut found,
        OBJECT_SEARCH_BUDGET,
    );

    trusted.sort();
    trusted.dedup();
    trusted.first().map(|ranks| {
        let mut selection = BTreeMap::new();
        for (stripe, rank) in ranks.iter().enumerate() {
            selection.insert(stripe, *rank);
        }
        (selection, found.len(), examined)
    })
}

/// Load committed shard bytes for an assembled object (None unless fully committed).
pub fn load_committed_object(store: &Store, obj: &ObjectRow) -> Option<Vec<u8>> {
    let mut stripes = Vec::with_capacity(obj.stripe_count);
    for stripe in 0..obj.stripe_count {
        let sc = store.get_stripe(&obj.id, stripe).ok().flatten()?;
        if sc.status != "committed" || sc.object_digest.is_none() {
            return None;
        }
        let mut shards = vec![Vec::new(); obj.data_shards + obj.parity_shards];
        for idx in 0..shards.len() {
            let (hex, _) = store.committed_shard_hex(&obj.id, stripe, idx).ok().flatten()?;
            shards[idx] = decode_hex(&hex);
            if shards[idx].len() != obj.shard_len {
                return None;
            }
        }
        stripes.push(shards);
    }
    Some(assemble_object(&stripes, obj.data_shards, obj.shard_len, obj.data_len))
}

pub fn run_object_recovery(
    store: &Store,
    object_id: &str,
    crash: CrashPoint,
) -> anyhow::Result<RunReport> {
    let gf = Gf256::new();
    let obj = match store.get_object(object_id)? {
        Some(o) => o,
        None => anyhow::bail!("unknown object {object_id}"),
    };
    let params = CodingParams {
        version: obj.version,
        k: obj.data_shards,
        n: obj.data_shards + obj.parity_shards,
        shard_len: obj.shard_len,
    };
    params.validate().map_err(anyhow::Error::msg)?;

    store.set_run_status(object_id, "running", "enumerating candidates")?;

    // Recovered stripes from a previous interrupted run are reused only when
    // their committed shard set is complete.
    let incomplete = store.verify_committed_completeness(object_id, params.n)?;
    for stripe in &incomplete {
        store.add_evidence(
            object_id,
            Some(*stripe),
            None,
            None,
            None,
            EvidenceKind::DigestMismatch,
            "incomplete committed stripe found on startup; discarded for recompute",
        )?;
    }

    let mut results: BTreeMap<usize, StripeResult> = BTreeMap::new();
    let mut committed = BTreeMap::new();
    let mut reused = 0usize;
    let mut failed = Vec::new();

    for stripe in 0..obj.stripe_count {
        if !incomplete.contains(&stripe) {
            if let Some((rank, bytes)) = decode_committed_stripes(store, &obj).remove(&stripe) {
                let mut result = StripeResult {
                    stripe,
                    status: "committed".into(),
                    generation: None,
                    detail: "reused complete committed stripe from interrupted run".into(),
                    solutions: vec![],
                    excluded: vec![],
                    reused: true,
                };
                result.generation = store
                    .get_stripe(object_id, stripe)?
                    .and_then(|s| s.generation.map(|g| g as i64));
                results.insert(stripe, result);
                committed.insert(stripe, (rank, bytes));
                reused += 1;
                continue;
            }
        }
        let (groups, excluded) = build_candidates(store, &obj, stripe);
        let result = solve_numbered(&gf, params, stripe, groups, excluded);
        if result.status == "unrecoverable" {
            failed.push(stripe);
        }
        results.insert(stripe, result);
    }

    // Object-level cross-stripe validation chooses which feasible stripe
    // reconstruction (if several) actually matches the manifest digest.
    // Every stripe is represented here: reused stripes carry their committed
    // bytes separately (they have no freshly computed solutions), newly solved
    // stripes carry their feasible solutions.
    let refs: BTreeMap<usize, &StripeResult> =
        results.iter().map(|(k, v)| (*k, v)).collect();
    let trusted = find_trusted_assembly(&obj, &refs, &committed);

    let mut newly_committed = 0usize;
    let mut run_status = "recovered".to_string();
    let mut run_detail;
    let mut assembled_digest: Option<String> = None;

    match trusted {
        Some((selection, trusted_count, examined)) => {
            // Commit each still-uncommitted stripe independently; earlier
            // stripes survive a later crash or simulated disk failure.
            for stripe in 0..obj.stripe_count {
                if committed.contains_key(&stripe) {
                    continue;
                }
                let chosen_rank = *selection.get(&stripe).unwrap_or(&0);
                let result = results.get(&stripe).expect("stripe result present");
                let sol = match result.solutions.get(chosen_rank as usize) {
                    Some(s) => s,
                    None => {
                        failed.push(stripe);
                        continue;
                    }
                };

                if let CrashPoint::StagingWriteFail(s) = crash {
                    if s == stripe {
                        store.set_run_status(
                            object_id,
                            "interrupted",
                            &format!("simulated disk write failure staging stripe {stripe}"),
                        )?;
                        anyhow::bail!("simulated disk write failure while staging stripe {stripe}");
                    }
                }

                let staged_shards: Vec<StagedShard> = sol
                    .shards
                    .iter()
                    .enumerate()
                    .map(|(idx, bytes)| StagedShard {
                        shard_index: idx,
                        generation: sol.generation,
                        content_digest: sha256_hex(bytes),
                        shard_hex: encode_hex(bytes),
                    })
                    .collect();
                // Stage into the pending table first; final reads never use it.
                store.stage_pending(object_id, stripe, &staged_shards)?;

                let staged_solutions: Vec<StagedSolution> = result
                    .solutions
                    .iter()
                    .enumerate()
                    .map(|(rank, s)| StagedSolution {
                        gen: s.generation,
                        rank_order: rank as i64,
                        combo_json: serde_json::to_string(&s.combo).unwrap_or_default(),
                        excluded_json: serde_json::to_string(&s.excluded).unwrap_or_default(),
                        reconstructed_digest: {
                            let mut all = Vec::new();
                            for sh in &s.shards {
                                all.extend_from_slice(sh);
                            }
                            sha256_hex(&all)
                        },
                        shards_json: serde_json::to_string(
                            &s.shards.iter().map(|b| encode_hex(b)).collect::<Vec<_>>(),
                        )
                        .unwrap_or_default(),
                    })
                    .collect();

                let crash = matches!(crash, CrashPoint::BeforeCommit(s) if s == stripe);
                let mut detail = result.detail.clone();
                if result.solutions.len() > 1 {
                    detail.push_str(&format!(
                        "; {trusted_count} distinct trusted assembly(ies), chose rank {chosen_rank}"
                    ));
                }
                if let Err(e) = store.commit_staged_stripe(
                    object_id,
                    stripe,
                    "committed",
                    StagedStripe {
                        generation: sol.generation,
                        detail,
                        chosen_rank: Some(chosen_rank),
                        solutions: staged_solutions,
                        shards: staged_shards,
                    },
                    crash,
                ) {
                    store.set_run_status(object_id, "interrupted", &e.to_string())?;
                    return Err(e);
                }
                // Backfill object digest + chosen rank annotation.
                {
                    let conn = store.lock();
                    conn.execute(
                        "UPDATE stripe_commits SET object_digest=?1 WHERE object_id=?2 AND stripe=?3",
                        params![obj.object_digest_hex, object_id, stripe],
                    )?;
                }
                newly_committed += 1;
            }

            let bytes = load_committed_object(store, &obj).expect("fully committed object loads");
            let digest = sha256_hex(&bytes);
            debug_assert_eq!(digest, obj.object_digest_hex.to_lowercase());
            assembled_digest = Some(digest);
            run_detail = format!(
                "all {} stripes committed ({} new, {} reused); object digest verified; \
                 {} trusted assembly(ies), {} candidate assemblies examined (budget {})",
                obj.stripe_count, newly_committed, reused, trusted_count, examined, OBJECT_SEARCH_BUDGET
            );
            if trusted_count > 1 {
                run_status = "recovered_ambiguous".into();
            }
        }
        None => {
            run_status = if failed.is_empty() { "untrusted".into() } else { "unrecoverable".into() };
            run_detail = format!(
                "no cross-stripe assembly reproduces manifest object digest; \
                 feasible stripes: {}, failed: {:?}; nothing committed",
                results.values().filter(|r| r.status == "feasible").count(),
                failed
            );
            store.add_evidence(
                object_id,
                None,
                None,
                None,
                None,
                EvidenceKind::DigestMismatch,
                "object digest verification failed for every candidate assembly",
            )?;
        }
    }

    store.set_run_status(object_id, &run_status, &run_detail)?;

    Ok(RunReport {
        object_id: object_id.to_string(),
        status: run_status,
        detail: run_detail,
        stripes: results.into_values().collect(),
        committed: newly_committed + reused,
        reused,
        failed,
        assembled_object_digest: assembled_digest,
    })
}
