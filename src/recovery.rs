//! Stripe analysis and reconstruction.
//!
//! The engine never reports a bare "success". For every stripe it records:
//! shard health (each received fragment with its evidence), the candidate
//! combinations that were tried, every feasible reconstruction (participating
//! shards, excluded corruption evidence, recomputed digests), and why the
//! stripe was or was not committed.
//!
//! Candidate selection is never first-come-first-served: fragments for one
//! shard index are enumerated under generation/digest/stripe constraints,
//! k-of-position combinations are generated in a deterministic order under a
//! search budget, and all distinct feasible answers are retained.

use crate::erasure;
use crate::model::Manifest;
use crate::store::{FragmentRow, Store};
use serde::Serialize;
use std::collections::HashSet;

/// Deterministic upper bound on the number of k-subsets/cartesian choices
/// examined for a single stripe.
pub const DEFAULT_SEARCH_BUDGET: usize = 2048;
/// Upper bound on cross-stripe solution combinations for object verification.
pub const OBJECT_COMBO_BUDGET: usize = 1024;

#[derive(Debug, Clone, Serialize)]
pub struct Evidence {
    pub fragment_id: i64,
    pub source: String,
    pub shard: usize,
    pub generation: u64,
    pub kind: String,
    pub detail: String,
    pub digest_actual: Option<String>,
    pub digest_claim: Option<String>,
    pub digest_expected: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CandidateView {
    pub fragment_id: i64,
    pub source: String,
    pub generation: u64,
    pub length: usize,
    pub actual_digest: String,
    pub claim_digest: Option<String>,
    pub expected_digest: Option<String>,
    pub claim_ok: bool,
    pub expected_ok: Option<bool>,
    pub generation_ok: bool,
    pub length_ok: bool,
    pub isolated: bool,
    pub eligible: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Participant {
    pub shard: usize,
    pub fragment_id: i64,
    pub source: String,
    pub generation: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Solution {
    pub participants: Vec<Participant>,
    pub generations_used: Vec<u64>,
    pub missing_before: Vec<usize>,
    pub rebuilt_digests: Vec<(usize, String)>,
    pub data_digest: String,
    pub all_digest: String,
    pub corroborating: Vec<usize>,
    pub anchor_matches: Vec<usize>,
    /// Self-consistent received shards whose content contradicts this answer.
    pub contradictions: Vec<(usize, Evidence)>,
    /// Warnings attached to participating fragments.
    pub participant_warnings: Vec<Evidence>,
    pub trust: String,
    pub trust_reason: String,
    /// All corruption evidence excluded from this reconstruction.
    pub excluded_evidence: Vec<Evidence>,
    #[serde(skip)]
    pub rebuilt: Vec<(usize, Vec<u8>)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TriedCombination {
    pub fragment_ids: Vec<i64>,
    pub result: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StripeReport {
    pub object_id: String,
    pub stripe_index: usize,
    pub required_generation: u64,
    pub k: usize,
    pub m: usize,
    pub n: usize,
    pub shard_len: usize,
    pub eligible_positions: Vec<usize>,
    pub candidates: Vec<(usize, Vec<CandidateView>)>,
    pub evidence: Vec<Evidence>,
    pub tried: Vec<TriedCombination>,
    pub combinations_examined: usize,
    pub search_budget: usize,
    pub search_exhausted: bool,
    pub solutions: Vec<Solution>,
    pub status: String,
    pub status_detail: String,
    pub committed: bool,
    pub committed_run_id: Option<i64>,
    pub object_digest: Option<String>,
    pub object_digest_ok: Option<bool>,
    #[serde(skip)]
    pub rebuilt_stripe: Vec<(usize, Vec<u8>)>,
}

pub struct AnalyzeOpts {
    pub search_budget: usize,
}

impl Default for AnalyzeOpts {
    fn default() -> Self {
        Self {
            search_budget: DEFAULT_SEARCH_BUDGET,
        }
    }
}

#[derive(Clone)]
struct Ctx {
    manifest: Manifest,
    stripe: usize,
    required_generation: u64,
    isolated: Vec<String>,
    rows: Vec<FragmentRow>,
    bytes: Vec<Vec<u8>>,
    actual_digests: Vec<String>,
}

impl Ctx {
    fn expected(&self, shard: usize) -> Option<&str> {
        self.manifest.shard_digest(self.stripe, shard)
    }
}

/// Analyze one stripe. Reuses verified commits when their blocks re-verify.
pub fn analyze_stripe(
    store: &Store,
    manifest: &Manifest,
    stripe: usize,
    isolated: &[String],
    opts: &AnalyzeOpts,
) -> StripeReport {
    let k = manifest.codec.k;
    let m = manifest.codec.m;
    let n = manifest.codec.n();
    let shard_len = manifest.codec.shard_len;
    let required_generation = manifest.stripe_generation(stripe);

    let rows = store.fragments_for(&manifest.object_id, stripe);
    let mut bytes = Vec::with_capacity(rows.len());
    let mut actual_digests = Vec::with_capacity(rows.len());
    for row in &rows {
        let b = store.read_fragment(row).unwrap_or_default();
        actual_digests.push(crate::digest::of_bytes(&b));
        bytes.push(b);
    }
    let ctx = Ctx {
        manifest: manifest.clone(),
        stripe,
        required_generation,
        isolated: isolated.to_vec(),
        rows,
        bytes,
        actual_digests,
    };

    let mut report = StripeReport {
        object_id: manifest.object_id.clone(),
        stripe_index: stripe,
        required_generation,
        k,
        m,
        n,
        shard_len,
        eligible_positions: Vec::new(),
        candidates: Vec::new(),
        evidence: Vec::new(),
        tried: Vec::new(),
        combinations_examined: 0,
        search_budget: opts.search_budget,
        search_exhausted: true,
        solutions: Vec::new(),
        status: "unknown".into(),
        status_detail: String::new(),
        committed: false,
        committed_run_id: None,
        object_digest: manifest.object_digest.clone(),
        object_digest_ok: None,
        rebuilt_stripe: Vec::new(),
    };

    // ---- Per-fragment health and candidate views ------------------------------
    let mut by_shard: Vec<Vec<usize>> = vec![Vec::new(); n];
    for idx in 0..ctx.rows.len() {
        let row = &ctx.rows[idx];
        let view = assess_fragment(&ctx, idx);
        by_shard[row.shard_index].push(idx);
        if view.eligible && !report.eligible_positions.contains(&row.shard_index) {
            report.eligible_positions.push(row.shard_index);
        }
        if let Some(bucket) = report
            .candidates
            .iter_mut()
            .find(|(s, _)| *s == row.shard_index)
        {
            bucket.1.push(view);
        } else {
            report.candidates.push((row.shard_index, vec![view]));
        }
        collect_evidence(&ctx, idx, &mut report.evidence);
    }
    report.candidates.sort_by(|a, b| a.0.cmp(&b.0));
    report.eligible_positions.sort_unstable();

    // ---- Reuse previously committed, verified stripe --------------------------
    if let Some(commit) = store.committed(&manifest.object_id, stripe) {
        if commit.verified && commit.generation == required_generation {
            let blocks = store.committed_shards(&manifest.object_id, stripe);
            if blocks.len() == n
                && blocks.iter().all(|(_, b, d)| {
                    b.len() == shard_len && crate::digest::of_bytes(b) == *d
                })
            {
                report.committed = true;
                report.committed_run_id = Some(commit.run_id);
                report.status = "recovered-committed".into();
                report.status_detail =
                    "reusing committed stripe; recovered blocks re-verified on disk".into();
                report.rebuilt_stripe = blocks.into_iter().map(|(i, b, _)| (i, b)).collect();
                return report;
            }
        }
    }

    // ---- Enumerate k-position subsets x per-position candidates ---------------
    let positions: Vec<usize> = (0..n)
        .filter(|&p| by_shard[p].iter().any(|&i| is_eligible(&ctx, i)))
        .collect();
    let mut lists: Vec<Vec<usize>> = Vec::new();
    for &p in &positions {
        let mut v: Vec<usize> = by_shard[p]
            .iter()
            .copied()
            .filter(|&i| is_eligible(&ctx, i))
            .collect();
        v.sort_by(|&a, &b| candidate_order(&ctx, a, b));
        lists.push(v);
    }

    let mut solutions: Vec<Solution> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut examined = 0usize;
    let mut exhausted = true;

    if positions.len() >= k {
        let mut subset = vec![0usize; k];
        for first in 0..=positions.len() - k {
            subset[0] = first;
            if !fill_subsets(
                &ctx,
                &positions,
                &lists,
                &mut subset,
                1,
                opts.search_budget,
                &mut examined,
                &mut exhausted,
                &mut report.tried,
                &mut solutions,
                &mut seen,
            ) {
                break;
            }
        }
    }

    report.combinations_examined = examined;
    report.search_exhausted = exhausted;
    report.solutions = solutions;
    rank_solutions(&mut report.solutions);

    choose_preferred(&ctx, &mut report);
    report
}

fn fill_subsets(
    ctx: &Ctx,
    positions: &[usize],
    lists: &[Vec<usize>],
    subset: &mut [usize],
    depth: usize,
    budget: usize,
    examined: &mut usize,
    exhausted: &mut bool,
    tried: &mut Vec<TriedCombination>,
    solutions: &mut Vec<Solution>,
    seen: &mut HashSet<String>,
) -> bool {
    let k = subset.len();
    if depth == k {
        let chosen_lists: Vec<&Vec<usize>> = subset.iter().map(|&i| &lists[i]).collect();
        let mut picks = vec![0usize; k];
        loop {
            if *examined >= budget {
                *exhausted = false;
                return false;
            }
            let chosen: Vec<usize> = (0..k).map(|j| chosen_lists[j][picks[j]]).collect();
            *examined += 1;
            evaluate(ctx, &chosen, tried, solutions, seen);
            // cartesian increment, rightmost fastest (deterministic)
            let mut j = k;
            loop {
                if j == 0 {
                    return true;
                }
                j -= 1;
                picks[j] += 1;
                if picks[j] < chosen_lists[j].len() {
                    break;
                }
                picks[j] = 0;
            }
        }
    }
    let start = subset[depth - 1] + 1;
    let max = positions.len() - (k - depth);
    for v in start..=max {
        subset[depth] = v;
        if !fill_subsets(
            ctx, positions, lists, subset, depth + 1, budget, examined, exhausted, tried,
            solutions, seen,
        ) {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Fragment health and evidence.
// ---------------------------------------------------------------------------

fn assess_fragment(ctx: &Ctx, idx: usize) -> CandidateView {
    let row = &ctx.rows[idx];
    let actual = &ctx.actual_digests[idx];
    let isolated = ctx.isolated.iter().any(|s| s == &row.source);
    let claim = row.digest.clone();
    let claim_ok = claim.as_ref().map(|c| c == actual).unwrap_or(true);
    let expected = ctx.expected(row.shard_index).map(|s| s.to_string());
    let expected_ok = expected.as_ref().map(|e| e == actual);
    let generation_ok = row.generation == ctx.required_generation;
    let length_ok = ctx.bytes[idx].len() == ctx.manifest.codec.shard_len;
    let eligible = !isolated
        && claim_ok
        && generation_ok
        && length_ok
        && expected_ok.unwrap_or(true);
    CandidateView {
        fragment_id: row.id,
        source: row.source.clone(),
        generation: row.generation,
        length: row.length,
        actual_digest: actual.clone(),
        claim_digest: claim,
        expected_digest: expected,
        claim_ok,
        expected_ok,
        generation_ok,
        length_ok,
        isolated,
        eligible,
    }
}

fn make_evidence(ctx: &Ctx, idx: usize, kind: &str, detail: String) -> Evidence {
    let row = &ctx.rows[idx];
    Evidence {
        fragment_id: row.id,
        source: row.source.clone(),
        shard: row.shard_index,
        generation: row.generation,
        kind: kind.into(),
        detail,
        digest_actual: Some(ctx.actual_digests[idx].clone()),
        digest_claim: row.digest.clone(),
        digest_expected: ctx.expected(row.shard_index).map(|s| s.to_string()),
    }
}

fn collect_evidence(ctx: &Ctx, idx: usize, out: &mut Vec<Evidence>) {
    let row = &ctx.rows[idx];
    if ctx.isolated.iter().any(|s| s == &row.source) {
        out.push(make_evidence(
            ctx,
            idx,
            "isolated-source",
            format!("source '{}' is manually isolated", row.source),
        ));
    }
    if ctx.bytes[idx].len() != ctx.manifest.codec.shard_len {
        out.push(make_evidence(
            ctx,
            idx,
            "length-mismatch",
            format!(
                "fragment length {} != manifest shard_len {}",
                ctx.bytes[idx].len(),
                ctx.manifest.codec.shard_len
            ),
        ));
    }
    if row.generation != ctx.required_generation {
        out.push(make_evidence(
            ctx,
            idx,
            "generation-mismatch",
            format!(
                "fragment generation {} != stripe required generation {}",
                row.generation, ctx.required_generation
            ),
        ));
    }
    if let Some(claim) = &row.digest {
        if claim != &ctx.actual_digests[idx] {
            out.push(make_evidence(
                ctx,
                idx,
                "claim-digest-mismatch",
                "recomputed digest differs from sidecar claim: bit flip or torn write".into(),
            ));
        }
    }
    if let Some(exp) = ctx.expected(row.shard_index) {
        if exp != ctx.actual_digests[idx] {
            out.push(make_evidence(
                ctx,
                idx,
                "manifest-digest-mismatch",
                "recomputed digest differs from manifest anchor for this shard".into(),
            ));
        }
    }
    // Same-number group diagnostics: duplicate content vs two content candidates.
    let group: Vec<usize> = ctx
        .rows
        .iter()
        .enumerate()
        .filter(|(_, r)| r.shard_index == row.shard_index)
        .map(|(i, _)| i)
        .collect();
    let same_content = group
        .iter()
        .any(|&j| j != idx && ctx.actual_digests[j] == ctx.actual_digests[idx]);
    let diff_content = group
        .iter()
        .any(|&j| j != idx && ctx.actual_digests[j] != ctx.actual_digests[idx]);
    if same_content && row.generation == ctx.required_generation {
        out.push(make_evidence(
            ctx,
            idx,
            "duplicate-candidate",
            "duplicate shard number with identical content from another source".into(),
        ));
    }
    if diff_content && row.generation == ctx.required_generation {
        out.push(make_evidence(
            ctx,
            idx,
            "conflicting-content",
            "same shard number has a second content candidate".into(),
        ));
    }
}

fn is_eligible(ctx: &Ctx, idx: usize) -> bool {
    let row = &ctx.rows[idx];
    if ctx.isolated.iter().any(|s| s == &row.source) {
        return false;
    }
    if row.generation != ctx.required_generation {
        return false;
    }
    if ctx.bytes[idx].len() != ctx.manifest.codec.shard_len {
        return false;
    }
    if let Some(claim) = &row.digest {
        if claim != &ctx.actual_digests[idx] {
            return false;
        }
    }
    if let Some(exp) = ctx.expected(row.shard_index) {
        if exp != ctx.actual_digests[idx] {
            return false;
        }
    }
    true
}

fn candidate_order(ctx: &Ctx, a: usize, b: usize) -> std::cmp::Ordering {
    let ra = &ctx.rows[a];
    let rb = &ctx.rows[b];
    score_candidate(ctx, b)
        .cmp(&score_candidate(ctx, a))
        .then_with(|| ra.source.cmp(&rb.source))
        .then_with(|| ra.id.cmp(&rb.id))
}

fn score_candidate(ctx: &Ctx, idx: usize) -> u8 {
    let row = &ctx.rows[idx];
    let mut score = 0u8;
    if ctx.expected(row.shard_index) == Some(ctx.actual_digests[idx].as_str()) {
        score += 4;
    }
    if row.digest.is_some() {
        score += 1;
    }
    score
}

// ---------------------------------------------------------------------------
// Combination evaluation and solution construction.
// ---------------------------------------------------------------------------

fn evaluate(
    ctx: &Ctx,
    chosen: &[usize],
    tried: &mut Vec<TriedCombination>,
    solutions: &mut Vec<Solution>,
    seen: &mut HashSet<String>,
) {
    let ids: Vec<i64> = chosen.iter().map(|&i| ctx.rows[i].id).collect();
    let positions: Vec<usize> = chosen.iter().map(|&i| ctx.rows[i].shard_index).collect();
    let available: Vec<(usize, Vec<u8>)> = chosen
        .iter()
        .map(|&i| (ctx.rows[i].shard_index, ctx.bytes[i].clone()))
        .collect();
    let k = ctx.manifest.codec.k;
    let m = ctx.manifest.codec.m;
    let n = ctx.manifest.codec.n();

    let rebuilt = match erasure::decode(&available, k, m) {
        Some(v) if v.len() == n => v,
        _ => {
            tried.push(TriedCombination {
                fragment_ids: ids,
                result: "rejected".into(),
                reason: "decode failed: set is not a consistent k-subspace".into(),
            });
            return;
        }
    };

    // Hard anchors: any non-participating received fragment whose claim is
    // valid and whose manifest anchor matches it but which contradicts the
    // rebuilt stripe proves this combination corrupt.
    let mut anchor_conflict: Option<usize> = None;
    let mut corroborating = Vec::new();
    let mut contradictions: Vec<(usize, Evidence)> = Vec::new();
    let mut participant_warnings: Vec<Evidence> = Vec::new();

    for idx in 0..ctx.rows.len() {
        let row = &ctx.rows[idx];
        if ctx.isolated.iter().any(|s| s == &row.source) {
            continue;
        }
        if ctx.bytes[idx].len() != ctx.manifest.codec.shard_len {
            continue;
        }
        let claim_ok = row
            .digest
            .as_ref()
            .map(|c| c == &ctx.actual_digests[idx])
            .unwrap_or(true);
        if !claim_ok {
            continue;
        }
        let participating = positions.contains(&row.shard_index);
        let matches_rebuilt = ctx.bytes[idx] == rebuilt[row.shard_index];
        if matches_rebuilt {
            if !participating {
                corroborating.push(row.shard_index);
            }
        } else if participating {
            // Should be impossible for decode inputs; guard anyway.
            participant_warnings.push(make_evidence(
                ctx,
                idx,
                "participant-inconsistency",
                "participating shard did not match rebuilt output".into(),
            ));
        } else {
            let anchored = ctx.expected(row.shard_index)
                == Some(ctx.actual_digests[idx].as_str());
            if anchored {
                anchor_conflict = Some(row.shard_index);
                contradictions.push((
                    row.shard_index,
                    make_evidence(
                        ctx,
                        idx,
                        "excluded-corruption",
                        "anchor-verified received shard contradicts this combination".into(),
                    ),
                ));
            } else {
                contradictions.push((
                    row.shard_index,
                    make_evidence(
                        ctx,
                        idx,
                        "conflicting-content",
                        "non-participating shard offers a different feasible content candidate"
                            .into(),
                    ),
                ));
            }
        }
    }

    if let Some(pos) = anchor_conflict {
        tried.push(TriedCombination {
            fragment_ids: ids,
            result: "rejected".into(),
            reason: format!("rebuilt shard {pos} contradicts an anchor-verified fragment"),
        });
        return;
    }

    corroborating.sort_unstable();
    corroborating.dedup();

    // Anchored positions that agree with the rebuilt output.
    let mut anchor_matches: Vec<usize> = (0..n)
        .filter(|&p| ctx.expected(p) == Some(crate::digest::of_bytes(&rebuilt[p]).as_str()))
        .collect();
    anchor_matches.sort_unstable();

    let rebuilt_pairs: Vec<(usize, Vec<u8>)> =
        rebuilt.into_iter().enumerate().map(|(i, b)| (i, b)).collect();
    let data_digest = data_stripe_digest(&rebuilt_pairs, k);
    let all_digest = all_shards_digest(&rebuilt_pairs);
    if !seen.insert(data_digest.clone()) {
        tried.push(TriedCombination {
            fragment_ids: ids,
            result: "duplicate-solution".into(),
            reason: "same reconstructed data already produced by another combination".into(),
        });
        return;
    }

    let missing_before: Vec<usize> = (0..n)
        .filter(|&p| {
            !ctx.rows.iter().enumerate().any(|(i, r)| {
                r.shard_index == p
                    && is_eligible(ctx, i)
                    && ctx.bytes[i] == rebuilt_pairs[p].1
            })
        })
        .collect();

    let rebuilt_digests: Vec<(usize, String)> = rebuilt_pairs
        .iter()
        .map(|(p, b)| (*p, crate::digest::of_bytes(b)))
        .collect();

    let mut participants: Vec<Participant> = chosen
        .iter()
        .map(|&i| Participant {
            shard: ctx.rows[i].shard_index,
            fragment_id: ctx.rows[i].id,
            source: ctx.rows[i].source.clone(),
            generation: ctx.rows[i].generation,
        })
        .collect();
    participants.sort_by_key(|p| p.shard);
    let mut generations_used: Vec<u64> =
        chosen.iter().map(|&i| ctx.rows[i].generation).collect();
    generations_used.sort_unstable();
    generations_used.dedup();

    // Excluded evidence: every received fragment in this stripe that could
    // not take part in this answer (corrupt/wrong-generation/conflicting),
    // minus evidence about the winning fragments themselves.
    let participant_ids: HashSet<i64> =
        chosen.iter().map(|&i| ctx.rows[i].id).collect();
    let mut excluded_evidence: Vec<Evidence> = Vec::new();
    let mut all_evidence = Vec::new();
    for idx in 0..ctx.rows.len() {
        collect_evidence(ctx, idx, &mut all_evidence);
    }
    for e in all_evidence {
        if !participant_ids.contains(&e.fragment_id) {
            excluded_evidence.push(e);
        }
    }
    dedup_evidence(&mut excluded_evidence);
    dedup_pairs(&mut contradictions);
    dedup_evidence(&mut participant_warnings);

    let (trust, reason) = classify_trust(
        &anchor_matches,
        &corroborating,
        &contradictions,
        k,
        m,
        n,
    );

    solutions.push(Solution {
        participants,
        generations_used,
        missing_before,
        rebuilt_digests,
        data_digest,
        all_digest,
        corroborating,
        anchor_matches,
        contradictions,
        participant_warnings,
        trust,
        trust_reason: reason,
        excluded_evidence,
        rebuilt: rebuilt_pairs,
    });
    tried.push(TriedCombination {
        fragment_ids: ids,
        result: "feasible".into(),
        reason: "reconstruction self-consistent; retained as a feasible answer".into(),
    });
}

fn classify_trust(
    anchor_matches: &[usize],
    corroborating: &[usize],
    contradictions: &[(usize, Evidence)],
    k: usize,
    _m: usize,
    _n: usize,
) -> (String, String) {
    let has_conflict = !contradictions.is_empty();
    if !anchor_matches.is_empty() {
        return if has_conflict {
            (
                "anchor-consistent".into(),
                format!(
                    "matches {} manifest-anchored shard(s) but an unanchored conflicting candidate remains",
                    anchor_matches.len()
                ),
            )
        } else {
            (
                "stripe-verified".into(),
                format!(
                    "{} manifest-anchored shard(s) confirm the reconstruction",
                    anchor_matches.len()
                ),
            )
        };
    }
    if !has_conflict && corroborating.len() + k >= k + 1 {
        return (
            "corroborated".into(),
            format!(
                "no manifest anchor; {} extra consistent shard(s) corroborate the answer",
                corroborating.len()
            ),
        );
    }
    if has_conflict {
        (
            "ambiguous".into(),
            "no anchor resolves competing feasible content candidates".into(),
        )
    } else {
        (
            "minimum-feasible".into(),
            "recovered at exactly the k-shard threshold with no extra verification".into(),
        )
    }
}

fn dedup_evidence(v: &mut Vec<Evidence>) {
    v.sort_by(|a, b| {
        a.fragment_id
            .cmp(&b.fragment_id)
            .then_with(|| a.kind.cmp(&b.kind))
            .then_with(|| a.detail.cmp(&b.detail))
    });
    v.dedup_by(|a, b| {
        a.fragment_id == b.fragment_id && a.kind == b.kind && a.detail == b.detail
    });
}

fn dedup_pairs(v: &mut Vec<(usize, Evidence)>) {
    v.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| a.1.fragment_id.cmp(&b.1.fragment_id))
            .then_with(|| a.1.kind.cmp(&b.1.kind))
    });
    v.dedup_by(|a, b| a.0 == b.0 && a.1.fragment_id == b.1.fragment_id && a.1.kind == b.1.kind);
}

fn data_stripe_digest(shards: &[(usize, Vec<u8>)], k: usize) -> String {
    let mut h = sha2::Sha256::new();
    use sha2::Digest;
    h.update(b"STRIPE-DATA/v1");
    for p in 0..k {
        h.update(&shards[p].1);
    }
    let bytes = h.finalize();
    format!("{}{}", crate::digest::PREFIX, hex::encode_upper(bytes))
}

fn all_shards_digest(shards: &[(usize, Vec<u8>)]) -> String {
    let mut h = sha2::Sha256::new();
    use sha2::Digest;
    h.update(b"STRIPE-ALL/v1");
    for (_, b) in shards {
        h.update(b);
    }
    let bytes = h.finalize();
    format!("{}{}", crate::digest::PREFIX, hex::encode_upper(bytes))
}

fn rank_solutions(solutions: &mut [Solution]) {
    solutions.sort_by(|a, b| {
        trust_rank(&b.trust)
            .cmp(&trust_rank(&a.trust))
            .then_with(|| b.anchor_matches.len().cmp(&a.anchor_matches.len()))
            .then_with(|| b.corroborating.len().cmp(&a.corroborating.len()))
            .then_with(|| a.contradictions.len().cmp(&b.contradictions.len()))
            .then_with(|| a.data_digest.cmp(&b.data_digest))
    });
}

fn trust_rank(t: &str) -> u8 {
    match t {
        "object-verified" => 5,
        "stripe-verified" => 4,
        "corroborated" => 3,
        "anchor-consistent" => 2,
        "minimum-feasible" => 1,
        "ambiguous" => 0,
        _ => 0,
    }
}

fn choose_preferred(ctx: &Ctx, report: &mut StripeReport) {
    if report.solutions.is_empty() {
        if report.eligible_positions.len() < report.k {
            report.status = "unrecoverable".into();
            report.status_detail = format!(
                "only {} distinct shard position(s) eligible, need {} (recovery threshold)",
                report.eligible_positions.len(),
                report.k
            );
        } else {
            report.status = "inconsistent".into();
            report.status_detail =
                "enough positions present but no consistent k-subspace found".into();
        }
        return;
    }
    let unique_data: HashSet<String> =
        report.solutions.iter().map(|s| s.data_digest.clone()).collect();
    let top = report.solutions[0].clone();
    report.rebuilt_stripe = top.rebuilt.clone();
    if unique_data.len() > 1 {
        report.status = "ambiguous".into();
        report.status_detail = format!(
            "{} distinct feasible reconstructions retained; differences listed per solution",
            unique_data.len()
        );
        return;
    }
    report.status = match top.trust.as_str() {
        "stripe-verified" => "recoverable-verified".into(),
        "corroborated" => "recoverable-corroborated".into(),
        "minimum-feasible" => "recoverable-threshold".into(),
        other => other.to_string(),
    };
    report.status_detail = top.trust_reason.clone();
    let _ = ctx;
}

// ---------------------------------------------------------------------------
// Object-level verification across stripes.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ObjectVerdict {
    pub object_digest_ok: bool,
    pub unique_match: bool,
    pub combinations_examined: usize,
    pub budget: usize,
    pub complete: bool,
    pub matched_keys: Vec<String>,
}

#[derive(Debug, Clone)]
struct Choice {
    stripe: usize,
    sol_idx: usize,
    data_digest: String,
}

/// Enumerate stripe-solution combinations (bounded), recompute the object
/// digest and record which combinations match the manifest anchor. Updates
/// per-solution trust labels to `object-verified` when the matching
/// combination is unique.
pub fn verify_object(
    manifest: &Manifest,
    reports: &mut [StripeReport],
) -> Option<ObjectVerdict> {
    let anchor = manifest.object_digest.as_ref()?;
    let stripe_count = manifest.stripes.len();
    if reports.len() != stripe_count {
        return None;
    }

    let mut options: Vec<Vec<Choice>> = Vec::with_capacity(stripe_count);
    let mut complete = true;
    for r in reports.iter() {
        if r.rebuilt_stripe.len() != manifest.codec.n() {
            complete = false;
        }
        let mut seen = HashSet::new();
        let mut opts = Vec::new();
        for (i, s) in r.solutions.iter().enumerate() {
            if seen.insert(s.data_digest.clone()) {
                opts.push(Choice {
                    stripe: r.stripe_index,
                    sol_idx: i,
                    data_digest: s.data_digest.clone(),
                });
            }
        }
        if opts.is_empty() && r.committed {
            // Committed stripe: synthesize a single pseudo-option.
            opts.push(Choice {
                stripe: r.stripe_index,
                sol_idx: usize::MAX,
                data_digest: String::new(),
            });
        }
        if opts.is_empty() {
            complete = false;
        }
        options.push(opts);
    }
    if !complete {
        return Some(ObjectVerdict {
            object_digest_ok: false,
            unique_match: false,
            combinations_examined: 0,
            budget: OBJECT_COMBO_BUDGET,
            complete: false,
            matched_keys: Vec::new(),
        });
    }

    let k = manifest.codec.k;
    let n = manifest.codec.n();
    let shard_len = manifest.codec.shard_len;

    let mut examined = 0usize;
    let mut matched_keys: Vec<String> = Vec::new();
    let mut picks = vec![0usize; stripe_count];
    'outer: loop {
        if examined >= OBJECT_COMBO_BUDGET {
            break 'outer;
        }
        examined += 1;

        // Build full stripes for this combination: prefer solution bytes,
        // otherwise the committed rebuilt bytes.
        let mut stripes: Vec<Vec<Vec<u8>>> = Vec::with_capacity(stripe_count);
        for (st, report) in reports.iter().enumerate() {
            let sol_idx = options[st][picks[st]].sol_idx;
            if sol_idx == usize::MAX {
                let mut sorted = report.rebuilt_stripe.clone();
                sorted.sort_by_key(|(p, _)| *p);
                stripes.push(sorted.into_iter().map(|(_, b)| b).collect());
            } else {
                let mut sorted = report.solutions[sol_idx].rebuilt.clone();
                sorted.sort_by_key(|(p, _)| *p);
                stripes.push(sorted.into_iter().map(|(_, b)| b).collect());
            }
        }
        let computed = crate::digest::of_object(
            &stripes,
            shard_len,
            n,
            manifest.data_len.unwrap_or(k * shard_len * stripe_count),
        );
        if computed.eq_ignore_ascii_case(anchor) {
            let key = picks
                .iter()
                .zip(options.iter())
                .map(|(p, opts)| opts[*p].data_digest.clone())
                .collect::<Vec<_>>()
                .join("|");
            matched_keys.push(key);
        }

        let mut j = stripe_count;
        loop {
            if j == 0 {
                break 'outer;
            }
            j -= 1;
            picks[j] += 1;
            if picks[j] < options[j].len() {
                break;
            }
            picks[j] = 0;
        }
    }

    matched_keys.sort();
    matched_keys.dedup();
    let unique = matched_keys.len() == 1;
    let ok = !matched_keys.is_empty();

    if unique {
        let winning: Vec<HashSet<String>> = matched_keys[0]
            .split('|')
            .map(|s| {
                let mut h = HashSet::new();
                h.insert(s.to_string());
                h
            })
            .collect();
        for (st, report) in reports.iter_mut().enumerate() {
            for sol in report.solutions.iter_mut() {
                if winning[st].contains(&sol.data_digest) {
                    sol.trust = "object-verified".into();
                    sol.trust_reason =
                        "full object digest anchors this solution uniquely".into();
                }
            }
        }
    }
    for r in reports.iter_mut() {
        rank_solutions(&mut r.solutions);
        r.object_digest_ok = Some(ok);
        if !ok {
            r.status_detail = format!(
                "{} (object digest verification failed)",
                r.status_detail
            );
        }
    }

    Some(ObjectVerdict {
        object_digest_ok: ok,
        unique_match: unique,
        combinations_examined: examined,
        budget: OBJECT_COMBO_BUDGET,
        complete: true,
        matched_keys,
    })
}

// ---------------------------------------------------------------------------
// Recovery run: analyze all stripes, verify object anchor, commit per stripe.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct RunSummary {
    pub run_id: i64,
    pub object_id: String,
    pub stripe_count: usize,
    pub committed: Vec<usize>,
    pub reused: Vec<usize>,
    pub ambiguous: Vec<usize>,
    pub unrecoverable: Vec<usize>,
    pub object_verified: Option<bool>,
    pub unique_object_match: bool,
    pub object_combos_examined: usize,
    pub errors: Vec<(usize, String)>,
}

pub fn run_recovery(
    store: &Store,
    object_id: &str,
    only_stripe: Option<usize>,
) -> Result<RunSummary, String> {
    let manifest = store
        .get_manifest(object_id)
        .ok_or_else(|| format!("unknown object: {object_id}"))?;
    manifest.validate()?;
    let isolated = store.isolated_sources();
    let opts = AnalyzeOpts::default();
    let run_id = store.start_run(&format!("recovery {object_id}"));

    let stripes: Vec<usize> = match only_stripe {
        Some(s) => vec![s],
        None => (0..manifest.stripes.len()).collect(),
    };
    let mut reports: Vec<StripeReport> = stripes
        .iter()
        .map(|&s| analyze_stripe(store, &manifest, s, &isolated, &opts))
        .collect();

    let mut verdict_combos = 0usize;
    let mut object_ok: Option<bool> = None;
    let mut unique = false;
    if only_stripe.is_none() {
        if let Some(v) = verify_object(&manifest, &mut reports) {
            verdict_combos = v.combinations_examined;
            object_ok = Some(v.object_digest_ok);
            unique = v.unique_match;
        }
    }

    let mut summary = RunSummary {
        run_id,
        object_id: object_id.into(),
        stripe_count: manifest.stripes.len(),
        committed: Vec::new(),
        reused: Vec::new(),
        ambiguous: Vec::new(),
        unrecoverable: Vec::new(),
        object_verified: object_ok,
        unique_object_match: unique,
        object_combos_examined: verdict_combos,
        errors: Vec::new(),
    };

    for report in &mut reports {
        if report.committed {
            summary.reused.push(report.stripe_index);
            continue;
        }
        let distinct: HashSet<String> =
            report.solutions.iter().map(|s| s.data_digest.clone()).collect();
        if distinct.is_empty() {
            summary.unrecoverable.push(report.stripe_index);
            continue;
        }
        if distinct.len() > 1 {
            summary.ambiguous.push(report.stripe_index);
            continue;
        }
        let sol = &report.solutions[0];
        let trusted = matches!(
            sol.trust.as_str(),
            "object-verified" | "stripe-verified"
        );
        if !trusted {
            // corroborated / minimum-feasible answers are retained but not
            // auto-committed; the UI lists them for human confirmation.
            summary.ambiguous.push(report.stripe_index);
            continue;
        }

        // Commit only the blocks that were actually missing before recovery;
        // original fragment bytes are never overwritten.
        let missing: Vec<(usize, Vec<u8>)> = sol
            .rebuilt
            .iter()
            .filter(|(p, _)| sol.missing_before.contains(p))
            .cloned()
            .collect();
        let analysis_json = serde_json::to_string(&*report).unwrap_or_default();
        match store.commit_stripe(
            object_id,
            report.stripe_index,
            report.required_generation,
            run_id,
            &missing,
            &analysis_json,
        ) {
            Ok(()) => {
                report.committed = true;
                report.committed_run_id = Some(run_id);
                report.status = "recovered-committed".into();
                report.status_detail =
                    "committed atomically per stripe; blocks on disk re-hashed".into();
                summary.committed.push(report.stripe_index);
            }
            Err(e) => {
                summary.errors.push((report.stripe_index, e));
            }
        }
    }

    let ok = summary.errors.is_empty()
        && summary.ambiguous.is_empty()
        && summary.unrecoverable.is_empty();
    store.finish_run(
        run_id,
        if ok {
            "completed"
        } else if summary.committed.is_empty() && summary.reused.is_empty() {
            "failed"
        } else {
            "partial"
        },
    );
    Ok(summary)
}

/// Drop the commit of every stripe that contains an isolated source, then run
/// recovery again for exactly those stripes.
pub fn recompute_after_isolation(
    store: &Store,
    object_id: &str,
    sources: &[String],
) -> Result<RunSummary, String> {
    let manifest = store
        .get_manifest(object_id)
        .ok_or_else(|| format!("unknown object: {object_id}"))?;
    let mut affected: Vec<usize> = Vec::new();
    for stripe in 0..manifest.stripes.len() {
        let rows = store.fragments_for(object_id, stripe);
        let touches = rows
            .iter()
            .any(|r| sources.iter().any(|s| s == &r.source));
        if touches && store.committed(object_id, stripe).is_some() {
            store.delete_commit(object_id, stripe)?;
        }
        if touches {
            affected.push(stripe);
        }
    }
    let isolated = store.isolated_sources();
    let opts = AnalyzeOpts::default();
    let run_id = store.start_run(&format!("recompute {object_id}"));
    let mut summary = RunSummary {
        run_id,
        object_id: object_id.into(),
        stripe_count: manifest.stripes.len(),
        committed: Vec::new(),
        reused: Vec::new(),
        ambiguous: Vec::new(),
        unrecoverable: Vec::new(),
        object_verified: None,
        unique_object_match: false,
        object_combos_examined: 0,
        errors: Vec::new(),
    };

    // Recompute affected stripes, but object-digest verification is performed
    // over the whole object using committed + recomputed stripes.
    let mut all_reports: Vec<StripeReport> = (0..manifest.stripes.len())
        .map(|s| analyze_stripe(store, &manifest, s, &isolated, &opts))
        .collect();
    if let Some(v) = verify_object(&manifest, &mut all_reports) {
        summary.object_verified = Some(v.object_digest_ok);
        summary.unique_object_match = v.unique_match;
        summary.object_combos_examined = v.combinations_examined;
    }

    for stripe in affected {
        let rep = &mut all_reports[stripe];
        if rep.committed {
            summary.reused.push(rep.stripe_index);
            continue;
        }
        let distinct: HashSet<String> =
            rep.solutions.iter().map(|s| s.data_digest.clone()).collect();
        if distinct.is_empty() {
            summary.unrecoverable.push(rep.stripe_index);
            continue;
        }
        if distinct.len() > 1 {
            summary.ambiguous.push(rep.stripe_index);
            continue;
        }
        let sol = &rep.solutions[0];
        if !matches!(sol.trust.as_str(), "object-verified" | "stripe-verified") {
            summary.ambiguous.push(rep.stripe_index);
            continue;
        }
        let missing: Vec<(usize, Vec<u8>)> = sol
            .rebuilt
            .iter()
            .filter(|(p, _)| sol.missing_before.contains(p))
            .cloned()
            .collect();
        let analysis_json = serde_json::to_string(&*rep).unwrap_or_default();
        match store.commit_stripe(
            object_id,
            rep.stripe_index,
            rep.required_generation,
            run_id,
            &missing,
            &analysis_json,
        ) {
            Ok(()) => {
                rep.committed = true;
                rep.committed_run_id = Some(run_id);
                rep.status = "recovered-committed".into();
                rep.status_detail =
                    "recommitted after isolation change; blocks re-hashed".into();
                summary.committed.push(rep.stripe_index);
            }
            Err(e) => summary.errors.push((rep.stripe_index, e)),
        }
    }
    store.finish_run(run_id, if summary.errors.is_empty() { "completed" } else { "partial" });
    Ok(summary)
}
