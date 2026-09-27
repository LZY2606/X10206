//! Feasible-set enumeration and reconstruction for one stripe.
//!
//! Selection is never first-come-first-served: every content candidate per
//! shard position is enumerated under generation, digest and stripe-length
//! constraints. All feasible reconstructions are retained; distinct feasible
//! results are reported as ambiguity with the differing shard positions.

use crate::coding::{decode, CodingParams};
use crate::model::{digest_hex, FragmentRecord};
use serde::Serialize;

pub const DEFAULT_SEARCH_BUDGET: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyState {
    Match,
    Mismatch,
    Unknown,
}

impl VerifyState {
    pub fn as_str(self) -> &'static str {
        match self {
            VerifyState::Match => "match",
            VerifyState::Mismatch => "mismatch",
            VerifyState::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Exclusion {
    pub fragment_id: i64,
    pub shard_index: u8,
    pub generation: u64,
    pub source: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Participant {
    pub shard_index: u8,
    pub fragment_id: i64,
    pub source: String,
    pub generation: u64,
    pub digest: Option<String>,
    pub digest_check: VerifyState,
}

#[derive(Debug, Clone, Serialize)]
pub struct PositionInfo {
    pub shard_index: u8,
    pub candidate_fragment_ids: Vec<i64>,
    pub chosen_fragment_id: Option<i64>,
    pub expected_digest: Option<String>,
    pub recomputed_digest: Option<String>,
    pub digest_check: VerifyState,
}

#[derive(Debug, Clone, Serialize)]
pub struct Solution {
    /// Stable id = digest of the reconstructed stripe bytes.
    pub id: String,
    pub combo_ordinal: usize,
    pub participant_combos: Vec<Vec<i64>>,
    pub participants: Vec<Participant>,
    pub positions: Vec<PositionInfo>,
    /// Recomputed digest of reconstructed stripe data (k data shards, in order).
    pub stripe_data_digest: String,
    pub generation: u64,
    /// Full reconstructed shards, one per position 0..k+m.
    #[serde(skip)]
    pub reconstructed: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CandidateInfo {
    pub shard_index: u8,
    pub fragment_ids: Vec<i64>,
    pub sources: Vec<String>,
    pub generations: Vec<u64>,
    pub distinct_contents: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StripeStatus {
    Committed,
    Recoverable,
    Ambiguous,
    Blocked,
}

impl StripeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            StripeStatus::Committed => "committed",
            StripeStatus::Recoverable => "recoverable",
            StripeStatus::Ambiguous => "ambiguous",
            StripeStatus::Blocked => "blocked",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StripeAnalysis {
    pub object_id: String,
    pub stripe_index: u32,
    pub expected_generation: u64,
    pub shard_len: u32,
    pub coding_version: String,
    pub status: StripeStatus,
    pub committed: bool,
    pub committed_trusted: Option<bool>,
    pub candidates: Vec<CandidateInfo>,
    pub solutions: Vec<Solution>,
    pub exclusions: Vec<Exclusion>,
    pub combos_tried: usize,
    pub search_budget: usize,
    pub budget_exhausted: bool,
    pub feasible_count: usize,
    pub differing_positions: Vec<u8>,
    pub summary: String,
}

struct ContentCandidate {
    shard_index: u8,
    fragment_id: i64,
    source: String,
    generation: u64,
    bytes: Vec<u8>,
    digest: Option<String>,
    duplicate_ids: Vec<i64>,
}

fn digest_state(expected: Option<&str>, recomputed: &str) -> VerifyState {
    match expected {
        None => VerifyState::Unknown,
        Some(exp) => {
            if crate::model::normalize_digest(exp) == recomputed {
                VerifyState::Match
            } else {
                VerifyState::Mismatch
            }
        }
    }
}

/// Enumerate feasible reconstructions for a single stripe.
#[allow(clippy::too_many_arguments)]
pub fn analyze_stripe(
    object_id: &str,
    stripe_index: u32,
    params: CodingParams,
    expected_generation: u64,
    expected_shard_len: u32,
    shard_digests: &[Option<String>],
    fragments: Vec<FragmentRecord>,
    isolated_sources: &[String],
    search_budget: usize,
    load_bytes: impl Fn(&FragmentRecord) -> std::io::Result<Vec<u8>>,
) -> StripeAnalysis {
    let n = params.n() as u8;
    let mut exclusions = Vec::new();
    let mut eligible: Vec<FragmentRecord> = Vec::new();
    let mut raw_bytes: std::collections::HashMap<i64, Vec<u8>> = std::collections::HashMap::new();

    for frag in fragments {
        let bytes = match load_bytes(&frag) {
            Ok(b) => b,
            Err(e) => {
                exclusions.push(Exclusion {
                    fragment_id: frag.id,
                    shard_index: frag.shard_index,
                    generation: frag.generation,
                    source: frag.source.clone(),
                    reason: format!("raw bytes unreadable: {e}"),
                });
                continue;
            }
        };
        let recomputed = digest_hex(&bytes);
        let reason = if isolated_sources.iter().any(|s| s == &frag.source) {
            Some(format!("source `{}` manually isolated", frag.source))
        } else if frag.shard_index >= n {
            Some(format!(
                "shard index {} outside 0..{} for {}",
                frag.shard_index,
                n - 1,
                params.version.as_str()
            ))
        } else if frag.generation != expected_generation {
            Some(format!(
                "generation {} != manifest generation {} (partial-write mixture)",
                frag.generation, expected_generation
            ))
        } else if frag.length != expected_shard_len as usize {
            Some(format!(
                "fragment length {} disagrees with manifest shard_len {}",
                frag.length, expected_shard_len
            ))
        } else {
            match frag.digest.as_deref() {
                Some(claimed)
                    if crate::model::normalize_digest(claimed) != recomputed =>
                {
                    Some(format!(
                        "claimed digest {} disagrees with recomputed digest {recomputed} (sidecar bytes differ)",
                        claimed
                    ))
                }
                _ => None,
            }
        };
        match reason {
            Some(why) => exclusions.push(Exclusion {
                fragment_id: frag.id,
                shard_index: frag.shard_index,
                generation: frag.generation,
                source: frag.source,
                reason: why,
            }),
            None => {
                raw_bytes.insert(frag.id, bytes);
                eligible.push(frag);
            }
        }
    }

    // Group eligible fragments by shard position, merging identical content.
    let mut by_pos: Vec<Vec<ContentCandidate>> = vec![Vec::new(); params.n()];
    let mut candidate_info: Vec<CandidateInfo> = Vec::new();
    let mut pos_order: Vec<u8> = Vec::new();
    for pos in 0..params.n() {
        let mut here: Vec<&FragmentRecord> = eligible
            .iter()
            .filter(|f| f.shard_index as usize == pos)
            .collect();
        if here.is_empty() {
            continue;
        }
        here.sort_by_key(|f| f.id);
        pos_order.push(pos as u8);
        let mut contents: Vec<ContentCandidate> = Vec::new();
        for frag in here {
            let bytes = raw_bytes[&frag.id].clone();
            if let Some(slot) = contents.iter_mut().find(|c| c.bytes == bytes) {
                slot.duplicate_ids.push(frag.id);
            } else {
                contents.push(ContentCandidate {
                    shard_index: pos as u8,
                    fragment_id: frag.id,
                    source: frag.source.clone(),
                    generation: frag.generation,
                    bytes,
                    digest: frag.digest.clone(),
                    duplicate_ids: Vec::new(),
                });
            }
        }
        contents.sort_by_key(|c| c.fragment_id);
        candidate_info.push(CandidateInfo {
            shard_index: pos as u8,
            fragment_ids: contents.iter().flat_map(|c| {
                let mut ids = vec![c.fragment_id];
                ids.extend(c.duplicate_ids.iter().copied());
                ids
            }).collect(),
            sources: contents.iter().map(|c| c.source.clone()).collect(),
            generations: contents.iter().map(|c| c.generation).collect(),
            distinct_contents: contents.len(),
        });
        by_pos[pos] = contents;
    }

    let available_positions = pos_order.len();
    let k = params.k as usize;
    let mut analysis = StripeAnalysis {
        object_id: object_id.to_string(),
        stripe_index,
        expected_generation,
        shard_len: expected_shard_len,
        coding_version: params.version.as_str().to_string(),
        status: StripeStatus::Blocked,
        committed: false,
        committed_trusted: None,
        candidates: candidate_info,
        solutions: Vec::new(),
        exclusions,
        combos_tried: 0,
        search_budget,
        budget_exhausted: false,
        feasible_count: 0,
        differing_positions: Vec::new(),
        summary: String::new(),
    };

    if available_positions < k {
        analysis.summary = format!(
            "below recovery floor: {available_positions} shard positions available, need {k}"
        );
        return analysis;
    }

    // DFS: choose exactly k positions and one content candidate at each.
    // Order is fully deterministic (position asc, fragment id asc).
    let mut solutions: Vec<Solution> = Vec::new();
    let mut combos_tried = 0usize;
    let mut budget_exhausted = false;

    fn dfs(
        params: CodingParams,
        pos_order: &[u8],
        by_pos: &[Vec<ContentCandidate>],
        shard_digests: &[Option<String>],
        start: usize,
        chosen_pos: &mut Vec<usize>,
        pick: &mut Vec<(usize, usize)>,
        combos_tried: &mut usize,
        budget_exhausted: &mut bool,
        budget: usize,
        solutions: &mut Vec<Solution>,
    ) {
        let k = params.k as usize;
        if pick.len() == k {
            *combos_tried += 1;
            if *combos_tried > budget {
                *budget_exhausted = true;
                return;
            }
            if let Some(sol) =
                try_combo(params, pos_order, by_pos, shard_digests, pick, *combos_tried)
            {
                if let Some(existing) = solutions.iter_mut().find(|s| {
                    s.stripe_data_digest == sol.stripe_data_digest
                        && s.reconstructed == sol.reconstructed
                }) {
                    existing
                        .participant_combos
                        .push(sol.participant_combos.into_iter().next().unwrap());
                } else {
                    solutions.push(sol);
                }
            }
            return;
        }
        let remaining_need = k - pick.len();
        for idx in start..=pos_order.len() - remaining_need {
            let contents = &by_pos[pos_order[idx] as usize];
            for (cand_idx, _cand) in contents.iter().enumerate() {
                chosen_pos.push(idx);
                pick.push((idx, cand_idx));
                dfs(
                    params,
                    pos_order,
                    by_pos,
                    shard_digests,
                    idx + 1,
                    chosen_pos,
                    pick,
                    combos_tried,
                    budget_exhausted,
                    budget,
                    solutions,
                );
                pick.pop();
                chosen_pos.pop();
                if *budget_exhausted {
                    return;
                }
            }
        }
    }

    let mut chosen_pos = Vec::new();
    let mut pick = Vec::new();
    dfs(
        params,
        &pos_order,
        &by_pos,
        shard_digests,
        0,
        &mut chosen_pos,
        &mut pick,
        &mut combos_tried,
        &mut budget_exhausted,
        search_budget,
        &mut solutions,
    );

    // Record corruption evidence for candidates that never appear feasible.
    let feasible_ids: std::collections::HashSet<i64> = solutions
        .iter()
        .flat_map(|s| s.participants.iter().map(|p| p.fragment_id))
        .collect();
    for contents in by_pos.iter().filter(|c| !c.is_empty()) {
        for cand in contents {
            if !feasible_ids.contains(&cand.fragment_id) {
                analysis.exclusions.push(Exclusion {
                    fragment_id: cand.fragment_id,
                    shard_index: cand.shard_index,
                    generation: cand.generation,
                    source: cand.source.clone(),
                    reason: format!(
                        "content candidate excluded: no feasible reconstruction uses shard {} fragment {} (digest/parity evidence)",
                        cand.shard_index, cand.fragment_id
                    ),
                });
            }
        }
    }

    solutions.sort_by(|a, b| {
        a.stripe_data_digest
            .cmp(&b.stripe_data_digest)
            .then(a.combo_ordinal.cmp(&b.combo_ordinal))
    });
    if solutions.len() > 1 {
        let first = &solutions[0].reconstructed;
        for (i, (a, b)) in first.iter().zip(solutions[1].reconstructed.iter()).enumerate() {
            if a != b {
                analysis.differing_positions.push(i as u8);
            }
        }
    }
    analysis.combos_tried = combos_tried;
    analysis.budget_exhausted = budget_exhausted;
    analysis.feasible_count = solutions.len();
    analysis.solutions = solutions;
    analysis.status = match analysis.feasible_count {
        0 => StripeStatus::Blocked,
        1 => StripeStatus::Recoverable,
        _ => StripeStatus::Ambiguous,
    };
    analysis.summary = match analysis.feasible_count {
        0 => format!("no feasible reconstruction among {combos_tried} tried candidate sets"),
        1 => format!("one feasible reconstruction found after {combos_tried} candidate sets"),
        n => format!(
            "{n} distinct feasible reconstructions after {combos_tried} candidate sets; positions {:?} differ",
            analysis.differing_positions
        ),
    };
    analysis
}

fn try_combo(
    params: CodingParams,
    pos_order: &[u8],
    by_pos: &[Vec<ContentCandidate>],
    shard_digests: &[Option<String>],
    pick: &[(usize, usize)],
    ordinal: usize,
) -> Option<Solution> {
    let available: Vec<(usize, Vec<u8>)> = pick
        .iter()
        .map(|&(pi, ci)| {
            let pos = pos_order[pi] as usize;
            (pos, by_pos[pos][ci].bytes.clone())
        })
        .collect();
    let reconstructed = decode(params, &available).ok()?;

    // Every manifest-known shard digest must match the reconstruction.
    for (pos, bytes) in reconstructed.iter().enumerate() {
        if let Some(Some(expected)) = shard_digests.get(pos) {
            if crate::model::normalize_digest(expected) != digest_hex(bytes) {
                return None;
            }
        }
    }

    let chosen: std::collections::HashMap<usize, &ContentCandidate> = pick
        .iter()
        .map(|&(pi, ci)| {
            let pos = pos_order[pi] as usize;
            (pos, &by_pos[pos][ci])
        })
        .collect();

    let mut participants = Vec::new();
    for &(pi, ci) in pick {
        let pos = pos_order[pi] as usize;
        let cand = &by_pos[pos][ci];
        let recomputed = digest_hex(&cand.bytes);
        let expected = shard_digests.get(pos).and_then(|o| o.as_deref());
        participants.push(Participant {
            shard_index: pos as u8,
            fragment_id: cand.fragment_id,
            source: cand.source.clone(),
            generation: cand.generation,
            digest: cand.digest.clone(),
            digest_check: digest_state(expected, &recomputed),
        });
    }
    participants.sort_by_key(|p| p.shard_index);

    let mut positions = Vec::new();
    for pos in 0..params.n() {
        let recomputed = digest_hex(&reconstructed[pos]);
        let expected = shard_digests.get(pos).and_then(|o| o.clone());
        positions.push(PositionInfo {
            shard_index: pos as u8,
            candidate_fragment_ids: by_pos[pos].iter().map(|c| c.fragment_id).collect(),
            chosen_fragment_id: chosen.get(&pos).map(|c| c.fragment_id),
            expected_digest: expected,
            recomputed_digest: Some(recomputed),
            digest_check: digest_state(
                shard_digests.get(pos).and_then(|o| o.as_deref()),
                &recomputed,
            ),
        });
    }

    let mut data_bytes = Vec::new();
    for shard in reconstructed.iter().take(params.k as usize) {
        data_bytes.extend_from_slice(shard);
    }
    let stripe_data_digest = digest_hex(&data_bytes);
    let generation = pick
        .first()
        .map(|&(pi, ci)| by_pos[pos_order[pi] as usize][ci].generation)
        .unwrap_or(0);
    let combo: Vec<i64> = participants.iter().map(|p| p.fragment_id).collect();

    Some(Solution {
        id: stripe_data_digest.clone(),
        combo_ordinal: ordinal,
        participant_combos: vec![combo],
        participants,
        positions,
        stripe_data_digest,
        generation,
        reconstructed,
    })
}
