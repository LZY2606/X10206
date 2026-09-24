//! Feasible-set enumeration for one stripe.
//!
//! Rules implemented here (all deterministic):
//!
//! * Candidates are never first-come-first-served. Within a
//!   `(stripe, shard_index, generation)` slot they are ranked by digest
//!   match, then sidecar match, then candidate id.
//! * For every manifest generation that covers the stripe, enumerate
//!   candidate combinations (slot iteration order, combination lexicographic
//!   order) until the search budget is exhausted.
//! * A combination must be coding-consistent to become a solution.
//! * Duplicate *content* (identical rebuilt stripe) collapses into one
//!   solution; the highest-ranked contributing combination wins the
//!   signature, every other combination is recorded as an alias.
//! * Every excluded candidate carries an explicit evidence kind.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::coding;
use crate::gf::GfTables;
use crate::model::{object_digest, Manifest, StripeSpec};

/// Hard cap on candidate combinations evaluated per generation. Fixtures are
/// tiny so the budget is only hit under deliberately pathological input.
pub const DEFAULT_SEARCH_BUDGET: u64 = 4096;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzedCandidate {
    pub candidate_id: String,
    pub shard_index: usize,
    pub generation: Option<u64>,
    pub source_id: String,
    pub len: usize,
    pub computed_digest: String,
    pub received_digest: Option<String>,
    pub manifest_generation: Option<u64>,
    pub gen_match: bool,
    pub digest_match: bool,
    pub length_status: String,
    pub sidecar_status: String,
    pub active: bool,
    pub duplicate_of: Option<String>,
    pub bytes_b64: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Exclusion {
    pub candidate_id: Option<String>,
    pub shard_index: Option<usize>,
    pub generation: Option<u64>,
    pub source_id: Option<String>,
    pub kind: String,
    pub detail: String,
    pub observed: Option<String>,
    pub expected: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Alias {
    pub candidate_ids: Vec<String>,
    pub present_indexes: Vec<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Solution {
    pub generation: u64,
    pub candidate_ids: Vec<String>,
    pub participant_indexes: Vec<usize>,
    pub present_indexes: Vec<usize>,
    pub rebuilt_indexes: Vec<usize>,
    /// Rebuilt stripe content for every row, keyed by row index.
    pub rebuilt_rows: BTreeMap<usize, Vec<u8>>,
    pub row_digests: BTreeMap<usize, String>,
    pub signature: String,
    pub solution_digest: String,
    pub object_data: Vec<u8>,
    pub object_digest_match: bool,
    pub aliases: Vec<Alias>,
    pub rank_candidates: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct StripeAnalysis {
    pub object_id: String,
    pub stripe_idx: usize,
    pub generations_analyzed: Vec<u64>,
    pub solutions: Vec<Solution>,
    pub ranked: Vec<usize>,
    pub exclusions: Vec<Exclusion>,
    pub budget: u64,
    pub budget_exhausted: bool,
    pub feasible: bool,
}

pub struct StripeInput {
    pub object_id: String,
    pub stripe: StripeSpec,
    pub manifests: BTreeMap<u64, Manifest>,
    pub candidates: Vec<AnalyzedCandidate>,
    pub isolated_sources: BTreeSet<String>,
    pub budget: u64,
}

/// Iterate lexicographic combinations of slot options without materializing
/// the full cartesian product. Option lists are per slot, already ranked;
/// combination order follows (slot 0 option, slot 1 option, ...) counting.
struct ComboIter<'a> {
    options: Vec<Vec<&'a AnalyzedCandidate>>,
    counter: Vec<usize>,
    done: bool,
}

impl<'a> ComboIter<'a> {
    fn new(options: Vec<Vec<&'a AnalyzedCandidate>>) -> Self {
        let slots = options.len();
        ComboIter {
            options,
            counter: vec![0; slots],
            done: false,
        }
    }
}

impl<'a> Iterator for ComboIter<'a> {
    type Item = Vec<&'a AnalyzedCandidate>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.options.is_empty() || self.options.iter().any(|o| o.is_empty()) {
            return None;
        }
        let picked: Vec<&AnalyzedCandidate> = self
            .options
            .iter()
            .zip(self.counter.iter())
            .map(|(opts, &i)| opts[i])
            .collect();
        // Increment the mixed-radix counter.
        let mut carry = true;
        for i in (0..self.counter.len()).rev() {
            if !carry {
                break;
            }
            self.counter[i] += 1;
            if self.counter[i] == self.options[i].len() {
                self.counter[i] = 0;
            } else {
                carry = false;
            }
        }
        if carry {
            self.done = true;
        }
        Some(picked)
    }
}

fn cand_rank_key(c: &AnalyzedCandidate) -> (u8, u8, String) {
    let digest = if c.digest_match { 0 } else { 1 };
    let sidecar = match c.sidecar_status.as_str() {
        "ok" => 0,
        "absent" => 1,
        _ => 2,
    };
    (digest, sidecar, c.candidate_id.clone())
}

/// Decode stored base64 shard bytes.
fn decode(c: &AnalyzedCandidate) -> Vec<u8> {
    use std::io::Cursor;
    // Tiny custom standard-alphabet base64 decoder to avoid an extra dep.
    fn val(ch: u8) -> Option<u8> {
        match ch {
            b'A'..=b'Z' => Some(ch - b'A'),
            b'a'..=b'z' => Some(ch - b'a' + 26),
            b'0'..=b'9' => Some(ch - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::new();
    let bytes = c.bytes_b64.as_bytes();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &b in bytes {
        if b == b'=' {
            break;
        }
        if let Some(v) = val(b) {
            buf = (buf << 6) | v as u32;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((buf >> bits) as u8);
                buf &= (1 << bits) - 1;
            }
        }
    }
    let _ = Cursor::new(bytes);
    out
}

pub fn b64_encode(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let trip = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[((trip >> 18) & 63) as usize] as char);
        out.push(T[((trip >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(T[((trip >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(T[(trip & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

pub fn analyze_stripe(t: &GfTables, input: StripeInput) -> StripeAnalysis {
    let StripeInput {
        object_id,
        stripe,
        manifests,
        candidates,
        isolated_sources,
        budget,
    } = input;

    let mut exclusions: Vec<Exclusion> = Vec::new();

    // Evidence for candidates rejected before any combination is tried.
    let mut rejected: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut exclude = |c: Option<&AnalyzedCandidate>,
                       idx: Option<usize>,
                       kind: &str,
                       detail: String,
                       observed: Option<String>,
                       expected: Option<String>| {
        if let Some(c) = c {
            if !rejected.insert(c.candidate_id.clone() + ":" + kind) {
                return;
            }
            exclusions.push(Exclusion {
                candidate_id: Some(c.candidate_id.clone()),
                shard_index: Some(c.shard_index),
                generation: c.generation,
                source_id: Some(c.source_id.clone()),
                kind: kind.to_string(),
                detail,
                observed,
                expected,
            });
        } else {
            exclusions.push(Exclusion {
                candidate_id: None,
                shard_index: idx,
                generation: None,
                source_id: None,
                kind: kind.to_string(),
                detail,
                observed,
                expected,
            });
        }
    };

    for c in &candidates {
        if !c.active {
            exclude(Some(c), None, "duplicate_superseded",
                format!("identical slot content from {} superseded", c.source_id),
                Some(c.candidate_id.clone()), c.duplicate_of.clone());
            continue;
        }
        if isolated_sources.contains(&c.source_id) {
            exclude(Some(c), None, "isolated_source",
                format!("source {} manually isolated by operator", c.source_id),
                Some(c.source_id.clone()), None);
            continue;
        }
        match c.length_status.as_str() {
 "mismatch" => {
                exclude(Some(c), None, "length_mismatch",
                    format!("candidate is {} bytes", c.len),
                    Some(c.len.to_string()), None);
                continue;
            }
            "no_manifest" => {
                exclude(Some(c), None, "no_manifest",
                    "no manifest covers this stripe/generation".to_string(), None, None);
                continue;
            }
            _ => {}
        }
        if c.received_digest.is_some() && c.sidecar_status == "mismatch" {
            exclude(Some(c), None, "sidecar_mismatch",
                "sidecar digest disagrees with recomputed bytes".to_string(),
                c.received_digest.clone(), Some(c.computed_digest.clone()));
        }
        match (c.digest_match, c.manifest_generation) {
            (true, Some(g)) if Some(g) == c.generation => {}
            (true, Some(g)) => {
                exclude(Some(c), None, "generation_excluded",
                    format!("digest matches generation {g} but fragment labels generation {:?}", c.generation),
                    c.generation.map(|v| v.to_string()), Some(g.to_string()));
            }
            _ => {
                exclude(Some(c), None, "digest_mismatch",
                    "recomputed digest matches no manifest entry".to_string(),
                    Some(c.computed_digest.clone()), None);
            }
        }
    }

    // Index candidates by (generation, slot) for all digest+generation matches.
    let mut eligible: BTreeMap<(u64, usize), Vec<&AnalyzedCandidate>> = BTreeMap::new();
    for c in &candidates {
        if !c.active || isolated_sources.contains(&c.source_id) {
            continue;
        }
        if c.length_status != "ok" || !c.digest_match {
            continue;
        }
        let Some(mg) = c.manifest_generation else { continue };
        if Some(mg) != c.generation {
            continue;
        }
        eligible.entry((mg, c.shard_index)).or_default().push(c);
    }
    for list in eligible.values_mut() {
        list.sort_by_key(|c| cand_rank_key(c));
        list.dedup_by_key(|c| c.candidate_id.clone());
    }

    let mut all_solutions: Vec<Solution> = Vec::new();
    let mut budget_exhausted = false;
    let mut generations_analyzed: Vec<u64> = Vec::new();

    // Newest generation first, but solutions are later merged deterministically.
    for (&gen, manifest) in manifests.iter().rev() {
        generations_analyzed.push(gen);
        let k = manifest.data_shards;
        let m = manifest.parity_shards;
        let n = k + m;
        if n > 256 {
            exclude(None, Some(stripe.stripe_idx), "bad_coding_params",
                format!("data+parity={n} exceeds GF(256) capacity"), None, None);
            continue;
        }

        let mut options: Vec<Vec<&AnalyzedCandidate>> = Vec::new();
        let mut missing_slots: Vec<usize> = Vec::new();
        for &idx in &stripe.shard_indexes {
            match eligible.get(&(gen, idx)) {
                Some(list) => options.push(list.clone()),
                None => {
                    options.push(Vec::new());
                    missing_slots.push(idx);
                }
            }
        }

        let present_row_count = options.iter().filter(|o| !o.is_empty()).count();
        if present_row_count < k {
            for idx in &missing_slots {
                exclude(None, Some(*idx), "below_threshold",
                    format!("generation {gen} has {present_row_count} verified rows, needs {k}"),
                    Some(present_row_count.to_string()), Some(k.to_string()));
            }
            continue;
        }

        // Boundary case: exactly k rows present - the row-set is fixed, but
        // duplicate content candidates per slot can still vary. Enumeration
        // happens in slot/candidate order up to the search budget.
        let mut spent: u64 = 0;
        let (sols, hit_budget) = try_generation(
            t,
            gen,
            manifest,
            &stripe,
            &options,
            budget,
            &mut spent,
            &mut exclusions,
        );
        budget_exhausted |= hit_budget;
        all_solutions.extend(sols);
    }

    // Global deterministic ranking: more present rows, then newer generation,
    // then lexicographic signature.
    all_solutions.sort_by(|a, b| {
        b.present_indexes
            .len()
            .cmp(&a.present_indexes.len())
            .then_with(|| b.generation.cmp(&a.generation))
            .then_with(|| a.signature.cmp(&b.signature))
            .then_with(|| a.solution_digest.cmp(&b.solution_digest))
    });
    let ranked: Vec<usize> = (0..all_solutions.len()).collect();
    StripeAnalysis {
        object_id,
        stripe_idx: stripe.stripe_idx,
        generations_analyzed,
        feasible: !all_solutions.is_empty(),
        solutions: all_solutions,
        ranked,
        exclusions,
        budget,
        budget_exhausted,
    }
}
