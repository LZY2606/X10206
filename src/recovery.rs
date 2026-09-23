//! Pure, deterministic stripe recovery planner.
//!
//! Candidate selection is never first-come-first-served: eligible candidates
//! are enumerated under generation coherence, manifest anchors and stripe
//! coding constraints. Every exclusion and failed attempt keeps its evidence.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use serde::Serialize;

use crate::gf::{Gf256, CODEC_VERSION};
use crate::models::{digest_prefix, sha256_hex, CodecParams};

#[derive(Debug, Clone)]
pub struct Anchor {
    pub shard_index: i64,
    pub digest: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Cand {
    pub candidate_id: i64,
    pub shard_index: i64,
    pub generation: i64,
    pub source: String,
    pub payload: Vec<u8>,
    pub received_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Excluded {
    pub candidate_id: i64,
    pub shard_index: i64,
    pub generation: i64,
    pub source: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Member {
    pub candidate_id: i64,
    pub shard_index: i64,
    pub generation: i64,
    pub source: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FailedAttempt {
    pub members: Vec<Member>,
    pub coherent_generation: Option<i64>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OutputShard {
    pub shard_index: i64,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Feasible {
    pub members: Vec<Member>,
    pub coherent_generation: Option<i64>,
    /// `None` for mixed-generation sets, `Some(g)` otherwise.
    pub outputs: Vec<OutputShard>,
    pub anchor_verified: bool,
    pub supporting_sets: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StripeStatus {
    Infeasible,
    Unique,
    Ambiguous,
}

#[derive(Debug, Clone, Serialize)]
pub struct StripePlan {
    pub stripe: i64,
    pub status: StripeStatus,
    pub excluded: Vec<Excluded>,
    pub failed_attempts: Vec<FailedAttempt>,
    pub feasible: Vec<Feasible>,
    pub attempts_used: usize,
    pub budget: usize,
    pub budget_truncated: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub output_payloads: Vec<Vec<Vec<u8>>>,
}

pub struct StripeCase {
    pub stripe: i64,
    pub codec: CodecParams,
    pub anchors: Vec<Anchor>,
    pub candidates: Vec<Cand>,
    pub isolated_sources: HashSet<String>,
    pub budget: usize,
}

#[derive(Clone)]
struct CandView {
    cand: Cand,
    computed_digest: String,
    received_ok: bool,
}

impl StripePlan {
    pub fn unique_payload(&self) -> Option<&Vec<Vec<u8>>> {
        if self.feasible.len() == 1 {
            self.output_payloads.first()
        } else {
            None
        }
    }
}

fn view_members(picked: &[&CandView]) -> Vec<Member> {
    picked
        .iter()
        .map(|v| Member {
            candidate_id: v.cand.candidate_id,
            shard_index: v.cand.shard_index,
            generation: v.cand.generation,
            source: v.cand.source.clone(),
        })
        .collect()
}

/// Enumerate every size-`k` index subset (ascending) and every candidate
/// combination for the chosen indices. `filter_gen` restricts to one
/// generation; when `None` mixed-generation combinations are produced.
fn enumerate_combos<'a>(
    by_index: &'a BTreeMap<i64, Vec<CandView>>,
    k: usize,
    filter_gen: Option<i64>,
) -> Vec<Vec<&'a CandView>> {
    let indices: Vec<i64> = match filter_gen {
        Some(g) => by_index
            .iter()
            .filter(|(_, cs)| cs.iter().any(|c| c.cand.generation == g))
            .map(|(i, _)| *i)
            .collect(),
        None => by_index.keys().copied().collect(),
    };
    if indices.len() < k {
        return Vec::new();
    }
    let mut combos: Vec<Vec<&CandView>> = Vec::new();
    let mut chosen_idx: Vec<usize> = Vec::with_capacity(k);

    fn rec<'a>(
        k: usize,
        start: usize,
        chosen_idx: &mut Vec<usize>,
        indices: &[i64],
        by_index: &'a BTreeMap<i64, Vec<CandView>>,
        filter_gen: Option<i64>,
        picked: &mut Vec<&'a CandView>,
        combos: &mut Vec<Vec<&'a CandView>>,
    ) {
        if chosen_idx.len() == k {
            combos.push(picked.clone());
            return;
        }
        let need = k - chosen_idx.len();
        for pos in start..=(indices.len().saturating_sub(need)) {
            for view in &by_index[&indices[pos]] {
                if let Some(g) = filter_gen {
                    if view.cand.generation != g {
                        continue;
                    }
                }
                picked.push(view);
                chosen_idx.push(pos);
                rec(
                    k,
                    pos + 1,
                    chosen_idx,
                    indices,
                    by_index,
                    filter_gen,
                    picked,
                    combos,
                );
                picked.pop();
                chosen_idx.pop();
            }
        }
    }

    let mut picked: Vec<&CandView> = Vec::new();
    rec(
        k,
        0,
        &mut chosen_idx,
        &indices,
        by_index,
        filter_gen,
        &mut picked,
        &mut combos,
    );
    combos
}

pub fn plan_stripe(gf: &Gf256, case: StripeCase) -> StripePlan {
    assert_eq!(case.codec.version, CODEC_VERSION, "unknown codec version");
    let k = case.codec.k;
    let n = case.codec.n;
    let stripe = case.stripe;

    let mut excluded: Vec<Excluded> = Vec::new();
    let mut failed: Vec<FailedAttempt> = Vec::new();

    let anchor_map: BTreeMap<i64, String> = case
        .anchors
        .iter()
        .filter_map(|a| {
            a.digest
                .as_ref()
                .map(|d| (a.shard_index, d.trim().to_string()))
        })
        .collect();

    // Eligibility screening with recorded evidence.
    let mut views: Vec<CandView> = Vec::new();
    for cand in case.candidates {
        let computed = digest_prefix(&sha256_hex(&cand.payload));
        let mut reject: Option<String> = None;
        if !(0..n as i64).contains(&cand.shard_index) {
            reject = Some(format!("shard_index {} 超出编码参数 n={}", cand.shard_index, n));
        } else if cand.payload.len() != case.codec.shard_size {
            reject = Some(format!(
                "payload 长度 {} 与 manifest shard_size {} 不符",
                cand.payload.len(),
                case.codec.shard_size
            ));
        } else if case.isolated_sources.contains(&cand.source) {
            reject = Some(format!("来源 {} 已被人工隔离", cand.source));
        } else if let Some(claimed) = &cand.received_digest {
            if claimed.trim() != computed {
                reject = Some(format!(
                    "接收摘要校验失败：声称 {}，实算 {}",
                    claimed.trim(),
                    computed
                ));
            }
        }
        let received_ok = cand
            .received_digest
            .as_ref()
            .map(|c| c.trim() == computed)
            .unwrap_or(false);
        if let Some(reason) = reject {
            excluded.push(Excluded {
                candidate_id: cand.candidate_id,
                shard_index: cand.shard_index,
                generation: cand.generation,
                source: cand.source,
                reason,
            });
            continue;
        }
        views.push(CandView {
            cand,
            computed_digest: computed,
            received_ok,
        });
    }

    // Deterministic ordering: index asc, generation desc, source asc, digest asc.
    views.sort_by(|a, b| {
        a.cand
            .shard_index
            .cmp(&b.cand.shard_index)
            .then(b.cand.generation.cmp(&a.cand.generation))
            .then(a.cand.source.cmp(&b.cand.source))
            .then(a.computed_digest.cmp(&b.computed_digest))
    });

    // Deduplicate same (index, generation, content); retain provenance evidence.
    let mut seen: BTreeSet<(i64, i64, String)> = BTreeSet::new();
    let mut deduped: Vec<CandView> = Vec::new();
    for v in views {
        let key = (v.cand.shard_index, v.cand.generation, v.computed_digest.clone());
        if !seen.insert(key) {
            excluded.push(Excluded {
                candidate_id: v.cand.candidate_id,
                shard_index: v.cand.shard_index,
                generation: v.cand.generation,
                source: v.cand.source,
                reason: "重复候选（同编号、同 generation、同内容）".to_string(),
            });
            continue;
        }
        deduped.push(v);
    }

    let mut by_index: BTreeMap<i64, Vec<CandView>> = BTreeMap::new();
    for v in deduped {
        by_index.entry(v.cand.shard_index).or_default().push(v);
    }

    // Coherent generations first, newest to oldest; mixed sets afterwards.
    let generations: BTreeSet<i64> = by_index
        .values()
        .flatten()
        .map(|v| v.cand.generation)
        .collect();
    let mut ordered_combos: Vec<(Option<i64>, Vec<&CandView>)> = Vec::new();
    for g in generations.iter().rev() {
        for combo in enumerate_combos(&by_index, k, Some(*g)) {
            ordered_combos.push((Some(*g), combo));
        }
    }
    for combo in enumerate_combos(&by_index, k, None) {
        let gens: BTreeSet<i64> = combo.iter().map(|v| v.cand.generation).collect();
        if gens.len() == 1 {
            continue; // already enumerated as coherent
        }
        ordered_combos.push((None, combo));
    }

    let mut attempts_used = 0usize;
    let mut budget_truncated = false;
    let mut feasible: Vec<Feasible> = Vec::new();
    let mut payloads: Vec<Vec<Vec<u8>>> = Vec::new();

    for (coherent_gen, combo) in ordered_combos {
        if attempts_used >= case.budget {
            budget_truncated = true;
            break;
        }
        attempts_used += 1;

        let rows: Vec<usize> = combo.iter().map(|v| v.cand.shard_index as usize).collect();
        let values: Vec<Vec<u8>> = combo.iter().map(|v| v.cand.payload.clone()).collect();
        let members = view_members(&combo);

        let rebuilt = match gf.reconstruct(&rows, &values, k, n) {
            Some(r) => r,
            None => {
                failed.push(FailedAttempt {
                    members,
                    coherent_generation: coherent_gen,
                    reason: "GF(256) 矩阵不可逆或长度不一致".to_string(),
                });
                continue;
            }
        };

        let mut output_digests: Vec<String> = Vec::with_capacity(n);
        for shard in &rebuilt {
            output_digests.push(digest_prefix(&sha256_hex(shard)));
        }

        let mut anchor_checked = 0usize;
        let mut mismatch: Option<String> = None;
        for (idx, digest) in output_digests.iter().enumerate() {
            if let Some(expected) = anchor_map.get(&(idx as i64)) {
                anchor_checked += 1;
                if expected != digest {
                    mismatch = Some(format!(
                        "shard {} 重算摘要 {} 与 manifest 锚定摘要 {} 不符",
                        idx, digest, expected
                    ));
                    break;
                }
            }
        }
        if let Some(reason) = mismatch {
            failed.push(FailedAttempt {
                members,
                coherent_generation: coherent_gen,
                reason,
            });
            continue;
        }

        let outputs: Vec<OutputShard> = output_digests
            .into_iter()
            .enumerate()
            .map(|(idx, digest)| OutputShard {
                shard_index: idx as i64,
                digest,
            })
            .collect();
        let signature: Vec<String> = outputs.iter().map(|o| o.digest.clone()).collect();

        if let Some(existing) = feasible.iter_mut().find(|f| {
            f.outputs.iter().map(|o| &o.digest).collect::<Vec<_>>()
                == signature.iter().collect::<Vec<_>>()
        }) {
            existing.supporting_sets += 1;
            continue;
        }
        feasible.push(Feasible {
            members,
            coherent_generation: coherent_gen,
            outputs,
            anchor_verified: anchor_checked > 0,
            supporting_sets: 1,
        });
        payloads.push(rebuilt);
    }

    let status = match feasible.len() {
        0 => StripeStatus::Infeasible,
        1 => StripeStatus::Unique,
        _ => StripeStatus::Ambiguous,
    };

    StripePlan {
        stripe,
        status,
        excluded,
        failed_attempts: failed,
        feasible,
        attempts_used,
        budget: case.budget,
        budget_truncated,
        output_payloads: payloads,
    }
}
