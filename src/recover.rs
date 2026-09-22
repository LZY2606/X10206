use crate::coding::{encode, reconstruct, Params};
use crate::store::{sha256_hex, FragmentRecord, ObjectRecord, StripeRecord, Store};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;

#[derive(Debug, Clone)]
struct Candidate {
    fragment: FragmentRecord,
    shard_index: usize,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
struct Answer {
    combination_key: String,
    participating: serde_json::Value,
    excluded_evidence: serde_json::Value,
    digests: serde_json::Value,
    logical: Vec<u8>,
    full_shards: BTreeMap<usize, Vec<u8>>,
}

pub fn recover_object(store: &Store, object: &ObjectRecord, isolated_sources: &[String], budget: i64) -> std::io::Result<String> {
    let isolated: BTreeSet<String> = isolated_sources.iter().cloned().collect();
    let run_id = store.create_run(object.pk, isolated_sources, budget).map_err(io_err)?;
    let result = recover_object_inner(store, object, &isolated, budget, run_id);
    match result {
        Ok(status) => {
            store.finish_run(run_id, &status).map_err(io_err)?;
            Ok(status)
        }
        Err(error) => {
            store.finish_run(run_id, "failed").map_err(io_err)?;
            Err(error)
        }
    }
}

fn recover_object_inner(store: &Store, object: &ObjectRecord, isolated: &BTreeSet<String>, budget: i64, run_id: i64) -> std::io::Result<String> {
    let stripes = store.list_stripes(object.pk).map_err(io_err)?;
    let fragments = store.list_fragments(object.pk).map_err(io_err)?;
    let params = Params {
        data_shards: object.data_shards,
        parity_shards: object.parity_shards,
        generation: object.generation,
        stripe_size: object.stripe_size,
    };
    let mut committed_count = 0usize;
    let mut total_answers = 0usize;
    for stripe in &stripes {
        if store.verify_committed_stripe(&object.object_id, object.generation, stripe.index, &stripe.expected_digest) && stripe.status == "committed" {
            committed_count += 1;
            continue;
        }
        let mut candidates = Vec::new();
        let mut excluded = Vec::new();
        for fragment in fragments.iter().filter(|fragment| fragment.stripe_index == stripe.index) {
            if isolated.contains(&fragment.received_from) {
                excluded.push(excluded_json(fragment, "source manually isolated"));
                continue;
            }
            if fragment.health == "healthy" || fragment.health == "generation_mixed_eligible" {
                if let Some(shard_index) = fragment.shard_index {
                    let bytes = fs::read(&fragment.raw_path)?;
                    candidates.push(Candidate { fragment: fragment.clone(), shard_index, bytes });
                }
            } else {
                excluded.push(excluded_json(fragment, &fragment.evidence));
            }
        }
        candidates.sort_by(|a, b| {
            (a.shard_index, a.fragment.received_from.as_str(), a.fragment.actual_sha256.as_str())
                .cmp(&(b.shard_index, b.fragment.received_from.as_str(), b.fragment.actual_sha256.as_str()))
        });
        let outcome = recover_stripe(store, object, stripe, params, candidates, excluded, run_id, budget)?;
        total_answers += outcome.valid_answers;
        if outcome.committed {
            committed_count += 1;
        }
    }
    let status = if committed_count == stripes.len() {
        "committed"
    } else if total_answers > 0 {
        "partial"
    } else {
        "unrecoverable"
    };
    Ok(status.to_string())
}

struct StripeOutcome {
    valid_answers: usize,
    committed: bool,
}

fn recover_stripe(
    store: &Store,
    object: &ObjectRecord,
    stripe: &StripeRecord,
    params: Params,
    candidates: Vec<Candidate>,
    excluded: Vec<serde_json::Value>,
    run_id: i64,
    budget: i64,
) -> std::io::Result<StripeOutcome> {
    let k = params.data_shards;
    if candidates.len() < k {
        store.mark_stripe(stripe.pk, "below_threshold").map_err(io_err)?;
        return Ok(StripeOutcome { valid_answers: 0, committed: false });
    }
    let combinations = combinations_with_budget(&candidates, k, budget.max(1) as usize);
    let mut valid_answers = Vec::new();
    for (ordinal, combination) in combinations.items.iter().enumerate() {
        let mut available = BTreeMap::new();
        let mut participating = Vec::new();
        for candidate in combination {
            available.insert(candidate.shard_index, candidate.bytes.clone());
            participating.push(json!({
                "fragment_id": candidate.fragment.id,
                "shard": candidate.shard_index,
                "source": candidate.fragment.received_from,
                "generation": candidate.fragment.shard_generation,
                "sha256": candidate.fragment.actual_sha256,
                "health": candidate.fragment.health
            }));
        }
        let missing: Vec<usize> = (0..params.total()).filter(|index| !available.contains_key(index)).collect();
        let reconstructed = match reconstruct(&available, &missing, params) {
            Some(value) => value,
            None => continue,
        };
        let mut full_shards = available.clone();
        for (index, bytes) in reconstructed {
            full_shards.insert(index, bytes);
        }
        if full_shards.len() != params.total() {
            continue;
        }
        let data_shards: Vec<Vec<u8>> = (0..k).map(|index| full_shards[&index].clone()).collect();
        let recomputed_parity = encode(&data_shards, params.parity_shards, params.stripe_size);
        let mut parity_mismatch = Vec::new();
        for p in 0..params.parity_shards {
            if recomputed_parity[p] != full_shards[&(k + p)] {
                parity_mismatch.push(k + p);
            }
        }
        let mut logical = Vec::new();
        for shard in &data_shards {
            logical.extend_from_slice(shard);
        }
        logical.truncate(stripe.data_len);
        let stripe_digest = sha256_hex(&logical);
        let mut shard_digests = serde_json::Map::new();
        for (index, bytes) in &full_shards {
            shard_digests.insert(index.to_string(), json!(sha256_hex(bytes)));
        }
        let valid = stripe_digest == stripe.expected_digest && parity_mismatch.is_empty();
        let combination_key = combination.iter().map(|c| format!("{:03}:{}:{}", c.shard_index, c.fragment.received_from, &c.fragment.actual_sha256[..12])).collect::<Vec<_>>().join("|");
        let mut excluded_evidence = excluded.clone();
        for candidate in &candidates {
            let used = combination.iter().any(|used| used.fragment.id == candidate.fragment.id);
            let same_shard = combination.iter().any(|used| used.shard_index == candidate.shard_index);
            if !used && same_shard {
                let mut value = serde_json::Value::Object(serde_json::Map::new());
                if let Ok(value_mut) = serde_json::to_value(&candidate.fragment) {
                    value = value_mut;
                }
                excluded_evidence.push(json!({
                    "fragment": value,
                    "reason": "duplicate shard number candidate not selected in this deterministic combination"
                }));
            }
        }
        let digests = json!({
            "stripe_sha256": stripe_digest,
            "expected_stripe_sha256": stripe.expected_digest,
            "all_shard_sha256": shard_digests,
            "recomputed_parity_mismatches": parity_mismatch,
            "search_budget": budget,
            "budget_exhausted": combinations.budget_exhausted
        });
        store.insert_reconstruction(
            run_id,
            stripe.pk,
            ordinal as i64,
            valid,
            false,
            &combination_key,
            &json!(participating),
            &json!(excluded_evidence),
            &digests,
            "",
        ).map_err(io_err)?;
        if valid {
            valid_answers.push(Answer {
                combination_key,
                participating: json!(participating),
                excluded_evidence: json!(excluded_evidence),
                digests,
                logical,
                full_shards,
            });
        }
    }

    let distinct: BTreeSet<String> = valid_answers.iter().map(|answer| sha256_hex(&answer.logical)).collect();
    if distinct.len() > 1 {
        store.mark_stripe(stripe.pk, "ambiguous_outputs").map_err(io_err)?;
        return Ok(StripeOutcome { valid_answers: valid_answers.len(), committed: false });
    }
    if valid_answers.is_empty() {
        let status = if combinations.budget_exhausted { "budget_exhausted" } else { "corrupt_or_insufficient" };
        store.mark_stripe(stripe.pk, status).map_err(io_err)?;
        return Ok(StripeOutcome { valid_answers: 0, committed: false });
    }
    let chosen = valid_answers.into_iter().min_by(|a, b| a.combination_key.cmp(&b.combination_key)).unwrap();
    for (shard, bytes) in &chosen.full_shards {
        store.write_temp_block(&object.object_id, run_id, stripe.index, *shard, bytes)?;
    }
    let logical_digest = sha256_hex(&chosen.logical);
    store.commit_stripe_file(&object.object_id, object.generation, stripe.index, &chosen.logical, &logical_digest)?;
    store.mark_stripe(stripe.pk, "committed").map_err(io_err)?;
    Ok(StripeOutcome { valid_answers: 1, committed: true })
}

struct CombinationList {
    items: Vec<Vec<Candidate>>,
    budget_exhausted: bool,
}

fn combinations_with_budget(candidates: &[Candidate], k: usize, budget: usize) -> CombinationList {
    let mut by_shard: BTreeMap<usize, Vec<&Candidate>> = BTreeMap::new();
    for candidate in candidates {
        by_shard.entry(candidate.shard_index).or_default().push(candidate);
    }
    let groups: Vec<Vec<&Candidate>> = by_shard.into_values().collect();
    let mut items = Vec::new();
    let mut budget_exhausted = false;
    let mut count = 0usize;
    fn select<'a>(groups: &[Vec<&'a Candidate>], start: usize, need: usize, chosen: &mut Vec<&'a Candidate>, out: &mut Vec<Vec<Candidate>>, budget: usize, count: &mut usize, exhausted: &mut bool) -> bool {
        if need == 0 {
            *count += 1;
            if *count > budget {
                *exhausted = true;
                return false;
            }
            out.push(chosen.iter().map(|c| (*c).clone()).collect());
            return true;
        }
        if start + need > groups.len() {
            return true;
        }
        for index in start..=groups.len().saturating_sub(need) {
            for candidate in &groups[index] {
                chosen.push(candidate);
                if !select(groups, index + 1, need - 1, chosen, out, budget, count, exhausted) {
                    return false;
                }
                chosen.pop();
            }
        }
        true
    }
    select(&groups, 0, k, &mut Vec::new(), &mut items, budget, &mut count, &mut budget_exhausted);
    CombinationList { items, budget_exhausted }
}

fn excluded_json(fragment: &FragmentRecord, reason: &str) -> serde_json::Value {
    json!({
        "fragment_id": fragment.id,
        "shard": fragment.shard_index,
        "source": fragment.received_from,
        "generation": fragment.shard_generation,
        "actual_sha256": fragment.actual_sha256,
        "health": fragment.health,
        "evidence": fragment.evidence,
        "exclusion_reason": reason
    })
}

fn io_err(error: rusqlite::Error) -> std::io::Error {
    std::io::Error::other(error.to_string())
}
