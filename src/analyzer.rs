use crate::erasure::{encode, AvailableShard, EncodingParams};
use crate::models::*;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn digest_data(data: &[Vec<u8>]) -> String {
    let mut hasher = Sha256::new();
    for shard in data {
        hasher.update((shard.len() as u64).to_le_bytes());
        hasher.update(shard);
    }
    hex::encode(hasher.finalize())
}

fn digest_object(data_digests: &[String]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"stripe-recovery-bay/object/v1");
    for digest in data_digests {
        hasher.update(digest.as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn solution_id(generation: i64, participating: &[ParticipatingShard], data_digest: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(generation.to_le_bytes());
    hasher.update(data_digest.as_bytes());
    for shard in participating {
        hasher.update(shard.shard_index.to_le_bytes());
        hasher.update(shard.fragment_id.as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn expected_stripe<'a>(manifest: &'a Manifest, stripe_index: usize) -> Option<&'a StripeSpec> {
    manifest
        .stripes
        .iter()
        .find(|stripe| stripe.index == stripe_index)
}

fn expected_shard(stripe: &StripeSpec, shard_index: usize) -> Option<&ExpectedShard> {
    stripe.shards.iter().find(|shard| shard.index == shard_index)
}

fn normalize_digest(value: &str) -> String {
    value.trim_start_matches("0x").to_ascii_lowercase()
}

fn check_manifest(manifest: &Manifest, fragments: &[ReceivedFragmentInput]) -> Vec<ExcludedEvidence> {
    let mut rejected = Vec::new();
    let spec = manifest.encoding;
    if manifest.stripes.len() != manifest.stripe_count {
        for fragment in fragments {
            rejected.push(ExcludedEvidence {
                fragment_id: fragment.fragment_id.clone(),
                source_id: fragment.source_id.clone(),
                shard_index: fragment.shard_index,
                generation: fragment.generation,
                actual_digest_sha256: sha256_hex(&fragment.bytes),
                reasons: vec!["manifest stripe_count 与 stripe 明细数量不一致".into()],
            });
        }
        return rejected;
    }
    let stripe_indices: BTreeSet<usize> = manifest.stripes.iter().map(|stripe| stripe.index).collect();
    if stripe_indices.len() != manifest.stripe_count
        || stripe_indices.iter().copied().min() != Some(0)
        || stripe_indices.iter().copied().max().map(|max| max + 1) != Some(manifest.stripe_count)
    {
        for fragment in fragments {
            rejected.push(ExcludedEvidence {
                fragment_id: fragment.fragment_id.clone(),
                source_id: fragment.source_id.clone(),
                shard_index: fragment.shard_index,
                generation: fragment.generation,
                actual_digest_sha256: sha256_hex(&fragment.bytes),
                reasons: vec!["manifest stripe 编号必须从 0 连续且唯一".into()],
            });
        }
        return rejected;
    }
    let _ = spec.validate();
    for fragment in fragments {
        let mut reasons = Vec::new();
        if fragment.shard_index >= spec.n() {
            reasons.push("shard 编号超出 manifest 的 n".into());
        }
        let Some(stripe) = expected_stripe(manifest, fragment.stripe_index) else {
            reasons.push("stripe 编号不在 manifest 中".into());
            rejected.push(excluded(fragment, &sha256_hex(&fragment.bytes), reasons));
            continue;
        };
        if fragment.bytes.len() != spec.stripe_size() {
            reasons.push(format!(
                "实际长度 {} 与编码参数 stripe_size {} 不符",
                fragment.bytes.len(),
                spec.stripe_size()
            ));
        }
        if let Some(expected) = expected_shard(stripe, fragment.shard_index) {
            if let Some(length) = expected.length {
                if length != fragment.bytes.len() {
                    reasons.push(format!("实际长度 {} 与 manifest 长度 {length} 不符", fragment.bytes.len()));
                }
            }
            if let Some(expected_digest) = &expected.digest_sha256 {
                let actual = sha256_hex(&fragment.bytes);
                if &normalize_digest(expected_digest) != &actual {
                    reasons.push("块摘要与 manifest 期望不一致：位翻转或内容损坏".into());
                }
            }
        } else {
            reasons.push("shard 编号没有对应的 manifest 明细".into());
        }
        if let Some(claimed) = &fragment.claimed_digest_sha256 {
            let actual = sha256_hex(&fragment.bytes);
            if normalize_digest(claimed) != actual {
                reasons.push("随包声明摘要与重算摘要不一致".into());
            }
        }
        if !reasons.is_empty() {
            rejected.push(excluded(fragment, &sha256_hex(&fragment.bytes), reasons));
        }
    }
    rejected
}

fn excluded(fragment: &ReceivedFragmentInput, actual: &str, mut reasons: Vec<String>) -> ExcludedEvidence {
    reasons.sort();
    reasons.dedup();
    ExcludedEvidence {
        fragment_id: fragment.fragment_id.clone(),
        source_id: fragment.source_id.clone(),
        shard_index: fragment.shard_index,
        generation: fragment.generation,
        actual_digest_sha256: actual.to_string(),
        reasons,
    }
}

struct IndexCandidate {
    fragment_id: String,
    source_id: String,
    generation: i64,
    shard_index: usize,
    digest: String,
    bytes: Vec<u8>,
}

fn make_participating(candidate: &IndexCandidate) -> ParticipatingShard {
    ParticipatingShard {
        shard_index: candidate.shard_index,
        fragment_id: candidate.fragment_id.clone(),
        source_id: candidate.source_id.clone(),
        generation: candidate.generation,
        length: candidate.bytes.len(),
        digest_sha256: candidate.digest.clone(),
    }
}

#[derive(Clone)]
struct Reconstruction {
    generation: i64,
    participating: Vec<ParticipatingShard>,
    excluded: Vec<ExcludedEvidence>,
    reconstructed_indices: Vec<usize>,
    recomputed_shard_digests: Vec<RecomputedShardDigest>,
    data_digest: String,
    trust: String,
}

struct GeneratedStripe {
    combinations_considered: usize,
    budget_exhausted: bool,
    reconstructions: Vec<Reconstruction>,
    candidates_by_index: BTreeMap<usize, Vec<IndexCandidate>>,
    rejected: Vec<ExcludedEvidence>,
}

fn candidate_sort_key(candidate: &IndexCandidate, received_at: i64) -> (String, i64, String, String) {
    (candidate.digest.clone(), received_at, candidate.source_id.clone(), candidate.fragment_id.clone())
}

fn evaluate_reconstruction(
    params: EncodingParams,
    generation: i64,
    selected: &[&IndexCandidate],
    all_by_index: &BTreeMap<usize, Vec<(IndexCandidate, i64)>>,
    expected_data_digest: Option<&str>,
) -> Option<Reconstruction> {
    let available = selected
        .iter()
        .map(|candidate| AvailableShard {
            index: candidate.shard_index,
            bytes: candidate.bytes.clone(),
        })
        .collect::<Vec<_>>();
    let data = reconstruct(params, &available).ok()?;
    let all_shards = encode(params, &data).ok()?;
    let expected_digests: Vec<String> = all_shards.iter().map(|bytes| sha256_hex(bytes)).collect();
    let mut excluded = Vec::new();
    let mut contradiction = false;

    for (index, candidates) in all_by_index {
        for (candidate, _) in candidates {
            let selected_here = selected
                .iter()
                .any(|chosen| chosen.fragment_id == candidate.fragment_id);
            if selected_here {
                continue;
            }
            let agrees = expected_digests
                .get(*index)
                .is_some_and(|digest| digest == &candidate.digest);
            if agrees {
                excluded.push(ExcludedEvidence {
                    fragment_id: candidate.fragment_id.clone(),
                    source_id: candidate.source_id.clone(),
                    shard_index: candidate.shard_index,
                    generation: candidate.generation,
                    actual_digest_sha256: candidate.digest.clone(),
                    reasons: vec!["未参与计算；与重算 shard 约束一致的健康旁证".into()],
                });
            } else {
                contradiction = true;
                excluded.push(ExcludedEvidence {
                    fragment_id: candidate.fragment_id.clone(),
                    source_id: candidate.source_id.clone(),
                    shard_index: candidate.shard_index,
                    generation: candidate.generation,
                    actual_digest_sha256: candidate.digest.clone(),
                    reasons: vec!["与同一可行方程重算的 shard 摘要冲突".into()],
                });
            }
        }
    }
    if contradiction {
        return None;
    }

    let participating = selected.iter().map(|candidate| make_participating(candidate)).collect::<Vec<_>>();
    let selected_indices: BTreeSet<usize> = selected.iter().map(|candidate| candidate.shard_index).collect();
    let reconstructed_indices = (0..params.n).filter(|index| !selected_indices.contains(index)).collect();
    let recomputed_shard_digests = expected_digests
        .into_iter()
        .enumerate()
        .map(|(index, digest)| RecomputedShardDigest {
            index,
            length: params.stripe_size,
            digest_sha256: digest,
        })
        .collect();
    let data_digest = digest_data(&data);
    let extra_indices = all_by_index.len().saturating_sub(params.k);
    let trust = if expected_data_digest.is_some_and(|digest| digest == data_digest) {
        "stripe_digest_verified"
    } else if expected_data_digest.is_some() {
        return None;
    } else if extra_indices > 0 {
        "stripe_parity_corroborated"
    } else {
        "threshold_only"
    };
    Some(Reconstruction {
        generation,
        participating,
        excluded,
        reconstructed_indices,
        recomputed_shard_digests,
        data_digest,
        trust: trust.into(),
    })
}

fn analyze_generation(
    manifest: &Manifest,
    stripe: &StripeSpec,
    generation: i64,
    fragments: &[ReceivedFragmentInput],
    rejected_ids: &BTreeSet<String>,
    budget: usize,
) -> GeneratedStripe {
    let spec = manifest.encoding;
    let params = EncodingParams {
        k: spec.k(),
        n: spec.n(),
        stripe_size: spec.stripe_size(),
    };
    let mut candidates_by_index: BTreeMap<usize, Vec<(IndexCandidate, i64)>> = BTreeMap::new();
    let mut rejected = Vec::new();
    for fragment in fragments
        .iter()
        .filter(|fragment| fragment.stripe_index == stripe.index && !rejected_ids.contains(&fragment.fragment_id))
    {
        let actual = sha256_hex(&fragment.bytes);
        if fragment.generation != generation {
            rejected.push(ExcludedEvidence {
                fragment_id: fragment.fragment_id.clone(),
                source_id: fragment.source_id.clone(),
                shard_index: fragment.shard_index,
                generation: fragment.generation,
                actual_digest_sha256: actual,
                reasons: vec![format!("generation {generation} 枚举中排除 generation {}", fragment.generation)],
            });
            continue;
        }
        let candidate = IndexCandidate {
            fragment_id: fragment.fragment_id.clone(),
            source_id: fragment.source_id.clone(),
            generation: fragment.generation,
            shard_index: fragment.shard_index,
            digest: actual,
            bytes: fragment.bytes.clone(),
        };
        candidates_by_index
            .entry(fragment.shard_index)
            .or_default()
            .push((candidate, fragment.received_at));
    }
    for candidates in candidates_by_index.values_mut() {
        candidates.sort_by(|left, right| {
            candidate_sort_key(&left.0, left.1).cmp(&candidate_sort_key(&right.0, right.1))
        });
    }

    let indices: Vec<usize> = candidates_by_index.keys().copied().collect();
    let mut combinations_considered = 0usize;
    let mut budget_exhausted = false;
    let mut reconstructions = Vec::new();
    let mut seen = BTreeSet::new();

    for subset_start in 0..=indices.len().saturating_sub(params.k) {
        let mut subset = Vec::new();
        let mut walk = vec![(subset_start, 0usize)];
        while let Some((position, chosen)) = walk.pop() {
            subset.truncate(chosen);
            if chosen == params.k {
                let mut selected: Vec<&IndexCandidate> = Vec::new();
                let mut branch = Vec::new();
                let mut branch_walk = vec![(0usize, 0usize)];
                while let Some((index_position, choice)) = branch_walk.pop() {
                    branch.truncate(choice);
                    if index_position == subset.len() {
                        combinations_considered += 1;
                        if combinations_considered > budget {
                            budget_exhausted = true;
                            break;
                        }
                        selected = branch
                            .iter()
                            .map(|index| &candidates_by_index[index].get(0).unwrap().0)
                            .cloned()
                            .collect();
                        let selected_refs: Vec<&IndexCandidate> = subset
                            .iter()
                            .enumerate()
                            .map(|(position, index)| {
                                let choice_index = branch[position];
                                &candidates_by_index[index][choice_index].0
                            })
                            .collect();
                        if let Some(reconstruction) = evaluate_reconstruction(
                            params,
                            generation,
                            &selected_refs,
                            &candidates_by_index,
                            stripe.data_digest_sha256.as_deref(),
                        ) {
                            let key = (
                                reconstruction.data_digest.clone(),
                                reconstruction
                                    .participating
                                    .iter()
                                    .map(|shard| shard.fragment_id.clone())
                                    .collect::<Vec<_>>(),
                            );
                            if seen.insert(key) {
                                reconstructions.push(reconstruction);
                            }
                        }
                        continue;
                    }
                    let choices = candidates_by_index[&subset[index_position]].len();
                    for choice_index in (0..choices).rev() {
                        branch_walk.push((index_position, choice));
                        branch_walk.push((index_position + 1, choice + 1));
                    }
                }
                if budget_exhausted {
                    break;
                }
                continue;
            }
            if position >= indices.len() || chosen + indices.len() - position < params.k {
                continue;
            }
            walk.push((position + 1, chosen));
            subset.push(indices[position]);
            walk.push((position + 1, chosen + 1));
        }
        if budget_exhausted {
            break;
        }
    }

    let clean_by_index = candidates_by_index
        .into_iter()
        .map(|(index, candidates)| (index, candidates.into_iter().map(|(candidate, _)| candidate).collect::<Vec<_>>()))
        .collect();
    GeneratedStripe {
        combinations_considered,
        budget_exhausted,
        reconstructions,
        candidates_by_index: clean_by_index,
        rejected,
    }
}

fn build_generation(
    manifest: &Manifest,
    stripe: &StripeSpec,
    generation: i64,
    fragments: &[ReceivedFragmentInput],
    rejected_ids: &BTreeSet<String>,
    budget: usize,
) -> GeneratedStripe {
    let spec = manifest.encoding;
    let params = EncodingParams {
        k: spec.k(),
        n: spec.n(),
        stripe_size: spec.stripe_size(),
    };
    let mut candidates_by_index: BTreeMap<usize, Vec<(IndexCandidate, i64)>> = BTreeMap::new();
    let mut rejected = Vec::new();

    for fragment in fragments
        .iter()
        .filter(|fragment| fragment.stripe_index == stripe.index && !rejected_ids.contains(&fragment.fragment_id))
    {
        let actual = sha256_hex(&fragment.bytes);
        if fragment.generation != generation {
            rejected.push(ExcludedEvidence {
                fragment_id: fragment.fragment_id.clone(),
                source_id: fragment.source_id.clone(),
                shard_index: fragment.shard_index,
                generation: fragment.generation,
                actual_digest_sha256: actual,
                reasons: vec![format!("generation {generation} 枚举中排除 generation {}", fragment.generation)],
            });
            continue;
        }
        let candidate = IndexCandidate {
            fragment_id: fragment.fragment_id.clone(),
            source_id: fragment.source_id.clone(),
            generation: fragment.generation,
            shard_index: fragment.shard_index,
            digest: actual,
            bytes: fragment.bytes.clone(),
        };
        candidates_by_index
            .entry(fragment.shard_index)
            .or_default()
            .push((candidate, fragment.received_at));
    }
    for candidates in candidates_by_index.values_mut() {
        candidates.sort_by(|left, right| {
            candidate_sort_key(&left.0, left.1).cmp(&candidate_sort_key(&right.0, right.1))
        });
    }

    let indices: Vec<usize> = candidates_by_index.keys().copied().collect();
    let mut subset_stack: Vec<(usize, Vec<usize>)> = vec![(0, Vec::new())];
    let mut combinations_considered = 0usize;
    let mut budget_exhausted = false;
    let mut reconstructions = Vec::new();
    let mut seen = BTreeSet::new();

    while let Some((next, mut chosen_indices)) = subset_stack.pop() {
        let remaining_needed = params.k - chosen_indices.len();
        if remaining_needed == 0 {
            let mut choice_stack: Vec<(usize, Vec<usize>)> = vec![(0, Vec::new())];
            while let Some((depth, mut choices)) = choice_stack.pop() {
                if depth == chosen_indices.len() {
                    combinations_considered += 1;
                    if combinations_considered > budget {
                        budget_exhausted = true;
                        break;
                    }
                    let selected: Vec<&IndexCandidate> = chosen_indices
                        .iter()
                        .zip(choices.iter())
                        .map(|(index, choice)| &candidates_by_index[index][*choice].0)
                        .collect();
                    if let Some(reconstruction) = evaluate_reconstruction(
                        params,
                        generation,
                        &selected,
                        &candidates_by_index,
                        stripe.data_digest_sha256.as_deref(),
                    ) {
                        let key = (
                            reconstruction.data_digest.clone(),
                            reconstruction
                                .participating
                                .iter()
                                .map(|shard| shard.fragment_id.clone())
                                .collect::<Vec<_>>(),
                        );
                        if seen.insert(key) {
                            reconstructions.push(reconstruction);
                        }
                    }
                    continue;
                }
                let choice_count = candidates_by_index[&chosen_indices[depth]].len();
                for choice in (0..choice_count).rev() {
                    let mut next_choices = choices.clone();
                    next_choices.push(choice);
                    choice_stack.push((depth + 1, next_choices));
                }
                choices.clear();
            }
            if budget_exhausted {
                break;
            }
            continue;
        }
        for position in (next..indices.len()).rev() {
            if indices.len() - position >= remaining_needed {
                let mut next_chosen = chosen_indices.clone();
                next_chosen.push(indices[position]);
                subset_stack.push((position + 1, next_chosen));
            }
        }
        chosen_indices.clear();
    }

    GeneratedStripe {
        combinations_considered,
        budget_exhausted,
        reconstructions,
        candidates_by_index: candidates_by_index
            .into_iter()
            .map(|(index, candidates)| (index, candidates.into_iter().map(|(candidate, _)| candidate).collect()))
            .collect(),
        rejected,
    }
}

pub struct AnalysisOptions {
    pub excluded_sources: BTreeSet<String>,
    pub stripe_budget: usize,
    pub object_budget: usize,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            excluded_sources: BTreeSet::new(),
            stripe_budget: 4096,
            object_budget: 4096,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObjectAnalysis {
    pub recoverable: bool,
    pub object_digest_sha256: Option<String>,
    pub object_combinations_considered: usize,
    pub object_budget_exhausted: bool,
    pub selected_solution_ids: Vec<String>,
    pub solutions: Vec<SolutionReport>,
    pub stripes: Vec<StripeAnalysis>,
    pub global_rejected: Vec<ExcludedEvidence>,
}

#[derive(Clone)]
struct StripeChoice {
    generation: i64,
    reconstruction: Reconstruction,
    global_excluded: Vec<ExcludedEvidence>,
}

fn shard_health(
    manifest: &Manifest,
    stripe_index: usize,
    fragments: &[ReceivedFragmentInput],
    rejected_ids: &BTreeSet<String>,
    generations: &BTreeSet<i64>,
) -> Vec<ShardHealth> {
    let n = manifest.encoding.n();
    (0..n)
        .map(|shard_index| {
            let candidates: Vec<&ReceivedFragmentInput> = fragments
                .iter()
                .filter(|fragment| {
                    fragment.stripe_index == stripe_index
                        && fragment.shard_index == shard_index
                        && !rejected_ids.contains(&fragment.fragment_id)
                        && generations.contains(&fragment.generation)
                })
                .collect();
            let best = candidates
                .iter()
                .min_by_key(|fragment| (-fragment.generation, &fragment.fragment_id))
                .map(|fragment| (fragment.generation, sha256_hex(&fragment.bytes)));
            ShardHealth {
                shard_index,
                eligible_candidate_count: candidates.len(),
                rejected_candidate_count: fragments
                    .iter()
                    .filter(|fragment| {
                        fragment.stripe_index == stripe_index
                            && fragment.shard_index == shard_index
                            && rejected_ids.contains(&fragment.fragment_id)
                    })
                    .count(),
                selected_generation: best.as_ref().map(|(generation, _)| *generation),
                best_digest: best.map(|(_, digest)| digest),
            }
        })
        .collect()
}

pub fn analyze_object(manifest: &Manifest, fragments: &[ReceivedFragmentInput], options: &AnalysisOptions) -> ObjectAnalysis {
    let fragments: Vec<ReceivedFragmentInput> = fragments
        .iter()
        .filter(|fragment| !options.excluded_sources.contains(&fragment.source_id))
        .cloned()
        .collect();
    let global_rejected = check_manifest(manifest, &fragments);
    let rejected_ids: BTreeSet<String> = global_rejected
        .iter()
        .map(|evidence| evidence.fragment_id.clone())
        .collect();
    let spec_error = manifest
        .encoding
        .validate()
        .map_err(|_| ())
        .err()
        .is_some();
    let mut stripe_choices: Vec<Vec<StripeChoice>> = Vec::new();
    let mut stripes = Vec::new();

    for stripe in &manifest.stripes {
        let generations: BTreeSet<i64> = fragments
            .iter()
            .filter(|fragment| fragment.stripe_index == stripe.index && !rejected_ids.contains(&fragment.fragment_id))
            .map(|fragment| fragment.generation)
            .collect();
        let mut choices = Vec::new();
        let mut combinations_considered = 0;
        let mut budget_exhausted = false;
        for generation in &generations {
            let result = build_generation(manifest, stripe, *generation, &fragments, &rejected_ids, options.stripe_budget);
            combinations_considered += result.combinations_considered;
            budget_exhausted |= result.budget_exhausted;
            for reconstruction in result.reconstructions {
                let mut evidence = global_rejected.clone();
                evidence.extend(
                    fragments
                        .iter()
                        .filter(|fragment| {
                            fragment.stripe_index == stripe.index
                                && !rejected_ids.contains(&fragment.fragment_id)
                                && fragment.generation != *generation
                        })
                        .map(|fragment| {
                            excluded(
                                fragment,
                                &sha256_hex(&fragment.bytes),
                                vec![format!("generation {generation} 枚举中排除 generation {}", fragment.generation)],
                            )
                        }),
                );
                choices.push(StripeChoice {
                    generation: *generation,
                    reconstruction,
                    global_excluded: evidence,
                });
            }
        }
        stripe_choices.push(choices.clone());
        stripes.push(StripeAnalysis {
            stripe_index: stripe.index,
            available_indices: fragments
                .iter()
                .filter(|fragment| fragment.stripe_index == stripe.index && !rejected_ids.contains(&fragment.fragment_id))
                .map(|fragment| fragment.shard_index)
                .collect::<BTreeSet<_>>()
                .len(),
            threshold: manifest.encoding.k(),
            recoverable: !spec_error && !choices.is_empty(),
            search_budget: options.stripe_budget,
            combinations_considered,
            budget_exhausted,
            solutions: Vec::new(),
            rejected: global_rejected
                .iter()
                .filter(|evidence| {
                    fragments.iter().any(|fragment| {
                        fragment.fragment_id == evidence.fragment_id && fragment.stripe_index == stripe.index
                    })
                })
                .cloned()
                .collect(),
            shard_health: shard_health(manifest, stripe.index, &fragments, &rejected_ids, &generations),
        });
    }

    let mut object_combinations_considered = 0usize;
    let mut object_budget_exhausted = false;
    let mut reports = Vec::new();
    let all_stripes_ready = stripe_choices.iter().all(|choices| !choices.is_empty()) && !spec_error;
    if all_stripes_ready {
        let mut stack: Vec<(usize, Vec<usize>)> = vec![(0, Vec::new())];
        while let Some((depth, mut picked)) = stack.pop() {
            if depth == stripe_choices.len() {
                object_combinations_considered += 1;
                if object_combinations_considered > options.object_budget {
                    object_budget_exhausted = true;
                    break;
                }
                let chosen: Vec<&StripeChoice> = stripe_choices
                    .iter()
                    .zip(picked.iter())
                    .map(|(choices, index)| &choices[*index])
                    .collect();
                let data_digests = chosen
                    .iter()
                    .map(|choice| choice.reconstruction.data_digest.clone())
                    .collect::<Vec<_>>();
                let object_digest = digest_object(&data_digests);
                let matches_object_digest = manifest
                    .object_digest_sha256
                    .as_deref()
                    .map(|expected| normalize_digest(expected) == object_digest);
                let generations: Vec<i64> = chosen.iter().map(|choice| choice.generation).collect();
                let generation = generations.iter().copied().max().unwrap_or_default();
                let participating = chosen
                    .iter()
                    .flat_map(|choice| choice.reconstruction.participating.clone())
                    .collect::<Vec<_>>();
                let data_digest = data_digests.join("|");
                let id = solution_id(generation, &participating, &data_digest);
                let trust = if matches_object_digest == Some(true) {
                    "object_digest_verified"
                } else if matches_object_digest == Some(false) {
                    "object_digest_conflict"
                } else if chosen
                    .iter()
                    .all(|choice| choice.reconstruction.trust != "threshold_only")
                {
                    "stripe_constraints_verified"
                } else {
                    "threshold_only"
                };
                let mut excluded = Vec::new();
                for choice in &chosen {
                    excluded.extend(choice.global_excluded.clone());
                    excluded.extend(choice.reconstruction.excluded.clone());
                }
                excluded.sort_by(|left, right| {
                    (left.shard_index, &left.fragment_id, &left.reasons[0]).cmp(&(
                        right.shard_index,
                        &right.fragment_id,
                        &right.reasons[0],
                    ))
                });
                excluded.dedup();
                reports.push(SolutionReport {
                    solution_id: id,
                    generation,
                    participating,
                    excluded,
                    reconstructed_indices: chosen
                        .iter()
                        .flat_map(|choice| {
                            choice
                                .reconstruction
                                .reconstructed_indices
                                .iter()
                                .map(move |index| (choice.reconstruction.generation, *index))
                        })
                        .enumerate()
                        .map(|(order, _)| order)
                        .collect(),
                    recomputed_shard_digests: chosen
                        .iter()
                        .flat_map(|choice| choice.reconstruction.recomputed_shard_digests.clone())
                        .collect(),
                    recomputed_data_digest_sha256: data_digest,
                    object_reconstruction_digest_sha256: object_digest,
                    matches_object_digest,
                    object_digest_inputs: data_digests.len(),
                    trust: trust.into(),
                    differences_from_primary: Vec::new(),
                });
                continue;
            }
            let count = stripe_choices[depth].len();
            for choice in (0..count).rev() {
                let mut next = picked.clone();
                next.push(choice);
                stack.push((depth + 1, next));
            }
            picked.clear();
        }
    }

    reports.sort_by(|left, right| {
        let score = |report: &SolutionReport| match report.trust.as_str() {
            "object_digest_verified" => 0,
            "stripe_constraints_verified" => 1,
            "threshold_only" => 2,
            _ => 3,
        };
        score(left)
            .cmp(&score(right))
            .then(left.solution_id.cmp(&right.solution_id))
    });
    if let Some(primary_digest) = reports.first().map(|report| report.recomputed_data_digest_sha256.clone()) {
        let primary_ids: BTreeSet<String> = reports[0]
            .participating
            .iter()
            .map(|shard| shard.fragment_id.clone())
            .collect();
        for report in &mut reports {
            if report.recomputed_data_digest_sha256 == primary_digest {
                continue;
            }
            report.differences_from_primary.push("对象数据摘要不同".into());
            for participant in &report.participating {
                if !primary_ids.contains(&participant.fragment_id) {
                    report.differences_from_primary.push(format!(
                        "使用了不同候选 {}（shard {}，来源 {}）",
                        participant.fragment_id, participant.shard_index, participant.source_id
                    ));
                }
            }
        }
    }

    let solutions_by_stripe: BTreeMap<usize, Vec<SolutionReport>> = reports
        .iter()
        .enumerate()
        .flat_map(|(object_order, report)| {
            let mut offset = 0;
            stripe_choices
                .iter()
                .enumerate()
                .map(move |(stripe_position, choices)| {
                    let selected = picked_for(report, choices)?;
                    let stripe_index = manifest.stripes[stripe_position].index;
                    let mut stripe_report = report.clone();
                    stripe_report.solution_id = format!("{}-s{}", report.solution_id, stripe_index);
                    stripe_report.recomputed_data_digest_sha256 =
                        stripe_report.recomputed_data_digest_sha256.split('|').nth(stripe_position)?.to_string();
                    stripe_report.reconstructed_indices =
                        selected.reconstruction.reconstructed_indices.clone();
                    stripe_report.recomputed_shard_digests =
                        selected.reconstruction.recomputed_shard_digests.clone();
                    stripe_report.object_digest_inputs = 1;
                    let _ = offset;
                    let _ = object_order;
                    Some((stripe_index, stripe_report))
                })
        })
        .flatten()
        .fold(BTreeMap::new(), |mut map, (index, report)| {
            map.entry(index).or_default().push(report);
            map
        });
    for stripe in &mut stripes {
        stripe.solutions = solutions_by_stripe.get(&stripe.index).cloned().unwrap_or_default();
    }

    let selected_solution_ids = reports
        .iter()
        .filter(|report| report.matches_object_digest != Some(false))
        .map(|report| report.solution_id.clone())
        .collect();
    ObjectAnalysis {
        recoverable: all_stripes_ready
            && !reports.is_empty()
            && manifest
                .object_digest_sha256
                .as_ref()
                .map(|_| reports.iter().any(|report| report.matches_object_digest == Some(true)))
                .unwrap_or(true),
        object_digest_sha256: manifest.object_digest_sha256.clone(),
        object_combinations_considered,
        object_budget_exhausted,
        selected_solution_ids,
        solutions: reports,
        stripes,
        global_rejected,
    }
}

fn picked_for<'a>(_report: &SolutionReport, _choices: &'a [StripeChoice]) -> Option<&'a StripeChoice> {
    None
}
