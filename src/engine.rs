use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::coding::{
    AvailableShard, CODE_VERSION, CodeParams, SlotKind, encode, reconstruct,
};
use crate::model::{
    CandidateOption, CandidateSolution, Evidence, FragmentView, Manifest, Participant,
    RunReport, ShardOutput, StoredShardKind, StripeReport,
};
use crate::store::{PreparedCommit, PreparedShard, Storage, digest_hex};

#[derive(Debug, Clone)]
pub struct RecoveryOptions {
    pub isolated_sources: Vec<String>,
    pub search_budget: usize,
    pub before_commit: Option<Box<dyn Fn(i64, usize) -> bool + Send + Sync>>,
}

impl Default for RecoveryOptions {
    fn default() -> Self {
        Self {
            isolated_sources: Vec::new(),
            search_budget: 1024,
            before_commit: None,
        }
    }
}

#[derive(Debug, Clone)]
struct CandidateGroup {
    kind: StoredShardKind,
    index: usize,
    generation: u64,
    digest: String,
    bytes: Vec<u8>,
    fragments: Vec<FragmentView>,
}

#[derive(Debug, Clone)]
struct PreparedSolution {
    report: CandidateSolution,
    commit: PreparedCommit,
    data: Vec<Vec<u8>>,
    signature: Vec<String>,
    local_trust: bool,
}

pub fn expected_manifest(manifest: &Manifest, stripe: usize, kind: StoredShardKind, index: usize) -> Option<&crate::model::ManifestShard> {
    manifest
        .shards
        .iter()
        .find(|item| item.stripe == stripe && item.kind == kind && item.index == index)
}

fn evidence(severity: &str, reason: &str, message: impl Into<String>, fragment_ids: Vec<i64>, sources: Vec<String>) -> Evidence {
    Evidence {
        severity: severity.to_string(),
        reason: reason.to_string(),
        message: message.into(),
        fragment_ids,
        sources,
    }
}

fn build_groups(
    manifest: &Manifest,
    stripe: usize,
    fragments: &[FragmentView],
    isolated: &BTreeSet<String>,
    stripe_evidence: &mut Vec<Evidence>,
) -> BTreeMap<u64, BTreeMap<(StoredShardKind, usize), Vec<CandidateGroup>>> {
    let mut groups: BTreeMap<u64, BTreeMap<(StoredShardKind, usize), Vec<CandidateGroup>>> =
        BTreeMap::new();

    for fragment in fragments.iter().filter(|item| item.stripe == stripe) {
        if fragment.index >= if fragment.kind == StoredShardKind::Data {
            manifest.data_shards
        } else {
            manifest.parity_shards
        } {
            stripe_evidence.push(evidence(
                "excluded",
                "shard_index_out_of_range",
                "Shard index is outside versioned coding parameters.",
                vec![fragment.id],
                vec![fragment.source.clone()],
            ));
            continue;
        }
        if isolated.contains(&fragment.source) {
            stripe_evidence.push(evidence(
                "excluded",
                "source_isolated",
                "Operator isolated this receive source for recomputation.",
                vec![fragment.id],
                vec![fragment.source.clone()],
            ));
            continue;
        }
        if let Some(received) = fragment.received_digest.as_ref() {
            if normalize_digest(received) != fragment.actual_digest {
                stripe_evidence.push(evidence(
                    "excluded",
                    "received_digest_mismatch",
                    "Stored bytes do not match the digest delivered with the fragment.",
                    vec![fragment.id],
                    vec![fragment.source.clone()],
                ));
                continue;
            }
        }
        if fragment.actual_length != manifest.shard_size {
            stripe_evidence.push(evidence(
                "excluded",
                "length_mismatch",
                format!(
                    "Actual length {} differs from versioned shard size {}.",
                    fragment.actual_length, manifest.shard_size
                ),
                vec![fragment.id],
                vec![fragment.source.clone()],
            ));
            continue;
        }
        if let Some(expected) = fragment.expected_digest.as_ref() {
            if normalize_digest(expected) != fragment.actual_digest {
                stripe_evidence.push(evidence(
                    "excluded",
                    "expected_digest_mismatch",
                    "Bit flip or replacement makes bytes disagree with the manifest digest.",
                    vec![fragment.id],
                    vec![fragment.source.clone()],
                ));
                continue;
            }
        }
        if let Some(declared_length) = fragment.declared_length {
            if declared_length != fragment.actual_length {
                stripe_evidence.push(evidence(
                    "warning",
                    "declared_length_mismatch",
                    format!(
                        "Sidecar/manifest declares length {} but the received bytes are {}.",
                        declared_length, fragment.actual_length
                    ),
                    vec![fragment.id],
                    vec![fragment.source.clone()],
                ));
            }
        }

        let bytes = std::fs::read(&fragment.raw_path).unwrap();
        let generation_groups = groups.entry(fragment.generation).or_default();
        let slot_groups = generation_groups
            .entry((fragment.kind, fragment.index))
            .or_default();
        if let Some(existing) = slot_groups.iter_mut().find(|group| group.digest == fragment.actual_digest) {
            existing.fragments.push(fragment.clone());
        } else {
            slot_groups.push(CandidateGroup {
                kind: fragment.kind,
                index: fragment.index,
                generation: fragment.generation,
                digest: fragment.actual_digest.clone(),
                bytes,
                fragments: vec![fragment.clone()],
            });
        }
    }

    for generation_groups in groups.values() {
        for ((kind, index), slot_groups) in generation_groups {
            if slot_groups.len() > 1 {
                let ids = slot_groups.iter().flat_map(|group| group.fragments.iter().map(|item| item.id)).collect();
                let sources = slot_groups.iter().flat_map(|group| group.fragments.iter().map(|item| item.source.clone())).collect();
                stripe_evidence.push(evidence(
                    "warning",
                    "duplicate_shard_number_with_distinct_content",
                    format!(
                        "{} shard {} has {} independent content candidates; all combinations are enumerated.",
                        if *kind == StoredShardKind::Data { "Data" } else { "Parity" },
                        index,
                        slot_groups.len()
                    ),
                    ids,
                    sources,
                ));
            }
        }
    }

    groups
}

fn normalize_digest(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn stable_hash(values: &[String]) -> String {
    digest_hex(serde_json::to_vec(values).unwrap().as_slice())
}

fn analyze_stripe(
    manifest: &Manifest,
    stripe: usize,
    fragments: &[FragmentView],
    isolated: &BTreeSet<String>,
    search_budget: usize,
    search_attempted: &mut usize,
) -> (StripeReport, Vec<PreparedSolution>) {
    let params = CodeParams {
        data_shards: manifest.data_shards,
        parity_shards: manifest.parity_shards,
    };
    let mut global_evidence = Vec::new();
    let generation_groups = build_groups(manifest, stripe, fragments, isolated, &mut global_evidence);
    let mut solutions = Vec::new();
    let mut candidates = Vec::new();

    for (_, slot_groups) in generation_groups.iter() {
        for (_, options) in slot_groups {
            for option in options {
                let mut sources: Vec<_> = option.fragments.iter().map(|item| item.source.clone()).collect();
                sources.sort();
                sources.dedup();
                candidates.push(CandidateOption {
                    generation: option.generation,
                    digest: option.digest.clone(),
                    sources,
                    fragment_ids: option.fragments.iter().map(|item| item.id).collect(),
                });
            }
        }
    }
    candidates.sort_by(|left, right| {
        left.generation
            .cmp(&right.generation)
            .then(left.digest.cmp(&right.digest))
    });
    candidates.dedup_by(|left, right| left.generation == right.generation && left.digest == right.digest);

    let mut eligible_slots = 0usize;
    for (generation, slots) in &generation_groups {
        let data_keys: Vec<_> = slots.keys().filter(|(kind, _)| *kind == StoredShardKind::Data).copied().collect();
        let parity_keys: Vec<_> = slots.keys().filter(|(kind, _)| *kind == StoredShardKind::Parity).copied().collect();
        let present_data: BTreeSet<usize> = data_keys.iter().map(|(_, index)| *index).collect();
        let missing_data: Vec<usize> = (0..manifest.data_shards).filter(|index| !present_data.contains(index)).collect();
        eligible_slots = eligible_slots.max(data_keys.len() + parity_keys.len());

        if missing_data.len() > parity_keys.len() {
            global_evidence.push(evidence(
                "blocking",
                "below_recovery_threshold",
                format!(
                    "Generation {generation} has {} missing data shard(s) but only {} eligible parity shard(s).",
                    missing_data.len(),
                    parity_keys.len()
                ),
                Vec::new(),
                Vec::new(),
            ));
            continue;
        }

        let mut ordered_keys = data_keys.clone();
        ordered_keys.extend(parity_keys);
        ordered_keys.sort_by(|left, right| {
            slot_rank(left, manifest.data_shards)
                .cmp(&slot_rank(right, manifest.data_shards))
        });

        let mut leaves: Vec<Vec<&CandidateGroup>> = Vec::new();
        enumerate_choices(
            &ordered_keys,
            slots,
            manifest.data_shards,
            0,
            &mut Vec::new(),
            &mut leaves,
            search_budget,
            &mut search_attempted,
        );

        for leaf in leaves {
            if let Some(solution) = evaluate_leaf(
                manifest,
                params,
                stripe,
                *generation,
                leaf,
                &missing_data,
                &parity_keys,
                slots,
            ) {
                solutions.push(solution);
            }
        }
    }

    solutions.sort_by(|left, right| {
        left.signature
            .cmp(&right.signature)
            .then(left.report.id.cmp(&right.report.id))
    });
    solutions.dedup_by(|left, right| left.signature == right.signature);
    annotate_differences(&mut solutions);

    let status = if solutions.iter().any(|item| item.local_trust) {
        "locally_trusted"
    } else if !solutions.is_empty() {
        "feasible_untrusted"
    } else if *search_attempted > search_budget {
        "budget_exhausted"
    } else {
        "unrecoverable"
    };

    let report = StripeReport {
        stripe,
        status: status.to_string(),
        required_for_threshold: manifest.data_shards,
        eligible_shard_slots: eligible_slots,
        candidates,
        solutions: solutions.into_iter().map(|item| item.report).collect(),
        evidence: global_evidence,
        committed_solution_id: None,
    };
    (report, solutions)
}

fn slot_rank(key: &(StoredShardKind, usize), data_shards: usize) -> usize {
    match key.0 {
        StoredShardKind::Data => key.1,
        StoredShardKind::Parity => data_shards + key.1,
    }
}

fn enumerate_choices<'a>(
    keys: &[(StoredShardKind, usize)],
    slots: &BTreeMap<(StoredShardKind, usize), Vec<CandidateGroup>>,
    target: usize,
    position: usize,
    selected: &mut Vec<&'a CandidateGroup>,
    leaves: &mut Vec<Vec<&'a CandidateGroup>>,
    budget: usize,
    attempted: &mut usize,
) -> bool {
    if *attempted >= budget {
        return false;
    }
    if selected.len() == target {
        *attempted += 1;
        leaves.push(selected.iter().copied().collect());
        return *attempted < budget;
    }
    if position == keys.len() {
        return true;
    }
    let key = keys[position];
    let options = slots.get(&key).unwrap();
    if key.0 == StoredShardKind::Data {
        for option in options {
            selected.push(option);
            if !enumerate_choices(keys, slots, target, position + 1, selected, leaves, budget, attempted) {
                selected.pop();
                return false;
            }
            selected.pop();
        }
    } else {
        let remaining_slots = keys.len() - position - 1;
        if selected.len() + remaining_slots >= target {
            if !enumerate_choices(keys, slots, target, position + 1, selected, leaves, budget, attempted) {
                return false;
            }
        }
        if selected.len() < target {
            for option in options {
                selected.push(option);
                if !enumerate_choices(keys, slots, target, position + 1, selected, leaves, budget, attempted) {
                    selected.pop();
                    return false;
                }
                selected.pop();
            }
        }
    }
    true
}

fn evaluate_leaf(
    manifest: &Manifest,
    params: CodeParams,
    stripe: usize,
    generation: u64,
    selected: Vec<&CandidateGroup>,
    missing_data: &[usize],
    parity_keys: &[(StoredShardKind, usize)],
    all_slots: &BTreeMap<(StoredShardKind, usize), Vec<CandidateGroup>>,
) -> Option<PreparedSolution> {
    let mut selected = selected;
    selected.sort_by(|left, right| {
        slot_rank(&(left.kind, left.index), params.data_shards)
            .cmp(&slot_rank(&(right.kind, right.index), params.data_shards))
    });

    let available: Vec<_> = selected
        .iter()
        .map(|group| AvailableShard {
            kind: group.kind.into(),
            index: group.index,
            bytes: group.bytes.clone(),
        })
        .collect();
    let reconstructed_data = reconstruct(&available, params)?;

    let encoded = encode(&reconstructed_data, params);
    let mut excluded = Vec::new();

    for (_, index) in parity_keys {
        for group in all_slots.get(&(StoredShardKind::Parity, *index)).unwrap_or(&Vec::new()) {
            if selected.iter().any(|selected_group| selected_group.digest == group.digest && selected_group.index == group.index) {
                continue;
            }
            if group.bytes != encoded.parity[*index] {
                excluded.push(evidence(
                    "excluded",
                    "parity_equation_failed",
                    format!("Parity shard {index} is inconsistent with the selected data/parity equations."),
                    group.fragments.iter().map(|item| item.id).collect(),
                    group.fragments.iter().map(|item| item.source.clone()).collect(),
                ));
            }
        }
    }
    for group in &selected {
        if group.fragments.len() > 1 {
            excluded.push(evidence(
                "warning",
                "identical_duplicate_collapsed",
                "Repeated shard numbers contained identical bytes; one receive source was used in the equation.",
                group.fragments.iter().skip(1).map(|item| item.id).collect(),
                group.fragments.iter().skip(1).map(|item| item.source.clone()).collect(),
            ));
        }
    }

    let chosen_fragment = |group: &&CandidateGroup| group.fragments.first().unwrap();
    let mut participants: Vec<Participant> = selected
        .iter()
        .map(|group| {
            let fragment = chosen_fragment(&group);
            Participant {
                fragment_id: fragment.id,
                source: fragment.source.clone(),
                kind: group.kind,
                index: group.index,
                generation: group.generation,
                digest: group.digest.clone(),
            }
        })
        .collect();
    participants.sort_by(|left, right| {
        slot_rank(&(left.kind, left.index), params.data_shards)
            .cmp(&slot_rank(&(right.kind, right.index), params.data_shards))
            .then(left.fragment_id.cmp(&right.fragment_id))
    });

    let mut outputs = Vec::new();
    let mut all_trusted = true;
    let mut shard_bytes: BTreeMap<(StoredShardKind, usize), (Vec<u8>, bool)> = BTreeMap::new();

    for index in 0..params.data_shards {
        let rebuilt = missing_data.contains(&index);
        let bytes = encoded.data[index].clone();
        let digest = digest_hex(&bytes);
        let expected = expected_manifest(manifest, stripe, StoredShardKind::Data, index)
            .and_then(|item| item.digest.clone())
            .map(|value| normalize_digest(&value));
        let trusted = expected.as_ref().map_or(false, |value| value == &digest);
        all_trusted &= trusted;
        outputs.push(ShardOutput {
            kind: StoredShardKind::Data,
            index,
            digest: digest.clone(),
            length: bytes.len(),
            rebuilt,
            expected_digest: expected,
            trusted,
        });
        shard_bytes.insert((StoredShardKind::Data, index), (bytes, rebuilt));
    }

    for index in 0..params.parity_shards {
        let bytes = encoded.parity[index].clone();
        let digest = digest_hex(&bytes);
        let expected = expected_manifest(manifest, stripe, StoredShardKind::Parity, index)
            .and_then(|item| item.digest.clone())
            .map(|value| normalize_digest(&value));
        let existing = all_slots.get(&(StoredShardKind::Parity, index));
        let rebuilt = !existing.map_or(false, |options| options.iter().any(|option| option.digest == digest));
        let trusted = expected.as_ref().map_or(false, |value| value == &digest);
        all_trusted &= trusted;
        outputs.push(ShardOutput {
            kind: StoredShardKind::Parity,
            index,
            digest: digest.clone(),
            length: bytes.len(),
            rebuilt,
            expected_digest: expected,
            trusted,
        });
        shard_bytes.insert((StoredShardKind::Parity, index), (bytes, rebuilt));
    }

    let participant_signature: Vec<String> = participants
        .iter()
        .map(|item| format!("{}:{}:{}:{}", item.generation, kind_text(item.kind), item.index, item.digest))
        .collect();
    let output_signature: Vec<String> = outputs
        .iter()
        .map(|item| format!("{}:{}:{}", kind_text(item.kind), item.index, item.digest))
        .collect();
    let solution_id = stable_hash(
        &participant_signature
            .iter()
            .chain(output_signature.iter())
            .cloned()
            .collect::<Vec<_>>(),
    );

    let mut commit_shards = Vec::new();
    for ((kind, index), (bytes, rebuilt)) in shard_bytes {
        let digest = digest_hex(&bytes);
        commit_shards.push(PreparedShard {
            kind,
            index,
            generation,
            rebuilt,
            digest,
            bytes,
        });
    }
    commit_shards.sort_by(|left, right| {
        slot_rank(&(left.kind, left.index), params.data_shards)
            .cmp(&slot_rank(&(right.kind, right.index), params.data_shards))
    });

    Some(PreparedSolution {
        report: CandidateSolution {
            id: solution_id.clone(),
            generation,
            participants,
            outputs,
            object_digest: None,
            locally_trusted: all_trusted,
            object_trusted: false,
            excluded_evidence: excluded,
            differences: Vec::new(),
        },
        commit: PreparedCommit {
            object_id: manifest.object_id.clone(),
            generation,
            solution_id,
            object_digest: None,
            shards: commit_shards,
            participant_fragment_ids: participants
                .iter()
                .map(|item| (item.fragment_id, item.source.clone()))
                .collect(),
        },
        data: encoded.data,
        signature: output_signature,
        local_trust: all_trusted,
    })
}

fn kind_text(kind: StoredShardKind) -> &'static str {
    crate::store::kind_name(kind)
}

fn annotate_differences(solutions: &mut [PreparedSolution]) {
    if solutions.len() < 2 {
        return;
    }
    let first_outputs: BTreeMap<String, String> = solutions[0].report.outputs.iter().map(|item| {
        (format!("{}:{}", kind_text(item.kind), item.index), item.digest.clone())
    }).collect();
    for solution in solutions.iter_mut().skip(1) {
        for output in &solution.report.outputs {
            let key = format!("{}:{}", kind_text(output.kind), output.index);
            if first_outputs.get(&key) != Some(&output.digest) {
                solution.report.differences.push(format!("{} digest differs from first feasible answer", key));
            }
        }
        if solution.report.generation != solutions[0].report.generation {
            solution.report.differences.push(format!("generation differs: {} vs {}", solution.report.generation, solutions[0].report.generation));
        }
    }
}

pub fn validate_manifest(manifest: &Manifest) -> Result<(), String> {
    if manifest.schema_version != "manifest.v1" {
        return Err(format!("unsupported manifest schema {}", manifest.schema_version));
    }
    if manifest.code_version != CODE_VERSION {
        return Err(format!("unsupported code version {}", manifest.code_version));
    }
    if manifest.data_shards == 0 || manifest.parity_shards == 0 {
        return Err("data_shards and parity_shards must be non-zero".to_string());
    }
    if manifest.data_shards + manifest.parity_shards > 255 {
        return Err("GF(256) fixtures support at most 255 total shards".to_string());
    }
    if manifest.shard_size == 0 {
        return Err("shard_size must be non-zero".to_string());
    }
    if manifest.stripe_count == 0 {
        return Err("stripe_count must be non-zero".to_string());
    }
    Ok(())
}

pub fn recover_object(
    storage: &Storage,
    manifest: &Manifest,
    options: &RecoveryOptions,
) -> std::io::Result<RunReport> {
    validate_manifest(manifest).map_err(|message| std::io::Error::new(std::io::ErrorKind::InvalidData, message))?;
    let fragments = storage.fragments(&manifest.object_id)?;
    let isolated: BTreeSet<String> = options.isolated_sources.iter().cloned().collect();

    let mut stripes = Vec::new();
    let mut attempted = 0usize;
    let mut analyzed: BTreeMap<usize, Vec<PreparedSolution>> = BTreeMap::new();
    for stripe in 0..manifest.stripe_count {
        let (stripe_report, solutions) = analyze_stripe(
            manifest,
            stripe,
            &fragments,
            &isolated,
            options.search_budget,
            &mut attempted,
        );
        stripes.push(stripe_report);
        analyzed.insert(stripe, solutions);
    }

    let mut report = RunReport {
        run_id: 0,
        object_id: manifest.object_id.clone(),
        state: "running".to_string(),
        code_version: manifest.code_version.clone(),
        data_shards: manifest.data_shards,
        parity_shards: manifest.parity_shards,
        stripe_count: manifest.stripe_count,
        shard_size: manifest.shard_size,
        object_digest_expected: manifest.object_digest.as_ref().map(|value| normalize_digest(value)),
        object_digest_recomputed: None,
        isolated_sources: options.isolated_sources.clone(),
        stripes,
        search_budget: options.search_budget,
        search_attempted: attempted,
    };
    let run_id = storage.start_run(&manifest.object_id, &options.isolated_sources, &report)?;
    report.run_id = run_id;

    for stripe_report in &mut report.stripes {
        if let Some(items) = analyzed.get(&stripe_report.stripe) {
            stripe_report.solutions = items.iter().map(|item| item.report.clone()).collect();
        }
    }

    let selected = choose_solutions(manifest, &analyzed, &mut report);

    for stripe in 0..manifest.stripe_count {
        if let Some(solution_index) = selected.get(&stripe).copied() {
            let can_reuse = committed_matches(
                storage,
                manifest,
                stripe,
                &analyzed[&stripe][solution_index],
                &isolated,
            )?;
            let solution = &analyzed[&stripe][solution_index];
            if can_reuse {
                report.stripes[stripe].status = "committed".to_string();
                report.stripes[stripe].committed_solution_id = Some(solution.report.id.clone());
                continue;
            }
            if let Some(hook) = &options.before_commit {
                if !hook(run_id, stripe) {
                    report.state = "interrupted".to_string();
                    storage.update_run(run_id, &report)?;
                    return Ok(report);
                }
            }
            let mut prepared = solution.commit.clone();
            if solution.report.object_trusted {
                prepared.object_digest = report.object_digest_expected.clone();
            }
            if let Err(error) = storage.commit_solution(run_id, stripe, &prepared) {
                report.state = "disk_write_failed".to_string();
                report.stripes[stripe].evidence.push(evidence(
                    "fatal",
                    "disk_write_failed",
                    error.to_string(),
                    Vec::new(),
                    Vec::new(),
                ));
                storage.update_run(run_id, &report)?;
                return Err(error);
            }
            report.stripes[stripe].status = "committed".to_string();
            report.stripes[stripe].committed_solution_id = Some(solution.report.id.clone());
            storage.update_run(run_id, &report)?;
        } else {
            invalidate_isolated_commit(storage, manifest.object_id.clone(), stripe, &isolated)?;
        }
    }

    finalize_report(storage, manifest, &mut report, &analyzed, &selected)?;
    storage.update_run(run_id, &report)?;
    Ok(report)
}

fn choose_solutions(
    manifest: &Manifest,
    analyzed: &mut BTreeMap<usize, Vec<PreparedSolution>>,
    report: &mut RunReport,
) -> BTreeMap<usize, usize> {
    let mut selected: BTreeMap<usize, usize> = BTreeMap::new();
    let stripes: Vec<usize> = (0..manifest.stripe_count).collect();

    for stripe in &stripes {
        let trusted: Vec<usize> = analyzed
            .get(stripe)
            .unwrap()
            .iter()
            .enumerate()
            .filter(|(_, item)| item.local_trust)
            .map(|(index, _)| index)
            .collect();
        if trusted.len() == 1 {
            selected.insert(*stripe, trusted[0]);
        } else if trusted.len() > 1 {
            report.stripes[*stripe].evidence.push(evidence(
                "blocking",
                "multiple_locally_trusted_answers",
                "More than one feasible answer satisfies the available stripe digests; object digest or manual adjudication is required.",
                Vec::new(),
                Vec::new(),
            ));
        }
    }

    let expected_digest = report.object_digest_expected.clone();
    if let Some(expected_digest) = expected_digest {
        let unresolved: Vec<usize> = stripes.iter().copied().filter(|stripe| !selected.contains_key(stripe)).collect();
        let mut matched: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
        enumerate_objects(
            manifest,
            analyzed,
            &unresolved,
            0,
            &mut Vec::new(),
            &expected_digest,
            &mut matched,
            report.search_budget,
            &mut report.search_attempted,
        );

        for stripe in &unresolved {
            let matches = matched.get(stripe).cloned().unwrap_or_default();
            if matches.len() == 1 {
                selected.insert(*stripe, *matches.iter().next().unwrap());
            } else if matches.len() > 1 {
                report.stripes[*stripe].evidence.push(evidence(
                    "blocking",
                    "multiple_object_matching_answers",
                    "More than one full-object reconstruction matches the object digest; stripe outputs remain ambiguous.",
                    Vec::new(),
                    Vec::new(),
                ));
            }
        }

        for stripe in &stripes {
            if let Some(index) = selected.get(stripe) {
                analyzed.get_mut(stripe).unwrap()[*index].report.object_trusted = true;
                analyzed.get_mut(stripe).unwrap()[*index].report.object_digest = Some(expected_digest.clone());
            }
        }
    }

    selected
}

fn enumerate_objects(
    manifest: &Manifest,
    analyzed: &BTreeMap<usize, Vec<PreparedSolution>>,
    unresolved: &[usize],
    position: usize,
    chosen: &mut Vec<(usize, usize)>,
    expected_digest: &str,
    matched: &mut BTreeMap<usize, BTreeSet<usize>>,
    budget: usize,
    attempted: &mut usize,
) -> bool {
    if *attempted >= budget {
        return false;
    }
    if position == unresolved.len() {
        *attempted += 1;
        let mut bytes = Vec::new();
        for stripe in 0..manifest.stripe_count {
            let data = if let Some((_, index)) = chosen.iter().find(|(item_stripe, _)| *item_stripe == stripe) {
                analyzed[&stripe][*index].data.clone()
            } else {
                analyzed[&stripe]
                    .iter()
                    .find(|item| item.local_trust)
                    .unwrap()
                    .data
                    .clone()
            };
            for shard in data {
                bytes.extend(shard);
            }
        }
        if digest_hex(&bytes) == expected_digest {
            for (stripe, index) in chosen.iter() {
                matched.entry(*stripe).or_default().insert(*index);
            }
        }
        return *attempted < budget;
    }
    let stripe = unresolved[position];
    for (index, _solution) in analyzed[&stripe].iter().enumerate() {
        chosen.push((stripe, index));
        if !enumerate_objects(manifest, analyzed, unresolved, position + 1, chosen, expected_digest, matched, budget, attempted) {
            chosen.pop();
            return false;
        }
        chosen.pop();
    }
    true
}

fn committed_matches(
    storage: &Storage,
    manifest: &Manifest,
    stripe: usize,
    solution: &PreparedSolution,
    isolated: &BTreeSet<String>,
) -> std::io::Result<bool> {
    let committed_solution_id = storage.committed_solution_id(&manifest.object_id, stripe)?;
    if committed_solution_id.as_deref() != Some(solution.report.id.as_str()) {
        return Ok(false);
    }
    let sources = storage.committed_sources(&manifest.object_id, stripe)?;
    if sources.iter().any(|source| isolated.contains(source)) {
        return Ok(false);
    }
    let shards = storage.committed_shards(&manifest.object_id, stripe)?;
    if shards.len() != solution.commit.shards.len() {
        return Ok(false);
    }
    for (committed, expected) in shards.iter().zip(solution.commit.shards.iter()) {
        if committed.kind != expected.kind
            || committed.index != expected.index
            || committed.generation != expected.generation
            || committed.digest != expected.digest
        {
            return Ok(false);
        }
        if digest_hex(&std::fs::read(Path::new(&committed.path))?) != committed.digest {
            return Ok(false);
        }
    }
    Ok(true)
}

fn invalidate_isolated_commit(
    storage: &Storage,
    object_id: String,
    stripe: usize,
    isolated: &BTreeSet<String>,
) -> std::io::Result<()> {
    if !isolated.is_empty() {
        let sources = storage.committed_sources(&object_id, stripe)?;
        if sources.iter().any(|source| isolated.contains(source)) {
            storage.delete_commit(&object_id, stripe)?;
        }
    }
    Ok(())
}

fn finalize_report(
    storage: &Storage,
    manifest: &Manifest,
    report: &mut RunReport,
    analyzed: &BTreeMap<usize, Vec<PreparedSolution>>,
    selected: &BTreeMap<usize, usize>,
) -> std::io::Result<()> {
    for stripe in 0..manifest.stripe_count {
        if let Some(items) = analyzed.get(&stripe) {
            report.stripes[stripe].solutions = items.iter().map(|item| item.report.clone()).collect();
        }
    }

    if selected.len() == manifest.stripe_count {
        let mut bytes = Vec::new();
        for stripe in 0..manifest.stripe_count {
            let solution = &analyzed[&stripe][selected[&stripe]];
            for shard in &solution.data {
                bytes.extend(shard);
            }
        }
        let digest = digest_hex(&bytes);
        report.object_digest_recomputed = Some(digest.clone());
        report.state = match &report.object_digest_expected {
            Some(expected) if expected == &digest => "completed".to_string(),
            Some(_) => "object_digest_mismatch".to_string(),
            None => "committed_without_object_digest".to_string(),
        };
        for stripe in 0..manifest.stripe_count {
            let solution = &mut analyzed
                .get_mut(&stripe)
                .unwrap()
                .get_mut(selected[&stripe])
                .unwrap();
            solution.report.object_trusted = report.state == "completed";
            solution.report.object_digest = Some(digest.clone());
            report.stripes[stripe].solutions = analyzed[&stripe].iter().map(|item| item.report.clone()).collect();
            report.stripes[stripe].status = if report.state == "completed" {
                "committed_object_trusted".to_string()
            } else {
                "committed_locally_trusted".to_string()
            };
        }
    } else if selected.is_empty() {
        report.state = if report.search_attempted > report.search_budget {
            "budget_exhausted".to_string()
        } else if report.stripes.iter().any(|stripe| !stripe.solutions.is_empty()) {
            "feasible_untrusted"
        } else {
            "unrecoverable"
        }
        .to_string();
    } else {
        report.state = "partially_committed".to_string();
    }

    let _ = storage;
    Ok(())
}
PATCH