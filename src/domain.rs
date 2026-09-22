use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::gf::Gf256;

pub const DEFAULT_SEARCH_BUDGET: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportRequest {
    pub object_id: String,
    pub generation: i64,
    pub data_shards: usize,
    pub parity_shards: usize,
    pub object_len: usize,
    pub shard_len: usize,
    pub object_digest: Option<String>,
    pub fragments: Vec<ImportedFragment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedFragment {
    pub shard_index: usize,
    pub generation: i64,
    pub source: String,
    #[serde(with = "hex_bytes")]
    pub bytes: Vec<u8>,
    pub manifest_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Candidate {
    pub id: i64,
    pub object_id: String,
    pub stripe_index: usize,
    pub shard_index: usize,
    pub generation: i64,
    pub source: String,
    pub raw_path: String,
    pub actual_digest: String,
    pub manifest_digest: Option<String>,
    pub byte_len: usize,
    pub digest_ok: bool,
    pub length_ok: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExcludedEvidence {
    pub fragment_id: i64,
    pub shard_index: usize,
    pub generation: i64,
    pub source: String,
    pub actual_digest: String,
    pub manifest_digest: Option<String>,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutputEvidence {
    pub shard_index: usize,
    pub actual_digest: String,
    pub recomputed_digest: String,
    pub digest_matches: bool,
    pub participant_fragment_ids: Vec<i64>,
    pub participant_sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeasiblePlan {
    pub participant_fragment_ids: Vec<i64>,
    pub participant_sources: Vec<String>,
    pub missing_shard_indices: Vec<usize>,
    pub outputs: Vec<OutputEvidence>,
    pub excluded_evidence: Vec<ExcludedEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlanResult {
    pub stripe_index: usize,
    pub status: String,
    pub generation: i64,
    pub search_budget: usize,
    pub combinations_tried: usize,
    pub feasible_plans: Vec<FeasiblePlan>,
    pub excluded_evidence: Vec<ExcludedEvidence>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverRequest {
    pub object_id: Option<String>,
    pub stripe_index: Option<usize>,
    pub excluded_sources: Vec<String>,
    pub search_budget: Option<usize>,
    pub force: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportManifest {
    pub object_id: String,
    pub generation: i64,
    pub data_shards: usize,
    pub parity_shards: usize,
    pub object_len: usize,
    pub shard_len: usize,
    pub object_digest_expected: Option<String>,
    pub object_digest_recomputed: Option<String>,
    pub stripes: Vec<ExportStripe>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportStripe {
    pub stripe_index: usize,
    pub status: String,
    pub shards: Vec<ExportShard>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportShard {
    pub shard_index: usize,
    pub generation: i64,
    pub source: String,
    pub digest: String,
    pub path: String,
    pub rebuilt: bool,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub fn normalize_digest(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

pub fn enumerate_stripe(
    stripe_index: usize,
    generation: i64,
    data_shards: usize,
    parity_shards: usize,
    shard_len: usize,
    expected_shard_digests: &[Option<String>],
    candidates_by_fragment: &[(Candidate, Vec<u8>)],
    excluded_sources: &[String],
    search_budget: usize,
) -> PlanResult {
    let total_shards = data_shards + parity_shards;
    let mut result = PlanResult {
        stripe_index,
        status: "unrecoverable".to_string(),
        generation,
        search_budget,
        combinations_tried: 0,
        feasible_plans: Vec::new(),
        excluded_evidence: Vec::new(),
        errors: Vec::new(),
    };

    if data_shards == 0 || parity_shards == 0 || total_shards > 255 {
        result
            .errors
            .push("编码参数必须满足 data>0、parity>0、data+parity<=255".to_string());
        return result;
    }

    let mut groups: Vec<Vec<(Candidate, Vec<u8>)>> = vec![Vec::new(); total_shards];
    for entry @ (candidate, _) in candidates_by_fragment {
        let mut reasons = Vec::new();
        if candidate.generation != generation {
            reasons.push(format!(
                "generation 混杂：候选 {}，stripe {}",
                candidate.generation, generation
            ));
        }
        if !candidate.digest_ok {
            reasons.push("每块摘要不匹配或缺失，疑似位翻转".to_string());
        }
        if !candidate.length_ok {
            reasons.push(format!(
                "实际长度 {} 与 manifest shard_len {} 不符",
                candidate.byte_len, shard_len
            ));
        }
        if excluded_sources.iter().any(|source| source == &candidate.source) {
            reasons.push("来源被人工隔离".to_string());
        }
        if candidate.shard_index >= total_shards {
            reasons.push(format!("shard 编号超出 0..{}", total_shards - 1));
        }
        if reasons.is_empty() {
            groups[candidate.shard_index].push(entry.clone());
        } else {
            result.excluded_evidence.push(ExcludedEvidence {
                fragment_id: candidate.id,
                shard_index: candidate.shard_index,
                generation: candidate.generation,
                source: candidate.source.clone(),
                actual_digest: candidate.actual_digest.clone(),
                manifest_digest: candidate.manifest_digest.clone(),
                reasons,
            });
        }
    }

    let occupied: Vec<usize> = groups
        .iter()
        .enumerate()
        .filter_map(|(index, group)| (!group.is_empty()).then_some(index))
        .collect();
    let missing: Vec<usize> = (0..total_shards)
        .filter(|index| groups[*index].is_empty())
        .collect();

    if occupied.len() < data_shards {
        result.errors.push(format!(
            "可用 shard {} 少于恢复下限 {data_shards}；缺失 {}",
            occupied.len(),
            missing.len()
        ));
        return result;
    }

    for group in groups.iter_mut() {
        group.sort_by(|left, right| {
            left.0.source
                .cmp(&right.0.source)
                .then(left.0.id.cmp(&right.0.id))
        });
    }

    let mut combinations: Vec<Vec<usize>> = vec![Vec::new()];
    for group in &groups {
        if group.is_empty() {
            continue;
        }
        let mut next = Vec::new();
        for combination in &combinations {
            for candidate_index in 0..group.len() {
                next.push({
                    let mut cloned = combination.clone();
                    cloned.push(candidate_index);
                    next.len();
                    cloned
                });
            }
        }
        combinations = next;
    }

    let mut participant_indices: Vec<Vec<usize>> = Vec::new();
    enumerate_participants(
        &occupied,
        data_shards,
        0,
        &mut Vec::new(),
        &mut participant_indices,
    );

    let gf = Gf256::new();
    'outer: for candidate_combo in &combinations {
        for participant_combo in &participant_indices {
            if result.combinations_tried >= search_budget {
                result.status = "budget_exceeded".to_string();
                result.errors.push(format!(
                    "确定性搜索达到预算 {search_budget}，未枚举完全部候选组合"
                ));
                break 'outer;
            }
            result.combinations_tried += 1;
            let mut chosen = Vec::new();
            for (occupied_slot, candidate_slot) in
                participant_combo.iter().zip(candidate_combo.iter())
            {
                let shard_index = occupied[*occupied_slot];
                chosen.push(groups[shard_index][*candidate_slot].clone());
            }
            chosen.sort_by_key(|(candidate, _)| candidate.shard_index);
            let available: Vec<(usize, Vec<u8>)> = chosen
                .iter()
                .map(|(candidate, bytes)| (candidate.shard_index, bytes.clone()))
                .collect();
            let rebuilt = match gf.reconstruct(data_shards, &available, &missing) {
                Ok(bytes) => bytes,
                Err(error) => {
                    result.errors.push(error);
                    continue;
                }
            };
            let mut outputs = Vec::new();
            let mut valid = true;
            for (missing_index, bytes) in missing.iter().zip(rebuilt) {
                let recomputed = sha256_hex(&bytes);
                let expected = expected_shard_digests
                    .get(*missing_index)
                    .cloned()
                    .flatten();
                let digest_matches = expected
                    .as_ref()
                    .is_none_or(|expected| normalize_digest(expected) == recomputed);
                if !digest_matches {
                    valid = false;
                }
                outputs.push(OutputEvidence {
                    shard_index: *missing_index,
                    actual_digest: expected.unwrap_or_else(|| recomputed.clone()),
                    recomputed_digest: recomputed,
                    digest_matches,
                    participant_fragment_ids: chosen
                        .iter()
                        .map(|(candidate, _)| candidate.id)
                        .collect(),
                    participant_sources: chosen
                        .iter()
                        .map(|(candidate, _)| candidate.source.clone())
                        .collect(),
                });
            }
            if valid {
                result.feasible_plans.push(FeasiblePlan {
                    participant_fragment_ids: chosen
                        .iter()
                        .map(|(candidate, _)| candidate.id)
                        .collect(),
                    participant_sources: chosen
                        .iter()
                        .map(|(candidate, _)| candidate.source.clone())
                        .collect(),
                    missing_shard_indices: missing.clone(),
                    outputs,
                    excluded_evidence: result.excluded_evidence.clone(),
                });
            }
        }
    }

    if !result.feasible_plans.is_empty() {
        result.feasible_plans.sort_by(|left, right| {
            left.participant_fragment_ids
                .cmp(&right.participant_fragment_ids)
        });
        result.feasible_plans.dedup();
        let first_outputs = result.feasible_plans[0]
            .outputs
            .iter()
            .map(|output| (output.shard_index, output.recomputed_digest.clone()))
            .collect::<Vec<_>>();
        let all_same = result.feasible_plans.iter().all(|plan| {
            plan.outputs
                .iter()
                .map(|output| (output.shard_index, output.recomputed_digest.clone()))
                .collect::<Vec<_>>()
                == first_outputs
        });
        result.status = if all_same {
            "reconstructed"
        } else {
            "ambiguous"
        };
    }
    result
}

fn enumerate_participants(
    occupied: &[usize],
    needed: usize,
    start: usize,
    current: &mut Vec<usize>,
    output: &mut Vec<Vec<usize>>,
) {
    if current.len() == needed {
        output.push(current.clone());
        return;
    }
    for index in start..occupied.len() {
        current.push(index);
        enumerate_participants(occupied, needed, index + 1, current, output);
        current.pop();
    }
}

pub mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        hex::decode(value.trim_start_matches("0x")).map_err(serde::de::Error::custom)
    }
}
