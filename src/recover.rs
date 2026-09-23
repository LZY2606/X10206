//! 候选枚举：在 generation、manifest 摘要与 stripe 约束下枚举可行重建集合。
//! 排序完全确定，搜索次数受 budget 限制。
use crate::ec::{self, EcParams};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

pub const DEFAULT_BUDGET: usize = 4096;

#[derive(Clone, Debug)]
pub struct ShardCandidate {
    pub index: u32,
    pub generation: u64,
    pub sources: Vec<String>,
    pub digest: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Excluded {
    pub index: u32,
    pub generation: u64,
    pub sources: Vec<String>,
    pub digest: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct ShardRef {
    pub index: u32,
    pub generation: u64,
    pub sources: Vec<String>,
    pub digest: String,
}

#[derive(Clone, Debug)]
pub struct Reconstruction {
    pub result_digest: String,
    pub recomputed: BTreeMap<u32, String>,
    pub sets: Vec<Vec<ShardRef>>,
    pub data: Vec<u8>,
    pub shards: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub enum StripeStatus {
    Recovered,
    Ambiguous,
    Unrecoverable,
}

#[derive(Clone, Debug)]
pub struct StripeReport {
    pub stripe: u32,
    pub status: StripeStatus,
    pub attempts: usize,
    pub budget_exhausted: bool,
    pub reused: bool,
    pub committed: bool,
    pub note: Option<String>,
    pub excluded: Vec<Excluded>,
    pub reconstructions: Vec<Reconstruction>,
}

impl StripeReport {
    pub fn reused(stripe: u32, digest: &str) -> Self {
        StripeReport {
            stripe,
            status: StripeStatus::Recovered,
            attempts: 0,
            budget_exhausted: false,
            reused: true,
            committed: true,
            note: Some(format!("复用已提交 stripe（摘要 {}）", digest)),
            excluded: Vec::new(),
            reconstructions: Vec::new(),
        }
    }
}

fn combinations(indices: &[u32], k: usize) -> Vec<Vec<u32>> {
    fn rec(indices: &[u32], start: usize, k: usize, cur: &mut Vec<u32>, out: &mut Vec<Vec<u32>>) {
        if cur.len() == k {
            out.push(cur.clone());
            return;
        }
        for i in start..indices.len() {
            cur.push(indices[i]);
            rec(indices, i + 1, k, cur, out);
            cur.pop();
        }
    }
    let mut out = Vec::new();
    if indices.len() >= k {
        rec(indices, 0, k, &mut Vec::new(), &mut out);
    }
    out
}

/// 枚举一个 stripe 的所有可行重建。
pub fn enumerate_stripe(
    params: &EcParams,
    shard_len: usize,
    stripe: u32,
    candidates: &[ShardCandidate],
    manifest: &BTreeMap<u32, String>,
    budget: usize,
) -> StripeReport {
    let mut excluded: Vec<Excluded> = Vec::new();
    let mut by_index: BTreeMap<u32, Vec<&ShardCandidate>> = BTreeMap::new();
    for c in candidates {
        if c.bytes.len() != shard_len {
            excluded.push(Excluded {
                index: c.index,
                generation: c.generation,
                sources: c.sources.clone(),
                digest: c.digest.clone(),
                reason: format!("长度 {} 与 manifest 声明的 {} 不符", c.bytes.len(), shard_len),
            });
            continue;
        }
        if let Some(expect) = manifest.get(&c.index) {
            if expect != &c.digest {
                excluded.push(Excluded {
                    index: c.index,
                    generation: c.generation,
                    sources: c.sources.clone(),
                    digest: c.digest.clone(),
                    reason: "摘要与 manifest 不符（疑似损坏/串代）".to_string(),
                });
                continue;
            }
        }
        by_index.entry(c.index).or_default().push(c);
    }
    // 确定性排序：generation 降序、摘要升序、来源升序。
    for list in by_index.values_mut() {
        list.sort_by(|a, b| {
            b.generation
                .cmp(&a.generation)
                .then(a.digest.cmp(&b.digest))
                .then(a.sources.cmp(&b.sources))
        });
    }
    let indices: Vec<u32> = by_index.keys().copied().collect();
    let mut attempts = 0usize;
    let mut budget_exhausted = false;
    let mut results: BTreeMap<String, Reconstruction> = BTreeMap::new();

    'outer: for combo in combinations(&indices, params.k) {
        // 同一集合内 generation 必须一致：取各编号共同拥有的 generation。
        let mut common: BTreeSet<u64> = by_index[&combo[0]].iter().map(|c| c.generation).collect();
        for idx in &combo[1..] {
            let gens: BTreeSet<u64> = by_index[idx].iter().map(|c| c.generation).collect();
            common = common.intersection(&gens).copied().collect();
        }
        for g in common.into_iter().rev() {
            let pools: Vec<Vec<&ShardCandidate>> = combo
                .iter()
                .map(|i| {
                    by_index[i]
                        .iter()
                        .copied()
                        .filter(|c| c.generation == g)
                        .collect()
                })
                .collect();
            // 笛卡尔积，确定性顺序；总量做硬上限保护。
            let mut choices: Vec<Vec<&ShardCandidate>> = vec![Vec::new()];
            for pool in &pools {
                let mut next = Vec::new();
                for prefix in &choices {
                    for c in pool {
                        let mut v = prefix.clone();
                        v.push(*c);
                        next.push(v);
                    }
                }
                next.truncate(budget.saturating_mul(2).max(16));
                choices = next;
            }
            for choice in choices {
                if attempts >= budget {
                    budget_exhausted = true;
                    break 'outer;
                }
                attempts += 1;
                let shards: Vec<(usize, Vec<u8>)> = combo
                    .iter()
                    .zip(choice.iter())
                    .map(|(i, c)| (*i as usize, c.bytes.clone()))
                    .collect();
                let Some(full) = ec::decode(params, &shards) else {
                    continue;
                };
                let mut recomputed: BTreeMap<u32, String> = BTreeMap::new();
                let mut ok = true;
                for (idx, shard) in full.iter().enumerate() {
                    let d = sha256_hex(shard);
                    if let Some(expect) = manifest.get(&(idx as u32)) {
                        if expect != &d {
                            ok = false;
                            break;
                        }
                    }
                    recomputed.insert(idx as u32, d);
                }
                if !ok {
                    continue;
                }
                let data: Vec<u8> = full[..params.k].concat();
                let rd = sha256_hex(&data);
                let set: Vec<ShardRef> = combo
                    .iter()
                    .zip(choice.iter())
                    .map(|(i, c)| ShardRef {
                        index: *i,
                        generation: c.generation,
                        sources: c.sources.clone(),
                        digest: c.digest.clone(),
                    })
                    .collect();
                results
                    .entry(rd.clone())
                    .and_modify(|r: &mut Reconstruction| r.sets.push(set.clone()))
                    .or_insert(Reconstruction {
                        result_digest: rd,
                        recomputed,
                        sets: vec![set],
                        data,
                        shards: full,
                    });
            }
        }
    }

    let reconstructions: Vec<Reconstruction> = results.into_values().collect();
    let status = match reconstructions.len() {
        0 => StripeStatus::Unrecoverable,
        1 => StripeStatus::Recovered,
        _ => StripeStatus::Ambiguous,
    };
    StripeReport {
        stripe,
        status,
        attempts,
        budget_exhausted,
        reused: false,
        committed: false,
        note: None,
        excluded,
        reconstructions,
    }
}
