//! 恢复引擎：在 generation / 长度 / stripe 约束下枚举可行 shard 集合，
//! 而不是"先到先得"。枚举顺序完全确定，受搜索预算约束。
//!
//! 判定模型：
//! * 枚举所有"k 个不同 shard 位置各取 1 个候选"的子集并重建。
//! * 对每个重建，核对所有未入选位置的候选：一致集合 = 参与块 + 一致块；
//!   与重建矛盾的未入选块即"被排除的损坏证据"。
//! * 含坏块的子集只能与更少的块自洽；因此可行解 = 一致块数最大的那些重建。
//!   最大一致数出现多个不同输出 => 多个可行答案（ambiguous，由对象摘要裁决）。
//!   恰好 k 块、无冗余时无法证伪坏块，天然产生多答案 —— 这正是设计预期。
//! * strict 只用最新代、长度正确、摘要完好的候选 => trusted；
//!   fallback 放宽到较早代（混代）=> degraded，仅保留为低可信答案。

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::db::{Storage, StripeRow};
use crate::gf::Gf256;
use crate::types::{lookup_params, SolutionTier};

#[derive(Debug, Clone, Serialize)]
pub struct CandidateInfo {
    pub fragment_id: i64,
    pub shard: u32,
    pub generation: i64,
    pub length: i64,
    pub digest: String,
    pub health: String,
    pub source_id: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SolutionInfo {
    pub tier: SolutionTier,
    /// 参与块代次：同代为该代，混代为 -1。
    pub generation: i64,
    pub output_digest: String,
    /// 参与计算的 fragment id（按 shard 位置顺序）。
    pub participant_ids: Vec<i64>,
    /// 与该重建矛盾、被排除的损坏证据 fragment id。
    pub excluded_ids: Vec<i64>,
    /// 与该重建自洽的块数（参与块 + 一致块），用于最大一致性裁决。
    pub consistent_count: usize,
    pub output: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct EnumerationResult {
    pub combos: u64,
    pub budget_exceeded: bool,
    /// 全部不同输出的解（不止成功状态）。
    pub solutions: Vec<SolutionInfo>,
    /// 最终可行解（最高 tier 下一致块数最大者，可能多个）。
    pub winners: Vec<SolutionInfo>,
    pub stale_ids: BTreeSet<i64>,
    pub candidates: Vec<CandidateInfo>,
    pub present_positions: usize,
    pub latest_positions: usize,
}

#[derive(Debug, Clone)]
struct Cand {
    fragment_id: i64,
    row: u32,
    gen: i64,
    bytes: Vec<u8>,
}

pub fn enumerate_stripe(
    storage: &mut Storage,
    stripe: &StripeRow,
    object_db_id: i64,
    budget: u64,
) -> EnumerationResult {
    let object = storage
        .get_object(object_db_id)
        .expect("query")
        .expect("object row");
    let params = lookup_params(&object.coding_version).expect("known coding version");
    let gf = Gf256::new(params.poly);
    let (k, m) = (params.k, params.m);
    let stripe_len = params.stripe_bytes;

    let frags = storage.list_fragments(object_db_id).expect("list fragments");
    let max_gen = frags
        .iter()
        .filter(|f| f.stripe_idx == stripe.stripe_idx)
        .map(|f| f.generation)
        .max()
        .unwrap_or(0);

    let mut candidates: Vec<CandidateInfo> = Vec::new();
    let mut latest_by_row: BTreeMap<u32, Vec<Cand>> = BTreeMap::new();
    let mut all_by_row: BTreeMap<u32, Vec<Cand>> = BTreeMap::new();
    let mut stale_ids: BTreeSet<i64> = BTreeSet::new();

    for f in frags.iter().filter(|f| f.stripe_idx == stripe.stripe_idx) {
        candidates.push(CandidateInfo {
            fragment_id: f.id,
            shard: f.shard_idx as u32,
            generation: f.generation,
            length: f.actual_length,
            digest: f.digest_actual.clone(),
            health: f.health.clone(),
            source_id: f.source_id,
        });
        let digest_ok = matches!(f.health.as_str(), "intact" | "length_mismatch");
        if !digest_ok || f.shard_idx >= k as i64 + m as i64 {
            continue;
        }
        if f.generation < max_gen {
            stale_ids.insert(f.id);
        }
        if f.actual_length != stripe_len as i64 {
            continue;
        }
        let cand = Cand {
            fragment_id: f.id,
            row: f.shard_idx as u32,
            gen: f.generation,
            bytes: f.content.clone(),
        };
        all_by_row.entry(cand.row).or_default().push(cand.clone());
        if f.generation == max_gen {
            latest_by_row.entry(cand.row).or_default().push(cand);
        }
    }
    for v in latest_by_row.values_mut() {
        v.sort_by_key(|c| c.fragment_id);
    }
    for v in all_by_row.values_mut() {
        v.sort_by_key(|c| c.fragment_id);
    }

    let mut result = EnumerationResult {
        candidates,
        stale_ids,
        present_positions: all_by_row.len(),
        latest_positions: latest_by_row.len(),
        ..Default::default()
    };

    let mut combos: u64 = 0;
    let mut budget_exceeded = false;
    run_mode(
        &gf,
        k,
        m,
        stripe_len,
        &latest_by_row,
        SolutionTier::Trusted,
        budget,
        &mut combos,
        &mut budget_exceeded,
        &mut result.solutions,
    );
    result.combos = combos;
    result.budget_exceeded = budget_exceeded;

    let trusted_count = result
        .solutions
        .iter()
        .filter(|s| matches!(s.tier, SolutionTier::Trusted))
        .count();
    if trusted_count == 0 && combos < budget {
        run_mode(
            &gf,
            k,
            m,
            stripe_len,
            &all_by_row,
            SolutionTier::Degraded,
            budget.saturating_sub(combos),
            &mut combos,
            &mut budget_exceeded,
            &mut result.solutions,
        );
        result.combos = combos;
        result.budget_exceeded = budget_exceeded;
    }

    result.winners = select_winners(&result.solutions);
    result
}

/// 可行解：优先 trusted；同 tier 内只保留一致块数最大的不同输出。
fn select_winners(all: &[SolutionInfo]) -> Vec<SolutionInfo> {
    let preferred = if all.iter().any(|s| matches!(s.tier, SolutionTier::Trusted)) {
        SolutionTier::Trusted
    } else {
        SolutionTier::Degraded
    };
    let same: Vec<&SolutionInfo> = all
        .iter()
        .filter(|s| s.tier == preferred)
        .collect();
    let max_consistent = same.iter().map(|s| s.consistent_count).max().unwrap_or(0);
    same.into_iter()
        .filter(|s| s.consistent_count == max_consistent)
        .cloned()
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn run_mode(
    gf: &Gf256,
    k: u8,
    m: u8,
    stripe_len: usize,
    by_row: &BTreeMap<u32, Vec<Cand>>,
    tier: SolutionTier,
    budget: u64,
    combos: &mut u64,
    budget_exceeded: &mut bool,
    out: &mut Vec<SolutionInfo>,
) {
    let positions: Vec<u32> = by_row.keys().copied().collect();

    'outer: for position_set in k_combinations(&positions, k as usize) {
        let groups: Vec<&Vec<Cand>> = position_set.iter().map(|p| &by_row[p]).collect();
        let lens: Vec<usize> = groups.iter().map(|g| g.len()).collect();
        let mut pick = vec![0usize; groups.len()];
        let mut exhausted = groups.iter().any(|g| g.is_empty());
        while !exhausted {
            *combos += 1;
            if *combos > budget {
                *budget_exceeded = true;
                break 'outer;
            }
            let chosen: Vec<(u8, Vec<u8>)> = groups
                .iter()
                .enumerate()
                .map(|(gi, g)| (g[pick[gi]].row as u8, g[pick[gi]].bytes.clone()))
                .collect();
            let chosen_ids: Vec<i64> = groups
                .iter()
                .enumerate()
                .map(|(gi, g)| g[pick[gi]].fragment_id)
                .collect();

            if let Some(full) = gf.reconstruct(k, m, stripe_len, &chosen) {
                let data = &full[..k as usize];
                let chosen_positions: BTreeSet<u32> = position_set.iter().copied().collect();
                let mut excluded: BTreeSet<i64> = BTreeSet::new();
                let mut agreeing = 0usize;
                for (row, cands) in by_row.iter().filter(|(r, _)| !chosen_positions.contains(r)) {
                    for c in cands {
                        if gf.verify_row(k, m, data, *row as u8, &c.bytes) {
                            agreeing += 1;
                        } else {
                            excluded.insert(c.fragment_id);
                        }
                    }
                }
                let gens: Vec<i64> = groups
                    .iter()
                    .enumerate()
                    .map(|(gi, g)| g[pick[gi]].gen)
                    .collect();
                let same_gen = gens.iter().all(|g| *g == gens[0]);
                let generation = if same_gen { gens[0] } else { -1 };
                // 混代或 fallback 一律降级。
                let eff_tier = match tier {
                    SolutionTier::Trusted if same_gen => SolutionTier::Trusted,
                    _ => SolutionTier::Degraded,
                };
                let output = full[..k as usize].concat();
                let digest = crate::hashutil::sha256_hex(&output);
                let consistent_count = chosen_ids.len() + agreeing;

                // 同 (tier, 输出) 合并：更新最大一致数、并入损坏证据与代次。
                if let Some(existing) = out
                    .iter_mut()
                    .find(|s| s.tier == eff_tier && s.output_digest == digest)
                {
                    existing.consistent_count = existing.consistent_count.max(consistent_count);
                    let mut merged: BTreeSet<i64> =
                        existing.excluded_ids.iter().copied().collect();
                    merged.extend(excluded.iter().copied());
                    existing.excluded_ids = merged.into_iter().collect();
                    existing.generation = existing.generation.max(generation);
                } else {
                    out.push(SolutionInfo {
                        tier: eff_tier,
                        generation,
                        output_digest: digest,
                        participant_ids: chosen_ids,
                        excluded_ids: excluded.into_iter().collect(),
                        consistent_count,
                        output,
                    });
                }
            }

            // 多进制 odometer 递增（从最后一位开始）。
            let mut i = groups.len();
            loop {
                if i == 0 {
                    exhausted = true;
                    break;
                }
                i -= 1;
                pick[i] += 1;
                if pick[i] < lens[i] {
                    for p in &mut pick[i + 1..] {
                        *p = 0;
                    }
                    break;
                }
                pick[i] = 0;
            }
        }
    }

    // 确定排序：tier、一致数、代次、摘要。
    out.sort_by(|a, b| {
        let ta = matches!(a.tier, SolutionTier::Trusted);
        let tb = matches!(b.tier, SolutionTier::Trusted);
        tb.cmp(&ta)
            .then(b.consistent_count.cmp(&a.consistent_count))
            .then(b.generation.cmp(&a.generation))
            .then(a.output_digest.cmp(&b.output_digest))
    });
    out.dedup_by(|a, b| a.tier == b.tier && a.output_digest == b.output_digest);
}

/// 字典序 C(n, k) 组合，输入元素已排序。
pub fn k_combinations(items: &[u32], k: usize) -> Vec<Vec<u32>> {
    let mut out = Vec::new();
    if k == 0 || items.len() < k {
        return out;
    }
    let mut idx: Vec<usize> = (0..k).collect();
    loop {
        out.push(idx.iter().map(|&i| items[i]).collect());
        let mut i = k;
        let mut back_to_start = false;
        while i > 0 {
            i -= 1;
            if idx[i] + (k - i) < items.len() {
                idx[i] += 1;
                for j in i + 1..k {
                    idx[j] = idx[j - 1] + 1;
                }
                break;
            }
            if i == 0 {
                back_to_start = true;
            }
        }
        if back_to_start {
            return out;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combinations_sorted() {
        assert_eq!(
            k_combinations(&[0, 1, 2, 3], 3),
            vec![vec![0, 1, 2], vec![0, 1, 3], vec![0, 2, 3], vec![1, 2, 3]]
        );
        assert_eq!(k_combinations(&[1, 2], 3), Vec::<Vec<u32>>::new());
    }
}
