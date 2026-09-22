//! 可行集合枚举引擎：不采用先到先得；在 generation、对象摘要与 stripe 约束下
//! 确定性枚举候选组合，保留全部可行重建并记录被排除的损坏证据。

use crate::coding::Coding;
use crate::model::*;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const DEFAULT_STRIPE_BUDGET: usize = 256;
pub const DEFAULT_OBJECT_BUDGET: usize = 1024;

#[derive(Clone)]
struct Cand {
    fragment_id: String,
    generation: u64,
    source: String,
    bytes: Vec<u8>,
    state: DigestState,
    digest: String,
    claimed: Option<String>,
}

#[derive(Clone)]
struct Combo {
    /// shard 编号 -> 选中候选。
    picks: BTreeMap<usize, Cand>,
    generations: BTreeSet<u64>,
    mixed: bool,
}

pub struct Engine {
    coding: Coding,
    stripe_budget: usize,
}

impl Engine {
    pub fn new(manifest: &Manifest) -> Result<Engine, String> {
        let field = manifest.field()?;
        manifest.codec()?;
        let coding = Coding::new(field, manifest.k, manifest.m)?;
        Ok(Engine {
            coding,
            stripe_budget: DEFAULT_STRIPE_BUDGET,
        })
    }

    pub fn with_stripe_budget(mut self, budget: usize) -> Self {
        self.stripe_budget = budget;
        self
    }

    pub fn k(&self) -> usize {
        self.coding.k
    }
    pub fn m(&self) -> usize {
        self.coding.m
    }
    pub fn n(&self) -> usize {
        self.coding.n()
    }

    /// 分析单个 stripe。
    pub fn analyze_stripe(
        &self,
        object_id: &str,
        stripe: usize,
        expected_len: usize,
        frags: &[FragmentInput],
        isolated_sources: &BTreeSet<String>,
    ) -> StripeAnalysis {
        let mut global_excluded: Vec<ExcludedEvidence> = Vec::new();
        let mut present: BTreeSet<usize> = BTreeSet::new();

        // 按 shard 编号分组候选。
        let mut by_shard: BTreeMap<usize, Vec<Cand>> = BTreeMap::new();
        for f in frags {
            present.insert(f.shard);
            let recomputed = sha256_hex(&f.bytes);
            let state = match &f.claimed_digest {
                None => DigestState::NoDigest,
                Some(claimed) => {
                    if claimed.eq_ignore_ascii_case(&recomputed) {
                        DigestState::Verified
                    } else {
                        DigestState::DigestMismatch
                    }
                }
            };
            if f.shard >= self.coding.n() {
                global_excluded.push(evidence(
                    f,
                    ExcludeReason::ShardOutOfRange,
                    format!("shard 编号 {} 超出 0..{}", f.shard, self.coding.n() - 1),
                    recomputed,
                ));
                continue;
            }
            if isolated_sources.contains(&f.source) {
                global_excluded.push(evidence(
                    f,
                    ExcludeReason::SourceIsolated,
                    format!("来源 {} 已被人工隔离", f.source),
                    recomputed,
                ));
                continue;
            }
            if f.bytes.len() != expected_len {
                global_excluded.push(evidence(
                    f,
                    ExcludeReason::LengthMismatch,
                    format!(
                        "实际长度 {} 与 manifest stripe_length {} 不符",
                        f.bytes.len(),
                        expected_len
                    ),
                    recomputed,
                ));
                continue;
            }
            if state == DigestState::DigestMismatch {
                global_excluded.push(evidence(
                    f,
                    ExcludeReason::DigestMismatch,
                    format!(
                        "重算摘要 {} 与登记摘要 {} 不符（疑似位翻转/损坏）",
                        recomputed,
                        f.claimed_digest.clone().unwrap_or_default()
                    ),
                    recomputed,
                ));
                continue;
            }
            by_shard.entry(f.shard).or_default().push(Cand {
                fragment_id: f.fragment_id.clone(),
                generation: f.generation,
                source: f.source.clone(),
                bytes: f.bytes.clone(),
                state,
                digest: recomputed,
                claimed: f.claimed_digest.clone(),
            });
        }

        // 每个 shard 编号的候选确定性排序：
        // 已验证优先于未验证；generation 新者优先；fragment_id 字典序兜底。
        for cands in by_shard.values_mut() {
            cands.sort_by(|a, b| {
                let av = a.state == DigestState::Verified;
                let bv = b.state == DigestState::Verified;
                bv.cmp(&av)
                    .then(b.generation.cmp(&a.generation))
                    .then(a.fragment_id.cmp(&b.fragment_id))
            });
            // 字节完全相同的候选去重（保留信息最完整的一个）。
            cands.dedup_by(|a, b| a.bytes == b.bytes);
        }

        // 出现在候选中的 generation（降序）。
        let gens: BTreeSet<u64> = by_shard
            .values()
            .flatten()
            .map(|c| c.generation)
            .collect();
        let mut gen_desc: Vec<u64> = gens.iter().rev().copied().collect();
        if gen_desc.is_empty() {
            gen_desc.push(0);
        }

        // 枚举所有 k 元 shard 编号子集（按编号升序字典序），并对每个编号展开其全部候选。
        // 第一轮只接受纯 generation；若没有任何纯 generation 组合达到 k，第二轮允许混杂。
        let allow_mixed_rounds: [bool; 2] = [false, true];
        let mut combos: Vec<Combo> = Vec::new();
        let mut truncated = false;

        let indexes: Vec<usize> = by_shard.keys().copied().collect();
        for (round, allow_mixed) in allow_mixed_rounds.into_iter().enumerate() {
            if combos.len() >= self.stripe_budget {
                truncated = true;
                break;
            }
            // 第二轮仅在第一轮没有产出任何组合时进行。
            if round == 1 && !combos.is_empty() {
                break;
            }
            let mut chosen = vec![0usize; self.coding.k];
            let mut stack: Vec<(usize, usize)> = vec![(0, 0)];
            'subsets: while let Some((depth, start_idx)) = stack.pop() {
                if combos.len() >= self.stripe_budget {
                    truncated = true;
                    break 'subsets;
                }
                if depth == self.coding.k {
                    // 对选中编号收集允许的候选列表（受 generation 约束）。
                    let selected_indexes: Vec<usize> =
                        chosen.iter().map(|&i| indexes[i]).collect();
                    let options: Vec<&Vec<Cand>> = selected_indexes
                        .iter()
                        .map(|idx| {
                            let cands = &by_shard[idx];
                            if allow_mixed {
                                cands
                            } else {
                                // 纯 generation：候选必须共享同一 generation；
                                // 为每个出现过的 generation 各产出一组。
                                cands
                            }
                        })
                        .collect();

                    if allow_mixed {
                        // 笛卡尔展开候选（受预算限制）。
                        self.expand_options(&options, &mut |picks_flat: &[&Cand]| {
                            if combos.len() >= self.stripe_budget {
                                truncated = true;
                                return;
                            }
                            let mut picks = BTreeMap::new();
                            let mut gens = BTreeSet::new();
                            for (i, c) in picks_flat.iter().enumerate() {
                                picks.insert(selected_indexes[i], (*c).clone());
                                gens.insert(c.generation);
                            }
                            if !combos
                                .iter()
                                .any(|e| same_picks(&e.picks, &picks))
                            {
                                combos.push(Combo {
                                    picks,
                                    generations: gens,
                                    mixed: false,
                                });
                            }
                        });
                    } else {
                        // 纯 generation：找出这些编号上共同存在的 generation 集合。
                        let mut common: Option<BTreeSet<u64>> = None;
                        for cands in &options {
                            let gs: BTreeSet<u64> =
                                cands.iter().map(|c| c.generation).collect();
                            common = Some(match common {
                                None => gs,
                                Some(prev) => prev.intersection(&gs).copied().collect(),
                            });
                        }
                        if let Some(gs) = common {
                            // generation 新者优先（降序）。
                            let mut gs_desc: Vec<u64> = gs.iter().rev().copied().collect();
                            gs_desc.sort_by(|a, b| b.cmp(a));
                            for g in gs_desc {
                                let filtered: Vec<Vec<&Cand>> = options
                                    .iter()
                                    .map(|cands| {
                                        cands.iter().filter(|c| c.generation == g).collect()
                                    })
                                    .collect();
                                                        self.expand_options_refs(
                                    &filtered,
                                    &mut |picks_flat: &[&Cand]| {
                                        if combos.len() >= self.stripe_budget {
                                            truncated = true;
                                            return;
                                        }
                                        let mut picks = BTreeMap::new();
                                        let mut gens = BTreeSet::new();
                                        for (i, c) in picks_flat.iter().enumerate() {
                                            picks.insert(selected_indexes[i], (*c).clone());
                                            gens.insert(c.generation);
                                        }
                                        let dup = combos.iter().any(|e| same_picks(&e.picks, &picks));
                                        if !dup {
                                            combos.push(Combo { picks, generations: gens, mixed: false });
                                        }
                                    },
                                );
                                if truncated {
                                    break 'subsets;
                                }
                            }
                        }
                    }
                    continue;
                }
                let remaining = self.coding.k - depth;
                if indexes.len() < remaining || start_idx > indexes.len() - remaining {
                    continue;
                }
                let last_start = indexes.len() - remaining;
                if start_idx <= last_start {
                    stack.push((depth, start_idx + 1));
                    chosen[depth] = start_idx;
                    stack.push((depth + 1, start_idx + 1));
                }
            }
        }

        // 第二轮（允许混杂）时标记 mixed。
        for c in combos.iter_mut() {
            c.mixed = c.generations.len() > 1;
        }

        // 对每个组合执行重建 + 冗余核对。
        let mut solutions: BTreeMap<String, StripeSolution> = BTreeMap::new();
        if combos.len() > self.stripe_budget {
            truncated = true;
        }
        combos.truncate(self.stripe_budget);

        for combo in combos {
            let result = self.eval_combo(&combo, &by_shard, stripe);
            match result {
                Ok(sol) => {
                    let id = sol.solution_id.clone();
                    match solutions.get_mut(&id) {
                        Some(existing) => {
                            existing.equivalent_combos += 1;
                            for p in sol.participants {
                                if !existing.participants.iter().any(|x| x.fragment_id == p.fragment_id) {
                                    existing.participants.push(p);
                                }
                            }
                            for e in sol.excluded {
                                if !existing.excluded.iter().any(|x| x.fragment_id == e.fragment_id && x.reason == e.reason) {
                                    existing.excluded.push(e);
                                }
                            }
                            if sol.mixed_generation {
                                existing.mixed_generation = true;
                            }
                        }
                        None => {
                            let mut sol = sol;
                            sol.truncated_by_budget = truncated;
                            solutions.insert(id, sol);
                        }
                    }
                }
                Err(evs) => {
                    // 组合被"组合外、同代已验证冗余"否决时，只说明该组合不可行，
                    // 不代表该已验证块损坏；这类证据不提升为全局损坏证据。
                    for e in evs {
                        let is_corrupt_input = !matches!(
                            e.reason,
                            ExcludeReason::RedundantInconsistency
                        ) || e.claimed_digest.is_some() == false;
                        let _ = is_corrupt_input;
                        // 仅保留矩阵失败等结构性证据；已验证块的冗余矛盾不写全局。
                        let structural = e.fragment_id == "(matrix)";
                        if structural
                            && !global_excluded
                                .iter()
                                .any(|x| x.fragment_id == e.fragment_id && x.reason == e.reason)
                        {
                            global_excluded.push(e);
                        }
                    }
                }
            }
        }
        if truncated {
            for (idx, cands) in by_shard.iter() {
                for c in cands {
                    let used = solutions.values().any(|sol| {
                        sol.participants.iter().any(|p| p.fragment_id == c.fragment_id)
                            || sol.excluded.iter().any(|e| e.fragment_id == c.fragment_id)
                    });
                    if !used {
                        global_excluded.push(cand_evidence(
                            c,
                            *idx,
                            ExcludeReason::SearchBudget,
                            format!("枚举组合达到搜索预算 {}，未参与任何可行解", self.stripe_budget),
                        ));
                    }
                }
            }
        }

        // 可行解确定性排序：纯 generation 优先、generation 更新优先、参与编号少优先、id 兜底。
        let mut sol_list: Vec<StripeSolution> = solutions.into_values().collect();
        sol_list.sort_by(|a, b| {
            a.mixed_generation
                .cmp(&b.mixed_generation)
                .then(b.generations.iter().rev().cmp(a.generations.iter().rev()))
                .then(a.participants.len().cmp(&b.participants.len()))
                .then(a.solution_id.cmp(&b.solution_id))
        });

        // 健康：唯一内容解、无任何损坏/冲突证据、参与者全部摘要验证、无 generation 混杂。
        let clean = |sol: &StripeSolution| {
            !sol.mixed_generation
                && sol.participants.iter().all(|p| p.digest_state == DigestState::Verified)
                && !sol.excluded.iter().any(|e| {
                    matches!(
                        e.reason,
                        ExcludeReason::RedundantInconsistency | ExcludeReason::DigestMismatch
                    )
                })
        };
        let health = if sol_list.is_empty() {
            StripeHealth::BelowThreshold
        } else if sol_list.len() == 1 && clean(&sol_list[0]) {
            StripeHealth::Healthy
        } else {
            StripeHealth::Recoverable
        };

        StripeAnalysis {
            object_id: object_id.to_string(),
            stripe,
            health,
            solutions: sol_list,
            global_excluded,
            present_shards: present.into_iter().collect(),
            expected_length: expected_len,
            budget: self.stripe_budget,
        }
    }

    /// 对每个编号的候选列表做笛卡尔积，回调给出 &Cand 选择序列。
    fn expand_options(&self, options: &[&Vec<Cand>], emit: &mut dyn FnMut(&[&Cand])) {
        let mut picked: Vec<&Cand> = Vec::with_capacity(options.len());
        self.expand_options_walk(options, 0, &mut picked, emit);
    }

    fn expand_options_refs(&self, options: &[Vec<&Cand>], emit: &mut dyn FnMut(&[&Cand])) {
        let mut picked: Vec<&Cand> = Vec::with_capacity(options.len());
        self.expand_options_refs_walk(options, 0, &mut picked, emit);
    }

    fn expand_options_walk<'a>(
        &self,
        options: &[&'a Vec<Cand>],
        depth: usize,
        picked: &mut Vec<&'a Cand>,
        emit: &mut dyn FnMut(&[&'a Cand]),
    ) {
        if depth == options.len() {
            emit(picked);
            return;
        }
        for c in options[depth] {
            picked.push(c);
            self.expand_options_walk(options, depth + 1, picked, emit);
            picked.pop();
        }
    }

    fn expand_options_refs_walk<'a>(
        &self,
        options: &[Vec<&'a Cand>],
        depth: usize,
        picked: &mut Vec<&'a Cand>,
        emit: &mut dyn FnMut(&[&'a Cand]),
    ) {
        if depth == options.len() {
            emit(picked);
            return;
        }
        for c in &options[depth] {
            picked.push(c);
            self.expand_options_refs_walk(options, depth + 1, picked, emit);
            picked.pop();
        }
    }

    /// 对一个组合重建，并与组合外候选做冗余一致性核对。
    /// - 重建失败 / 组合内不自洽 => Err（组合不可行）；
    /// - 与未验证（NoDigest）候选冲突 => 该候选作为损坏证据排除，组合仍可行；
    /// - 与同编号"已验证"候选冲突 => 无法本地裁定，形成歧义：两个内容分支都保留，
    ///   冲突候选记入该解证据，最终由对象摘要跨 stripe 裁定；
    /// - 与不同 generation 的已验证候选冲突（部分写）=> 非致命，记录混杂证据。
    fn eval_combo(
        &self,
        combo: &Combo,
        by_shard: &BTreeMap<usize, Vec<Cand>>,
        stripe: usize,
    ) -> Result<StripeSolution, Vec<ExcludedEvidence>> {
        let avail: Vec<(usize, Vec<u8>)> = combo
            .picks
            .iter()
            .map(|(idx, c)| (*idx, c.bytes.clone()))
            .collect();
        let reconstructed = self.coding.reconstruct_bytes(&avail).map_err(|e| {
            vec![ExcludedEvidence {
                fragment_id: "(matrix)".into(),
                shard: usize::MAX,
                generation: 0,
                source: "-".into(),
                reason: ExcludeReason::RedundantInconsistency,
                detail: format!("stripe {} 重建失败: {}", stripe, e),
                recomputed_digest: String::new(),
                claimed_digest: None,
            }]
        })?;

        let mut fatal = Vec::new();
        let mut ambiguous = Vec::new();
        let mut participants: Vec<Participant> = combo
            .picks
            .iter()
            .map(|(shard, c)| Participant {
                fragment_id: c.fragment_id.clone(),
                shard: *shard,
                generation: c.generation,
                source: c.source.clone(),
                digest_state: c.state.clone(),
                recomputed_digest: c.digest.clone(),
            })
            .collect();

        // 组合内自洽性（恒等检查，防止理论外的异常）。
        for (idx, c) in combo.picks.iter() {
            if reconstructed[*idx] != c.bytes {
                fatal.push(cand_evidence(
                    c,
                    *idx,
                    ExcludeReason::RedundantInconsistency,
                    "参与块与重建结果不自洽".into(),
                ));
            }
        }
        // 组合外的所有同编号候选。
        for (idx, cands) in by_shard.iter() {
            for c in cands {
                let used = combo.picks.get(idx).map(|u| u.fragment_id == c.fragment_id).unwrap_or(false);
                if used || reconstructed[*idx] == c.bytes {
                    continue;
                }
                let ev = cand_evidence(
                    c,
                    *idx,
                    ExcludeReason::RedundantInconsistency,
                    format!(
                        "冗余核对冲突：重建 shard {} 摘要 {}，候选 {} 摘要 {}（generation {}）",
                        idx,
                        sha256_hex(&reconstructed[*idx]),
                        c.fragment_id,
                        c.digest,
                        c.generation
                    ),
                );
                // 该候选是否属于本组合的同一 generation 集合。
                let same_gen = combo.generations.contains(&c.generation);
                // 同编号的另一个内容候选 => 歧义（无论是否同代，分别走自己的组合）。
                let alt_content_branch = combo.picks.contains_key(idx);
                match c.state {
                    DigestState::NoDigest | DigestState::DigestMismatch => {
                        // 无摘要/已知摘要损坏：作为损坏证据排除，不影响本解可行性。
                        ambiguous.push(ev);
                    }
                    DigestState::Verified if alt_content_branch => {
                        // 同编号的另一个已验证内容候选：真歧义，两个内容分支都保留。
                        ambiguous.push(ev);
                    }
                    DigestState::Verified if same_gen => {
                        // 组合外、同代已验证冗余与重建矛盾 => 组合不自洽，判死。
                        fatal.push(ev);
                    }
                    DigestState::Verified => {
                        // 其它 generation 的已验证块：部分写的旧/新代证据，非致命。
                        ambiguous.push(ExcludedEvidence {
                            reason: ExcludeReason::GenerationMixed,
                            ..ev
                        });
                    }
                }
            }
        }

        if !fatal.is_empty() {
            return Err(fatal);
        }

        let mut gens: Vec<u64> = combo.generations.iter().copied().collect();
        gens.sort_unstable();
        let recomputed_shard_digests: Vec<String> =
            reconstructed.iter().map(|s| sha256_hex(s)).collect();

        // 解身份仅由"重建内容"决定（不同碎片路径得到相同字节 => 同一个解）。
        let mut hasher = Sha256::new();
        for d in &recomputed_shard_digests {
            hasher.update(d.as_bytes());
        }
        hasher.update(b"|");
        for g in &gens {
            hasher.update(g.to_le_bytes());
        }
        let solution_id = hex::encode(hasher.finalize());

        // 只有组合自身跨了多个 generation 才算混杂；存在被取代的旧代/新代证据不算。
        let mixed = combo.generations.len() > 1;

        // 参与者补充：与重建结果一致的组合外候选也算"可参与计算/冗余佐证"。
        for (idx, cands) in by_shard.iter() {
            for c in cands {
                let already = participants.iter().any(|p| p.fragment_id == c.fragment_id);
                if !already && reconstructed[*idx] == c.bytes {
                    participants.push(Participant {
                        fragment_id: c.fragment_id.clone(),
                        shard: *idx,
                        generation: c.generation,
                        source: c.source.clone(),
                        digest_state: c.state.clone(),
                        recomputed_digest: c.digest.clone(),
                    });
                }
            }
        }
        participants.sort_by(|a, b| {
            a.shard
                .cmp(&b.shard)
                .then(a.fragment_id.cmp(&b.fragment_id))
        });

        Ok(StripeSolution {
            solution_id,
            participants,
            excluded: ambiguous,
            generations: gens,
            mixed_generation: mixed,
            shards: reconstructed,
            recomputed_shard_digests,
            equivalent_combos: 1,
            truncated_by_budget: false,
        })
    }
}

fn same_picks(a: &BTreeMap<usize, Cand>, b: &BTreeMap<usize, Cand>) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .all(|((ai, ac), (bi, bc))| ai == bi && ac.fragment_id == bc.fragment_id)
}

fn evidence(
    f: &FragmentInput,
    reason: ExcludeReason,
    detail: String,
    recomputed: String,
) -> ExcludedEvidence {
    ExcludedEvidence {
        fragment_id: f.fragment_id.clone(),
        shard: f.shard,
        generation: f.generation,
        source: f.source.clone(),
        reason,
        detail,
        recomputed_digest: recomputed,
        claimed_digest: f.claimed_digest.clone(),
    }
}

fn cand_evidence(
    c: &Cand,
    shard: usize,
    reason: ExcludeReason,
    detail: String,
) -> ExcludedEvidence {
    ExcludedEvidence {
        fragment_id: c.fragment_id.clone(),
        shard,
        generation: c.generation,
        source: c.source.clone(),
        reason,
        detail,
        recomputed_digest: c.digest.clone(),
        claimed_digest: c.claimed.clone(),
    }
}

/// 跨 stripe 组装对象结果：在预算内按确定性顺序枚举 stripe 解的笛卡尔积。
/// 若 manifest 提供对象摘要，只保留匹配结果；否则保留所有不同结果。
pub fn assemble_outcomes(
    manifest: &Manifest,
    analyses: &[StripeAnalysis],
    object_budget: usize,
) -> Result<Vec<ObjectOutcome>, String> {
    if analyses.len() != manifest.stripe_count {
        return Err(format!(
            "分析 stripe 数 {} 与 manifest.stripe_count {} 不符",
            analyses.len(),
            manifest.stripe_count
        ));
    }
    for a in analyses {
        if a.solutions.is_empty() {
            return Err(format!("stripe {} 没有可行解，无法组装对象", a.stripe));
        }
    }

    let mut outcomes: BTreeMap<String, ObjectOutcome> = BTreeMap::new();
    let mut counter = 0usize;
    let mut truncated = false;
    let mut idx = vec![0usize; analyses.len()];

    loop {
        if counter >= object_budget {
            truncated = true;
            break;
        }
        let mut bytes = Vec::new();
        let mut stripe_solutions = Vec::new();
        let mut gens_all = BTreeSet::new();
        let mut mixed = false;
        for (s, a) in analyses.iter().enumerate() {
            let sol = &a.solutions[idx[s]];
            // 对象字节 = 每个 stripe 前 k 个 data shard 顺序拼接。
            for shard_bytes in sol.shards.iter().take(manifest.k) {
                bytes.extend_from_slice(shard_bytes);
            }
            stripe_solutions.push(sol.solution_id.clone());
            for g in &sol.generations {
                gens_all.insert(*g);
            }
            mixed |= sol.mixed_generation;
        }
        if let Some(limit) = manifest.object_length {
            if bytes.len() < limit {
                return Err(format!(
                    "重组对象长度 {} 小于 manifest object_length {}",
                    bytes.len(),
                    limit
                ));
            }
            bytes.truncate(limit);
        }
        let digest = sha256_hex(&bytes);
        let matches_manifest = manifest
            .object_digest
            .as_ref()
            .map(|d| d.eq_ignore_ascii_case(&digest));
        let keep = matches_manifest.unwrap_or(true);
        if keep {
            let key = digest.clone();
            let mut generations: Vec<u64> = gens_all.iter().rev().copied().collect();
            generations.sort_unstable();
            let diff = if outcomes.is_empty() {
                Vec::new()
            } else {
                analyses
                    .iter()
                    .enumerate()
                    .filter_map(|(s, a)| {
                        let first_id = &a.solutions[0].solution_id;
                        if stripe_solutions[s] != *first_id {
                            Some(s)
                        } else {
                            None
                        }
                    })
                    .collect()
            };
            outcomes
                .entry(key)
                .and_modify(|o: &mut ObjectOutcome| {
                    // 同一字节结果可能由不同碎片路径得到，差异 stripe 取并集。
                    for d in &diff {
                        if !o.diff_stripes_vs_first.contains(d) {
                            o.diff_stripes_vs_first.push(*d);
                        }
                    }
                })
                .or_insert(ObjectOutcome {
                    outcome_id: digest.clone(),
                    stripe_solutions,
                    generations,
                    mixed_generation: mixed,
                    object_digest: digest,
                    digest_matches_manifest: matches_manifest,
                    diff_stripes_vs_first: diff,
                    bytes,
                });
        }
        counter += 1;

        // 下一个笛卡尔积索引（字典序）。
        let mut carry = analyses.len();
        loop {
            if carry == 0 {
                carry = usize::MAX;
                break;
            }
            carry -= 1;
            idx[carry] += 1;
            if idx[carry] < analyses[carry].solutions.len() {
                for j in (carry + 1)..analyses.len() {
                    idx[j] = 0;
                }
                break;
            }
            idx[carry] = 0;
        }
        if carry == usize::MAX {
            break;
        }
    }

    let mut list: Vec<ObjectOutcome> = outcomes.into_values().collect();
    // 确定性排序：与"每个 stripe 的首选解"完全一致的结果排第一。
    list.sort_by(|a, b| {
        let ap = a
            .stripe_solutions
            .iter()
            .zip(analyses.iter())
            .filter(|(sid, an)| **sid != an.solutions[0].solution_id)
            .count();
        let bp = b
            .stripe_solutions
            .iter()
            .zip(analyses.iter())
            .filter(|(sid, an)| **sid != an.solutions[0].solution_id)
            .count();
        ap.cmp(&bp).then(a.outcome_id.cmp(&b.outcome_id))
    });
    let _ = truncated;
    if list.is_empty() {
        return Err("枚举结束后没有匹配对象摘要的可行组装".into());
    }
    Ok(list)
}
