//! 恢复引擎：在 generation、对象摘要与 stripe 约束下枚举可行集合。
//!
//! 确定性规则（任何机器上结果顺序一致）：
//! - 候选排序键：(摘要正常优先, generation 升序, 接收序号升序, 内容摘要升序)；
//! - 组合按 slot 升序、每 slot 候选在 None 之前做字典序 DFS；
//! - 方案排序键：(rank 升序, 未污染优先, 输出摘要升序)；
//! - 搜索预算：默认每 stripe 10_000 个叶组合、全局 100_000 个跨 stripe 组合，
//!   耗尽则落 `budget_exhausted` 证据且该 stripe 不自动提交。

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use crate::coding::{reconstruct, verify_full};
use crate::model::{object_digest_hex, sha256_hex, EvidenceKind};
use crate::store::{ExcludedNote, PartShard, ReplicaRow, SolutionRec, Store};

pub const DEFAULT_PER_STRIPE_BUDGET: u64 = 10_000;
pub const DEFAULT_GLOBAL_BUDGET: u64 = 100_000;

#[derive(Clone, Debug)]
pub struct StripeSolutionView {
    pub db_id: i64,
    pub rank: usize,
    pub replica_ids: Vec<i64>,
    pub generation: i64,
    pub data_digests: Vec<String>,
    pub output_digest: String,
    pub tainted: bool,
    pub matches_object_digest: Option<bool>,
}

#[derive(Clone, Debug, Default)]
pub struct StripeReport {
    pub stripe: usize,
    pub candidates_total: usize,
    pub candidates_excluded: usize,
    pub combos_checked: u64,
    pub budget_exhausted: bool,
    pub solutions: Vec<StripeSolutionView>,
    pub committed: bool,
    pub reused: bool,
    pub blocked_reason: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct RecoverReport {
    pub run_id: String,
    pub stripes_total: usize,
    pub stripes_committed_new: usize,
    pub stripes_reused: usize,
    pub stripes_blocked: Vec<(usize, String)>,
    pub object_digest_matched: Option<bool>,
    pub global_combos_checked: u64,
    pub write_failure: bool,
    pub aborted: bool,
}

#[derive(Clone)]
struct Cand {
    replica: ReplicaRow,
    bytes: Vec<u8>,
    digest_ok: bool,
}

struct SlotCandidates {
    slot: usize,
    cands: Vec<Cand>,
}

struct EnumeratedStripe {
    report: StripeReport,
    // db 方案 id -> 完整 n 块网格，供跨 stripe 对象摘要校验。
    grids: HashMap<i64, Vec<Vec<u8>>>,
    // db 方案 id -> 参与候选（确定性代表组合）。
    chosen_cands: HashMap<i64, Vec<Cand>>,
    exclusions: Vec<ExcludedNote>,
}

pub struct Engine {
    pub per_stripe_budget: u64,
    pub global_budget: u64,
    pub cancel: Arc<AtomicBool>,
    abort_after_commits: AtomicU64,
}

impl Engine {
    pub fn new() -> Self {
        Engine {
            per_stripe_budget: DEFAULT_PER_STRIPE_BUDGET,
            global_budget: DEFAULT_GLOBAL_BUDGET,
            cancel: Arc::new(AtomicBool::new(false)),
            abort_after_commits: AtomicU64::new(u64::MAX),
        }
    }

    /// 测试用：成功新提交 N 个 stripe 后模拟进程中断。
    pub fn abort_after_commits(&self, n: u64) {
        self.abort_after_commits.store(n, Ordering::SeqCst);
    }

    pub fn run(&self, store: &Store, object_id: &str) -> std::io::Result<RecoverReport> {
        let obj = store
            .get_object(object_id)?
            .ok_or_else(|| std::io::Error::other(format!("未知对象 {object_id}")))?;
        let params = crate::coding::CodingParams {
            field_bits: obj.field_bits as u32,
            k: obj.k as usize,
            m: obj.m as usize,
            shard_size: obj.shard_size as usize,
        };
        let field = params.field();
        let run_id = format!("run-{}", crate::store::store_run_ts());
        store.start_run(&run_id, obj.id, self.per_stripe_budget)?;

        let quarantined: HashSet<String> =
            store.quarantined(obj.id)?.into_iter().collect();

        // 上次未完成运行 => 记录中断残留证据（临时块在 Store::open 时已清理）。
        if let Some((_, _, _, false)) = store.last_run(obj.id)? {
            store.add_evidence(
                obj.id,
                0,
                None,
                None,
                EvidenceKind::StaleTempBlock,
                "检测到上次未完成运行；临时块已清除，仅复用 provenance 与摘要完整的已提交 stripe",
                "enumeration",
            )?;
        }

        let mut report = RecoverReport {
            run_id: run_id.clone(),
            stripes_total: obj.stripes as usize,
            ..Default::default()
        };

        let mut enumerated: Vec<EnumeratedStripe> = Vec::new();
        for stripe in 0..obj.stripes as usize {
            let en = self.enumerate_stripe(
                store,
                &obj,
                &params,
                stripe,
                &quarantined,
            )?;
            report.stripes_blocked.extend(
                en.report
                    .blocked_reason
                    .clone()
                    .map(|r| (stripe, r)),
            );
            enumerated.push(en);
        }

        // 跨 stripe 对象摘要校验。
        let mut chosen_solution: Vec<Option<i64>> = vec![None; enumerated.len()];
        if let Some(obj_dig) = &obj.object_digest {
            let matched = self.resolve_by_object_digest(
                store,
                &obj,
                obj_dig,
                &enumerated,
                &mut chosen_solution,
                &mut report,
            );
            report.object_digest_matched = Some(matched);
            for (i, en) in enumerated.iter().enumerate() {
                for sol in &en.report.solutions {
                    let involved = self.solution_participates(
                        &enumerated,
                        i,
                        sol.db_id,
                        &chosen_solution,
                        matched,
                    );
                    store.set_object_match(obj.id, i, sol.db_id, involved)?;
                }
            }
        } else {
            report.object_digest_matched = None;
            for (i, en) in enumerated.iter().enumerate() {
                if en.report.solutions.len() == 1 {
                    chosen_solution[i] = Some(en.report.solutions[0].db_id);
                }
            }
        }

        let mut new_commits = 0u64;
        for (i, en) in enumerated.iter().enumerate() {
            // 复用检查：provenance 与所有块摘要必须完整。
            if let Some((committed_sol, _, _)) = store.committed_solution(obj.id, i)? {
                match store.load_committed(&obj, i) {
                    Ok(prov) if prov.output_digest
                        == en
                            .report
                            .solutions
                            .iter()
                            .find(|s| s.db_id == committed_sol)
                            .map(|s| s.output_digest.clone())
                            .unwrap_or_default() =>
                    {
                        let usable = match (obj.object_digest.as_ref(), chosen_solution[i]) {
                            (Some(_), Some(sel)) => sel == committed_sol,
                            (None, Some(_)) => true,
                            (Some(_), None) => false,
                            (None, None) => false,
                        };
                        if usable {
                            report.stripes_reused += 1;
                            continue;
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        store.add_evidence(
                            obj.id,
                            i,
                            None,
                            None,
                            EvidenceKind::StaleTempBlock,
                            &format!("已提交 stripe 摘要不完整，禁止复用: {e}"),
                            "enumeration",
                        )?;
                        store.drop_commit(obj.id, i)?;
                    }
                }
            }

            let Some(sol_id) = chosen_solution[i] else {
                if en.report.blocked_reason.is_none() && !en.report.solutions.is_empty() {
                    // 无对象摘要且多解：保留全部，交人工，绝不先到先得。
                    let msg = format!("存在 {} 个互相不同的可行重建，等待人工或对象摘要确认",
                        en.report.solutions.len());
                    report.stripes_blocked.push((i, msg));
                }
                continue;
            };

            // 无对象摘要时，唯一解若含摘要损坏候选且没有冗余校验，不自动提交。
            if obj.object_digest.is_none() {
                let sol = en.report.solutions.iter().find(|s| s.db_id == sol_id).unwrap();
                if sol.tainted && sol.rank == obj.k as usize {
                    let msg = "唯一可行解使用了摘要不符的候选且无冗余校验，暂不提交".to_string();
                    report.stripes_blocked.push((i, msg));
                    continue;
                }
            }

            let grid = &en.grids[&sol_id];
            let sol_rec = self.solution_rec(store, sol_id)?;
            let participating = en.chosen_cands[&sol_id]
                .iter()
                .map(|c| PartShard {
                    slot: c.replica.slot as usize,
                    generation: c.replica.generation,
                    source: c.replica.source.clone(),
                    digest: c.replica.digest_actual.clone(),
                    replica_id: c.replica.id,
                })
                .collect::<Vec<_>>();
            match store.commit_solution(
                &obj, i, &sol_rec, grid, &participating, &en.exclusions, &run_id,
            ) {
                Ok(_) => {
                    new_commits += 1;
                    report.stripes_committed_new += 1;
                    if new_commits >= self.abort_after_commits.load(Ordering::SeqCst) {
                        report.aborted = true;
                        break;
                    }
                    if self.cancel.load(Ordering::SeqCst) {
                        report.aborted = true;
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Other => {
                    store
                        .add_evidence(
                            obj.id,
                            i,
                            None,
                            None,
                            EvidenceKind::WriteFailure,
                            &e.to_string(),
                            "enumeration",
                        )
                        .ok();
                    report.write_failure = true;
                    break;
                }
                Err(e) => return Err(e),
            }
        }

        let total_checked: u64 =
            enumerated.iter().map(|e| e.report.combos_checked).sum::<u64>()
                + report.global_combos_checked;
        store.update_run(&run_id, total_checked, !report.aborted && !report.write_failure)?;
        Ok(report)
    }

    fn solution_rec(&self, store: &Store, sol_id: i64) -> std::io::Result<SolutionRec> {
        // sol_id 所属 stripe 通过直接查询（测试规模下足够）。
        let (stripe, opk): (i64, i64) = store.db_row(
            "SELECT stripe_idx,object_pk FROM stripe_solutions WHERE id=?1",
            sol_id,
        )?;
        let sols = store.list_solutions(opk, stripe as usize)?;
        let s = sols.into_iter().find(|s| s.id == sol_id).unwrap();
        Ok(SolutionRec {
            replica_ids: s.replica_ids,
            generation: s.generation,
            data_digests: serde_json::from_str(
                &store.scalar_string(
                    "SELECT data_digests FROM stripe_solutions WHERE id=?1",
                    sol_id,
                )?,
            )
            .unwrap(),
            output_digest: s.output_digest,
            tainted: s.tainted,
        })
    }
}

impl Engine {
    #[allow(clippy::too_many_arguments)]
    fn enumerate_stripe(
        &self,
        store: &Store,
        obj: &crate::store::ObjectRow,
        params: &crate::coding::CodingParams,
        stripe: usize,
        quarantined: &HashSet<String>,
    ) -> std::io::Result<EnumeratedStripe> {
        let field = params.field();
        let k = params.k;
        let n = params.n();
        store.clear_enum_evidence(obj.id, stripe)?;
        let replicas = store.list_replicas(obj.id)?;
        let mut by_slot: BTreeMap<usize, SlotCandidates> = BTreeMap::new();
        let mut excluded = Vec::new();
        let mut excluded_count = 0usize;

        for r in replicas.into_iter().filter(|r| {
            r.stripe_idx as usize == stripe && !quarantined.contains(&r.source)
        }) {
            let slot = r.slot as usize;
            let bytes = store.read_replica(&r)?;
            let mut problems: Vec<(EvidenceKind, String)> = Vec::new();
            if r.byte_len as usize != params.shard_size || bytes.len() != params.shard_size {
                problems.push((
                    EvidenceKind::LengthMismatch,
                    format!("长度 {} != 声明 {}", bytes.len(), params.shard_size),
                ));
            }
            if !field.check_symbols(&bytes) {
                problems.push((
                    EvidenceKind::OutOfField,
                    "包含域外符号，无法参与线性运算".into(),
                ));
            }
            let digest_ok = match &r.digest_expected {
                Some(exp) if !exp.eq_ignore_ascii_case(&r.digest_actual) => {
                    problems.push((
                        EvidenceKind::DigestMismatch,
                        format!("摘要 {} 与重算 {} 不符", exp, r.digest_actual),
                    ));
                    false
                }
                _ => true,
            };
            if !problems.is_empty() {
                excluded_count += 1;
                for (kind, detail) in &problems {
                    store.add_evidence(
                        obj.id,
                        stripe,
                        Some(slot),
                        Some(r.id),
                        *kind,
                        detail,
                        "enumeration",
                    )?;
                    excluded.push(ExcludedNote {
                        kind: kind.as_str().into(),
                        detail: format!("[replica#{} slot{slot}] {detail}", r.id),
                    });
                }
                continue;
            }
            by_slot.entry(slot).or_insert(SlotCandidates { slot, cands: Vec::new() }).cands.push(
                Cand { replica: r, bytes, digest_ok },
            );
        }

        // 候选排序：摘要正常优先，generation 升序，接收序号升序，内容摘要升序。
        for sc in by_slot.values_mut() {
            sc.cands.sort_by(|a, b| {
                b.digest_ok
                    .cmp(&a.digest_ok)
                    .then_with(|| a.replica.generation.cmp(&b.replica.generation))
                    .then_with(|| a.replica.received_seq.cmp(&b.replica.received_seq))
                    .then_with(|| a.replica.digest_actual.cmp(&b.replica.digest_actual))
            });
        }

        let mut report = StripeReport {
            stripe,
            candidates_total: by_slot.values().map(|s| s.cands.len()).sum(),
            candidates_excluded: excluded_count,
            ..Default::default()
        };

        // 同 slot 多内容候选：记录重复编号（含两个内容候选）证据。
        for sc in by_slot.values() {
            let distinct: BTreeSet<String> =
                sc.cands.iter().map(|c| c.replica.digest_actual.clone()).collect();
            if distinct.len() > 1 {
                store.add_evidence(
                    obj.id,
                    stripe,
                    Some(sc.slot),
                    None,
                    EvidenceKind::DuplicateSlot,
                    &format!("slot {} 存在 {} 个不同内容候选，均参与枚举", sc.slot, distinct.len()),
                    "enumeration",
                )?;
            }
        }

        let slots: Vec<SlotCandidates> = by_slot.into_values().collect();
        let mut grids: HashMap<i64, Vec<Vec<u8>>> = HashMap::new();
        let mut chosen_cands: HashMap<i64, Vec<Cand>> = HashMap::new();
        let mut distinct_outputs: BTreeMap<String, SolutionRec> = BTreeMap::new();
        let mut output_provenance: HashMap<String, Vec<Cand>> = HashMap::new();
        let mut leaves = 0u64;
        let mut exhausted = false;

        // DFS：每个 slot 的选择依次为候选0..候选j-1、最后 None。
        fn dfs(
            this: &Engine,
            params: &crate::coding::CodingParams,
            slots: &[SlotCandidates],
            idx: usize,
            chosen: &mut Vec<(usize, Cand)>,
            leaves: &mut u64,
            exhausted: &mut bool,
            outputs: &mut BTreeMap<String, SolutionRec>,
            provenance: &mut HashMap<String, Vec<Cand>>,
        ) {
            if *leaves >= this.per_stripe_budget {
                *exhausted = true;
                return;
            }
            if idx == slots.len() {
                if chosen.len() < params.k {
                    return;
                }
                *leaves += 1;
                // generation 混杂：该叶不可行。
                let gens: BTreeSet<i64> = chosen.iter().map(|(_, c)| c.replica.generation).collect();
                if gens.len() > 1 {
                    return;
                }
                let present: Vec<(usize, Vec<u8>)> = chosen
                    .iter()
                    .map(|(slot, c)| (*slot, c.bytes.clone()))
                    .collect();
                let field = params.field();
                let data = match reconstruct(&field, params.k, params.shard_size, &present) {
                    Ok(d) => d,
                    Err(reason) => {
                        if reason.contains("disagree") {
                            outputs
                                .entry(format!("!contradiction:{reason}"))
                                .or_insert_with(|| SolutionRec {
                                    replica_ids: vec![],
                                    generation: 0,
                                    data_digests: vec![],
                                    output_digest: String::new(),
                                    tainted: false,
                                });
                        }
                        return;
                    }
                };
                let full = match verify_full(&field, &data, params.m, &present) {
                    Ok(f) => f,
                    Err(_) => return,
                };
                let output_digest = object_digest_hex(&[full.clone()]);
                let data_digests: Vec<String> =
                    data.iter().map(|d| sha256_hex(d)).collect();
                let tainted = chosen.iter().any(|(_, c)| !c.digest_ok);
                let rec = SolutionRec {
                    replica_ids: chosen.iter().map(|(_, c)| c.replica.id).collect(),
                    generation: chosen[0].1.replica.generation,
                    data_digests,
                    output_digest: output_digest.clone(),
                    tainted,
                };
                // 不同组合可能给出相同输出（重复副本）；保留代表组合即可。
                outputs.entry(output_digest.clone()).or_insert(rec);
                provenance
                    .entry(output_digest)
                    .or_insert_with(|| chosen.iter().map(|(_, c)| c.clone()).collect());
                return;
            }
            // 候选优先于 None，保证字典序确定。
            for ci in 0..slots[idx].cands.len() {
                let cand = slots[idx].cands[ci].clone();
                chosen.push((slots[idx].slot, cand));
                dfs(this, params, slots, idx + 1, chosen, leaves, exhausted, outputs, provenance);
                chosen.pop();
                if *exhausted {
                    return;
                }
            }
            dfs(this, params, slots, idx + 1, chosen, leaves, exhausted, outputs, provenance);
        }

        let mut chosen_vec: Vec<(usize, Cand)> = Vec::new();
        dfs(
            self,
            params,
            &slots,
            0,
            &mut chosen_vec,
            &mut leaves,
            &mut exhausted,
            &mut distinct_outputs,
            &mut output_provenance,
        );
        report.combos_checked = leaves;
        report.budget_exhausted = exhausted;

        // generation 混杂证据（枚举期间观察到的情况汇总一次）。
        let any_gen_mix = slots.iter().any(|sc| {
            let g: BTreeSet<i64> = sc.cands.iter().map(|c| c.replica.generation).collect();
            g.len() > 1
        });
        if any_gen_mix {
            store.add_evidence(
                obj.id,
                stripe,
                None,
                None,
                EvidenceKind::GenerationMix,
                "存在不同 generation 的候选；混代组合一律排除，只在同代内枚举",
                "enumeration",
            )?;
        }
        if exhausted {
            store.add_evidence(
                obj.id,
                stripe,
                None,
                None,
                EvidenceKind::BudgetExhausted,
                &format!("每 stripe 预算 {} 个叶组合耗尽，枚举可能不完整", self.per_stripe_budget),
                "enumeration",
            )?;
        }
        distinct_outputs.retain(|k, r| !k.starts_with('!'));
        // 矛盾组合证据：位翻转等。
        if distinct_outputs.is_empty() && leaves > 0 {
            store.add_evidence(
                obj.id,
                stripe,
                None,
                None,
                EvidenceKind::Contradiction,
                "所有参与集合均无法通过超定一致性校验（疑似位翻转/损坏证据）",
                "enumeration",
            )?;
        }

        let mut recs: Vec<SolutionRec> = distinct_outputs.values().cloned().collect();
        recs.sort_by(|a, b| {
            a.replica_ids
                .len()
                .cmp(&b.replica_ids.len())
                .then_with(|| a.tainted.cmp(&b.tainted))
                .then_with(|| a.output_digest.cmp(&b.output_digest))
        });
        let ids = store.replace_solutions(obj.id, stripe, &recs)?;
        for (id, rec) in ids.iter().zip(recs.iter()) {
            let key = &rec.output_digest;
            grids.insert(*id, {
                // 重新算网格：provenance 仅存候选，重算一次成本低。
                let chosen_c: Vec<(usize, Vec<u8>)> = output_provenance[key]
                    .iter()
                    .map(|c| (c.replica.slot as usize, c.bytes.clone()))
                    .collect();
                let data = reconstruct(&field, params.k, params.shard_size, &chosen_c).unwrap();
                verify_full(&field, &data, params.m, &chosen_c).unwrap()
            });
            chosen_cands.insert(*id, output_provenance[key].clone());
        }
        report.solutions = store
            .list_solutions(obj.id, stripe)?
            .into_iter()
            .map(|s| StripeSolutionView {
                db_id: s.id,
                rank: s.rank as usize,
                replica_ids: s.replica_ids,
                generation: s.generation,
                data_digests: serde_json::from_str(
                    &store
                        .scalar_string("SELECT data_digests FROM stripe_solutions WHERE id=?1", s.id)
                        .unwrap_or_default(),
                )
                .unwrap_or_default(),
                output_digest: s.output_digest,
                tainted: s.tainted,
                matches_object_digest: s.matches_object_digest,
            })
            .collect();

        if report.solutions.is_empty() {
            report.blocked_reason = Some(if report.budget_exhausted {
                "搜索预算耗尽且尚无可行集合".to_string()
            } else if report.candidates_total < k {
                format!("可用 shard 数 {} 未达到恢复下限 {k}", report.candidates_total)
            } else {
                "没有任何候选集合能同时满足长度/域/generation/校验约束".to_string()
            });
        }
        let _ = n;
        Ok(EnumeratedStripe { report, grids, chosen_cands, exclusions: excluded })
    }
}


impl Engine {
    /// 跨 stripe 枚举组合：每条 stripe 选一个可行方案，按 stripe 升序 /
    /// 方案排序（rank 升序、未污染优先、输出摘要升序）做确定性字典序 DFS。
    /// 返回是否找到与对象摘要一致的全局组合；命中时把每条 stripe 选中的方案
    /// 写入 `chosen`。多个 stripe 存在多个方案时差异全部保留在数据库中。
    fn resolve_by_object_digest(
        &self,
        store: &Store,
        obj: &crate::store::ObjectRow,
        object_digest: &str,
        enumerated: &[EnumeratedStripe],
        chosen: &mut [Option<i64>],
        report: &mut RecoverReport,
    ) -> bool {
        let ordered: Vec<Vec<&StripeSolutionView>> = enumerated
            .iter()
            .map(|en| {
                let mut v: Vec<&StripeSolutionView> = en.report.solutions.iter().collect();
                v.sort_by(|a, b| {
                    a.rank
                        .cmp(&b.rank)
                        .then_with(|| a.tainted.cmp(&b.tainted))
                        .then_with(|| a.output_digest.cmp(&b.output_digest))
                });
                v
            })
            .collect();

        let mut picked: Vec<usize> = vec![0; ordered.len()];
        let mut checked = 0u64;
        let mut matched: Option<Vec<usize>> = None;

        fn next_tuple(picked: &mut [usize], widths: &[usize]) -> bool {
            let mut i = picked.len();
            loop {
                if i == 0 {
                    return false;
                }
                i -= 1;
                picked[i] += 1;
                if picked[i] < widths[i] {
                    for j in (i + 1)..picked.len() {
                        picked[j] = 0;
                    }
                    return true;
                }
                picked[i] = 0;
            }
        }

        let widths: Vec<usize> = ordered.iter().map(|v| v.len()).collect();
        if widths.iter().any(|w| *w == 0) {
            // 至少一条 stripe 无可行解，无法组装对象。
            return false;
        }
        loop {
            if checked >= self.global_budget {
                report.global_combos_checked = checked;
                // 预算耗尽证据落在第 0 条可行 stripe 上。
                let s = enumerated
                    .iter()
                    .position(|e| !e.report.solutions.is_empty())
                    .unwrap_or(0);
                store
                    .add_evidence(
                        obj.id,
                        s,
                        None,
                        None,
                        EvidenceKind::BudgetExhausted,
                        &format!("跨 stripe 全局预算 {} 个组合耗尽，对象摘要未确认", self.global_budget),
                        "enumeration",
                    )
                    .ok();
                return false;
            }
            let grid: Vec<&Vec<Vec<u8>>> = ordered
                .iter()
                .zip(picked.iter())
                .enumerate()
                .map(|(i, (sols, &pi))| &enumerated[i].grids[&sols[pi].db_id])
                .collect();
            // object_digest_hex 需要拥有所有权的网格。
            let owned: Vec<Vec<Vec<u8>>> = grid.into_iter().cloned().collect();
            let digest = object_digest_hex(&owned);
            checked += 1;
            if digest.eq_ignore_ascii_case(object_digest) {
                matched = Some(picked.clone());
                break;
            }
            if !next_tuple(&mut picked, &widths) {
                break;
            }
        }
        report.global_combos_checked = checked;
        if let Some(p) = matched {
            for (i, pi) in p.into_iter().enumerate() {
                chosen[i] = Some(ordered[i][pi].db_id);
            }
            true
        } else {
            false
        }
    }

    /// 对象摘要校验阶段，标记某 stripe 的某方案是否参与“唯一一致全局组合”。
    fn solution_participates(
        &self,
        enumerated: &[EnumeratedStripe],
        stripe: usize,
        sol_id: i64,
        chosen: &[Option<i64>],
        matched: bool,
    ) -> bool {
        matched && chosen[stripe] == Some(sol_id)
    }
}
