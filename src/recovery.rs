//! 恢复流程：按 stripe 枚举、落盘临时块、原子提交；进程中断后只复用
//! "摘要完整且文件校验通过"的已提交 stripe，临时块绝不被最终读取。

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::db::{Storage, StripeRow};
use crate::engine::{enumerate_stripe, SolutionInfo};
use crate::hashutil::{sha256_concat, sha256_hex};
use crate::types::{
    EvidenceKind, ObjectStatus, SolutionTier, StripeStatus, DEFAULT_SEARCH_BUDGET,
};

/// 磁盘写故障注入：在写入"第 fault_after 个 stripe 的第 1 个临时块"时报错。
#[derive(Debug, Clone)]
pub struct Fault {
    pub kind: FaultKind,
    pub stripe_seen: u64,
    pub fault_after: u64,
}

#[derive(Debug, Clone)]
pub enum FaultKind {
    DiskWrite,
    Crash,
}

/// 输出块落盘抽象，便于注入故障。
pub trait OutputSink {
    /// 原子写入一个输出块；返回最终路径与摘要。
    fn write_temp(&mut self, rel: &str, data: &[u8]) -> std::io::Result<PathBuf>;
    fn promote(&mut self, tmp: &Path, rel: &str) -> std::io::Result<()>;
    fn cleanup_temp(&mut self);
    fn read(&self, rel: &str) -> std::io::Result<Vec<u8>>;
    fn exists(&self, rel: &str) -> bool;
}

pub struct FsSink {
    root: PathBuf,
    temp_dir: PathBuf,
    temp_files: Vec<PathBuf>,
}

impl FsSink {
    pub fn new(root: &Path) -> std::io::Result<Self> {
        let temp_dir = root.join("recovered").join(".tmp");
        fs::create_dir_all(&temp_dir)?;
        Ok(FsSink { root: root.to_path_buf(), temp_dir, temp_files: Vec::new() })
    }
}

impl OutputSink for FsSink {
    fn write_temp(&mut self, rel: &str, data: &[u8]) -> std::io::Result<PathBuf> {
        let tmp = self.temp_dir.join(format!(
            "{}.{}",
            rel.replace('/', "_"),
            std::process::id()
        ));
        fs::write(&tmp, data)?;
        self.temp_files.push(tmp.clone());
        Ok(tmp)
    }

    fn promote(&mut self, tmp: &Path, rel: &str) -> std::io::Result<()> {
        let dest = self.root.join("recovered").join(rel);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(tmp, dest)?;
        self.temp_files.retain(|p| p != tmp);
        Ok(())
    }

    fn cleanup_temp(&mut self) {
        for p in self.temp_files.drain(..) {
            let _ = fs::remove_file(&p);
        }
        // 启动时也会整体清扫 .tmp。
    }

    fn read(&self, rel: &str) -> std::io::Result<Vec<u8>> {
        fs::read(self.root.join("recovered").join(rel))
    }

    fn exists(&self, rel: &str) -> bool {
        self.root.join("recovered").join(rel).exists()
    }
}

/// 启动清扫：删除所有本/上次进程留下的临时块。
pub fn clean_temp_dir(data_root: &Path) -> std::io::Result<()> {
    let tmp = data_root.join("recovered").join(".tmp");
    if tmp.exists() {
        fs::remove_dir_all(&tmp)?;
    }
    fs::create_dir_all(&tmp)?;
    Ok(())
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RecoverProgress {
    pub run_id: i64,
    pub total: i64,
    pub done: i64,
    pub status: String,
    pub fault: Option<String>,
}

fn ev(k: EvidenceKind) -> &'static str {
    match k {
        EvidenceKind::DigestMismatch => "digest_mismatch",
        EvidenceKind::LengthMismatch => "length_mismatch",
        EvidenceKind::DuplicateShard => "duplicate_shard",
        EvidenceKind::ConflictingCandidates => "conflicting_candidates",
        EvidenceKind::StaleGeneration => "stale_generation",
        EvidenceKind::CodingInconsistent => "coding_inconsistent",
        EvidenceKind::SearchBudgetExceeded => "search_budget_exceeded",
    }
}

/// 对全部 pending stripe 执行一轮恢复。`fault` 用于磁盘写失败/中断测试。
pub fn run_recovery(
    storage: &mut Storage,
    sink: &mut dyn OutputSink,
    fault: Option<Fault>,
) -> RecoverProgress {
    let pending = storage.list_pending_stripe_ids().expect("list pending");
    let total = pending.len() as i64;
    let run_id = storage
        .start_run(total, fault.as_ref().map(|f| match f.kind {
            FaultKind::DiskWrite => "disk_write",
            FaultKind::Crash => "crash",
        }))
        .expect("start run");

    let mut done = 0i64;
    let mut interrupted = false;
    for (stripe_db_id, object_db_id, stripe_idx) in &pending {
        if let Some(f) = &fault {
            if done >= f.fault_after as i64 {
                interrupted = true;
                break;
            }
        }
        if let Err(e) = process_stripe(
            storage,
            sink,
            *stripe_db_id,
            *object_db_id,
            *stripe_idx,
            Some(run_id),
            fault.as_ref(),
            done,
        ) {
            storage
                .add_evidence(
                    Some(*stripe_db_id),
                    Some(*object_db_id),
                    None,
                    Some(run_id),
                    "disk_write",
                    &format!("输出落盘失败，stripe 未提交：{e}"),
                )
                .expect("evidence");
            interrupted = true;
            break;
        }
        done += 1;
    }

    sink.cleanup_temp();

    let status = if interrupted { "interrupted" } else { "completed" };
    storage.finish_run(run_id, done, status).expect("finish run");

    if status == "completed" {
        finalize_objects(storage);
    }

    RecoverProgress {
        run_id,
        total,
        done,
        status: status.into(),
        fault: fault.as_ref().map(|f| match f.kind {
            FaultKind::DiskWrite => "disk_write".into(),
            FaultKind::Crash => "crash".into(),
        }),
    }
}

#[allow(clippy::too_many_arguments)]
fn process_stripe(
    storage: &mut Storage,
    sink: &mut dyn OutputSink,
    stripe_db_id: i64,
    object_db_id: i64,
    stripe_idx: i64,
    run_id: Option<i64>,
    fault: Option<&Fault>,
    stripe_seen: i64,
) -> std::io::Result<()> {
    let stripe = storage.get_stripe(stripe_db_id).expect("stripe").expect("row");
    let object = storage.get_object(object_db_id).expect("obj").expect("row");
    let params = crate::types::lookup_params(&object.coding_version).expect("params");

    let result = enumerate_stripe(storage, &stripe, object_db_id, DEFAULT_SEARCH_BUDGET);

    // 清掉上一轮运行级证据与旧解，再重新记录（导入级证据如 digest_mismatch 保留）。
    storage.clear_run_evidence(stripe_db_id).expect("clear run evidence");
    storage.delete_solutions(stripe_db_id).expect("clear sols");

    // 记录候选证据：混代、编码矛盾、搜索预算。
    for fid in &result.stale_ids {
        storage
            .add_evidence(
                Some(stripe_db_id),
                Some(object_db_id),
                Some(*fid),
                run_id,
                ev(EvidenceKind::StaleGeneration),
                &format!("frag #{fid} generation 落后于本 stripe 最新代，被排除出 trusted 集合"),
            )
            .expect("ev");
    }
    // 各可行解（winners）排除的损坏块都记录为编码矛盾证据。
    let mut coding_bad: BTreeSet<i64> = BTreeSet::new();
    for w in &result.winners {
        coding_bad.extend(w.excluded_ids.iter().copied());
    }
    for fid in &coding_bad {
        storage
            .add_evidence(
                Some(stripe_db_id),
                Some(object_db_id),
                Some(*fid),
                run_id,
                ev(EvidenceKind::CodingInconsistent),
                &format!("frag #{fid} 摘要通过但与最高一致性重建矛盾，作为损坏证据排除"),
            )
            .expect("ev");
    }
    if result.budget_exceeded {
        storage
            .add_evidence(
                Some(stripe_db_id),
                Some(object_db_id),
                None,
                run_id,
                ev(EvidenceKind::SearchBudgetExceeded),
                &format!("枚举在预算 {} 内未穷尽，共试 {} 组", DEFAULT_SEARCH_BUDGET, result.combos),
            )
            .expect("ev");
    }

    // 保存全部可行解（不只是成功状态）。
    for sol in &result.solutions {
        let tier = match sol.tier {
            SolutionTier::Trusted => "trusted",
            SolutionTier::Degraded => "degraded",
        };
        let subset = serde_json::to_string(&sol.participant_ids).unwrap();
        storage
            .insert_solution(
                stripe_db_id,
                tier,
                sol.generation,
                &sol.output_digest,
                &format!("{}|{}|{}", tier, sol.generation, sol.output_digest),
                &subset,
                &sol.output,
            )
            .expect("insert solution");
    }

    let winners = &result.winners;
    let all_degraded = result
        .solutions
        .iter()
        .all(|s| matches!(s.tier, SolutionTier::Degraded));
    let winners_trusted = winners
        .iter()
        .any(|s| matches!(s.tier, SolutionTier::Trusted));

    // 决策：winners 唯一才自动提交；多个 => ambiguous；无 winner 且全降级 => degraded。
    let decision = if winners.len() == 1 && winners_trusted {
        Some((&winners[0], StripeStatus::Committed, "trusted"))
    } else if winners.len() == 1 && all_degraded {
        Some((&winners[0], StripeStatus::Degraded, "degraded"))
    } else {
        None
    };

    match decision {
        Some((sol, status, tier)) => {
            commit_solution(
                storage,
                sink,
                &object.object_id,
                stripe_idx,
                params.stripe_bytes,
                sol,
                status,
                tier,
                stripe_db_id,
                run_id,
                result.combos,
                result.budget_exceeded,
                fault,
                stripe_seen,
            )?;
        }
        None => {
            let status = if result.budget_exceeded {
                StripeStatus::BudgetLimited
            } else if winners.is_empty()
                && result.latest_positions < params.k as usize
                && result.present_positions < params.k as usize
            {
                StripeStatus::Unrecoverable
            } else {
                // 多个一致度并列的不同输出，或降级但无唯一答案 => ambiguous。
                StripeStatus::Ambiguous
            };
            storage
                .update_stripe_state(
                    stripe_db_id,
                    match status {
                        StripeStatus::BudgetLimited => "budget_limited",
                        StripeStatus::Ambiguous => "ambiguous",
                        StripeStatus::Unrecoverable => "unrecoverable",
                        _ => "ambiguous",
                    },
                    None,
                    max_stripe_generation(&result),
                    None,
                    None,
                    None,
                    result.combos as i64,
                    result.budget_exceeded,
                )
                .expect("state");
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn commit_solution(
    storage: &mut Storage,
    sink: &mut dyn OutputSink,
    object_id_str: &str,
    stripe_idx: i64,
    stripe_bytes: usize,
    sol: &SolutionInfo,
    status: StripeStatus,
    tier: &str,
    stripe_db_id: i64,
    run_id: Option<i64>,
    combos: u64,
    budget_exceeded: bool,
    fault: Option<&Fault>,
    stripe_seen: i64,
) -> std::io::Result<()> {
    // 临时写全部 k 块；任意一块写失败 => stripe 不提交（无临时块会被最终读取）。
    let mut temps: Vec<(PathBuf, String)> = Vec::new();
    for shard in 0..sol.output.len() / stripe_bytes {
        let start = shard * stripe_bytes;
        let chunk = &sol.output[start..start + stripe_bytes];
        let rel = format!("{object_id_str}/s{stripe_idx}/d{shard}.bin");
        let trigger = fault.is_some_and(|f| {
            matches!(f.kind, FaultKind::DiskWrite | FaultKind::Crash)
                && stripe_seen as u64 == f.fault_after
        });
        if trigger {
            sink.cleanup_temp();
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "injected write failure (partial stripe write)",
            ));
        }
        let tmp = sink.write_temp(&rel, chunk)?;
        temps.push((tmp, rel));
    }

    // 全部临时块落盘成功后才原子 promote + DB 提交（顺序提交，中途崩溃 =>
    // 下轮启动审计会发现 DB 未 committed 的孤儿文件，不读取）。
    for (tmp, rel) in temps {
        sink.promote(&tmp, &rel)?;
    }

    storage
        .update_stripe_state(
            stripe_db_id,
            match status {
                StripeStatus::Committed => "committed",
                StripeStatus::Degraded => "degraded",
                _ => tier,
            },
            Some(tier),
            sol.generation.max(0),
            run_id,
            Some(&sol.output_digest),
            Some(sol.output.len() as i64),
            combos as i64,
            budget_exceeded,
        )
        .expect("commit state");
    Ok(())
}

fn max_stripe_generation(result: &crate::engine::EnumerationResult) -> i64 {
    result.candidates.iter().map(|c| c.generation).max().unwrap_or(0)
}

/// 对象级收尾：汇总已提交 stripe -> 对象摘要裁决 -> 对象状态。
pub fn finalize_objects(storage: &mut Storage) {
    let objects = storage.list_objects().expect("objects");
    for object in objects {
        let params = crate::types::lookup_params(&object.coding_version).expect("params");
        let stripes = storage.list_stripes(object.id).expect("stripes");
        let total = object.stripe_count as usize;
        if stripes.len() < total {
            storage.set_object_status(object.id, "incomplete").ok();
            continue;
        }

        let has_unrecoverable = stripes
            .iter()
            .any(|s| matches!(s.status.as_str(), "unrecoverable" | "budget_limited"));
        let ambiguous_stripes: Vec<&StripeRow> =
            stripes.iter().filter(|s| s.status == "ambiguous").collect();

        // 对 ambiguous stripe 尝试对象摘要裁决（枚举 stripe 全部解与全局对象摘要）。
        if !ambiguous_stripes.is_empty() && object.object_digest.is_some() {
            resolve_ambiguous_by_object_digest(storage, &object, &stripes, &ambiguous_stripes);
        }

        // 重新读取最新状态。
        let stripes = storage.list_stripes(object.id).expect("stripes2");
        let all_committed = stripes.iter().all(|s| s.status == "committed");
        let all_ok_degraded = stripes
            .iter()
            .all(|s| matches!(s.status.as_str(), "committed" | "degraded"));
        let still_ambiguous = stripes.iter().any(|s| s.status == "ambiguous");

        if all_committed {
            let blocks = assemble_committed(storage, &object, &stripes, params.stripe_bytes);
            let total_len = object.declared_len.map(|v| v as usize);
            let digest = sha256_concat(&blocks, total_len);
            match &object.object_digest {
                Some(expected) if !digest.eq_ignore_ascii_case(expected) => {
                    storage.set_object_status(object.id, "digest_mismatch").ok();
                    storage
                        .add_evidence(
                            None,
                            Some(object.id),
                            None,
                            None,
                            "digest_mismatch",
                            &format!("对象摘要 {digest} 与声明 {expected} 不符"),
                        )
                        .ok();
                }
                _ => {
                    storage.set_object_status(object.id, "trusted").ok();
                }
            }
        } else if still_ambiguous {
            storage.set_object_status(object.id, "ambiguous").ok();
        } else if all_ok_degraded {
            storage.set_object_status(object.id, "degraded").ok();
        } else if has_unrecoverable {
            storage.set_object_status(object.id, "unrecoverable").ok();
        } else {
            storage.set_object_status(object.id, "incomplete").ok();
        }
    }
}

fn assemble_committed(
    storage: &mut Storage,
    object: &crate::db::ObjectRow,
    stripes: &[StripeRow],
    stripe_bytes: usize,
) -> Vec<Vec<u8>> {
    let mut blocks = Vec::new();
    for s in stripes {
        let out = storage
            .committed_solution_output(s.id)
            .expect("output query")
            .unwrap_or_default();
        for shard in 0..out.len() / stripe_bytes {
            blocks.push(out[shard * stripe_bytes..(shard + 1) * stripe_bytes].to_vec());
        }
    }
    let _ = object;
    blocks
}

/// 对象摘要裁决：ambiguous stripe 有多个 trusted 解时，组合它们并和对象摘要比对。
/// 唯一匹配 -> 提交；多个/零个 -> 保持 ambiguous 或 digest_mismatch。
fn resolve_ambiguous_by_object_digest(
    storage: &mut Storage,
    object: &crate::db::ObjectRow,
    stripes: &[StripeRow],
    ambiguous: &[&StripeRow],
) {
    let params = crate::types::lookup_params(&object.coding_version).expect("params");
    let expected = object.object_digest.clone().expect("digest present");
    let total_len = object.declared_len.map(|v| v as usize);

    // 固定部分：committed stripe 的输出。
    let mut fixed: BTreeMap<i64, Vec<u8>> = BTreeMap::new();
    for s in stripes {
        if s.status == "committed" {
            if let Some(out) = storage.committed_solution_output(s.id).expect("out") {
                fixed.insert(s.stripe_idx, out);
            }
        }
    }

    // 每个 ambiguous stripe 的 trusted 解列表。
    let options: Vec<(i64, Vec<crate::db::SolutionRow>)> = ambiguous
        .iter()
        .map(|s| {
            let sols = storage
                .list_solutions(s.id)
                .expect("sols")
                .into_iter()
                .filter(|sol| sol.tier == "trusted")
                .collect();
            (s.stripe_idx, sols)
        })
        .collect();

    const OBJ_BUDGET: u64 = 1024;
    let mut combos: u64 = 1;
    for (_, sols) in &options {
        combos = combos.saturating_mul(sols.len().max(1) as u64);
    }
    if combos > OBJ_BUDGET || combos == 0 {
        for (sidx, _) in &options {
            let sid = stripe_id_of(storage, object.id, *sidx);
            storage
                .add_evidence(
                    Some(sid),
                    Some(object.id),
                    None,
                    None,
                    ev(EvidenceKind::SearchBudgetExceeded),
                    &format!("对象摘要裁决组合数 {combos} 超预算 {OBJ_BUDGET}，保持 ambiguous"),
                )
                .ok();
        }
        return;
    }

    let lens: Vec<usize> = options.iter().map(|(_, sols)| sols.len().max(1)).collect();
    let mut pick = vec![0usize; options.len()];
    let mut matches: Vec<Vec<i64>> = Vec::new();
    let mut exhausted = options.is_empty();
    while !exhausted {
        let mut chosen: BTreeMap<i64, Vec<u8>> = fixed.clone();
        let mut solution_ids = Vec::new();
        for (oi, (stripe_idx, sols)) in options.iter().enumerate() {
            if sols.is_empty() {
                continue;
            }
            chosen.insert(*stripe_idx, sols[pick[oi]].output.clone());
            solution_ids.push(sols[pick[oi]].id);
        }
        let blocks: Vec<Vec<u8>> = stripes
            .iter()
            .filter_map(|s| chosen.get(&s.stripe_idx).cloned())
            .flat_map(|out| {
                (0..out.len() / params.stripe_bytes)
                    .map(|i| out[i * params.stripe_bytes..(i + 1) * params.stripe_bytes].to_vec())
                    .collect::<Vec<_>>()
            })
            .collect();
        let digest = sha256_concat(&blocks, total_len);
        if digest.eq_ignore_ascii_case(&expected) {
            matches.push(solution_ids);
        }

        let mut i = options.len();
        while i > 0 {
            i -= 1;
            if lens[i] == 0 {
                if i == 0 {
                    exhausted = true;
                }
                continue;
            }
            pick[i] += 1;
            if pick[i] < lens[i] {
                for p in &mut pick[i + 1..] {
                    *p = 0;
                }
                break;
            }
            pick[i] = 0;
            if i == 0 {
                exhausted = true;
            }
        }
    }

    if matches.len() == 1 {
        for (oi, (stripe_idx, sols)) in options.iter().enumerate() {
            if sols.is_empty() {
                continue;
            }
            let sol_id = matches[0][oi];
            let sol = sols.iter().find(|s| s.id == sol_id).expect("matched sol");
            let s_id = stripe_id_of(storage, object.id, *stripe_idx);
            storage
                .update_stripe_state(
                    s_id,
                    "committed",
                    Some("trusted"),
                    sol.generation,
                    None,
                    Some(&sol.output_digest),
                    Some(sol.output.len() as i64),
                    0,
                    false,
                )
                .expect("resolve commit");
            storage
                .add_evidence(
                    Some(s_id),
                    Some(object.id),
                    None,
                    None,
                    "object_digest_resolved",
                    "多个可行 trusted 答案中，唯一与对象摘要一致的解被选中提交",
                )
                .ok();
        }
    } else if matches.is_empty() {
        storage
            .add_evidence(
                None,
                Some(object.id),
                None,
                None,
                "digest_mismatch",
                "全部可行 stripe 组合均与对象摘要不符（可能部分写入/代次混杂）",
            )
            .ok();
    } else {
        storage
            .add_evidence(
                None,
                Some(object.id),
                None,
                None,
                "conflicting_candidates",
                &format!("{combos} 个组合中有 {} 个与对象摘要一致，仍需人工裁决", matches.len()),
            )
            .ok();
    }
}

fn stripe_id_of(storage: &mut Storage, object_id: i64, stripe_idx: i64) -> i64 {
    storage
        .list_stripes(object_id)
        .expect("stripes")
        .into_iter()
        .find(|s| s.stripe_idx == stripe_idx)
        .map(|s| s.id)
        .expect("stripe")
}

/// 启动审计：已提交 stripe 的落盘文件必须逐块存在且摘要一致，否则回退为 pending。
pub fn audit_committed(storage: &mut Storage, sink: &dyn OutputSink) {
    let objects = storage.list_objects().expect("objects");
    for object in objects {
        let params = crate::types::lookup_params(&object.coding_version).expect("params");
        let stripes = storage.list_stripes(object.id).expect("stripes");
        for s in stripes {
            if !matches!(s.status.as_str(), "committed" | "degraded") {
                continue;
            }
            let Some(output) = storage.committed_solution_output(s.id).expect("out") else {
                storage.reset_stripe(s.id).expect("reset");
                continue;
            };
            let mut concat = Vec::new();
            let mut ok = true;
            for shard in 0..output.len() / params.stripe_bytes {
                let rel = format!("{}/s{}/d{}.bin", object.object_id, s.stripe_idx, shard);
                match sink.read(&rel) {
                    Ok(bytes) => {
                        if sha256_hex(&bytes)
                            != sha256_hex(
                                &output[shard * params.stripe_bytes
                                    ..(shard + 1) * params.stripe_bytes],
                            )
                        {
                            ok = false;
                            break;
                        }
                        concat.extend(bytes);
                    }
                    Err(_) => {
                        ok = false;
                        break;
                    }
                }
            }
            let digest_ok = sha256_hex(&concat)
                == s.output_digest.clone().unwrap_or_default();
            if !ok || !digest_ok || concat.len() != output.len() {
                storage.reset_stripe(s.id).expect("reset after audit");
                storage
                    .add_evidence(
                        Some(s.id),
                        Some(object.id),
                        None,
                        None,
                        "incomplete_commit",
                        "已提交 stripe 的落盘文件缺失/摘要不符（疑似中断），回退重算",
                    )
                    .ok();
            }
        }
    }
}

pub fn object_status_str(s: ObjectStatus) -> &'static str {
    match s {
        ObjectStatus::Incomplete => "incomplete",
        ObjectStatus::Trusted => "trusted",
        ObjectStatus::Degraded => "degraded",
        ObjectStatus::Ambiguous => "ambiguous",
        ObjectStatus::DigestMismatch => "digest_mismatch",
        ObjectStatus::Unrecoverable => "unrecoverable",
    }
}

