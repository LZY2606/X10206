//! 条带恢复引擎：在 generation / 对象摘要 / stripe 约束下枚举可行集合，
//! 按确定性排序保留全部可行重建并指出差异；按 stripe 提交，崩溃后只复用
//! 摘要完整的已提交 stripe。

use crate::db::Db;
use crate::digest::{object_digest, sha256_hex};
use crate::gf256::Field;
use crate::model::ObjectManifest;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// 单 stripe 组合枚举搜索预算（确定性上限）。
pub const DEFAULT_COMBO_BUDGET: usize = 4096;
/// 每个 stripe 持久化的可行方案上限。
pub const STORED_PLAN_LIMIT: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Candidate {
    pub raw_block_id: i64,
    pub shard: usize,
    pub generation: u64,
    pub source: String,
    #[serde(skip)]
    pub bytes: Vec<u8>,
    pub recalculated: String,
    pub attached_digest: Option<String>,
    pub origin_path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExcludeReason {
    /// manifest 声明长度与实际不符。
    LengthMismatch,
    /// manifest / 随附摘要与重算摘要不符（位翻转等）。
    DigestMismatch,
}

impl ExcludeReason {
    pub fn as_str(self) -> &'static str {
        match self {
            ExcludeReason::LengthMismatch => "length_mismatch",
            ExcludeReason::DigestMismatch => "digest_mismatch",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PreExclusion {
    pub raw_block_id: i64,
    pub shard: usize,
    pub reason: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Participant {
    pub shard: usize,
    pub raw_block_id: i64,
    pub source: String,
    pub generation: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputInfo {
    pub shard: usize,
    pub source: String, // "received" | "rebuilt"
    pub recomputed: String,
    pub expected: Option<String>,
    pub digest_ok: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub rank: usize,
    pub generation: u64,
    pub uniform_gen: bool,
    pub participants: Vec<Participant>,
    pub missing: Vec<usize>,
    pub outputs: Vec<OutputInfo>,
    pub trust_ok: bool,
    pub content_sig: String,
    /// 组合内被排除的损坏候选（编号上被另一个候选挤掉且本身损坏）。
    pub combo_exclusions: Vec<PreExclusion>,
    /// 参与块的完整 n 块字节（含收到的 + 重建的），用于提交。
    pub full_blocks: BTreeMap<usize, Vec<u8>>,
    /// 重建后对未参与候选做交叉校验发现位翻转的证据。
    pub bitflip_evidence: Vec<PreExclusion>,
}

#[derive(Debug, Clone)]
pub struct StripeResult {
    pub object_id: String,
    pub stripe: usize,
    pub status: String, // recovered | already_complete | unrecoverable
    pub plans: Vec<Plan>,
    pub pre_exclusions: Vec<PreExclusion>,
    pub inspected_combos: usize,
    pub truncated: bool,
    pub content_diverge: bool,
    pub committed: bool,
    pub committed_generation: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct RecoverySummary {
    pub stripes_total: usize,
    pub stripes_committed: usize,
    pub stripes_reused: usize,
    pub stripes_rebuilt: usize,
    pub stripes_unrecoverable: usize,
    pub object_trusted: bool,
    pub object_digest_recomputed: Option<String>,
    pub object_digest_expected: Option<String>,
}

/// 写失败注入门：测试在"临时块写完、提交前"制造 IO 错误。
pub trait FailGate: std::fmt::Debug + Send + Sync {
    fn check(&self, object_id: &str, stripe: usize) -> std::io::Result<()> {
        let _ = (object_id, stripe);
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct NoFail;
impl FailGate for NoFail {}

// ----------------------------- 候选装载 -----------------------------

#[derive(Debug, Clone)]
pub struct LoadedCandidates {
    pub by_shard: BTreeMap<usize, Vec<Candidate>>,
    pub pre_exclusions: Vec<PreExclusion>,
}

pub fn load_candidates(
    db: &Db,
    manifest: &ObjectManifest,
    stripe: usize,
    isolated: &BTreeSet<String>,
) -> rusqlite::Result<LoadedCandidates> {
    let conn = db.conn.lock().unwrap();
    let expected_map = manifest.block_digests.get(&stripe).cloned().unwrap_or_default();
    let mut stmt = conn.prepare(
        "SELECT id, shard, generation, source, bytes, recalculated, attached_digest, origin_path
         FROM raw_blocks
         WHERE object_id=?1 AND stripe=?2
         ORDER BY shard ASC, generation DESC, source ASC, id ASC",
    )?;
    let rows = stmt.query_map(params![manifest.object_id, stripe as i64], |r| {
        let bytes: Vec<u8> = r.get(4)?;
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, i64>(1)? as usize,
            r.get::<_, i64>(2)? as u64,
            r.get::<_, String>(3)?,
            bytes,
            r.get::<_, String>(5)?,
            r.get::<_, Option<String>>(6)?,
            r.get::<_, String>(7)?,
        ))
    })?;

    let mut by_shard: BTreeMap<usize, Vec<Candidate>> = BTreeMap::new();
    let mut pre_exclusions = Vec::new();

    for row in rows {
        let (id, shard, generation, source, bytes, recalculated, attached, origin) = row?;
        if isolated.contains(&source) {
            continue;
        }
        let mut bad: Option<(String, String)> = None;
        if bytes.len() != manifest.block_len {
            bad = Some((
                ExcludeReason::LengthMismatch.as_str().to_string(),
                format!("实际长度 {} != block_len {}", bytes.len(), manifest.block_len),
            ));
        } else if let Some(expected) = expected_map.get(&shard) {
            if expected.ne_ignore_case(&recalculated) {
                bad = Some((
                    ExcludeReason::DigestMismatch.as_str().to_string(),
                    format!("重算摘要 {recalculated} 与 manifest 摘要 {expected} 不符"),
                ));
            }
        }
        if bad.is_none() {
            if let Some(att) = &attached {
                if att.ne_ignore_case(&recalculated) {
                    bad = Some((
                        ExcludeReason::DigestMismatch.as_str().to_string(),
                        format!("重算摘要 {recalculated} 与随附摘要 {att} 不符（疑似位翻转）"),
                    ));
                }
            }
        }
        let cand = Candidate {
            raw_block_id: id,
            shard,
            generation,
            source,
            bytes,
            recalculated,
            attached_digest: attached,
            origin_path: origin,
        };
        if let Some((reason, detail)) = bad {
            pre_exclusions.push(PreExclusion {
                raw_block_id: id,
                shard,
                reason,
                detail,
            });
        } else {
            by_shard.entry(shard).or_default().push(cand);
        }
    }
    Ok(LoadedCandidates {
        by_shard,
        pre_exclusions,
    })
}

trait StrExt {
    fn ne_ignore_case(&self, other: &str) -> bool;
}
impl StrExt for String {
    fn ne_ignore_case(&self, other: &str) -> bool {
        !self.eq_ignore_ascii_case(other)
    }
}

// ----------------------------- 组合枚举 -----------------------------

#[derive(Debug, Clone)]
struct RawCombo {
    chosen: Vec<Candidate>, // 每个选中 shard 一个，按 shard 升序
    uniform_gen: bool,
}

/// 确定性排序的键：
/// 1. generation 一致优先（uniform 在前）
/// 2. generation 高者在前
/// 3. 参与块 raw_block_id 元组字典序
fn combo_sort_key(c: &RawCombo) -> (u8, u64, Vec<i64>) {
    let uniform = if c.uniform_gen { 0 } else { 1 };
    let gen = c.chosen.first().map(|x| x.generation).unwrap_or(0);
    let ids: Vec<i64> = c.chosen.iter().map(|x| x.raw_block_id).collect();
    (uniform, gen, ids)
}

fn enumerate_combos(
    manifest: &ObjectManifest,
    loaded: &LoadedCandidates,
    budget: usize,
) -> (Vec<RawCombo>, bool) {
    let k = manifest.k;
    let n = manifest.n();
    // 每个 shard 的候选已按 generation desc, source asc, id asc 排序。
    let available_shards: Vec<usize> = loaded
        .by_shard
        .iter()
        .filter(|(_, cs)| !cs.is_empty())
        .map(|(s, _)| *s)
        .collect();

    let mut combos: Vec<RawCombo> = Vec::new();
    let mut truncated = false;

    // 枚举大小为 k 的 shard 子集（按编号升序的组合，顺序确定）。
    let subsets = combinations(&available_shards, k);
    'outer: for subset in subsets {
        let pools: Vec<&Vec<Candidate>> =
            subset.iter().map(|s| &loaded.by_shard[s]).collect();
        let sizes: Vec<usize> = pools.iter().map(|p| p.len()).collect();
        let total: usize = sizes.iter().product();
        let mut pick = vec![0usize; k];
        for _ in 0..total {
            if combos.len() >= budget {
                truncated = true;
                break 'outer;
            }
            let chosen: Vec<Candidate> = (0..k).map(|i| pools[i][pick[i]].clone()).collect();
            let gens: BTreeSet<u64> = chosen.iter().map(|c| c.generation).collect();
            let uniform = gens.len() == 1;
            combos.push(RawCombo { chosen, uniform_gen: uniform });

            // 混合进制递增（最后一维优先）
            let mut carry = k;
            while carry > 0 {
                carry -= 1;
                pick[carry] += 1;
                if pick[carry] < sizes[carry] {
                    break;
                }
                if carry != 0 {
                    pick[carry] = 0;
                }
            }
            if pick[0] >= sizes[0] {
                break;
            }
        }
    }
    let _ = n;
    combos.sort_by(|a, b| combo_sort_key(a).cmp(&combo_sort_key(b)));
    (combos, truncated)
}

/// 从有序集合中枚举大小为 r 的全部组合（保持升序）。
fn combinations(items: &[usize], r: usize) -> Vec<Vec<usize>> {
    let mut out = Vec::new();
    let mut idx: Vec<usize> = (0..r.min(items.len())).collect();
    if r > items.len() {
        return out;
    }
    loop {
        out.push(idx.iter().map(|&i| items[i]).collect());
        let mut pos = r;
        loop {
            if pos == 0 {
                return out;
            }
            pos -= 1;
            if idx[pos] != items.len() - r + pos {
                break;
            }
        }
        idx[pos] += 1;
        for j in (pos + 1)..r {
            idx[j] = idx[j - 1] + 1;
        }
    }
}

// ----------------------------- 单 stripe 分析 -----------------------------

/// 分析单个 stripe（纯计算，不写提交表）。
pub fn analyze_stripe(
    field: &Field,
    manifest: &ObjectManifest,
    stripe: usize,
    loaded: LoadedCandidates,
    budget: usize,
) -> StripeResult {
    let expected_map = manifest.block_digests.get(&stripe).cloned().unwrap_or_default();
    let n = manifest.n();
    let pre_exclusions = loaded.pre_exclusions.clone();

    // 条带已经完整（每个编号恰好一个可用候选）也走"完整自洽校验"路径。
    let full_no_choice = loaded.by_shard.len() == n
        && loaded.by_shard.values().all(|cs| cs.len() == 1);

    let (combos, truncated) = enumerate_combos(manifest, &loaded, budget);
    let inspected = combos.len();

    let mut plans: Vec<Plan> = Vec::new();
    let mut seen_sig = BTreeSet::<String>::new();

    if full_no_choice {
        if let Some(plan) = build_full_plan(manifest, stripe, &loaded, &expected_map, field) {
            seen_sig.insert(plan.content_sig.clone());
            plans.push(plan);
        }
    } else {
        for combo in combos {
            if plans.len() >= STORED_PLAN_LIMIT {
                break;
            }
            if let Some(plan) = build_decode_plan(
                manifest, stripe, &loaded, &expected_map, field, combo,
            ) {
                // 保留全部可行重建；相同重建内容（任意参与来源）只记一份但保留来源差异于 participants 展示？
                // 需求要求"保留全部并指出差异"：相同内容不同来源也保留，但 content_sig 用于识别内容分歧。
                plans.push(plan);
                if let Some(p) = plans.last() {
                    seen_sig.insert(p.content_sig.clone());
                }
            }
        }
    }

    // 同内容的方案只保留排名最靠前的一份（来源差异通过 chosen/输出来源展示在首选方案），
    // 但不同内容的答案全部保留。为满足"有多个可行重建时保留全部"，改为：
    // 相同内容的方案同样保留（上面未去重），content_diverge 用 sig 数量判断。
    let content_diverge = seen_sig.len() > 1;

    // 重新编号 rank
    for (i, p) in plans.iter_mut().enumerate() {
        p.rank = i;
    }

    let trusted_plans: Vec<&Plan> = plans.iter().filter(|p| p.trust_ok).collect();
    let status = if plans.is_empty() {
        "unrecoverable".to_string()
    } else if full_no_choice {
        "already_complete".to_string()
    } else {
        "recovered".to_string()
    };
    let _ = trusted_plans;

    StripeResult {
        object_id: manifest.object_id.clone(),
        stripe,
        status,
        plans,
        pre_exclusions,
        inspected_combos: inspected,
        truncated,
        content_diverge,
        committed: false,
        committed_generation: None,
    }
}

fn plan_outputs(
    manifest: &ObjectManifest,
    expected_map: &BTreeMap<usize, String>,
    full: &BTreeMap<usize, Vec<u8>>,
    chosen_by_shard: &BTreeMap<usize, &Candidate>,
) -> (Vec<OutputInfo>, bool) {
    let mut outputs = Vec::new();
    let mut trust = true;
    let mut any_check = false;
    for shard in 0..manifest.n() {
        let bytes = &full[&shard];
        let recomputed = sha256_hex(bytes);
        let received = chosen_by_shard.get(&shard).map(|c| *c);
        let source = if received.is_some() { "received" } else { "rebuilt" };
        let (expected, digest_ok) = match expected_map.get(&shard) {
            Some(exp) => {
                any_check = true;
                let ok = exp.eq_ignore_ascii_case(&recomputed);
                if !ok {
                    trust = false;
                }
                (Some(exp.clone()), Some(ok))
            }
            None => {
                // 收到块还可以与随附摘要比对。
                if let Some(c) = received {
                    if let Some(att) = &c.attached_digest {
                        any_check = true;
                        let ok = att.eq_ignore_ascii_case(&recomputed);
                        if !ok {
                            trust = false;
                        }
                        (Some(att.clone()), Some(ok))
                    } else {
                        (None, None)
                    }
                } else {
                    (None, None)
                }
            }
        };
        outputs.push(OutputInfo {
            shard,
            source: source.to_string(),
            recomputed,
            expected,
            digest_ok,
        });
    }
    // 无可核对摘要时无法判定可信
    if !any_check {
        trust = false;
    }
    (outputs, trust)
}

fn content_signature(manifest: &ObjectManifest, full: &BTreeMap<usize, Vec<u8>>) -> String {
    let mut h = sha2::Sha256::new();
    use sha2::Digest;
    for shard in 0..manifest.n() {
        h.update((shard as u32).to_le_bytes());
        h.update(&full[&shard]);
    }
    let d = h.finalize();
    d.iter().map(|b| format!("{b:02x}")).collect()
}

fn cross_check_unused(
    manifest: &ObjectManifest,
    loaded: &LoadedCandidates,
    full: &BTreeMap<usize, Vec<u8>>,
    chosen_ids: &BTreeSet<i64>,
) -> Vec<PreExclusion> {
    let mut ev = Vec::new();
    for candidates in loaded.by_shard.values() {
        for c in candidates {
            if chosen_ids.contains(&c.raw_block_id) {
                continue;
            }
            if let Some(actual) = full.get(&c.shard) {
                if c.bytes.len() == manifest.block_len && &c.bytes != actual {
                    ev.push(PreExclusion {
                        raw_block_id: c.raw_block_id,
                        shard: c.shard,
                        reason: "bitflip_crosscheck".into(),
                        detail: format!(
                            "同编号候选 {}（gen={}, src={}）与重建内容不一致，作为损坏候选排除",
                            c.recalculated, c.generation, c.source
                        ),
                    });
                }
            }
        }
    }
    ev
}

fn build_full_plan(
    manifest: &ObjectManifest,
    stripe: usize,
    loaded: &LoadedCandidates,
    expected_map: &BTreeMap<usize, String>,
    field: &Field,
) -> Option<Plan> {
    let mut full: BTreeMap<usize, Vec<u8>> = BTreeMap::new();
    let mut chosen: BTreeMap<usize, &Candidate> = BTreeMap::new();
    let mut chosen_ids = BTreeSet::new();
    let mut participants = Vec::new();
    for (shard, cands) in &loaded.by_shard {
        let c = &cands[0];
        full.insert(*shard, c.bytes.clone());
        chosen.insert(*shard, c);
        chosen_ids.insert(c.raw_block_id);
        participants.push(Participant {
            shard: *shard,
            raw_block_id: c.raw_block_id,
            source: c.source.clone(),
            generation: c.generation,
        });
    }
    // 完整条带必须编码自洽；不自洽说明存在位翻转且无法甄别 -> 不可行（需要缺块重建路径才可能甄别）。
    if !crate::gf256::verify_full_stripe(field, manifest.k, manifest.m, &full) {
        let _ = stripe;
        return None;
    }
    let (outputs, trust_ok) = plan_outputs(manifest, expected_map, &full, &chosen);
    let bitflip = cross_check_unused(manifest, loaded, &full, &chosen_ids);
    let gen = participants[0].generation;
    let uniform = participants.iter().all(|p| p.generation == gen);
    let sig = content_signature(manifest, &full);
    Some(Plan {
        rank: 0,
        generation: gen,
        uniform_gen: uniform,
        participants,
        missing: vec![],
        outputs,
        trust_ok,
        content_sig: sig,
        combo_exclusions: vec![],
        full_blocks: full,
        bitflip_evidence: bitflip,
    })
}

fn build_decode_plan(
    manifest: &ObjectManifest,
    stripe: usize,
    loaded: &LoadedCandidates,
    expected_map: &BTreeMap<usize, String>,
    field: &Field,
    combo: RawCombo,
) -> Option<Plan> {
    let n = manifest.n();
    let mut available: BTreeMap<usize, Vec<u8>> = BTreeMap::new();
    let mut chosen: BTreeMap<usize, &Candidate> = BTreeMap::new();
    let mut chosen_ids = BTreeSet::new();
    let mut participants = Vec::new();
    let mut combo_exclusions = Vec::new();

    for c in &combo.chosen {
        available.insert(c.shard, c.bytes.clone());
        chosen.insert(c.shard, c);
        chosen_ids.insert(c.raw_block_id);
        participants.push(Participant {
            shard: c.shard,
            raw_block_id: c.raw_block_id,
            source: c.source.clone(),
            generation: c.generation,
        });
    }

    let missing: Vec<usize> = (0..n).filter(|i| !available.contains_key(i)).collect();

    // 解码
    let decoded = crate::gf256::decode(field, manifest.k, manifest.m, &available, &missing)?;

    // 组装完整条带
    let mut full: BTreeMap<usize, Vec<u8>> = BTreeMap::new();
    for c in &combo.chosen {
        full.insert(c.shard, c.bytes.clone());
    }
    for (s, b) in decoded.missing {
        full.insert(s, b);
    }
    if full.len() != n {
        return None;
    }

    // 编码自洽校验：重建后完整条带必须满足校验方程（可捕获组合内部不一致）。
    if !crate::gf256::verify_full_stripe(field, manifest.k, manifest.m, &full) {
        return None;
    }

    // 参与块如果有摘要但不符 -> 方案不可信（正常预排除已剔除，这里双保险）
    let (outputs, trust_ok) = plan_outputs(manifest, expected_map, &full, &chosen);

    // 交叉校验：其它编号候选（含同编号未选中的损坏候选）
    let mut bitflip = cross_check_unused(manifest, loaded, &full, &chosen_ids);
    for candidates in loaded.by_shard.values() {
        for c in candidates {
            if chosen_ids.contains(&c.raw_block_id) {
                continue;
            }
            if let Some(att) = &c.attached_digest {
                let rec = &c.recalculated;
                if att.ne_ignore_case(rec) {
                    combo_exclusions.push(PreExclusion {
                        raw_block_id: c.raw_block_id,
                        shard: c.shard,
                        reason: ExcludeReason::DigestMismatch.as_str().into(),
                        detail: format!(
                            "编号 {} 的候选（gen={}, src={}）随附摘要与重算摘要不符，排除",
                            c.shard, c.generation, c.source
                        ),
                    });
                }
            }
        }
    }
    bitflip.append(&mut combo_exclusions);

    let gen = combo.chosen[0].generation;
    let sig = content_signature(manifest, &full);
    let _ = stripe;
    Some(Plan {
        rank: 0,
        generation: gen,
        uniform_gen: combo.uniform_gen,
        participants,
        missing,
        outputs,
        trust_ok,
        content_sig: sig,
        combo_exclusions: vec![],
        full_blocks: full,
        bitflip_evidence: bitflip,
    })
}

// ----------------------------- 持久化与提交 -----------------------------

fn persist_result(db: &Db, result: &StripeResult) -> rusqlite::Result<()> {
    let mut conn = db.conn.lock().unwrap();
    let tx = conn.transaction()?;
    tx.execute("DELETE FROM plans WHERE object_id=?1 AND stripe=?2",
        params![result.object_id, result.stripe as i64])?;
    tx.execute("DELETE FROM exclusions WHERE object_id=?1 AND stripe=?2",
        params![result.object_id, result.stripe as i64])?;

    for e in &result.pre_exclusions {
        tx.execute(
            "INSERT INTO exclusions(object_id, stripe, plan_rank, raw_block_id, shard, reason, detail)
             VALUES (?1,?2,NULL,?3,?4,?5,?6)",
            params![result.object_id, result.stripe as i64, e.raw_block_id, e.shard as i64, e.reason, e.detail],
        )?;
    }
    for p in &result.plans {
        let participants = serde_json::to_string(&p.participants).unwrap();
        let missing = serde_json::to_string(&p.missing).unwrap();
        let outputs = serde_json::to_string(&p.outputs).unwrap();
        tx.execute(
            "INSERT INTO plans(object_id, stripe, rank, generation, uniform_gen, participants,
                               missing, outputs, trust_ok, content_sig)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                result.object_id, result.stripe as i64, p.rank as i64, p.generation as i64,
                p.uniform_gen as i64, participants, missing, outputs, p.trust_ok as i64, p.content_sig
            ],
        )?;
        for e in &p.bitflip_evidence {
            tx.execute(
                "INSERT INTO exclusions(object_id, stripe, plan_rank, raw_block_id, shard, reason, detail)
                 VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![result.object_id, result.stripe as i64, p.rank as i64, e.raw_block_id,
                        e.shard as i64, e.reason, e.detail],
            )?;
        }
    }
    let trusted = result.plans.iter().any(|p| p.trust_ok);
    let chosen = result.plans.first().map(|p| p.rank as i64).unwrap_or(-1);
    tx.execute(
        "INSERT INTO stripe_reports(object_id, stripe, status, feasible_count, chosen_count,
                                    inspected_combos, truncated, trusted, committed,
                                    committed_gen, content_diverge)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
         ON CONFLICT(object_id, stripe) DO UPDATE SET
            status=excluded.status, feasible_count=excluded.feasible_count,
            chosen_count=excluded.chosen_count, inspected_combos=excluded.inspected_combos,
            truncated=excluded.truncated, trusted=excluded.trusted,
            committed=excluded.committed, committed_gen=excluded.committed_gen,
            content_diverge=excluded.content_diverge, updated_at=datetime('now')",
        params![
            result.object_id, result.stripe as i64, result.status,
            result.plans.len() as i64, chosen + 1, result.inspected_combos as i64,
            result.truncated as i64, trusted as i64, result.committed as i64,
            result.committed_generation.map(|g| g as i64), result.content_diverge as i64
        ],
    )?;
    tx.commit()?;
    Ok(())
}

/// 选择唯一可信方案：所有 trust_ok 方案内容签名必须一致，否则为内容分歧，拒绝提交。
fn select_committable(result: &StripeResult) -> Option<&Plan> {
    let trusted: Vec<&Plan> = result.plans.iter().filter(|p| p.trust_ok).collect();
    if trusted.is_empty() {
        return None;
    }
    let sig = &trusted[0].content_sig;
    if trusted.iter().any(|p| &p.content_sig != sig) {
        return None;
    }
    Some(trusted[0])
}

/// 提交一个 stripe：临时块写盘（由 FailGate 注入写失败）后在单事务中落库。
/// 临时块只在事务成功后可作为审计副本；最终读取只走 committed_blocks。
pub fn commit_stripe(
    db: &Db,
    staging_dir: &std::path::Path,
    result: &StripeResult,
    gate: &dyn FailGate,
) -> std::io::Result<bool> {
    let plan = match select_committable(result) {
        Some(p) => p,
        None => return Ok(false),
    };
    std::fs::create_dir_all(staging_dir)?;
    // 写每个重建/接收块的临时副本（原子落盘：tmp -> rename）
    let mut tmp_paths = Vec::new();
    for (shard, bytes) in &plan.full_blocks {
        let tmp = staging_dir.join(format!(
            "obj-{}__s{}__i{}__g{}.tmp",
            result.object_id, result.stripe, shard, plan.generation
        ));
        let final_tmp = staging_dir.join(format!(
            ".obj-{}__s{}__i{}__g{}.part",
            result.object_id, result.stripe, shard, plan.generation
        ));
        std::fs::write(&final_tmp, bytes)?;
        std::fs::rename(&final_tmp, &tmp)?;
        tmp_paths.push((tmp, shard, bytes));
    }

    // 注入点：模拟"部分写后进程中断"。
    gate.check(&result.object_id, result.stripe)?;

    {
        let mut conn = db.conn.lock().unwrap();
        let tx = conn.transaction().map_err(io_err)?;
        tx.execute("DELETE FROM committed_blocks WHERE object_id=?1 AND stripe=?2",
            rusqlite::params![result.object_id, result.stripe as i64]).map_err(io_err)?;
        tx.execute("DELETE FROM commits WHERE object_id=?1 AND stripe=?2",
            rusqlite::params![result.object_id, result.stripe as i64]).map_err(io_err)?;
        for (_shard_idx, shard, bytes) in &tmp_paths {
            let recomputed = sha256_hex(bytes);
            tx.execute(
                "INSERT INTO committed_blocks(object_id, stripe, shard, generation, bytes, recomputed)
                 VALUES (?1,?2,?3,?4,?5,?6)",
                rusqlite::params![result.object_id, result.stripe as i64, **shard as i64,
                                  plan.generation as i64, bytes, recomputed],
            ).map_err(io_err)?;
        }
        tx.execute(
            "INSERT INTO commits(object_id, stripe, generation, content_sig) VALUES (?1,?2,?3,?4)",
            rusqlite::params![result.object_id, result.stripe as i64,
                              plan.generation as i64, plan.content_sig],
        ).map_err(io_err)?;
        tx.execute(
            "UPDATE stripe_reports SET committed=1, committed_gen=?3,
                    trusted=1, chosen_count=?4, updated_at=datetime('now')
             WHERE object_id=?1 AND stripe=?2",
            rusqlite::params![result.object_id, result.stripe as i64, plan.generation as i64,
                              (plan.rank + 1) as i64],
        ).map_err(io_err)?;
        tx.commit().map_err(io_err)?;
    }

    // 事务成功后删除临时块（临时块不得被最终读取；staging 目录从不参与导入扫描）。
    for (tmp, _, _) in &tmp_paths {
        let _ = std::fs::remove_file(tmp);
    }
    Ok(true)
}

fn io_err(e: rusqlite::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e)
}

/// 启动/续跑校验：只复用摘要完整的已提交 stripe；任何缺块/摘要不符/编码不自洽都丢弃。
pub fn verify_committed_stripes(
    db: &Db,
    field: &Field,
    manifest: &ObjectManifest,
) -> rusqlite::Result<BTreeSet<usize>> {
    let mut valid = BTreeSet::new();
    let mut to_delete: Vec<usize> = Vec::new();
    {
        let conn = db.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT stripe, COUNT(*), MIN(recomputed) FROM committed_blocks
             WHERE object_id=?1 GROUP BY stripe ORDER BY stripe",
        )?;
        let stripes = stmt
            .query_map(params![manifest.object_id], |r| {
                Ok((r.get::<_, i64>(0)? as usize, r.get::<_, i64>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(stmt);
        for (stripe, cnt) in stripes {
            let mut blocks: BTreeMap<usize, Vec<u8>> = BTreeMap::new();
            {
                let mut q = conn.prepare(
                    "SELECT shard, bytes, recomputed FROM committed_blocks
                     WHERE object_id=?1 AND stripe=?2",
                )?;
                let rows = q.query_map(params![manifest.object_id, stripe as i64], |r| {
                    Ok((r.get::<_, i64>(0)? as usize, r.get::<_, Vec<u8>>(1)?, r.get::<_, String>(2)?))
                })?;
                for row in rows {
                    let (shard, bytes, recomputed) = row?;
                    if sha256_hex(&bytes) != recomputed {
                        to_delete.push(stripe);
                        blocks.clear();
                        break;
                    }
                    blocks.insert(shard, bytes);
                }
            }
            if blocks.is_empty() {
                continue;
            }
            let digest_complete = (0..manifest.n()).all(|s| {
                blocks
                    .get(&s)
                    .map(|b| {
                        manifest
                            .block_digests
                            .get(&stripe)
                            .and_then(|m| m.get(&s))
                            .map(|exp| exp.eq_ignore_ascii_case(&sha256_hex(b)))
                            .unwrap_or(true)
                    })
                    .unwrap_or(false)
            });
            let n = manifest.n();
            let self_consistent =
                cnt as usize == n && crate::gf256::verify_full_stripe(field, manifest.k, manifest.m, &blocks);
            if digest_complete && self_consistent {
                valid.insert(stripe);
            } else {
                to_delete.push(stripe);
            }
        }
    }
    if !to_delete.is_empty() {
        let mut conn = db.conn.lock().unwrap();
        let tx = conn.transaction()?;
        for stripe in &to_delete {
            tx.execute(
                "DELETE FROM committed_blocks WHERE object_id=?1 AND stripe=?2",
                params![manifest.object_id, *stripe as i64],
            )?;
            tx.execute(
                "DELETE FROM commits WHERE object_id=?1 AND stripe=?2",
                params![manifest.object_id, *stripe as i64],
            )?;
            tx.execute(
                "UPDATE stripe_reports SET committed=0, committed_gen=NULL,
                        updated_at=datetime('now') WHERE object_id=?1 AND stripe=?2",
                params![manifest.object_id, *stripe as i64],
            )?;
        }
        tx.commit()?;
    }
    Ok(valid)
}

/// 清理残留临时块（崩溃后 staging 中任何文件都不得被最终读取）。
pub fn sweep_staging(staging_dir: &std::path::Path) {
    if let Ok(rd) = std::fs::read_dir(staging_dir) {
        for entry in rd.flatten() {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

// ----------------------------- 对象级编排 -----------------------------

#[derive(Debug, Clone)]
pub struct RecoverOptions {
    pub budget: usize,
}

impl Default for RecoverOptions {
    fn default() -> Self {
        Self {
            budget: DEFAULT_COMBO_BUDGET,
        }
    }
}

/// 恢复对象全部 stripe。已有、摘要完整且自洽的已提交 stripe 直接复用。
pub fn recover_object(
    db: &Db,
    field: &Field,
    manifest: &ObjectManifest,
    staging_dir: &std::path::Path,
    opts: &RecoverOptions,
    gate: &dyn FailGate,
) -> std::io::Result<RecoverySummary> {
    let isolated: BTreeSet<String> =
        db.isolated_sources(&manifest.object_id).map_err(io_err)?.into_iter().collect();
    let reused = verify_committed_stripes(db, field, manifest).map_err(io_err)?;

    let mut summary = RecoverySummary::default();
    summary.stripes_total = manifest.stripe_count;
    summary.stripes_reused = reused.len();

    for stripe in 0..manifest.stripe_count {
        if reused.contains(&stripe) {
            summary.stripes_committed += 1;
            continue;
        }
        let loaded = load_candidates(db, manifest, stripe, &isolated).map_err(io_err)?;
        let mut result = analyze_stripe(field, manifest, stripe, loaded, opts.budget);
        persist_result(db, &result).map_err(io_err)?;
        let ok = commit_stripe(db, staging_dir, &result, gate)?;
        if ok {
            result.committed = true;
            result.committed_generation = select_committable(&result).map(|p| p.generation);
            summary.stripes_committed += 1;
            summary.stripes_rebuilt += 1;
            match result.status.as_str() {
                "already_complete" => {}
                _ => summary.stripes_rebuilt += 0,
            }
        } else if result.status == "unrecoverable" {
            summary.stripes_unrecoverable += 1;
        }
    }

    // 对象级可信判定：所有 stripe 已提交，且全部存在且 n 块齐全，对象摘要匹配。
    let blocks = load_all_committed(db, manifest).map_err(io_err)?;
    let all_committed = blocks.len() == manifest.stripe_count
        && blocks.values().all(|m| m.len() == manifest.n());
    if all_committed {
        // 按 stripe 顺序、每个 stripe 内数据块 0..k 顺序聚合，按 object_len 截断。
        let mut flat: Vec<Vec<u8>> = Vec::new();
        for s in 0..manifest.stripe_count {
            for i in 0..manifest.k {
                flat.push(blocks[&s][&i].clone());
            }
        }
        let recomputed = object_digest(&flat, manifest.object_len);
        summary.object_digest_recomputed = Some(recomputed.clone());
        summary.object_digest_expected = manifest.object_digest.clone();
        summary.object_trusted = match &manifest.object_digest {
            Some(exp) => exp.eq_ignore_ascii_case(&recomputed),
            None => true, // 未声明对象摘要时，逐块摘要+自洽即可信
        };
    }

    Ok(summary)
}

// ----------------------------- 查询辅助 -----------------------------

pub fn load_all_committed(
    db: &Db,
    manifest: &ObjectManifest,
) -> rusqlite::Result<BTreeMap<usize, BTreeMap<usize, Vec<u8>>>> {
    let conn = db.conn.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT stripe, shard, bytes FROM committed_blocks WHERE object_id=?1",
    )?;
    let rows = stmt.query_map(params![manifest.object_id], |r| {
        Ok((
            r.get::<_, i64>(0)? as usize,
            r.get::<_, i64>(1)? as usize,
            r.get::<_, Vec<u8>>(2)?,
        ))
    })?;
    let mut out: BTreeMap<usize, BTreeMap<usize, Vec<u8>>> = BTreeMap::new();
    for row in rows {
        let (s, i, b) = row?;
        out.entry(s).or_default().insert(i, b);
    }
    Ok(out)
}

#[derive(Debug, Clone, Serialize)]
pub struct StripeReportRow {
    pub stripe: usize,
    pub status: String,
    pub feasible_count: usize,
    pub chosen_count: usize,
    pub inspected_combos: usize,
    pub truncated: bool,
    pub trusted: bool,
    pub committed: bool,
    pub committed_gen: Option<u64>,
    pub content_diverge: bool,
}

pub fn list_stripe_reports(db: &Db, object_id: &str) -> rusqlite::Result<Vec<StripeReportRow>> {
    let conn = db.conn.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT stripe, status, feasible_count, chosen_count, inspected_combos, truncated,
                trusted, committed, committed_gen, content_diverge
         FROM stripe_reports WHERE object_id=?1 ORDER BY stripe",
    )?;
    let rows = stmt
        .query_map(params![object_id], |r| {
            Ok(StripeReportRow {
                stripe: r.get::<_, i64>(0)? as usize,
                status: r.get(1)?,
                feasible_count: r.get::<_, i64>(2)? as usize,
                chosen_count: r.get::<_, i64>(3)? as usize,
                inspected_combos: r.get::<_, i64>(4)? as usize,
                truncated: r.get::<_, i64>(5)? != 0,
                trusted: r.get::<_, i64>(6)? != 0,
                committed: r.get::<_, i64>(7)? != 0,
                committed_gen: r.get::<_, Option<i64>>(8)?.map(|v| v as u64),
                content_diverge: r.get::<_, i64>(9)? != 0,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

#[derive(Debug, Clone, Serialize)]
pub struct RawBlockRow {
    pub id: i64,
    pub stripe: usize,
    pub shard: usize,
    pub generation: u64,
    pub source: String,
    pub recalculated: String,
    pub attached_digest: Option<String>,
    pub origin_path: String,
    pub length: usize,
    pub kind: String,
}

pub fn list_raw_blocks(db: &Db, object_id: &str) -> rusqlite::Result<Vec<RawBlockRow>> {
    let conn = db.conn.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, stripe, shard, generation, source, recalculated, attached_digest,
                origin_path, length(bytes), kind
         FROM raw_blocks WHERE object_id=?1
         ORDER BY stripe, shard, generation DESC, source, id",
    )?;
    let rows = stmt
        .query_map(params![object_id], |r| {
            Ok(RawBlockRow {
                id: r.get(0)?,
                stripe: r.get::<_, i64>(1)? as usize,
                shard: r.get::<_, i64>(2)? as usize,
                generation: r.get::<_, i64>(3)? as u64,
                source: r.get(4)?,
                recalculated: r.get(5)?,
                attached_digest: r.get(6)?,
                origin_path: r.get(7)?,
                length: r.get::<_, i64>(8)? as usize,
                kind: r.get(9)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

#[derive(Debug, Clone, Serialize)]
pub struct PlanRow {
    pub rank: usize,
    pub generation: u64,
    pub uniform_gen: bool,
    pub participants: Vec<Participant>,
    pub missing: Vec<usize>,
    pub outputs: Vec<OutputInfo>,
    pub trust_ok: bool,
    pub content_sig: String,
    pub exclusions: Vec<(String, String)>,
}

pub fn list_plans(db: &Db, object_id: &str, stripe: usize) -> rusqlite::Result<Vec<PlanRow>> {
    let conn = db.conn.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT rank, generation, uniform_gen, participants, missing, outputs, trust_ok, content_sig
         FROM plans WHERE object_id=?1 AND stripe=?2 ORDER BY rank",
    )?;
    let mut out = Vec::new();
    let plans = stmt
        .query_map(params![object_id, stripe as i64], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)? as u64,
                r.get::<_, i64>(2)? != 0,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, i64>(6)? != 0,
                r.get::<_, String>(7)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(stmt);
    for (rank, generation, uniform_gen, participants, missing, outputs, trust_ok, content_sig) in plans {
        let participants: Vec<Participant> = serde_json::from_str(&participants).unwrap_or_default();
        let missing: Vec<usize> = serde_json::from_str(&missing).unwrap_or_default();
        let outputs: Vec<OutputInfo> = serde_json::from_str(&outputs).unwrap_or_default();
        let mut es = conn.prepare(
            "SELECT reason, detail FROM exclusions
             WHERE object_id=?1 AND stripe=?2 AND plan_rank=?3 ORDER BY id",
        )?;
        let exclusions = es
            .query_map(params![object_id, stripe as i64, rank as i64], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        out.push(PlanRow {
            rank: rank as usize,
            generation,
            uniform_gen,
            participants,
            missing,
            outputs,
            trust_ok,
            content_sig,
            exclusions,
        });
    }
    Ok(out)
}

#[derive(Debug, Clone, Serialize)]
pub struct ExclusionRow {
    pub plan_rank: Option<i64>,
    pub shard: Option<i64>,
    pub reason: String,
    pub detail: String,
}

pub fn list_pre_exclusions(db: &Db, object_id: &str, stripe: usize) -> rusqlite::Result<Vec<ExclusionRow>> {
    let conn = db.conn.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT plan_rank, shard, reason, detail FROM exclusions
         WHERE object_id=?1 AND stripe=?2 AND plan_rank IS NULL ORDER BY id",
    )?;
    let rows = stmt
        .query_map(params![object_id, stripe as i64], |r| {
            Ok(ExclusionRow {
                plan_rank: r.get(0)?,
                shard: r.get(1)?,
                reason: r.get(2)?,
                detail: r.get(3)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}
