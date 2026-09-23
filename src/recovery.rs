//! 条带恢复核心：枚举可行候选集合（非先到先得）、重建缺块、记录被排除的损坏证据。
//!
//! 规则：
//! * 同 (generation, shard_idx) 可有多个内容候选；候选组合按 shard_idx 升序、
//!   fragment_id 升序枚举，组合排序完全确定，并受 SEARCH_BUDGET 限制。
//! * 候选必须自洽：来源未隔离、字节实际摘要==声明摘要、长度==shard_len。
//! * 每个 generation 独立枚举；至少 k 个不同 shard 编号才可行。
//! * 重建后用 RS 重算全部 n 块并与自洽候选核对，再计算对象摘要。
//! * 优先选择对象摘要与清单一致的候选；一致候选中按 generation 新 -> 编号最小 ->
//!   fragment_id 最小排序选 preferred。对象摘要都不匹配时仍保留全部可行重建。

use crate::digest::{object_digest, sha256_hex};
use crate::gf::ReedSolomon;
use crate::model::{EvidenceKind, FragmentRow, ManifestVersion, StripeStatus};
use crate::store::Store;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// 枚举组合数预算（确定性搜索预算）。
pub const SEARCH_BUDGET: usize = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExcludedEvidence {
    pub fragment_id: i64,
    pub shard_idx: i64,
    pub generation: i64,
    pub source_name: String,
    pub kind: String,
    pub detail: String,
    pub claimed_digest: String,
    pub actual_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateMember {
    pub shard_idx: i64,
    pub fragment_ids: Vec<i64>,
    pub digest: String,
}

#[derive(Debug, Clone)]
pub struct Candidate {
    pub candidate_id: String,
    pub generation: i64,
    pub members: Vec<CandidateMember>,
    pub missing_shards: Vec<i64>,
    /// 重建（含直接采用）后的全部数据分片字节，键为 shard 编号。
    pub rebuilt_data: BTreeMap<i64, Vec<u8>>,
    pub rebuilt_digests: BTreeMap<i64, String>,
    pub object_digest: String,
    pub object_digest_ok: bool,
    /// 本 stripe 重算的每块摘要是否全部匹配清单期望。
    pub shard_digests_ok: bool,
    pub preferred: bool,
    pub differences: Vec<String>,
    pub excluded: Vec<ExcludedEvidence>,
}

/// 数据库行反序列化用的扁平结构。
#[derive(Debug, Clone)]
pub struct StoredCandidate {
    pub candidate_id: String,
    pub generation: i64,
    pub members_json: String,
    pub missing_json: String,
    pub rebuilt_json: String,
    pub rebuilt_digests_json: String,
    pub object_digest: String,
    pub object_digest_ok: bool,
    /// 本 stripe 重算的每块摘要是否全部匹配清单期望。
    pub shard_digests_ok: bool,
    pub preferred: bool,
    pub differences_json: String,
    pub excluded_json: String,
}

#[derive(Debug, Clone)]
pub struct ShardGroup {
    pub generation: i64,
    pub shard_idx: i64,
    /// 自洽候选：(fragment_id, digest)，按 fragment_id 升序。
    pub eligible: Vec<(i64, String)>,
    pub bytes: BTreeMap<i64, Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct Enumeration {
    pub status: StripeStatus,
    pub candidates: Vec<Candidate>,
    pub exclusions: Vec<ExcludedEvidence>,
    pub available_shards: i64,
}

fn ev_kind(k: EvidenceKind) -> String {
    serde_json::to_string(&k).unwrap().trim_matches('"').to_string()
}

/// 枚举单条 stripe 的全部可行重建。
pub fn enumerate_stripe(
    store: &Store,
    object_id: &str,
    stripe_idx: i64,
    version: &ManifestVersion,
    fragments: Vec<FragmentRow>,
    target_generation: i64,
) -> Enumeration {
    let k = version.k as usize;
    let m = version.m as usize;
    let n = k + m;
    let shard_len = version.shard_len as usize;
    let mut exclusions: Vec<ExcludedEvidence> = Vec::new();

    // 1) 逐块评估证据。旧 generation 记为 STALE 证据，仍进入各自 generation 的枚举。
    let mut by_key: BTreeMap<(i64, i64), Vec<FragmentRow>> = BTreeMap::new();
    for f in fragments {
        if f.isolated {
            exclusions.push(evidence(
                &f,
                EvidenceKind::SourceIsolated,
                format!("来源 '{}' 已被人工隔离", f.source_name),
            ));
            continue;
        }
        if f.generation != target_generation {
            exclusions.push(evidence(
                &f,
                EvidenceKind::StaleGeneration,
                format!(
                    "碎片 generation {}，目标 generation {}（旧版本候选仍单独枚举）",
                    f.generation, target_generation
                ),
            ));
        }
        if f.length as usize != shard_len {
            exclusions.push(evidence(
                &f,
                EvidenceKind::LengthMismatch,
                format!("实际长度 {}，清单要求 {}", f.length, shard_len),
            ));
            continue;
        }
        if f.actual_digest != f.claimed_digest {
            exclusions.push(evidence(
                &f,
                EvidenceKind::DigestMismatch,
                format!(
                    "随附声明 {}，实际重算 {}（疑似位翻转）",
                    f.claimed_digest, f.actual_digest
                ),
            ));
            continue;
        }
        if let Some(exp) = &f.expected_digest {
            if &f.actual_digest != exp {
                exclusions.push(evidence(
                    &f,
                    EvidenceKind::DigestMismatch,
                    format!("实际摘要 {} 与清单期望 {} 不符", f.actual_digest, exp),
                ));
                continue;
            }
        }
        by_key.entry((f.generation, f.shard_idx)).or_default().push(f);
    }

    // 2) 同编号多内容候选 -> 全部保留为可枚举选项，并记录重复编号证据。
    let mut groups: Vec<ShardGroup> = Vec::new();
    for ((gen, shard_idx), mut fs) in by_key {
        fs.sort_by_key(|f| f.id);
        let mut digests_seen: BTreeMap<String, Vec<i64>> = BTreeMap::new();
        let mut bytes = BTreeMap::new();
        for f in &fs {
            digests_seen.entry(f.actual_digest.clone()).or_default().push(f.id);
        }
        if digests_seen.len() > 1 {
            for f in &fs {
                let others: Vec<String> = digests_seen
                    .iter()
                    .filter(|(d, _)| **d != f.actual_digest)
                    .map(|(d, ids)| format!("{}#frag{}", short(d), ids[0]))
                    .collect();
                exclusions.push(evidence(
                    f,
                    EvidenceKind::DuplicateIndex,
                    format!(
                        "shard {shard_idx} 编号重复，generation {gen} 存在 {} 个不同内容候选：{}",
                        digests_seen.len(),
                        others.join(", ")
                    ),
                ));
            }
        }
        let eligible: Vec<(i64, String)> = fs.iter().map(|f| (f.id, f.actual_digest.clone())).collect();
        for f in fs {
            if let Ok(b) = store.read_fragment_bytes(&f.byte_path) {
                bytes.insert(f.id, b);
            }
        }
        groups.push(ShardGroup { generation: gen, shard_idx, eligible, bytes });
    }
    groups.sort_by_key(|g| (g.generation, g.shard_idx));

    // 3) 逐 generation 枚举（同一 generation 的编码参数一致）。
    let gens: Vec<i64> = {
        let mut g: Vec<i64> = groups.iter().map(|x| x.generation).collect();
        g.sort_unstable();
        g.dedup();
        g
    };
    let mut raw: Vec<Candidate> = Vec::new();
    let mut available = 0i64;
    for gen in gens {
        let gen_groups: Vec<ShardGroup> = groups.iter().filter(|g| g.generation == gen).cloned().collect();
        if gen == target_generation {
            available = gen_groups.len() as i64;
        }
        if gen_groups.len() < k {
            continue;
        }
        for combo in combinations(&gen_groups, k, SEARCH_BUDGET) {
            if let Some(cand) = build_candidate(
                gen,
                stripe_idx,
                &combo,
                version,
                n,
                k,
                m,
                shard_len,
                &gen_groups,
                &mut exclusions,
            ) {
                raw.push(cand);
            }
        }
    }

    // 4) 去重（同 generation 下相同数据内容），保留参与者来源最丰富的记录。
    raw = dedup(raw);

    // 5) 标注差异。
    annotate_differences(&mut raw);

    // 6) 选择 preferred：优先逐块校验通过 + generation 最新（generation 是条带硬约束）。
    let verified_exists = raw.iter().any(|c| c.shard_digests_ok);
    let mut best_key: Option<(bool, i64, Vec<(i64, Vec<i64>)>, String)> = None;
    for c in &raw {
        let usable = c.shard_digests_ok || !verified_exists;
        if !usable {
            continue;
        }
        let key = (
            c.shard_digests_ok,
            -c.generation,
            c.members
                .iter()
                .map(|m| (m.shard_idx, m.fragment_ids.clone()))
                .collect::<Vec<_>>(),
            c.candidate_id.clone(),
        );
        if best_key.as_ref().map_or(true, |b| &key < b) {
            best_key = Some(key);
        }
    }
    if let Some(bk) = &best_key {
        for c in &mut raw {
            c.preferred = c.candidate_id == bk.3;
        }
    }

    // 7) 输出排序：preferred -> generation 新 -> 数据内容确定序。
    raw.sort_by(|a, b| {
        b.preferred
            .cmp(&a.preferred)
            .then(b.generation.cmp(&a.generation))
            .then(a.rebuilt_digests.cmp(&b.rebuilt_digests))
            .then(a.candidate_id.cmp(&b.candidate_id))
    });

    let status = if raw.iter().any(|c| c.preferred) {
        if raw.len() > 1 {
            StripeStatus::Ambiguous
        } else {
            StripeStatus::Recoverable
        }
    } else if raw.is_empty() {
        StripeStatus::Unrecoverable
    } else {
        StripeStatus::Ambiguous
    };

    // 证据排序确定。
    exclusions.sort_by(|a, b| {
        a.shard_idx
            .cmp(&b.shard_idx)
            .then(a.fragment_id.cmp(&b.fragment_id))
            .then(a.kind.cmp(&b.kind))
    });
    exclusions.dedup_by(|a, b| {
        a.fragment_id == b.fragment_id && a.kind == b.kind && a.detail == b.detail
    });

    Enumeration {
        status,
        candidates: raw,
        exclusions,
        available_shards: available,
    }
}

fn evidence(f: &FragmentRow, kind: EvidenceKind, detail: String) -> ExcludedEvidence {
    ExcludedEvidence {
        fragment_id: f.id,
        shard_idx: f.shard_idx,
        generation: f.generation,
        source_name: f.source_name.clone(),
        kind: ev_kind(kind),
        detail,
        claimed_digest: f.claimed_digest.clone(),
        actual_digest: f.actual_digest.clone(),
    }
}

fn short(d: &str) -> String {
    d.chars().take(8).collect()
}

/// 枚举选择：从各 shard 组中选 k 个不同编号（编号升序），每编号内逐一尝试候选内容。
/// 返回 (generation, shard_idx, fragment_id) 的确定性有序列表。
fn combinations(groups: &[ShardGroup], k: usize, budget: usize) -> Vec<Vec<(i64, i64, i64)>> {
    let idx_groups: Vec<Vec<usize>> = (0..groups.len()).collect::<Vec<_>>().windows(k).map(|w| w.to_vec()).collect();
    // k-of-groups.len() 的全部编号组合（升序），确定性生成。
    let mut index_combos: Vec<Vec<usize>> = Vec::new();
    fn rec(
        start: usize,
        need: usize,
        cur: &mut Vec<usize>,
        groups_len: usize,
        out: &mut Vec<Vec<usize>>,
        budget: usize,
    ) -> bool {
        if need == 0 {
            out.push(cur.clone());
            return out.len() < budget;
        }
        for i in start..=groups_len.saturating_sub(need) {
            cur.push(i);
            if !rec(i + 1, need - 1, cur, groups_len, out, budget) {
                return false;
            }
            cur.pop();
        }
        true
    }
    let mut cur = Vec::new();
    rec(0, k, &mut cur, groups.len(), &mut index_combos, budget);
    let _ = idx_groups;

    let mut results: Vec<Vec<(i64, i64, i64)>> = Vec::new();
    for idxs in index_combos {
        // 每个选中编号的候选内容做笛卡尔积；fragment_id 升序保证确定性。
        let options: Vec<&Vec<(i64, String)>> =
            idxs.iter().map(|&i| &groups[i].eligible).collect();
        let mut cart: Vec<Vec<(i64, i64)>> = vec![Vec::new()];
        for opts in &options {
            let mut next = Vec::new();
            for prefix in &cart {
                for (fid, dig) in opts.iter() {
                    let mut v = prefix.clone();
                    v.push((*fid, 0));
                    let _ = dig;
                    next.push(v);
                }
            }
            cart = next;
        }
        for choice in cart {
            if results.len() >= budget {
                return results;
            }
            let row: Vec<(i64, i64, i64)> = idxs
                .iter()
                .zip(choice)
                .map(|(&gi, (fid, _))| (groups[gi].generation, groups[gi].shard_idx, fid))
                .collect();
            results.push(row);
        }
    }
    results
}

#[allow(clippy::too_many_arguments)]
fn build_candidate(
    gen: i64,
    stripe_idx: i64,
    combo: &[(i64, i64, i64)],
    version: &ManifestVersion,
    n: usize,
    k: usize,
    m: usize,
    shard_len: usize,
    groups: &[ShardGroup],
    exclusions: &mut Vec<ExcludedEvidence>,
) -> Option<Candidate> {
    let rs = ReedSolomon::new(k, m);
    // 找到选中字节。
    let mut known: Vec<(usize, Vec<u8>)> = Vec::new();
    let mut members: Vec<CandidateMember> = Vec::new();
    for &(_g, shard_idx, fid) in combo {
        let group = groups.iter().find(|g| g.shard_idx == shard_idx)?;
        let bytes = group.bytes.get(&fid)?.clone();
        known.push((shard_idx as usize, bytes));
        let dig = group.eligible.iter().find(|(id, _)| *id == fid)?.1.clone();
        members.push(CandidateMember {
            shard_idx,
            fragment_ids: vec![fid],
            digest: dig,
        });
    }
    members.sort_by_key(|x| x.shard_idx);

    let data = rs.reconstruct(&known)?;

    // 用恢复出的数据重算全部 n 块（参与计算的 shard 与被重建的校验块均可核对）。
    let parity = rs.encode(&data);
    let mut all: BTreeMap<i64, Vec<u8>> = BTreeMap::new();
    for (i, b) in data.iter().enumerate() {
        all.insert(i as i64, b.clone());
    }
    for (i, b) in parity.iter().enumerate() {
        all.insert((k + i) as i64, b.clone());
    }

    // 交叉验证：已知分片必须与重算完全一致，否则记录证据并拒绝该集合。
    for (idx, bytes) in &known {
        if all.get(&(*idx as i64)).map(|v| v.as_slice()) != Some(bytes.as_slice()) {
            if let Some(g) = groups.iter().find(|g| g.shard_idx == *idx as i64) {
                if let Some((fid, _)) = g.eligible.first() {
                    // 组合内碎片在已知场景下与 RS 约束矛盾。
                    exclusions.push(ExcludedEvidence {
                        fragment_id: *fid,
                        shard_idx: *idx as i64,
                        generation: gen,
                        source_name: String::new(),
                        kind: ev_kind(EvidenceKind::RecomputeMismatch),
                        detail: "该集合重建结果与已知分片不一致，组合被拒绝".to_string(),
                        claimed_digest: String::new(),
                        actual_digest: String::new(),
                    });
                }
            }
            return None;
        }
    }

    let expected_row = version
        .shard_digests
        .get(stripe_idx as usize)
        .filter(|r| r.len() >= n);
    let mut rebuilt_digests: BTreeMap<i64, String> = BTreeMap::new();
    for (idx, b) in &all {
        if b.len() != shard_len {
            return None;
        }
        let dig = sha256_hex(b);
        if let Some(row) = expected_row {
            if row[*idx as usize] != dig {
                return None;
            }
        }
        rebuilt_digests.insert(*idx, dig);
    }

    // 对象摘要：跨 stripe，单 stripe 场景即本 stripe 数据。
    let data_pairs: Vec<(usize, &[u8])> = (0..k)
        .map(|i| (i, all.get(&(i as i64)).unwrap().as_slice()))
        .collect();
    let obj_dig = object_digest(&data_pairs);
    let object_digest_ok = obj_dig == version.object_digest;

    let present: std::collections::BTreeSet<i64> = known.iter().map(|(i, _)| *i as i64).collect();
    let missing_shards: Vec<i64> = (0..n as i64).filter(|i| !present.contains(i)).collect();

    let id_parts: Vec<String> = combo
        .iter()
        .map(|(g, s, f)| format!("g{g}h{s}f{f}"))
        .collect();
    let candidate_id = format!("gen{}-{}", gen, id_parts.join("-"));

    Some(Candidate {
        candidate_id,
        generation: gen,
        members,
        missing_shards,
        rebuilt_data: (0..k as i64).map(|i| (i, all[&i].clone())).collect(),
        rebuilt_digests,
        object_digest: obj_dig,
        object_digest_ok,
        shard_digests_ok: expected_row.is_some(),
        preferred: false,
        differences: Vec::new(),
        excluded: Vec::new(),
    })
}

fn dedup(mut cands: Vec<Candidate>) -> Vec<Candidate> {
    // 同 generation + 同重建数据内容视为同一答案。
    let mut best: BTreeMap<(i64, BTreeMap<i64, String>), Candidate> = BTreeMap::new();
    for c in cands.drain(..) {
        let key = (c.generation, c.rebuilt_digests.clone());
        best.entry(key)
            .and_modify(|e| {
                if c.members.len() > e.members.len()
                    || (c.members.len() == e.members.len() && c.candidate_id < e.candidate_id)
                {
                    *e = c.clone();
                }
            })
            .or_insert(c);
    }
    best.into_values().collect()
}

fn annotate_differences(cands: &mut [Candidate]) {
    if cands.len() < 2 {
        return;
    }
    for i in 0..cands.len() {
        let mut diffs = Vec::new();
        for j in 0..cands.len() {
            if i == j {
                continue;
            }
            let a = &cands[i];
            let b = &cands[j];
            if a.generation != b.generation {
                diffs.push(format!("与 {}: generation {} vs {}", b.candidate_id, a.generation, b.generation));
            }
            for (idx, dig) in &a.rebuilt_digests {
                if b.rebuilt_digests.get(idx) != Some(dig) {
                    diffs.push(format!("与 {}: shard {} 重建内容不同", b.candidate_id, idx));
                }
            }
            if a.object_digest != b.object_digest {
                diffs.push(format!("与 {}: 对象摘要不同", b.candidate_id));
            }
        }
        diffs.sort();
        diffs.dedup();
        cands[i].differences = diffs;
    }
}

// ================= 编排：枚举/提交/续跑 =================

use crate::store::Store as PodStore;
use rusqlite::params;
use std::io::Write;

/// 重新枚举并持久化某个 stripe（不提交）。
pub fn analyze_stripe(store: &PodStore, object_id: &str, stripe_idx: i64) -> rusqlite::Result<Enumeration> {
    let cur_gen = store.current_generation(object_id)?;
    let version = store.manifest_version(object_id, cur_gen)?;
    let fragments = store.fragments_for(object_id, stripe_idx)?;
    let en = enumerate_stripe(store, object_id, stripe_idx, &version, fragments, cur_gen);
    store.replace_reconstructions(object_id, stripe_idx, en.status, &en.candidates)?;
    Ok(en)
}

fn now_ms() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().to_string())
        .unwrap_or_default()
}

/// 写一个块到 tmp，fsync 后原子 rename 到 committed；返回相对路径。
/// STRIPE_RECOVERY_FAIL_AFTER_BYTES 环境变量用于测试磁盘写失败。
fn atomic_write_committed(
    store: &PodStore,
    object_id: &str,
    stripe_idx: i64,
    shard_idx: i64,
    generation: i64,
    bytes: &[u8],
) -> std::io::Result<String> {
    if let Ok(limit) = std::env::var("STRIPE_RECOVERY_FAIL_AFTER_BYTES") {
        if let Ok(n) = limit.parse::<u64>() {
            let written: u64 = std::fs::read_dir(store.committed_dir())
                .map(|rd| {
                    rd.flatten()
                        .filter_map(|e| e.metadata().ok())
                        .map(|m| m.len())
                        .sum()
                })
                .unwrap_or(0);
            if written + bytes.len() as u64 > n {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "injected disk write failure",
                ));
            }
        }
    }
    let digest = sha256_hex(bytes);
    let fname = format!(
        "{}.g{}.s{}.h{}.{}.bin",
        object_id.replace('/', "_"),
        generation,
        stripe_idx,
        shard_idx,
        &digest[..16]
    );
    let tmp = store.tmp_dir().join(format!(".{fname}.tmp-{}", std::process::id()));
    let dst = store.committed_dir().join(&fname);
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, &dst)?;
    Ok(format!("committed/{fname}"))
}

/// 提交一个 stripe（使用 preferred 候选）。已提交且摘要完整的 stripe 直接复用。
pub fn commit_stripe(store: &PodStore, object_id: &str, stripe_idx: i64) -> rusqlite::Result<CommitOutcome> {
    // 续跑：只复用已登记且摘要完整的 committed stripe。
    if store.is_stripe_committed(object_id, stripe_idx)? {
        let shards = store.committed_shards(object_id, stripe_idx)?;
        let gen = store.committed_generation(object_id, stripe_idx)?.unwrap_or(0);
        let mut ok = true;
        for (_h, dig, rel) in &shards {
            match std::fs::read(store.data_dir.join(rel)) {
                Ok(b) if sha256_hex(&b) == *dig => {}
                _ => {
                    ok = false;
                }
            }
        }
        if ok {
            return Ok(CommitOutcome::Reused { generation: gen, shards: shards.len() as i64 });
        }
    }

    let en = analyze_stripe(store, object_id, stripe_idx)?;
    let cand = match en.candidates.iter().find(|c| c.preferred) {
        Some(c) => c,
        None => {
            return Ok(CommitOutcome::Unrecoverable);
        }
    };

    // 1) 先写临时块并原子改名，逐块重新核对摘要。
    let mut written: Vec<(i64, String, String)> = Vec::new();
    for (shard_idx, bytes) in &cand.rebuilt_data {
        let rel = atomic_write_committed(
            store,
            object_id,
            stripe_idx,
            *shard_idx,
            cand.generation,
            bytes,
        )
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        let back = std::fs::read(store.data_dir.join(&rel))
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        let dig = sha256_hex(&back);
        if dig != cand.rebuilt_digests[shard_idx] {
            // 绝不登记摘要不完整的输出。
            let _ = std::fs::remove_file(store.data_dir.join(&rel));
            return Ok(CommitOutcome::DigestFailure);
        }
        written.push((*shard_idx, dig, rel));
    }

    // 2) 元数据事务提交。若此步前崩溃：文件成为孤儿，启动清理移除。
    store.commit_stripe_metadata(
        object_id,
        stripe_idx,
        cand.generation,
        &cand.candidate_id,
        &written,
    )?;
    Ok(CommitOutcome::Committed {
        generation: cand.generation,
        shards: written.len() as i64,
    })
}

#[derive(Debug, Clone)]
pub enum CommitOutcome {
    Committed { generation: i64, shards: i64 },
    Reused { generation: i64, shards: i64 },
    Unrecoverable,
    DigestFailure,
}

/// 全对象恢复：逐 stripe 提交；遇到错误中断，返回已提交进度。
pub fn recover_object(store: &PodStore, object_id: &str) -> rusqlite::Result<RecoverySummary> {
    let cur_gen = store.current_generation(object_id)?;
    let version = store.manifest_version(object_id, cur_gen)?;
    let total = version.stripe_count;
    let run_id = store.start_run(total, &now_ms())?;
    let mut committed = 0i64;
    for s in 0..total {
        match commit_stripe(store, object_id, s) {
            Ok(CommitOutcome::Committed { .. }) | Ok(CommitOutcome::Reused { .. }) => {
                committed += 1;
                store.update_run_progress(run_id, committed)?;
            }
            Ok(CommitOutcome::Unrecoverable) => {
                store.finish_run(
                    run_id,
                    crate::model::RunStatus::Interrupted,
                    &now_ms(),
                    Some(s),
                    Some(&format!("stripe {s} 无可行重建，按 stripe 中断")),
                )?;
                return Ok(RecoverySummary {
                    run_id,
                    total,
                    committed,
                    failed_stripe: Some(s),
                    error: Some(format!("stripe {s} 无可行重建")),
                });
            }
            Ok(CommitOutcome::DigestFailure) => {
                store.finish_run(
                    run_id,
                    crate::model::RunStatus::Failed,
                    &now_ms(),
                    Some(s),
                    Some(&format!("stripe {s} 提交后摘要校验失败")),
                )?;
                return Ok(RecoverySummary {
                    run_id,
                    total,
                    committed,
                    failed_stripe: Some(s),
                    error: Some("摘要校验失败".into()),
                });
            }
            Err(e) => {
                store.finish_run(
                    run_id,
                    crate::model::RunStatus::Failed,
                    &now_ms(),
                    Some(s),
                    Some(&e.to_string()),
                )?;
                return Err(e);
            }
        }
    }
    store.finish_run(run_id, crate::model::RunStatus::Complete, &now_ms(), None, None)?;
    Ok(RecoverySummary {
        run_id,
        total,
        committed,
        failed_stripe: None,
        error: None,
    })
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RecoverySummary {
    pub run_id: i64,
    pub total: i64,
    pub committed: i64,
    pub failed_stripe: Option<i64>,
    pub error: Option<String>,
}

/// 隔离（或解除隔离）来源后，标记受影响 stripe 需要重算。
pub fn set_isolation_and_invalidate(store: &PodStore, source: &str, isolated: bool) -> rusqlite::Result<usize> {
    let n = store.set_source_isolated(source, isolated)?;
    if isolated {
        // 找到该来源参与过且已提交的 stripe：标 needs_recompute（committed_shards 保留可追溯）。
        let conn = store.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT DISTINCT f.object_id, f.stripe_idx
             FROM fragments f JOIN sources s ON s.id=f.source_id
             WHERE s.name=?1",
        )?;
        let pairs: Vec<(String, i64)> = stmt
            .query_map(params![source], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        drop(stmt);
        drop(conn);
        for (obj, stripe) in pairs {
            if store.is_stripe_committed(&obj, stripe)? {
                store.mark_needs_recompute(&obj, stripe)?;
            }
            // 重算枚举（新证据/候选立即可见）。
            let _ = analyze_stripe(store, &obj, stripe);
        }
    }
    Ok(n)
}
