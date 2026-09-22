//! 应用编排：分析、提交、来源隔离、导出所需的查询与操作。

use crate::commit::{commit_stripe, sha256_hex, stripe_digest, verify_committed};
use crate::db::Store;
use crate::gf::GfField;
use crate::model::{EncodingParamsV1, ShardHealth, StripeState};
use crate::recovery::{enumerate, Candidate, FeasibleOutcome};
use rusqlite::params;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::PathBuf;

/// 确定性搜索预算：每 stripe 至多尝试的 >=k 组合数。
pub const SEARCH_BUDGET: usize = 4096;

#[derive(Debug, Clone)]
pub struct ObjectRow {
    pub object_id: String,
    pub params: EncodingParamsV1,
    pub stripe_len: usize,
    pub stripe_count: usize,
    pub object_digest: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ShardRow {
    pub id: i64,
    pub stripe_idx: usize,
    pub shard_idx: usize,
    pub generation: u64,
    pub source: String,
    pub claimed_len: usize,
    pub actual_len: usize,
    pub claimed_digest: Option<String>,
    pub actual_digest: String,
    pub health: ShardHealth,
    pub bytes_path: String,
}

impl ShardRow {
    pub fn bytes(&self) -> std::io::Result<Vec<u8>> {
        std::fs::read(&self.bytes_path)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ParticipantReport {
    pub shard_id: i64,
    pub position: usize,
    pub generation: u64,
    pub source: String,
    pub role: String, // data / parity
    pub health: String,
    pub recomputed_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExcludedReport {
    pub shard_id: i64,
    pub position: usize,
    pub generation: u64,
    pub source: String,
    pub reason: String,
    pub claimed_sha256: Option<String>,
    pub recomputed_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ShardReport {
    pub shard_id: i64,
    pub position: usize,
    pub generation: u64,
    pub source: String,
    pub health: String,
    pub role: String,
    pub recomputed_sha256: String,
    pub status: String, // participating / consistent-redundant / excluded
    pub reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RankedSolution {
    pub solution_id: Option<i64>,
    pub rank: usize,
    pub data_digest: String,
    pub stripe_digest: String,
    pub matches_stripe_digest: bool,
    pub mix_level: usize,
    pub min_generation: u64,
    pub excluded_count: usize,
    pub full: Vec<Vec<u8>>,
    pub participating_ids: BTreeSet<i64>,
    pub participants: Vec<ParticipantReport>,
    pub excluded: Vec<ExcludedReport>,
    pub reports: Vec<ShardReport>,
    pub diff_positions: Vec<usize>,
}

pub struct AnalysisOutcome {
    pub state: StripeState,
    pub feasible_count: usize,
    pub visited: usize,
    pub truncated: bool,
    pub solutions: Vec<RankedSolution>,
}

// ---------- 查询 ----------

pub fn list_objects(store: &Store) -> Vec<ObjectRow> {
    let conn = store.conn.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT object_id, params_json, stripe_len, stripe_count, object_digest
             FROM objects ORDER BY object_id",
        )
        .unwrap();
    stmt.query_map([], |r| {
        let pj: String = r.get(1)?;
        Ok(ObjectRow {
            object_id: r.get(0)?,
            params: serde_json::from_str(&pj).unwrap(),
            stripe_len: r.get::<_, i64>(2)? as usize,
            stripe_count: r.get::<_, i64>(3)? as usize,
            object_digest: r.get(4)?,
        })
    })
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

pub fn get_object(store: &Store, object_id: &str) -> Option<ObjectRow> {
    list_objects(store).into_iter().find(|o| o.object_id == object_id)
}

pub fn list_shards(store: &Store, object_id: &str) -> Vec<ShardRow> {
    let conn = store.conn.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, stripe_idx, shard_idx, generation, source, claimed_len, actual_len,
                    claimed_digest, actual_digest, health, bytes_path
             FROM shards WHERE object_id=?1
             ORDER BY stripe_idx, shard_idx, generation DESC, source, id",
        )
        .unwrap();
    stmt.query_map(params![object_id], |r| {
        Ok(ShardRow {
            id: r.get(0)?,
            stripe_idx: r.get::<_, i64>(1)? as usize,
            shard_idx: r.get::<_, i64>(2)? as usize,
            generation: r.get::<_, i64>(3)? as u64,
            source: r.get(4)?,
            claimed_len: r.get::<_, i64>(5)? as usize,
            actual_len: r.get::<_, i64>(6)? as usize,
            claimed_digest: r.get(7)?,
            actual_digest: r.get(8)?,
            health: ShardHealth::code(r.get::<_, i64>(9)?),
            bytes_path: r.get(10)?,
        })
    })
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

pub fn expected_digest(store: &Store, object_id: &str, stripe_idx: usize) -> Option<String> {
    let conn = store.conn.lock().unwrap();
    conn.query_row(
        "SELECT digest FROM stripe_expected WHERE object_id=?1 AND stripe_idx=?2",
        params![object_id, stripe_idx as i64],
        |r| r.get::<_, String>(0),
    )
    .ok()
}

pub fn isolated_sources(store: &Store) -> BTreeSet<String> {
    let conn = store.conn.lock().unwrap();
    let mut stmt = conn.prepare("SELECT source FROM isolated_sources").unwrap();
    stmt.query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

pub fn set_source_isolated(store: &Store, source: &str, isolated: bool) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let conn = store.conn.lock().unwrap();
    if isolated {
        conn.execute(
            "INSERT OR IGNORE INTO isolated_sources(source, isolated_at) VALUES (?1,?2)",
            params![source, now],
        )
        .unwrap();
    } else {
        conn.execute("DELETE FROM isolated_sources WHERE source=?1", params![source])
            .unwrap();
    }
}

pub fn all_sources(store: &Store) -> Vec<(String, bool)> {
    let isolated = isolated_sources(store);
    let conn = store.conn.lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT DISTINCT source FROM shards ORDER BY source")
        .unwrap();
    let sources: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    sources
        .into_iter()
        .map(|s| {
            let iso = isolated.contains(&s);
            (s, iso)
        })
        .collect()
}

// ---------- 分析 ----------

struct BuiltOutcome {
    full: Vec<Vec<u8>>,
    participating_ids: BTreeSet<i64>,
    mix_level: usize,
    min_generation: u64,
    excluded_count: usize,
    data_digest: String,
    stripe_digest: String,
    matches_stripe_digest: bool,
    participants: Vec<ParticipantReport>,
    excluded: Vec<ExcludedReport>,
    reports: Vec<ShardReport>,
}

fn role_name(position: usize, k: usize) -> String {
    if position < k {
        "data".into()
    } else {
        "parity".into()
    }
}

fn build_outcome(
    outcome: &FeasibleOutcome,
    params: &EncodingParamsV1,
    rows: &[ShardRow],
    expected: Option<&str>,
    isolated: &HashSet<String>,
) -> BuiltOutcome {
    let by_id: BTreeMap<i64, &ShardRow> = rows.iter().map(|r| (r.id, r)).collect();
    let stripe_len = rows.first().map(|r| r.claimed_len).unwrap_or(0);
    let participating: BTreeSet<i64> = outcome.participating_ids.iter().copied().collect();

    let mut participants = Vec::new();
    for (p, c) in outcome
        .picked_positions
        .iter()
        .zip(outcome.participating_ids.iter())
    {
        let row = by_id[c];
        participants.push(ParticipantReport {
            shard_id: row.id,
            position: *p,
            generation: row.generation,
            source: row.source.clone(),
            role: role_name(*p, params.k),
            health: row.health.label().to_string(),
            recomputed_sha256: sha256_hex(&outcome.full[*p]),
        });
    }
    participants.sort_by_key(|r| r.position);

    let out_digest: BTreeMap<usize, String> = outcome
        .full
        .iter()
        .enumerate()
        .map(|(p, b)| (p, sha256_hex(b)))
        .collect();
    let reconstructed_digest: HashSet<String> = out_digest.values().cloned().collect();

    // 被排除的损坏证据：
    //  - 长度不符 / 摘要不符：结构性证据
    //  - 位置有候选但与本解输出字节不同：本解必须排除的矛盾证据
    let mut excluded = Vec::new();
    for row in rows {
        if participating.contains(&row.id) {
            continue;
        }
        let mut reason = None;
        if isolated.contains(&row.source) {
            reason = Some("来源已被人工隔离".to_string());
        } else if row.actual_len != stripe_len {
            reason = Some(format!(
                "长度不符：manifest 声明 {}，实际 {}",
                stripe_len, row.actual_len
            ));
        }
        if reason.is_none()
            && matches!(row.health, ShardHealth::DigestMismatch | ShardHealth::LengthMismatch)
        {
            reason = Some(match row.health {
                ShardHealth::DigestMismatch => format!(
                    "摘要不符（位翻转等）：声称 {}，重算 {}",
                    row.claimed_digest.clone().unwrap_or_default(),
                    row.actual_digest
                ),
                _ => format!(
                    "长度不符：manifest 声明 {}，实际 {}",
                    stripe_len, row.actual_len
                ),
            });
        }
        if reason.is_none() {
            if let Some(d) = out_digest.get(&row.shard_idx) {
                if d != &row.actual_digest {
                    reason = Some(format!(
                        "与本解位置 {} 输出矛盾：候选摘要 {}，本解重算 {}",
                        row.shard_idx, row.actual_digest, d
                    ));
                }
            }
        }
        if let Some(reason) = reason {
            excluded.push(ExcludedReport {
                shard_id: row.id,
                position: row.shard_idx,
                generation: row.generation,
                source: row.source.clone(),
                reason,
                claimed_sha256: row.claimed_digest.clone(),
                recomputed_sha256: row.actual_digest.clone(),
            });
        }
    }
    excluded.sort_by(|a, b| {
        a.position
            .cmp(&b.position)
            .then_with(|| a.shard_id.cmp(&b.shard_id))
    });

    // 每块报告：参与 / 一致但冗余 / 被排除。
    let mut reports = Vec::new();
    for row in rows {
        let (status, reason) = if participating.contains(&row.id) {
            ("participating", None)
        } else if let Some(e) = excluded.iter().find(|e| e.shard_id == row.id) {
            ("excluded", Some(e.reason.clone()))
        } else {
            ("consistent-redundant", None)
        };
        let mut health = row.health.label().to_string();
        if isolated.contains(&row.source) {
            health.push_str("（来源隔离）");
        }
        reports.push(ShardReport {
            shard_id: row.id,
            position: row.shard_idx,
            generation: row.generation,
            source: row.source.clone(),
            health,
            role: role_name(row.shard_idx, params.k),
            recomputed_sha256: row.actual_digest.clone(),
            status: status.into(),
            reason,
        });
    }
    // 对重建出来但没有任何候选的位置，也给出重算摘要行。
    for (p, digest) in &out_digest {
        let has = rows.iter().any(|r| r.shard_idx == *p);
        if !has {
            reports.push(ShardReport {
                shard_id: -1,
                position: *p,
                generation: 0,
                source: "（重新计算）".into(),
                health: "重算块".into(),
                role: role_name(*p, params.k),
                recomputed_sha256: digest.clone(),
                status: "recomputed".into(),
                reason: None,
            });
        }
    }
    reports.sort_by(|a, b| a.position.cmp(&b.position).then_with(|| a.shard_id.cmp(&b.shard_id)));
    let _ = reconstructed_digest;

    let mut data_concat = Vec::new();
    for b in &outcome.full[..params.k] {
        data_concat.extend_from_slice(b);
    }
    let data_digest = sha256_hex(&data_concat);
    let sdigest = stripe_digest(&outcome.full);
    let matches_expected = expected.map(|d| d.eq_ignore_ascii_case(&sdigest)).unwrap_or(false);

    let mut gens = outcome.generations.clone();
    gens.sort_unstable();
    gens.dedup();
    let min_generation = gens.first().copied().unwrap_or(0);
    let mix_level = if gens.len() <= 1 { 0 } else { gens.len() - 1 };

    BuiltOutcome {
        full: outcome.full.clone(),
        participating_ids: participating.clone(),
        mix_level,
        min_generation,
        excluded_count: excluded.len(),
        data_digest,
        stripe_digest: sdigest,
        matches_stripe_digest: matches_expected,
        participants,
        excluded,
        reports,
    }
}

pub fn analyze_stripe(
    store: &Store,
    obj: &ObjectRow,
    stripe_idx: usize,
    persist: bool,
) -> std::io::Result<AnalysisOutcome> {
    let isolated: HashSet<String> = isolated_sources(store).into_iter().collect();
    let field = GfField::new(obj.params.field_bits).map_err(io_other)?;

    let rows: Vec<ShardRow> = list_shards(store, &obj.object_id)
        .into_iter()
        .filter(|r| r.stripe_idx == stripe_idx)
        .collect();

    // 候选资格：长度匹配 manifest、摘要完整或无摘要、来源未隔离。
    // 摘要不符 / 长度不符的块从不进入枚举，只作为排除证据呈现。
    let mut by_pos: Vec<Vec<Candidate>> = vec![Vec::new(); obj.params.n()];
    for row in &rows {
        let eligible = row.actual_len == obj.stripe_len
            && !matches!(row.health, ShardHealth::DigestMismatch | ShardHealth::LengthMismatch)
            && !isolated.contains(&row.source);
        if eligible {
            by_pos[row.shard_idx].push(Candidate {
                shard_id: row.id,
                position: row.shard_idx,
                generation: row.generation,
                source: row.source.clone(),
                bytes: row.bytes()?,
                health: row.health as u8,
            });
        }
    }

    let enumeration =
        enumerate(&field, obj.params.k, obj.params.n(), by_pos, SEARCH_BUDGET).map_err(io_other)?;

    let expected = expected_digest(store, &obj.object_id, stripe_idx);
    let mut built: Vec<BuiltOutcome> = enumeration
        .outcomes
        .iter()
        .map(|o| build_outcome(o, &obj.params, &rows, expected.as_deref(), &isolated))
        .collect();

    // 去重：同一 stripe 输出只保留一条（参与集合最小的代表即可，
    // 冗余一致候选在 reports 中标记 consistent-redundant）。
    built.sort_by(|a, b| {
        a.stripe_digest
            .cmp(&b.stripe_digest)
            .then_with(|| a.participating_ids.len().cmp(&b.participating_ids.len()))
    });
    built.dedup_by(|a, b| a.stripe_digest == b.stripe_digest);

    // 确定性排序（generation 与 stripe 约束优先于排除数）：
    // 1) 与 manifest stripe 摘要一致优先
    // 2) generation 混杂程度更低优先（部分写混杂解排在纯净解之后）
    // 3) 最低 generation 更新者优先
    // 4) 排除损坏证据更少优先（同等 generation 下解释力更强）
    // 5) data 摘要字典序兜底
    built.sort_by(|a, b| {
        b.matches_stripe_digest
            .cmp(&a.matches_stripe_digest)
            .then_with(|| a.mix_level.cmp(&b.mix_level))
            .then_with(|| b.min_generation.cmp(&a.min_generation))
            .then_with(|| a.excluded_count.cmp(&b.excluded_count))
            .then_with(|| a.data_digest.cmp(&b.data_digest))
    });

    // 差异：各解相对榜首在哪些位置输出不同字节。
    let mut diffs: Vec<Vec<usize>> = vec![Vec::new(); built.len()];
    if let Some(best) = built.first() {
        for (i, o) in built.iter().enumerate().skip(1) {
            for p in 0..obj.params.n() {
                if o.full[p] != best.full[p] {
                    diffs[i].push(p);
                }
            }
        }
    }

    let existing = committed_solution_id(store, &obj.object_id, stripe_idx);
    let state = if built.is_empty() {
        if existing.is_some() {
            // 已提交目录本身决定状态，不应因分析变 unrecoverable；由 verify 决定。
            let dir = commit_dir(store, &obj.object_id, stripe_idx);
            if verify_committed(&dir).unwrap_or(false) {
                StripeState::Committed
            } else {
                StripeState::Broken
            }
        } else {
            StripeState::Unrecoverable
        }
    } else {
        StripeState::Solved
    };

    let mut solutions = Vec::new();
    for (i, b) in built.into_iter().enumerate() {
        solutions.push(RankedSolution {
            solution_id: None,
            rank: i,
            data_digest: b.data_digest,
            stripe_digest: b.stripe_digest,
            matches_stripe_digest: b.matches_stripe_digest,
            mix_level: b.mix_level,
            min_generation: b.min_generation,
            excluded_count: b.excluded_count,
            full: b.full,
            participating_ids: b.participating_ids,
            participants: b.participants,
            excluded: b.excluded,
            reports: b.reports,
            diff_positions: std::mem::take(&mut diffs[i]),
        });
    }

    if persist {
        persist_analysis(store, obj, stripe_idx, &state, &solutions, &enumeration)?;
    }

    Ok(AnalysisOutcome {
        state,
        feasible_count: solutions.len(),
        visited: enumeration.visited,
        truncated: enumeration.truncated,
        solutions,
    })
}

// ---------- 持久化 ----------

fn persist_analysis(
    store: &Store,
    obj: &ObjectRow,
    stripe_idx: usize,
    state: &StripeState,
    solutions: &[RankedSolution],
    enumeration: &crate::recovery::Enumeration,
) -> std::io::Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut conn = store.conn.lock().unwrap();
    let tx = conn.transaction().map_err(io_other)?;
    tx.execute("DELETE FROM solutions WHERE object_id=?1 AND stripe_idx=?2", params![obj.object_id, stripe_idx as i64])
        .map_err(io_other)?;
    let mut selected: Option<i64> = None;
    for (rank, sol) in solutions.iter().enumerate() {
        let participating_json = serde_json::to_string(&sol.participants).unwrap();
        let excluded_json = serde_json::to_string(&sol.excluded).unwrap();
        let reports_json = serde_json::to_string(&sol.reports).unwrap();
        let diff_json = serde_json::to_string(&sol.diff_positions).unwrap();
        tx.execute(
            "INSERT INTO solutions
             (object_id, stripe_idx, rank, data_digest, stripe_digest, matches_stripe_digest,
              mix_level, min_generation, excluded_count, participating_json, excluded_json,
              shard_reports_json, diff_json, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            params![
                obj.object_id,
                stripe_idx as i64,
                rank as i64,
                sol.data_digest,
                sol.stripe_digest,
                sol.matches_stripe_digest as i64,
                sol.mix_level as i64,
                sol.min_generation as i64,
                sol.excluded_count as i64,
                participating_json,
                excluded_json,
                reports_json,
                diff_json,
                now
            ],
        )
        .map_err(io_other)?;
        if rank == 0 {
            selected = Some(tx.last_insert_rowid());
        }
    }
    tx.execute(
        "INSERT INTO stripe_analysis
         (object_id, stripe_idx, state, feasible_count, search_budget, search_visited,
          search_truncated, selected_solution_id, analyzed_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)
         ON CONFLICT(object_id, stripe_idx) DO UPDATE SET
           state=excluded.state, feasible_count=excluded.feasible_count,
           search_budget=excluded.search_budget, search_visited=excluded.search_visited,
           search_truncated=excluded.search_truncated,
           selected_solution_id=excluded.selected_solution_id, analyzed_at=excluded.analyzed_at",
        params![
            obj.object_id,
            stripe_idx as i64,
            state_label(state),
            solutions.len() as i64,
            SEARCH_BUDGET as i64,
            enumeration.visited as i64,
            enumeration.truncated as i64,
            selected,
            now
        ],
    )
    .map_err(io_other)?;
    tx.commit().map_err(io_other)?;
    Ok(())
}

fn state_label(s: &StripeState) -> &'static str {
    match s {
        StripeState::Unrecoverable => "unrecoverable",
        StripeState::Solved => "solved",
        StripeState::Committed => "committed",
        StripeState::Broken => "broken",
    }
}

pub fn parse_state(s: &str) -> StripeState {
    match s {
        "committed" => StripeState::Committed,
        "broken" => StripeState::Broken,
        "solved" => StripeState::Solved,
        _ => StripeState::Unrecoverable,
    }
}

fn commit_dir(store: &Store, object_id: &str, stripe_idx: usize) -> PathBuf {
    store
        .commits_dir(object_id)
        .join(format!("stripe-{:06}", stripe_idx))
}

fn committed_solution_id(store: &Store, object_id: &str, stripe_idx: usize) -> Option<i64> {
    let conn = store.conn.lock().unwrap();
    conn.query_row(
        "SELECT solution_id FROM commits WHERE object_id=?1 AND stripe_idx=?2",
        params![object_id, stripe_idx as i64],
        |r| r.get::<_, i64>(0),
    )
    .ok()
}

#[derive(Debug, Clone, Serialize)]
pub struct StripeSummary {
    pub stripe_idx: usize,
    pub state: StripeState,
    pub feasible_count: usize,
    pub visited: usize,
    pub truncated: bool,
    pub committed_solution_id: Option<i64>,
    pub shard_total: usize,
    pub shard_verified: usize,
    pub shard_bad: usize,
    pub candidate_positions: usize,
}

pub fn stripe_summaries(store: &Store, obj: &ObjectRow) -> Vec<StripeSummary> {
    let isolated = isolated_sources(store);
    let all = list_shards(store, &obj.object_id);
    let conn = store.conn.lock().unwrap();
    (0..obj.stripe_count)
        .map(|idx| {
            let (state, feasible_count, visited, truncated, selected) = conn
                .query_row(
                    "SELECT state, feasible_count, search_visited, search_truncated, selected_solution_id
                     FROM stripe_analysis WHERE object_id=?1 AND stripe_idx=?2",
                    params![obj.object_id, idx as i64],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, i64>(1)? as usize,
                            r.get::<_, i64>(2)? as usize,
                            r.get::<_, i64>(3)? != 0,
                            r.get::<_, Option<i64>>(4)?,
                        ))
                    },
                )
                .unwrap_or_else(|_| ("new".to_string(), 0, 0, false, None));
            let rows: Vec<&ShardRow> = all.iter().filter(|r| r.stripe_idx == idx).collect();
            let shard_total = rows.len();
            let shard_verified = rows
                .iter()
                .filter(|r| matches!(r.health, ShardHealth::Verified | ShardHealth::Unverified))
                .count();
            let shard_bad = rows
                .iter()
                .filter(|r| matches!(r.health, ShardHealth::DigestMismatch | ShardHealth::LengthMismatch))
                .count();
            let candidate_positions = rows
                .iter()
                .filter(|r| {
                    r.actual_len == obj.stripe_len
                        && !matches!(r.health, ShardHealth::DigestMismatch | ShardHealth::LengthMismatch)
                        && !isolated.contains(&r.source)
                })
                .map(|r| r.shard_idx)
                .collect::<HashSet<_>>()
                .len();
            let mut st = parse_state(&state);
            if st == StripeState::Committed {
                let dir = commit_dir(store, &obj.object_id, idx);
                if !verify_committed(&dir).unwrap_or(false) {
                    st = StripeState::Broken;
                }
            }
            StripeSummary {
                stripe_idx: idx,
                state: st,
                feasible_count,
                visited,
                truncated,
                committed_solution_id: selected,
                shard_total,
                shard_verified,
                shard_bad,
                candidate_positions,
            }
        })
        .collect()
}

// ---------- 提交 / 导出 ----------

pub struct CommitResult {
    pub dir: PathBuf,
    pub manifest_digest: String,
    pub stripe_digest: String,
}

pub fn commit_solution(
    store: &Store,
    obj: &ObjectRow,
    stripe_idx: usize,
    rank: usize,
) -> std::io::Result<CommitResult> {
    // 用当前证据重新计算，绝不复用过期分析：先重算再提交指定名次的可行解。
    let outcome = analyze_stripe(store, obj, stripe_idx, true)?;
    let solution = outcome
        .solutions
        .get(rank)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "不存在该可行解"))?
        .clone();
    let out = commit_stripe(
        store,
        &obj.object_id,
        stripe_idx,
        &obj.params,
        solution.mix_level as u64,
        &solution.stripe_digest,
        &solution.participating_ids.iter().copied().collect::<Vec<_>>(),
        &solution.full,
    )?;

    let solution_id = {
        let conn = store.conn.lock().unwrap();
        conn.query_row(
            "SELECT id FROM solutions WHERE object_id=?1 AND stripe_idx=?2 AND rank=?3",
            params![obj.object_id, stripe_idx as i64, rank as i64],
            |r| r.get::<_, i64>(0),
        )
        .map_err(io_other)?
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    {
        let conn = store.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO commits(object_id, stripe_idx, solution_id, dir, manifest_digest, readback_ok, committed_at)
             VALUES (?1,?2,?3,?4,?5,1,?6)
             ON CONFLICT(object_id, stripe_idx) DO UPDATE SET
               solution_id=excluded.solution_id, dir=excluded.dir,
               manifest_digest=excluded.manifest_digest, readback_ok=1, committed_at=excluded.committed_at",
            params![
                obj.object_id,
                stripe_idx as i64,
                solution_id,
                out.dir.to_string_lossy(),
                out.manifest_digest,
                now
            ],
        )
        .map_err(io_other)?;
        conn.execute(
            "UPDATE stripe_analysis SET state='committed', selected_solution_id=?3
             WHERE object_id=?1 AND stripe_idx=?2",
            params![obj.object_id, stripe_idx as i64, solution_id],
        )
        .map_err(io_other)?;
    }
    Ok(CommitResult {
        dir: out.dir,
        manifest_digest: out.manifest_digest,
        stripe_digest: solution.stripe_digest,
    })
}

pub fn export_obj(store: &Store, obj: &ObjectRow) -> std::io::Result<crate::export::ExportResult> {
    crate::export::export_object(store, &obj.object_id, obj.stripe_count)
}

pub fn reanalyze_object(store: &Store, obj: &ObjectRow) -> std::io::Result<usize> {
    let mut solved = 0;
    for idx in 0..obj.stripe_count {
        if analyze_stripe(store, obj, idx, true)?.feasible_count > 0 {
            solved += 1;
        }
    }
    Ok(solved)
}

fn io_other<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
}
