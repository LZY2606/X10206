//! 恢复编排：先纯分析跨 stripe 组装对象结果，再按 stripe 原子提交。
//! 中断后续跑只复用"摘要完整"的已提交 stripe；tmp 下临时块绝不进入最终读取。

use crate::engine::{assemble_outcomes, Engine, DEFAULT_OBJECT_BUDGET};
use crate::model::*;
use crate::store::Store;
use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

fn now() -> String {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("unix:{}", ms)
}

fn unique_run_id(object_id: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("run_{}_{}_{}", object_id, ms, n)
}

#[derive(serde::Serialize)]
pub struct RecoveryProgress {
    pub run_id: String,
    pub stripes_total: usize,
    pub stripes_reused: usize,
    pub stripes_rebuilt: usize,
    pub outcomes: usize,
    pub primary_outcome_id: String,
    pub messages: Vec<String>,
}

pub fn load_manifest(store: &Store, object_id: &str) -> Result<Manifest, String> {
    let json = store
        .get_manifest_json(object_id)?
        .ok_or_else(|| format!("对象 {object_id} 不存在"))?;
    serde_json::from_str(&json).map_err(|e| e.to_string())
}

fn load_fragments(store: &Store, object_id: &str) -> Result<Vec<FragmentInput>, String> {
    let persisted = store.list_fragments(object_id)?;
    let mut out = Vec::new();
    for p in persisted {
        let bytes = store.read_raw(&p.rel_path)?;
        out.push(FragmentInput {
            fragment_id: p.fragment_id,
            object_id: p.object_id,
            stripe: p.stripe as usize,
            shard: p.shard as usize,
            generation: p.generation as u64,
            source: p.source,
            bytes,
            claimed_digest: p.claimed_digest,
            received_at: p.received_at,
        });
    }
    Ok(out)
}

/// 运行恢复。reuse=true 时复用摘要完整且解仍成立的已提交 stripe。
pub fn run_recovery(store: &Store, object_id: &str, reuse: bool) -> Result<RecoveryProgress, String> {
    store.clean_tmp()?;
    let manifest = load_manifest(store, object_id)?;
    let frags = load_fragments(store, object_id)?;
    let isolated = store.isolated_sources(object_id);
    let engine = Engine::new(&manifest)?;

    // 按 stripe 收集碎片。
    let mut by_stripe: Vec<Vec<FragmentInput>> = vec![Vec::new(); manifest.stripe_count];
    for f in frags {
        if f.stripe < manifest.stripe_count {
            by_stripe[f.stripe].push(f);
        }
    }

    // 纯分析。
    let analyses: Vec<StripeAnalysis> = by_stripe
        .iter()
        .enumerate()
        .map(|(s, fs)| {
            engine.analyze_stripe(object_id, s, manifest.stripe_length, fs, &isolated)
        })
        .collect();

    for a in &analyses {
        if a.solutions.is_empty() {
            return Err(format!(
                "stripe {} 不可恢复（健康度 below_threshold），{}",
                a.stripe,
                a.global_excluded
                    .iter()
                    .map(|e| e.detail.clone())
                    .collect::<Vec<_>>()
                    .join("；")
            ));
        }
    }

    let outcomes = assemble_outcomes(&manifest, &analyses, DEFAULT_OBJECT_BUDGET)?;

    // 保留结果涉及到的每个 stripe 的解集合（按结果顺序，去重）。
    let mut needed: Vec<BTreeSet<String>> = vec![BTreeSet::new(); manifest.stripe_count];
    for o in &outcomes {
        for (s, sid) in o.stripe_solutions.iter().enumerate() {
            needed[s].insert(sid.clone());
        }
    }

    let run_id = unique_run_id(object_id);
    store.start_run(&run_id, object_id, &now())?;

    let mut reused = 0usize;
    let mut rebuilt = 0usize;
    let mut messages = Vec::new();

    // 第二遍：按 stripe 提交块（先写 tmp 再提升，全部块就位后写 commit 行）。
    for (s, analysis) in analyses.iter().enumerate() {
        let needed_ids = &needed[s];
        let mut already_ok = false;
        if reuse {
            if let Some((primary_sid, analysis_json)) = store.get_stripe_commit(object_id, s) {
                if needed_ids.contains(&primary_sid) {
                    // 摘要完整性校验：所有需要的解的每个 shard 块都存在且摘要匹配。
                    let complete = needed_ids.iter().all(|sid| {
                        let sol = analysis.solutions.iter().find(|x| &x.solution_id == sid);
                        match sol {
                            None => false,
                            Some(sol) => sol.recomputed_shard_digests.iter().enumerate().all(
                                |(sh, digest)| {
                                    store
                                        .solution_block_digest(object_id, s, sid, sh)
                                        .as_deref()
                                        == Some(digest.as_str())
                                        && store.block_exists(digest)
                                },
                            ),
                        }
                    });
                    let _ = analysis_json;
                    if complete {
                        already_ok = true;
                    }
                }
            }
        }

        if already_ok {
            reused += 1;
            messages.push(format!("stripe {s}: 复用已提交 stripe（摘要完整）"));
            continue;
        }

        // 为每个需要的解写 shard 块。
        for sol in analysis.solutions.iter().filter(|x| needed_ids.contains(&x.solution_id)) {
            for (sh, bytes) in sol.shards.iter().enumerate() {
                let digest = &sol.recomputed_shard_digests[sh];
                if store.block_exists(digest) {
                    store.upsert_solution_block(object_id, s, &sol.solution_id, sh, digest)?;
                    continue;
                }
                let tmp_name = format!("{}_{}_{}.part", object_id, s, &sol.solution_id[..12]);
                let tmp = store.write_tmp_block(&tmp_name, bytes)?;
                let final_path = store.commit_block(&tmp, digest)?;
                let _ = final_path;
                store.upsert_solution_block(object_id, s, &sol.solution_id, sh, digest)?;
            }
        }

        let primary_sid = &outcomes[0].stripe_solutions[s];
        let analysis_json = serde_json::to_string(analysis).map_err(|e| e.to_string())?;
        store.put_stripe_commit(object_id, s, &run_id, primary_sid, &analysis_json, &now())?;
        rebuilt += 1;
        messages.push(format!("stripe {s}: 已重建并原子提交"));
    }

    // 持久化对象结果（不含字节，只存元信息；字节由提交块按需拼接）。
    let outcome_rows: Vec<(String, String)> = outcomes
        .iter()
        .map(|o| {
            let meta = serde_json::json!({
                "outcome_id": o.outcome_id,
                "stripe_solutions": o.stripe_solutions,
                "generations": o.generations,
                "mixed_generation": o.mixed_generation,
                "object_digest": o.object_digest,
                "digest_matches_manifest": o.digest_matches_manifest,
                "diff_stripes_vs_first": o.diff_stripes_vs_first,
                "length": o.bytes.len(),
            });
            (o.outcome_id.clone(), meta.to_string())
        })
        .collect();
    store.replace_outcomes(object_id, &outcome_rows)?;

    let detail = format!("reused={reused} rebuilt={rebuilt} outcomes={}", outcomes.len());
    store.finish_run(&run_id, "ok", &detail, &now())?;

    // 提交完成后清理 tmp（确保临时块不遗留、不被最终读取）。
    store.clean_tmp()?;

    Ok(RecoveryProgress {
        run_id,
        stripes_total: manifest.stripe_count,
        stripes_reused: reused,
        stripes_rebuilt: rebuilt,
        outcomes: outcomes.len(),
        primary_outcome_id: outcomes[0].outcome_id.clone(),
        messages,
    })
}
