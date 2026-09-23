//! 恢复引擎：健康判定、候选枚举（确定性排序 + 搜索预算）、
//! GF(256) 重建、证据链记录，以及按 stripe 的原子提交/续跑。

use crate::coding::{self, Available, CodingParams};
use crate::gf256::Gf;
use crate::model::{
    self, object_digest, shard_digest, stripe_digest, GenManifest, ImportManifest, ShardExpect,
};
use crate::storage::{BlobStore, Paths};
use rusqlite::{params, Connection};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// 默认搜索预算：每个 stripe 最多评估的“选 k 个候选”组合数。
pub const DEFAULT_SEARCH_BUDGET: usize = 4096;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Evidence {
    pub fragment_id: String,
    pub source: String,
    pub code: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Participant {
    pub fragment_id: String,
    pub source: String,
    pub shard_index: usize,
    pub shard_digest_hex: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ShardOutput {
    pub shard_index: usize,
    pub digest_hex: String,
    pub length: usize,
    pub reconstructed: bool,
    /// 非重建（直接采纳的健康块）时记录来源 fragment
    pub source_fragment_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StripeSolution {
    pub generation: u64,
    pub stripe: usize,
    pub k: usize,
    pub m: usize,
    pub participants: Vec<Participant>,
    pub excluded: Vec<Evidence>,
    pub unused_healthy: Vec<Participant>,
    pub outputs: Vec<ShardOutput>,
    pub stripe_digest_hex: String,
    pub combinations_tested: usize,
    pub budget_hit: bool,
    pub reused: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct StripeResult {
    pub stripe: usize,
    pub recoverable: bool,
    pub solutions: Vec<StripeSolution>,
    pub all_excluded: Vec<Evidence>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GenResult {
    pub generation: u64,
    pub object_digest_expected: String,
    pub object_digest_recomputed: Option<String>,
    pub object_digest_ok: Option<bool>,
    pub stripes: Vec<StripeResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ObjectReport {
    pub object_id: String,
    pub generations: Vec<GenResult>,
    pub isolated_sources: Vec<String>,
    pub search_budget: usize,
    pub combinations_tested: usize,
    pub committed_stripes: usize,
    pub total_stripes: usize,
}

#[derive(Debug, Clone)]
struct FragRow {
    fragment_id: String,
    source: String,
    shard_index: i64,
    length: i64,
    claimed: Option<String>,
    actual: String,
}

#[derive(Debug, Clone)]
struct Eligible {
    fragment_id: String,
    source: String,
    index: usize,
    digest: String,
    bytes: Vec<u8>,
    length: usize,
}

fn load_fragments(
    conn: &Connection,
    object_id: &str,
    generation: u64,
    stripe: usize,
    isolated: &BTreeSet<String>,
) -> Vec<FragRow> {
    let mut stmt = conn
        .prepare(
            "SELECT fragment_id, source, shard_index, length, claimed_digest_hex, actual_digest_hex
             FROM fragments
             WHERE object_id = ?1 AND generation = ?2 AND stripe = ?3
             ORDER BY shard_index, fragment_id",
        )
        .unwrap();
    let rows = stmt
        .query_map(params![object_id, generation as i64, stripe as i64], |r| {
            Ok(FragRow {
                fragment_id: r.get(0)?,
                source: r.get(1)?,
                shard_index: r.get(2)?,
                length: r.get(3)?,
                claimed: r.get(4)?,
                actual: r.get(5)?,
            })
        })
        .unwrap();
    rows.filter_map(|r| r.ok())
        .filter(|r| !isolated.contains(&r.source))
        .collect()
}

fn classify(
    paths: &Paths,
    expect_by_index: &BTreeMap<usize, ShardExpect>,
    rows: &[FragRow],
) -> (BTreeMap<usize, Vec<Eligible>>, Vec<Evidence>) {
    let mut eligible: BTreeMap<usize, Vec<Eligible>> = BTreeMap::new();
    let mut evidence = Vec::new();
    let mut seen_index: BTreeMap<usize, String> = BTreeMap::new();

    for row in rows {
        let index = row.shard_index as usize;
        let mut ev = |code: &str, detail: String| Evidence {
            fragment_id: row.fragment_id.clone(),
            source: row.source.clone(),
            code: code.to_string(),
            detail,
        };
        let expect = match expect_by_index.get(&index) {
            Some(e) => e,
            None => {
                evidence.push(ev("unknown_shard_index", format!("manifest 中无 shard {index}")));
                continue;
            }
        };
        if let Some(first) = seen_index.get(&index) {
            evidence.push(ev(
                "duplicate_shard_number",
                format!("shard {index} 编号重复，首见 fragment {first}"),
            ));
            continue;
        }
        let bytes = match std::fs::read(paths.fragment_bin(&row.fragment_id)) {
            Ok(b) => b,
            Err(e) => {
                evidence.push(ev("unreadable_fragment", format!("原始字节读取失败: {e}")));
                continue;
            }
        };
        if bytes.len() as i64 != row.length {
            evidence.push(ev(
                "db_length_mismatch",
                format!("登记长度 {} 与磁盘字节 {} 不符", row.length, bytes.len()),
            ));
            continue;
        }
        if bytes.len() != expect.length {
            evidence.push(ev(
                "length_mismatch",
                format!(
                    "shard {index} 实际长度 {}，manifest 要求 {}",
                    bytes.len(),
                    expect.length
                ),
            ));
            continue;
        }
        if shard_digest(&bytes) != row.actual {
            evidence.push(ev(
                "actual_digest_changed",
                "磁盘字节摘要与导入时记录不符（疑似部分写/篡改）".to_string(),
            ));
            continue;
        }
        if let Some(claimed) = &row.claimed {
            if claimed != &row.actual {
                evidence.push(ev(
                    "claimed_digest_mismatch",
                    format!("随块摘要与重算摘要不符，疑似位翻转/损坏"),
                ));
                continue;
            }
        }
        if expect.digest_hex != row.actual {
            evidence.push(ev(
                "manifest_digest_mismatch",
                format!("shard {index} 内容摘要与 manifest 版本不符"),
            ));
            continue;
        }
        seen_index.insert(index, row.fragment_id.clone());
        eligible.entry(index).or_default().push(Eligible {
            fragment_id: row.fragment_id.clone(),
            source: row.source.clone(),
            index,
            digest: row.actual.clone(),
            bytes,
            length: expect.length,
        });
    }
    (eligible, evidence)
}

/// 按字典序生成长度 k 的下标组合（下标在 0..len 内）。
fn index_combinations(len: usize, k: usize) -> Vec<Vec<usize>> {
    if k == 0 || k > len {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut cur: Vec<usize> = (0..k).collect();
    loop {
        out.push(cur.clone());
        let mut pos = k;
        loop {
            if pos == 0 {
                return out;
            }
            pos -= 1;
            if cur[pos] + (k - pos) < len {
                cur[pos] += 1;
                for q in (pos + 1)..k {
                    cur[q] = cur[q - 1] + 1;
                }
                break;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn solve_stripe_gen(
    gf: &Gf,
    paths: &Paths,
    gen: &GenManifest,
    stripe_no: usize,
    spec: &model::StripeSpec,
    rows: &[FragRow],
    budget: usize,
    total_tested: &mut usize,
    reused: bool,
) -> Option<StripeSolution> {
    let params = CodingParams { k: gen.k, m: gen.m };
    let expect: BTreeMap<usize, ShardExpect> = spec
        .shards
        .iter()
        .map(|s| (s.index, s.clone()))
        .collect();
    let (eligible, excluded) = classify(paths, &expect, rows);

    // 每个 shard 编号在同一 generation 下至多一个“与 manifest 一致”的内容候选。
    let mut chosen: Vec<&Eligible> = Vec::new();
    let mut indices: Vec<usize> = Vec::new();
    for (idx, cands) in &eligible {
        let winner = cands.first().unwrap();
        chosen.push(winner);
        indices.push(*idx);
    }
    if chosen.len() < params.k {
        return None;
    }
    let combos = index_combinations(chosen.len(), params.k);
    let mut tested_this = 0usize;
    let mut budget_hit = false;
    let mut witness: Option<(Vec<usize>, Vec<Vec<u8>>)> = None;

    for combo in combos {
        if tested_this >= budget {
            budget_hit = true;
            break;
        }
        tested_this += 1;
        *total_tested += 1;
        let avail: Vec<Available> = combo
            .iter()
            .map(|&ci| Available {
                index: chosen[ci].index,
                bytes: chosen[ci].bytes.clone(),
            })
            .collect();
        let shard_len = chosen[combo[0]].length;
        let rec = match coding::recover(&gf, params, shard_len, &avail) {
            Ok(r) => r,
            Err(_) => continue,
        };
        // 重算摘要并与 manifest 逐 shard 校验
        let mut ok = true;
        for (idx, data) in rec.iter().enumerate() {
            let exp = match expect.get(&idx) {
                Some(e) => e,
                None => {
                    ok = false;
                    break;
                }
            };
            if shard_digest(data) != exp.digest_hex {
                ok = false;
                break;
            }
        }
        if ok {
            witness = Some((combo, rec));
            break;
        }
    }

    let (combo, recovered) = witness?;
    let present: BTreeSet<usize> = indices.iter().copied().collect();
    let participants: Vec<Participant> = combo
        .iter()
        .map(|&ci| {
            let e = chosen[ci];
            Participant {
                fragment_id: e.fragment_id.clone(),
                source: e.source.clone(),
                shard_index: e.index,
                shard_digest_hex: e.digest.clone(),
            }
        })
        .collect();
    let used_ids: BTreeSet<String> = participants.iter().map(|p| p.fragment_id.clone()).collect();
    let unused_healthy: Vec<Participant> = chosen
        .iter()
        .filter(|e| !used_ids.contains(&e.fragment_id))
        .map(|e| Participant {
            fragment_id: e.fragment_id.clone(),
            source: e.source.clone(),
            shard_index: e.index,
            shard_digest_hex: e.digest.clone(),
        })
        .collect();
    let outputs: Vec<ShardOutput> = recovered
        .iter()
        .enumerate()
        .map(|(idx, data)| {
            let src = eligible
                .get(&idx)
                .and_then(|v| v.first())
                .map(|e| e.fragment_id.clone());
            ShardOutput {
                shard_index: idx,
                digest_hex: shard_digest(data),
                length: data.len(),
                reconstructed: !present.contains(&idx),
                source_fragment_id: if present.contains(&idx) { src } else { None },
            }
        })
        .collect();
    let sd = stripe_digest(&outputs.iter().map(|o| o.digest_hex.clone()).collect::<Vec<_>>());
    Some(StripeSolution {
        generation: gen.generation,
        stripe: stripe_no,
        k: gen.k,
        m: gen.m,
        participants,
        excluded,
        unused_healthy,
        outputs,
        stripe_digest_hex: sd,
        combinations_tested: tested_this,
        budget_hit,
        reused,
    })
}
