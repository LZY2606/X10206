//! Recovery engine: enumerates feasible candidate sets per stripe under
//! generation / digest / stripe constraints, commits per stripe, and
//! assembles whole-object solutions. All ordering is deterministic and the
//! combinatorial search is bounded by a budget.

use crate::model::*;
use crate::rs::Coder;
use crate::store::Store;
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct RecoveryConfig {
    /// Max candidate selections evaluated per stripe / max object assemblies.
    pub budget: usize,
    /// Test hook: simulate a crash after this many stripe commits.
    pub fail_after_commits: Option<usize>,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        RecoveryConfig { budget: 4096, fail_after_commits: None }
    }
}

#[derive(Clone, Debug)]
pub struct RecoveryReport {
    pub object_id: String,
    pub run_id: i64,
    pub status: String,
    pub computed_stripes: Vec<usize>,
    pub reused_stripes: Vec<usize>,
    pub stripes: Vec<StripeState>,
    pub solutions: Vec<ObjectSolution>,
    pub budget_exceeded: bool,
    pub notes: Vec<String>,
}

#[derive(Clone)]
struct Candidate {
    shard: ShardRecord,
    fragment: Vec<u8>,
}

/// Classify shard health against the manifest and persist it.
pub fn classify_shards(store: &Store, m: &Manifest) -> Result<Vec<ShardRecord>, String> {
    let shards = store.shards_for(&m.object_id).map_err(|e| e.to_string())?;
    for s in &shards {
        let health = if s.health == ShardHealth::Quarantined {
            ShardHealth::Quarantined
        } else if s.bytes.len() != m.shard_bytes {
            ShardHealth::LengthMismatch
        } else if let Some(d) = &m.shard_digests {
            if s.idx < d.len() && d[s.idx] != s.digest {
                ShardHealth::DigestMismatch
            } else {
                ShardHealth::Ok
            }
        } else {
            ShardHealth::Ok
        };
        if health != s.health && health != ShardHealth::Quarantined {
            store.set_shard_health(s.id, health.clone()).map_err(|e| e.to_string())?;
        }
    }
    store.shards_for(&m.object_id).map_err(|e| e.to_string())
}

/// Enumerate feasible reconstructions for one stripe. Deterministic order;
/// stops after `budget` selections and reports budget exhaustion.
fn enumerate_stripe(
    coder: &Coder,
    candidates: &BTreeMap<usize, Vec<Candidate>>,
    corrupt_evidence: &[ExcludedEvidence],
    budget: usize,
) -> (Vec<StripeAlternative>, bool) {
    let n = coder.params.total();
    let k = coder.params.k;
    // Option lists per index: candidates (already deterministically ordered),
    // then "absent". Index 0 is the most significant odometer digit.
    let mut options: Vec<Vec<Option<usize>>> = Vec::with_capacity(n);
    for idx in 0..n {
        let mut opts: Vec<Option<usize>> = match candidates.get(&idx) {
            Some(list) => (0..list.len()).map(Some).collect(),
            None => Vec::new(),
        };
        opts.push(None);
        options.push(opts);
    }
    let total: usize = options.iter().map(|o| o.len()).product();
    let mut alternatives: Vec<StripeAlternative> = Vec::new();
    let mut seen_rows: BTreeMap<String, usize> = BTreeMap::new();
    let mut evaluated = 0usize;
    let mut exhausted = false;

    'outer: for combo in 0..total {
        let mut rem = combo;
        let mut present: Vec<(usize, &Candidate)> = Vec::new();
        for idx in (0..n).rev() {
            let pick = rem % options[idx].len();
            rem /= options[idx].len();
            if let Some(ci) = options[idx][pick] {
                present.push((idx, &candidates[&idx][ci]));
            }
        }
        present.reverse();
        if present.len() < k {
            continue;
        }
        evaluated += 1;
        if evaluated > budget {
            exhausted = true;
            break 'outer;
        }
        let frags: Vec<(usize, Vec<u8>)> =
            present.iter().map(|(i, c)| (*i, c.fragment.clone())).collect();
        let row = match coder.decode(&frags) {
            Ok(r) => r,
            Err(_) => continue,
        };
        // Stripe constraint: every selected fragment must lie on the row.
        if present.iter().any(|(i, c)| row[*i] != c.fragment) {
            continue;
        }
        let flat: Vec<u8> = row.concat();
        let row_digest = sha256_hex(&flat);
        if let Some(&pos) = seen_rows.get(&row_digest) {
            alternatives[pos].equivalent_sets += 1;
            continue;
        }
        seen_rows.insert(row_digest.clone(), alternatives.len());
        let participants: Vec<Participant> = present
            .iter()
            .map(|(i, c)| Participant {
                shard_id: c.shard.id,
                idx: *i,
                generation: c.shard.generation,
                source: c.shard.source.clone(),
                digest: sha256_hex(&c.fragment),
            })
            .collect();
        // Excluded: corrupt evidence plus conflicting candidates not chosen.
        let mut excluded = corrupt_evidence.to_vec();
        for (i, c) in &present {
            for other in &candidates[i] {
                if other.shard.id != c.shard.id {
                    excluded.push(ExcludedEvidence {
                        shard_id: other.shard.id,
                        idx: *i,
                        generation: other.shard.generation,
                        source: other.shard.source.clone(),
                        reason: format!(
                            "候选冲突: 同编号 {} 的另一内容候选未被选中 (摘要 {})",
                            i, other.shard.digest
                        ),
                    });
                }
            }
        }
        let mut generations: Vec<u64> = present.iter().map(|(_, c)| c.shard.generation).collect();
        generations.sort_unstable();
        generations.dedup();
        alternatives.push(StripeAlternative {
            row_digest,
            row: flat,
            participants,
            excluded,
            at_recovery_floor: present.len() == k,
            generations,
            equivalent_sets: 0,
        });
    }
    (alternatives, exhausted)
}

fn corrupt_evidence(shards: &[ShardRecord], shard_bytes: usize) -> Vec<ExcludedEvidence> {
    let mut out: Vec<ExcludedEvidence> = shards
        .iter()
        .filter(|s| s.health != ShardHealth::Ok)
        .map(|s| ExcludedEvidence {
            shard_id: s.id,
            idx: s.idx,
            generation: s.generation,
            source: s.source.clone(),
            reason: match s.health {
                ShardHealth::LengthMismatch => format!(
                    "长度与 manifest 不符: 实际 {} 字节, 期望 {}",
                    s.bytes.len(),
                    shard_bytes
                ),
                ShardHealth::DigestMismatch => {
                    format!("摘要与 manifest 不符: 重算 {}", s.digest)
                }
                ShardHealth::Quarantined => "来源已被人工隔离".to_string(),
                ShardHealth::Ok => unreachable!(),
            },
        })
        .collect();
    out.sort_by_key(|e| (e.idx, e.shard_id));
    out
}

/// Run (or resume) recovery for an object. Committed stripes with complete
/// digests are reused; everything else is recomputed and committed
/// transactionally per stripe.
pub fn recover_object(
    store: &Store,
    object_id: &str,
    config: &RecoveryConfig,
) -> Result<RecoveryReport, String> {
    let m = store
        .get_manifest(object_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("对象 {} 没有 manifest", object_id))?;
    m.validate()?;
    let coder = Coder::new(m.encoding.clone())?;
    let stripe_count = m.stripe_count();
    let run_id = store.start_run(object_id).map_err(|e| e.to_string())?;

    // Crash recovery: temp blocks from any previous interrupted run are
    // dropped and never read by final assembly.
    store.clear_temp_blocks(object_id).map_err(|e| e.to_string())?;

    let shards = classify_shards(store, &m)?;
    let evidence = corrupt_evidence(&shards, m.shard_bytes);
    let healthy: Vec<&ShardRecord> = shards.iter().filter(|s| s.health == ShardHealth::Ok).collect();

    let committed = store.committed_stripes(object_id).map_err(|e| e.to_string())?;
    let mut reused_stripes = Vec::new();
    let mut computed_stripes = Vec::new();
    let mut budget_exceeded = false;
    let mut notes = Vec::new();
    let mut commits = 0usize;

    for stripe_no in 0..stripe_count {
        if committed.iter().any(|s| s.stripe_no == stripe_no) {
            reused_stripes.push(stripe_no);
            continue;
        }
        // Build per-index candidates for this stripe.
        let mut by_index: BTreeMap<usize, Vec<Candidate>> = BTreeMap::new();
        for s in &healthy {
            let start = stripe_no * m.encoding.stripe_size;
            let end = start + m.encoding.stripe_size;
            by_index.entry(s.idx).or_default().push(Candidate {
                shard: (*s).clone(),
                fragment: s.bytes[start..end].to_vec(),
            });
        }
        let (alternatives, exhausted) =
            enumerate_stripe(&coder, &by_index, &evidence, config.budget);
        budget_exceeded |= exhausted;
        if alternatives.is_empty() {
            notes.push(format!("stripe {} 无可行重建 (可用分片不足或相互矛盾)", stripe_no));
            continue;
        }
        // Stage recovered fragments as temp blocks first; they are deleted
        // by the commit and are never read by final assembly.
        let row = &alternatives[0].row;
        let size = m.encoding.stripe_size;
        for idx in 0..m.encoding.total() {
            store
                .add_temp_block(object_id, stripe_no, idx, &row[idx * size..(idx + 1) * size])
                .map_err(|e| e.to_string())?;
        }
        if let Some(limit) = config.fail_after_commits {
            if commits >= limit {
                store
                    .finish_run(run_id, "interrupted", "模拟中断: 提交前崩溃")
                    .map_err(|e| e.to_string())?;
                return Err(format!("interrupted after {} commits", commits));
            }
        }
        store
            .commit_stripe(object_id, stripe_no, &alternatives)
            .map_err(|e| e.to_string())?;
        commits += 1;
        computed_stripes.push(stripe_no);
    }

    let stripes = store
        .stripe_states(object_id, stripe_count)
        .map_err(|e| e.to_string())?;
    let (solutions, asm_exhausted) = assemble_solutions(&m, &stripes, config.budget);
    budget_exceeded |= asm_exhausted;
    if budget_exceeded {
        notes.push("搜索预算已用尽, 结果可能不完整".into());
    }
    store
        .finish_run(run_id, "completed", "")
        .map_err(|e| e.to_string())?;
    Ok(RecoveryReport {
        object_id: object_id.to_string(),
        run_id,
        status: "completed".into(),
        computed_stripes,
        reused_stripes,
        stripes,
        solutions,
        budget_exceeded,
        notes,
    })
}

/// Assemble whole-object solutions from committed stripe alternatives.
/// Cartesian product in deterministic order, bounded by budget; filtered by
/// the manifest object digest when present. All feasible answers are kept.
pub fn assemble_solutions(
    m: &Manifest,
    stripes: &[StripeState],
    budget: usize,
) -> (Vec<ObjectSolution>, bool) {
    if stripes.iter().any(|s| s.status != "committed" || s.alternatives.is_empty()) {
        return (Vec::new(), false);
    }
    let k = m.encoding.k;
    let size = m.encoding.stripe_size;
    let total: usize = stripes.iter().map(|s| s.alternatives.len()).product();
    let mut solutions: Vec<(String, Vec<u8>, Vec<(usize, usize)>)> = Vec::new();
    let mut evaluated = 0usize;
    let mut exhausted = false;
    'outer: for combo in 0..total {
        evaluated += 1;
        if evaluated > budget {
            exhausted = true;
            break 'outer;
        }
        let mut rem = combo;
        let mut picks = Vec::with_capacity(stripes.len());
        for s in stripes.iter().rev() {
            let alt = rem % s.alternatives.len();
            rem /= s.alternatives.len();
            picks.push((s.stripe_no, alt));
        }
        picks.reverse();
        let mut ordered = Vec::with_capacity(k * m.shard_bytes);
        for s in stripes {
            let alt = picks.iter().find(|(no, _)| *no == s.stripe_no).unwrap().1;
            let row = &s.alternatives[alt].row;
            for idx in 0..k {
                ordered.extend_from_slice(&row[idx * size..(idx + 1) * size]);
            }
        }
        ordered.truncate(m.object_length);
        let digest = sha256_hex(&ordered);
        if let Some(expected) = &m.object_digest {
            if *expected != digest {
                continue;
            }
        }
        solutions.push((digest, ordered, picks));
    }
    let mut out: Vec<ObjectSolution> = Vec::new();
    for (rank, (digest, _bytes, picks)) in solutions.iter().enumerate() {
        let diff = if rank == 0 {
            "基准解".to_string()
        } else {
            let base = &solutions[0].2;
            let diffs: Vec<String> = picks
                .iter()
                .zip(base.iter())
                .filter(|(a, b)| a != b)
                .map(|((no, alt), (_, balt))| {
                    format!("stripe {} 选候选#{} 而非 #{}", no, alt, balt)
                })
                .collect();
            if diffs.is_empty() {
                "与基准解相同".into()
            } else {
                diffs.join("; ")
            }
        };
        out.push(ObjectSolution {
            rank,
            object_digest: digest.clone(),
            digest_matches_manifest: m.object_digest.as_ref().map(|e| e == digest),
            picks: picks.clone(),
            diff_summary: diff,
        });
    }
    (out, exhausted)
}

/// Reconstruct the object bytes for a given solution rank.
pub fn object_bytes(
    m: &Manifest,
    stripes: &[StripeState],
    solution: &ObjectSolution,
) -> Result<Vec<u8>, String> {
    let k = m.encoding.k;
    let size = m.encoding.stripe_size;
    let mut bytes = Vec::with_capacity(k * m.shard_bytes);
    for s in stripes {
        let alt = solution
            .picks
            .iter()
            .find(|(no, _)| *no == s.stripe_no)
            .ok_or("解缺少 stripe")?
            .1;
        let row = &s.alternatives.get(alt).ok_or("解引用了不存在的候选")?.row;
        for idx in 0..k {
            bytes.extend_from_slice(&row[idx * size..(idx + 1) * size]);
        }
    }
    bytes.truncate(m.object_length);
    Ok(bytes)
}

/// Quarantine a source and recompute every stripe that referenced it.
pub fn quarantine_and_recompute(
    store: &Store,
    source: &str,
    config: &RecoveryConfig,
) -> Result<Vec<RecoveryReport>, String> {
    store.quarantine_source(source).map_err(|e| e.to_string())?;
    let objects = store.list_objects().map_err(|e| e.to_string())?;
    let mut reports = Vec::new();
    for m in objects {
        let shards = store.shards_for(&m.object_id).map_err(|e| e.to_string())?;
        if !shards.iter().any(|s| s.source == source) {
            continue;
        }
        // Invalidate committed stripes whose participants used this source.
        let committed = store.committed_stripes(&m.object_id).map_err(|e| e.to_string())?;
        for st in committed {
            let affected = st
                .alternatives
                .iter()
                .any(|a| a.participants.iter().any(|p| p.source == source));
            if affected {
                invalidate_stripe(store, &m.object_id, st.stripe_no)?;
            }
        }
        reports.push(recover_object(store, &m.object_id, config)?);
    }
    Ok(reports)
}

fn invalidate_stripe(store: &Store, object_id: &str, stripe_no: usize) -> Result<(), String> {
    store
        .reset_stripe(object_id, stripe_no)
        .map_err(|e| e.to_string())
}
