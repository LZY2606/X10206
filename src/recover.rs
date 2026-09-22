//! 恢复引擎：在 generation、对象摘要与 stripe 约束下枚举可行候选集合，
//! 保留全部可行重建并指出差异；按 stripe 提交，中断后仅复用摘要完整的已提交 stripe。

use crate::model::*;
use crate::rs::ReedSolomon;
use crate::store::{Fragment, Store};
use crate::util::{sha256_hex, short_digest};
use std::collections::{BTreeMap, HashSet};

pub const DEFAULT_BUDGET: usize = 4096;

pub struct Engine<'a> {
    pub store: &'a Store,
    pub budget: usize,
}

struct CommittedData {
    generation: u64,
    solution_digest: String,
    shards: Vec<(u32, Vec<u8>, String)>,
}

impl<'a> Engine<'a> {
    pub fn new(store: &'a Store) -> Self {
        Self {
            store,
            budget: DEFAULT_BUDGET,
        }
    }

    pub fn with_budget(store: &'a Store, budget: usize) -> Self {
        Self { store, budget }
    }

    pub fn recover_object(&self, obj: &ObjectRow) -> rusqlite::Result<Vec<StripeReport>> {
        let quarantined: HashSet<String> = self
            .store
            .quarantined_sources(&obj.id)?
            .into_iter()
            .collect();
        let total_shards = obj.params.k + obj.params.m;
        let mut reports = Vec::new();
        for stripe in 0..obj.stripe_count as u32 {
            if self.store.verify_committed(&obj.id, stripe, total_shards)? {
                reports.push(self.reused_report(obj, stripe)?);
                continue;
            }
            // 提交不完整或摘要校验失败：作废临时块，重新计算。
            self.store.delete_committed(&obj.id, stripe)?;
            let (report, commit) = self.recover_stripe(obj, stripe, &quarantined);
            if report.status == StripeStatus::Recovered {
                if let Some(data) = commit {
                    self.store.commit_stripe(
                        &obj.id,
                        stripe,
                        data.generation,
                        &data.solution_digest,
                        &data.shards,
                    )?;
                }
            }
            self.store.save_report(&obj.id, &report)?;
            reports.push(report);
        }
        Ok(reports)
    }

    fn reused_report(&self, obj: &ObjectRow, stripe: u32) -> rusqlite::Result<StripeReport> {
        let (generation, digest) = self.store.committed_stripe(&obj.id, stripe)?.unwrap();
        let shards = self.store.committed_shards(&obj.id, stripe)?;
        Ok(StripeReport {
            stripe_idx: stripe,
            status: StripeStatus::Reused,
            participating: Vec::new(),
            excluded: Vec::new(),
            solutions: vec![Solution {
                id: 0,
                generation,
                digest,
                shard_digests: shards.iter().map(|(i, d, _)| (*i, d.clone())).collect(),
                participating: Vec::new(),
            }],
            diffs: Vec::new(),
            warnings: vec!["复用已提交 stripe，全部 shard 摘要校验通过".to_string()],
        })
    }

    fn recover_stripe(
        &self,
        obj: &ObjectRow,
        stripe: u32,
        quarantined: &HashSet<String>,
    ) -> (StripeReport, Option<CommittedData>) {
        let p = &obj.params;
        let fragments = self
            .store
            .fragments_for_stripe(&obj.id, stripe)
            .unwrap_or_default();

        let mut excluded: Vec<Evidence> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();
        let mut healthy: Vec<Fragment> = Vec::new();

        for f in fragments {
            if quarantined.contains(&f.source) {
                excluded.push(Evidence {
                    shard_idx: Some(f.shard_idx),
                    source: f.source.clone(),
                    reason: "来源已被人工隔离".into(),
                });
            } else if f.declared_digest != f.computed_digest {
                excluded.push(Evidence {
                    shard_idx: Some(f.shard_idx),
                    source: f.source.clone(),
                    reason: format!(
                        "摘要不符（疑似位翻转）：声明 {}… 实算 {}…",
                        short_digest(&f.declared_digest),
                        short_digest(&f.computed_digest)
                    ),
                });
            } else if f.bytes.len() != p.shard_size {
                excluded.push(Evidence {
                    shard_idx: Some(f.shard_idx),
                    source: f.source.clone(),
                    reason: format!(
                        "长度 {} 与编码参数 shard_size={} 不符",
                        f.bytes.len(),
                        p.shard_size
                    ),
                });
            } else if f.shard_idx as usize >= p.k + p.m {
                excluded.push(Evidence {
                    shard_idx: Some(f.shard_idx),
                    source: f.source.clone(),
                    reason: format!("编号超出 stripe 容量 k+m={}", p.k + p.m),
                });
            } else {
                healthy.push(f);
            }
        }

        // 按 generation 分组，组内按 shard_idx 归集候选；排序确定。
        let mut by_gen: BTreeMap<u64, BTreeMap<u32, Vec<Fragment>>> = BTreeMap::new();
        for f in healthy {
            by_gen
                .entry(f.generation)
                .or_default()
                .entry(f.shard_idx)
                .or_default()
                .push(f);
        }
        for by_idx in by_gen.values_mut() {
            for cands in by_idx.values_mut() {
                cands.sort_by(|a, b| {
                    a.source
                        .cmp(&b.source)
                        .then(a.computed_digest.cmp(&b.computed_digest))
                        .then(a.id.cmp(&b.id))
                });
            }
        }

        let rs = ReedSolomon::new(p.k, p.m);
        let manifest_digests: Option<&[Option<String>]> = obj
            .manifest
            .stripes
            .get(stripe as usize)
            .map(|s| s.shard_digests.as_slice());

        let mut solutions: Vec<(u64, Vec<Vec<u8>>, Vec<ShardRef>)> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        let mut budget_left = self.budget;
        let mut budget_hit = false;

        for (gen, by_idx) in &by_gen {
            if by_idx.len() < p.k {
                warnings.push(format!(
                    "generation {} 仅有 {} 个不同编号，低于恢复下限 k={}",
                    gen,
                    by_idx.len(),
                    p.k
                ));
                continue;
            }
            let groups: Vec<(u32, &Vec<Fragment>)> =
                by_idx.iter().map(|(i, v)| (*i, v)).collect();
            let mut combo: Vec<&Fragment> = Vec::with_capacity(groups.len());
            let complete = enumerate(
                &groups,
                0,
                &mut combo,
                &mut budget_left,
                &mut |combo| {
                    let present: Vec<(usize, Vec<u8>)> = combo
                        .iter()
                        .map(|f| (f.shard_idx as usize, f.bytes.clone()))
                        .collect();
                    let Some(all) = rs.reconstruct(&present) else {
                        return true;
                    };
                    // stripe 约束：组合内每个候选都必须与重建结果一致。
                    let self_consistent = combo
                        .iter()
                        .all(|f| all[f.shard_idx as usize] == f.bytes);
                    if !self_consistent {
                        return true;
                    }
                    // 对象摘要约束：manifest 声明的 shard 摘要必须全部吻合。
                    if let Some(digests) = manifest_digests {
                        let ok = digests.iter().enumerate().all(|(i, d)| match d {
                            Some(d) => i < all.len() && sha256_hex(&all[i]) == *d,
                            None => true,
                        });
                        if !ok {
                            return true;
                        }
                    }
                    let shard_digests: Vec<String> =
                        all.iter().map(|s| sha256_hex(s)).collect();
                    let solution_digest = sha256_hex(shard_digests.concat().as_bytes());
                    if seen.insert(solution_digest.clone()) {
                        let participating: Vec<ShardRef> = combo
                            .iter()
                            .map(|f| ShardRef {
                                shard_idx: f.shard_idx,
                                generation: *gen,
                                source: f.source.clone(),
                                digest: f.computed_digest.clone(),
                            })
                            .collect();
                        solutions.push((*gen, all, participating));
                    }
                    true
                },
            );
            if !complete {
                budget_hit = true;
                break;
            }
        }

        if budget_hit {
            warnings.push(format!(
                "搜索预算 {} 已耗尽，枚举被截断，结果可能不完整",
                self.budget
            ));
        }

        let solutions_view: Vec<Solution> = solutions
            .iter()
            .enumerate()
            .map(|(id, (gen, shards, participating))| Solution {
                id,
                generation: *gen,
                digest: sha256_hex(
                    shards
                        .iter()
                        .map(|s| sha256_hex(s))
                        .collect::<String>()
                        .as_bytes(),
                ),
                shard_digests: shards
                    .iter()
                    .enumerate()
                    .map(|(i, s)| (i as u32, sha256_hex(s)))
                    .collect(),
                participating: participating.clone(),
            })
            .collect();

        let mut diffs = Vec::new();
        for a in 0..solutions_view.len() {
            for b in a + 1..solutions_view.len() {
                let sa = &solutions_view[a];
                let sb = &solutions_view[b];
                for (idx, da) in &sa.shard_digests {
                    if let Some((_, db)) = sb.shard_digests.iter().find(|(i, _)| i == idx) {
                        if da != db {
                            diffs.push(format!(
                                "解 #{} 与 #{}：shard {} 摘要 {}… vs {}…",
                                a,
                                b,
                                idx,
                                short_digest(da),
                                short_digest(db)
                            ));
                        }
                    }
                }
            }
        }

        let (status, participating, commit) = match solutions.len() {
            0 => (StripeStatus::Unrecoverable, Vec::new(), None),
            1 => {
                let (gen, shards, parts) = solutions.into_iter().next().unwrap();
                let digest = solutions_view[0].digest.clone();
                let committed = CommittedData {
                    generation: gen,
                    solution_digest: digest,
                    shards: shards
                        .into_iter()
                        .enumerate()
                        .map(|(i, b)| (i as u32, b.clone(), sha256_hex(&b)))
                        .collect(),
                };
                (StripeStatus::Recovered, parts, Some(committed))
            }
            _ => {
                let mut all_parts: Vec<ShardRef> = solutions_view
                    .iter()
                    .flat_map(|s| s.participating.clone())
                    .collect();
                all_parts.sort();
                all_parts.dedup();
                (StripeStatus::Ambiguous, all_parts, None)
            }
        };

        (
            StripeReport {
                stripe_idx: stripe,
                status,
                participating,
                excluded,
                solutions: solutions_view,
                diffs,
                warnings,
            },
            commit,
        )
    }
}

/// 确定性字典序枚举候选笛卡尔积；预算耗尽或访问者要求停止时返回 false。
fn enumerate<'f>(
    groups: &[(u32, &'f Vec<Fragment>)],
    pos: usize,
    combo: &mut Vec<&'f Fragment>,
    budget: &mut usize,
    visit: &mut dyn FnMut(&[&'f Fragment]) -> bool,
) -> bool {
    if pos == groups.len() {
        if *budget == 0 {
            return false;
        }
        *budget -= 1;
        return visit(combo);
    }
    for cand in groups[pos].1 {
        combo.push(cand);
        let go_on = enumerate(groups, pos + 1, combo, budget, visit);
        combo.pop();
        if !go_on {
            return false;
        }
    }
    true
}
