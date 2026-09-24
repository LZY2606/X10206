//! 条带分析与恢复：候选枚举、可行集合排序、按 stripe 提交。

use crate::coding;
use crate::db::{CommitRow, Db, FragmentRow, ManifestRow};
use crate::digest::sha256_hex;
use crate::model::Manifest;
use crate::store::{
    snapshot_from, stripe_output_digest, BlockStore, CommitManifest,
};
use anyhow::{bail, Result};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};

/// 默认枚举预算：每个 stripe 最多评估的候选组合数；可用 SR_COMBO_BUDGET 覆盖。
pub const DEFAULT_COMBO_BUDGET: usize = 4096;

// 候选/块健康度：越靠前越健康。
pub const HEALTH_OK: &str = "ok";
pub const HEALTH_DIGEST_MISMATCH: &str = "digest_mismatch";
pub const HEALTH_LENGTH_MISMATCH: &str = "length_mismatch";
pub const HEALTH_GENERATION_STALE: &str = "generation_stale";
pub const HEALTH_SOURCE_ISOLATED: &str = "source_isolated";

// 组合/候选排除证据原因。
pub const EV_SUPERSEDED_CANDIDATE: &str = "superseded_candidate";
pub const EV_DIGEST_MISMATCH: &str = "digest_mismatch";
pub const EV_LENGTH_MISMATCH: &str = "length_mismatch";
pub const EV_SOURCE_ISOLATED: &str = "source_isolated";
pub const EV_DECODE_FAILED: &str = "decode_failed";
pub const EV_DIGEST_RECHECK_FAILED: &str = "digest_recheck_failed";

pub const STATUS_VERIFIED: &str = "verified";
pub const STATUS_UNTRUSTED: &str = "untrusted";
pub const STATUS_UNRECOVERABLE: &str = "unrecoverable";

#[derive(Debug, Clone, Serialize)]
pub struct ExcludedEvidence {
    pub fragment_id: i64,
    pub shard_index: usize,
    pub generation: u64,
    pub content_digest: String,
    pub sources: Vec<String>,
    pub reason: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CandidateView {
    pub fragment_id: i64,
    pub shard_index: usize,
    pub generation: u64,
    pub content_digest: String,
    pub claimed_digest: Option<String>,
    pub actual_len: u64,
    pub sources: Vec<String>,
    pub health: String,
    pub eligible: bool,
    pub exclusion: Option<ExcludedEvidence>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ParticipantShard {
    pub shard_index: usize,
    pub fragment_id: i64,
    pub content_digest: String,
    pub sources: Vec<String>,
    pub recomputed_digest: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComboView {
    pub rank: usize,
    pub generation: u64,
    pub trusted: bool,
    pub witness_fragment_ids: Vec<i64>,
    pub participants: Vec<ParticipantShard>,
    pub excluded_evidence: Vec<ExcludedEvidence>,
    pub output_digest: String,
    pub shard_digests: Vec<String>,
    pub decoded_from: Vec<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StripeView {
    pub stripe: u64,
    pub status: String,
    pub generation: Option<u64>,
    pub shard_health: BTreeMap<usize, String>,
    pub candidates: Vec<CandidateView>,
    pub combos: Vec<ComboView>,
    pub rejected_evidence: Vec<ExcludedEvidence>,
    pub committed: bool,
    pub reused: bool,
    pub output_digest: Option<String>,
    pub recomputed_object_digest: Option<String>,
    pub budget_exceeded: bool,
    pub combos_evaluated: usize,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ObjectView {
    pub object_id: String,
    pub object_digest: String,
    pub object_size: u64,
    pub codec: String,
    pub k: usize,
    pub m: usize,
    pub shard_size: usize,
    pub current_generation: u64,
    pub status: String,
    pub stripe_count: usize,
    pub stripes_committed: usize,
    pub object_digest_matches: bool,
    pub exportable: bool,
    pub exports: Vec<String>,
    pub stripes: Vec<StripeView>,
    pub last_run_status: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StateView {
    pub objects: Vec<ObjectView>,
    pub isolated_sources: Vec<String>,
    pub all_sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunReport {
    pub run_id: i64,
    pub object_id: String,
    pub status: String,
    pub stripes_total: usize,
    pub stripes_committed: usize,
    pub stripes_reused: usize,
    pub interrupted: bool,
    pub error: Option<String>,
}

struct Candidate<'a> {
    fragment: &'a FragmentRow,
    sources: &'a [String],
    bytes: Vec<u8>,
    health: String,
    eligible: bool,
    exclusion: Option<ExcludedEvidence>,
}

/// 评估单块候选的健康度与可用性（不先到先得：全部保留参与枚举）。
fn assess_candidate(
    fragment: &FragmentRow,
    sources: &[String],
    bytes: Vec<u8>,
    expected_digest: Option<&str>,
    expected_len: usize,
    is_current_generation: bool,
    isolated: &HashSet<String>,
) -> Candidate<'_> {
    let all_isolated = !sources.is_empty() && sources.iter().all(|s| isolated.contains(s));
    let mut health = HEALTH_OK;
    let mut exclusion = None;

    if bytes.len() != expected_len {
        health = HEALTH_LENGTH_MISMATCH;
        exclusion = Some(ExcludedEvidence {
            fragment_id: fragment.id,
            shard_index: fragment.shard_index as usize,
            generation: fragment.generation as u64,
            content_digest: fragment.content_digest.clone(),
            sources: sources.to_vec(),
            reason: EV_LENGTH_MISMATCH.to_string(),
            detail: format!(
                "manifest 要求 {expected_len} 字节，实际 {} 字节",
                bytes.len()
            ),
        });
    } else if let Some(expected) = expected_digest {
        let claimed = fragment.claimed_digest.clone();
        let claimed_matches = claimed.as_deref().map(|d| d == expected).unwrap_or(true);
        let actual = sha256_hex(&bytes);
        if !claimed_matches {
            health = HEALTH_DIGEST_MISMATCH;
            exclusion = Some(ExcludedEvidence {
                fragment_id: fragment.id,
                shard_index: fragment.shard_index as usize,
                generation: fragment.generation as u64,
                content_digest: fragment.content_digest.clone(),
                sources: sources.to_vec(),
                reason: EV_DIGEST_MISMATCH.to_string(),
                detail: format!(
                    "每块摘要声称 {claimed:?}，manifest 期望 {expected}；重算 {actual}"
                ),
            });
        } else if actual != expected {
            health = HEALTH_DIGEST_MISMATCH;
            exclusion = Some(ExcludedEvidence {
                fragment_id: fragment.id,
                shard_index: fragment.shard_index as usize,
                generation: fragment.generation as u64,
                content_digest: fragment.content_digest.clone(),
                sources: sources.to_vec(),
                reason: EV_DIGEST_MISMATCH.to_string(),
                detail: format!("位翻转/内容损坏：重算 {actual}，manifest 期望 {expected}"),
            });
        }
    }

    if exclusion.is_none() && !is_current_generation {
        health = HEALTH_GENERATION_STALE;
        // 旧 generation 的健康块不作为证据排除，只在枚举时按 generation 分组。
    }

    let eligible = exclusion.is_none();
    let mut candidate = Candidate {
        fragment,
        sources,
        bytes,
        health: health.to_string(),
        eligible,
        exclusion,
    };

    if eligible && all_isolated {
        candidate.eligible = false;
        candidate.health = HEALTH_SOURCE_ISOLATED.to_string();
        candidate.exclusion = Some(ExcludedEvidence {
            fragment_id: fragment.id,
            shard_index: fragment.shard_index as usize,
            generation: fragment.generation as u64,
            content_digest: fragment.content_digest.clone(),
            sources: sources.to_vec(),
            reason: EV_SOURCE_ISOLATED.to_string(),
            detail: format!("来源 {} 均已人工隔离", sources.join(",")),
        });
    }
    candidate
}

pub struct Engine {
    pub db: Db,
    pub store: BlockStore,
    pub combo_budget: usize,
}

impl Engine {
    /// 按 stripe 执行恢复；已提交且摘要完整、隔离快照一致的 stripe 只复用不重算。
    /// 进程中断（failpoint）后再次调用时，临时块被清理、已提交 stripe 被复用。
    pub fn recover_object(&self, object_id: &str) -> Result<RunReport> {
        let (_, manifest) = self
            .manifest_by_object(object_id)?
            .ok_or_else(|| anyhow::anyhow!("unknown object: {object_id}"))?;
        if !coding::supported(&manifest.codec.codec) {
            bail!("unsupported codec: {}", manifest.codec.codec);
        }
        let fragments = self.db.fragments_for_object(object_id)?;
        let isolated = self.isolated_set()?;
        let stripes: Vec<u64> = manifest
            .current_plan()
            .map(|p| p.stripe_digests.iter().map(|s| s.stripe).collect())
            .unwrap_or_default();

        let run_id = self.db.start_run(object_id, stripes.len() as i64)?;
        let mut committed = 0usize;
        let mut reused = 0usize;
        let mut interrupted = false;
        let mut error: Option<String> = None;

        for stripe in &stripes {
            // 先尝试复用：manifest、块摘要、输出摘要、隔离快照全部一致才复用。
            let existing = self.db.commits_for_object(object_id)?;
            let commit_row = existing.iter().find(|c| c.stripe as u64 == *stripe);
            if let Some(row) = commit_row {
                if self.commit_reusable(row, &manifest, &isolated)? {
                    committed += 1;
                    reused += 1;
                    continue;
                }
                // 不可信的旧提交：删记录并把目录移入 quarantine。
                self.db.delete_commit(object_id, *stripe as i64)?;
                self.store.quarantine_commit(object_id, *stripe)?;
            }

            let analysis = self.analyze_stripe(&manifest, *stripe, &fragments, &isolated)?;
            let Some(best) = analysis.combos.first() else {
                continue;
            };
            if analysis.status != STATUS_VERIFIED {
                continue;
            }
            let canonical = best;
            let snapshot = snapshot_from(&all_sources(&fragments), &isolated);
            let commit_manifest = CommitManifest {
                kind: "stripe-recovery-commit".to_string(),
                object_id: object_id.to_string(),
                stripe: *stripe,
                generation: canonical.generation,
                object_digest: manifest.object_digest.clone(),
                combo_index: 0,
                output_digest: canonical.output_digest.clone(),
                shard_digests: canonical.shard_digests.clone(),
                block_digests: canonical.shard_digests.clone(),
                isolated_snapshot: snapshot.clone(),
            };
            let stage = self.store.write_staging(
                object_id,
                *stripe,
                &canonical.blocks,
                &commit_manifest,
            );
            match stage {
                Ok((_, _, output_digest)) => {
                    debug_assert_eq!(output_digest, canonical.output_digest);
                    let path = self.store.commit_stripe(object_id, *stripe)?;
                    self.db.upsert_commit(
                        object_id,
                        *stripe as i64,
                        canonical.generation as i64,
                        &manifest.object_digest,
                        0,
                        &canonical.output_digest,
                        &path.to_string_lossy(),
                        &serde_json::to_string(&snapshot)?,
                    )?;
                    committed += 1;
                }
                Err(err) => {
                    // 模拟进程中断：临时块作废（下次启动清理），已提交 stripe 不受影响。
                    interrupted = true;
                    error = Some(err.to_string());
                    break;
                }
            }
        }

        let status = if interrupted {
            "interrupted"
        } else if committed == stripes.len() {
            "committed_all"
        } else {
            "partial"
        };
        self.db
            .finish_run(run_id, status, committed as i64)?;
        Ok(RunReport {
            run_id,
            object_id: object_id.to_string(),
            status: status.to_string(),
            stripes_total: stripes.len(),
            stripes_committed: committed,
            stripes_reused: reused,
            interrupted,
            error,
        })
    }

    fn commit_reusable(
        &self,
        row: &CommitRow,
        manifest: &Manifest,
        isolated: &HashSet<String>,
    ) -> Result<bool> {
        if row.generation as u64 != manifest.current_generation
            || row.object_digest != manifest.object_digest
        {
            return Ok(false);
        }
        let Some(loaded) = self.store.load_committed(&manifest.object_id, row.stripe as u64)?
        else {
            return Ok(false);
        };
        let (cm, blocks) = loaded;
        if cm.output_digest != row.output_digest || cm.combo_index != row.combo_index as usize {
            return Ok(false);
        }
        let expected = manifest
            .stripe_spec(manifest.current_generation, row.stripe as u64)
            .map(|s| s.digests.clone())
            .unwrap_or_default();
        let actual: Vec<String> = blocks.iter().map(|b| sha256_hex(b)).collect();
        if expected != actual {
            return Ok(false);
        }
        let mut saved: Vec<String> = serde_json::from_str(&row.isolated_snapshot).unwrap_or_default();
        saved.sort();
        let mut current: Vec<String> = isolated.iter().cloned().collect();
        current.sort();
        Ok(saved == current)
    }
}

fn all_sources(fragments: &[(FragmentRow, Vec<String>)]) -> Vec<String> {
    let mut set: HashSet<String> = HashSet::new();
    for (_, sources) in fragments {
        set.extend(sources.iter().cloned());
    }
    set.into_iter().collect()
}

impl Engine {
    /// 汇总对象、stripe、shard 健康度、候选组合与提交进度。
    pub fn state(&self) -> Result<StateView> {
        let isolated = self.isolated_set()?;
        let manifests = self.db.list_manifests()?;
        let mut objects = Vec::new();
        let mut all_sources_set: HashSet<String> = HashSet::new();

        for row in manifests {
            let bytes = std::fs::read(&row.manifest_path)?;
            let manifest: Manifest = serde_json::from_slice(&bytes)?;
            let fragments = self.db.fragments_for_object(&manifest.object_id)?;
            for (_, sources) in &fragments {
                all_sources_set.extend(sources.iter().cloned());
            }
            let commits = self.db.commits_for_object(&manifest.object_id)?;
            let stripe_specs = &manifest.current_plan().cloned().unwrap_or_default().stripe_digests;

            let mut stripe_views = Vec::new();
            let mut committed_count = 0usize;
            for spec in stripe_specs {
                let analysis = self.analyze_stripe(
                    &manifest,
                    spec.stripe,
                    &fragments,
                    &isolated,
                )?;
                let commit = commits.iter().find(|c| c.stripe as u64 == analysis.stripe);
                let committed = commit.is_some();
                if committed {
                    committed_count += 1;
                }
                let (output_digest, generation, reused) = match commit {
                    Some(c) => (
                        Some(c.output_digest.clone()),
                        Some(c.generation as u64),
                        self.commit_reusable(c, &manifest, &isolated)?,
                    ),
                    None => (None, analysis.generation, false),
                };
                stripe_views.push(StripeView {
                    stripe: analysis.stripe,
                    status: if committed {
                        STATUS_VERIFIED.to_string()
                    } else {
                        analysis.status
                    },
                    generation,
                    shard_health: analysis.shard_health,
                    candidates: analysis.candidates,
                    combos: analysis
                        .combos
                        .iter()
                        .enumerate()
                        .map(combo_to_view)
                        .collect(),
                    rejected_evidence: analysis.rejected,
                    committed,
                    reused: committed && reused,
                    output_digest,
                    recomputed_object_digest: Some(manifest.object_digest.clone()),
                    budget_exceeded: analysis.budget_exceeded,
                    combos_evaluated: analysis.evaluated,
                    detail: analysis.detail,
                });
            }

            let all_verified = stripe_views.iter().all(|s| s.status == STATUS_VERIFIED);
            let object_digest_matches =
                all_verified && committed_count == stripe_specs.len();
            let exports = self.db.list_exports(&manifest.object_id)?;
            objects.push(ObjectView {
                object_id: manifest.object_id.clone(),
                object_digest: manifest.object_digest.clone(),
                object_size: manifest.object_size,
                codec: manifest.codec.codec.clone(),
                k: manifest.codec.k,
                m: manifest.codec.m,
                shard_size: manifest.codec.shard_size,
                current_generation: manifest.current_generation,
                status: if object_digest_matches {
                    STATUS_VERIFIED.to_string()
                } else if stripe_views
                    .iter()
                    .any(|s| s.status == STATUS_UNTRUSTED)
                {
                    STATUS_UNTRUSTED.to_string()
                } else {
                    STATUS_UNRECOVERABLE.to_string()
                },
                stripe_count: stripe_specs.len(),
                stripes_committed: committed_count,
                object_digest_matches,
                exportable: object_digest_matches,
                exports,
                stripes: stripe_views,
                last_run_status: None,
            });
        }

        let mut all_sources: Vec<String> = all_sources_set.into_iter().collect();
        all_sources.sort();
        Ok(StateView {
            objects,
            isolated_sources: isolated.into_iter().collect(),
            all_sources,
        })
    }

    /// 人工隔离/解除隔离一个来源，随后立即重算受影响 stripe 的提交。
    pub fn isolate_source(&self, source: &str, isolated: bool) -> Result<RunReports> {
        self.db.set_isolated(source, isolated)?;
        let manifests = self.db.list_manifests()?;
        let mut affected: HashSet<String> = HashSet::new();

        for mrow in manifests {
            let fragments = self.db.fragments_for_object(&mrow.object_id)?;
            // 凡有碎片从该来源接收，其 stripe 的隔离状态就可能改变：
            // 使旧提交失效（移入 quarantine），随后统一重算。
            let mut touched_stripes: HashSet<i64> = HashSet::new();
            for (frag, sources) in &fragments {
                if sources.iter().any(|s| s == source) {
                    touched_stripes.insert(frag.stripe);
                }
            }
            if !touched_stripes.is_empty() {
                affected.insert(mrow.object_id.clone());
            }
            for stripe in touched_stripes {
                self.db.delete_commit(&mrow.object_id, stripe)?;
                self.store.quarantine_commit(&mrow.object_id, stripe as u64)?;
            }
        }
        let mut affected: Vec<String> = affected.into_iter().collect();
        affected.sort();
        let mut reports = Vec::new();
        for object_id in affected {
            reports.push(self.recover_object(&object_id)?);
        }
        Ok(RunReports { reports })
    }

    /// 只有全部 stripe 已验证提交且对象摘要重算一致才允许导出。
    pub fn export_object(&self, object_id: &str) -> Result<String> {
        let (_, manifest) = self
            .manifest_by_object(object_id)?
            .ok_or_else(|| anyhow::anyhow!("unknown object: {object_id}"))?;
        let commits = self.db.commits_for_object(object_id)?;
        let stripe_count = manifest.stripe_count();
        if commits.len() != stripe_count {
            bail!("only {}/{} stripes committed; refusing export", commits.len(), stripe_count);
        }
        let mut stripe_blocks = Vec::new();
        for c in &commits {
            let loaded = self.store.load_committed(object_id, c.stripe as u64)?;
            let Some((_, blocks)) = loaded else {
                bail!("committed stripe {} failed verification", c.stripe);
            };
            stripe_blocks.push(blocks);
        }
        let path = self.store.export_object(
            object_id,
            &manifest.object_digest,
            manifest.object_size,
            &stripe_blocks,
            stripe_count,
            manifest.codec.shard_size,
            manifest.codec.k,
        )?;
        self.db.record_export(
            object_id,
            &path.to_string_lossy(),
            &manifest.object_digest,
        )?;
        Ok(path.to_string_lossy().to_string())
    }
}

#[derive(Debug, Serialize)]
pub struct RunReports {
    pub reports: Vec<RunReport>,
}

fn combo_to_view((rank, ec): (usize, &EvaluatedCombo)) -> ComboView {
    let participants = ec
        .participants
        .iter()
        .zip(ec.participant_indices.iter())
        .zip(ec.participant_sources.iter())
        .enumerate()
        .map(|(i, ((fragment_id, index), sources))| ParticipantShard {
            shard_index: *index,
            fragment_id: *fragment_id,
            content_digest: ec.shard_digests[*index].clone(),
            sources: sources.clone(),
            recomputed_digest: ec.shard_digests[*index].clone(),
        })
        .collect::<Vec<_>>();
    let mut decoded_from: Vec<usize> = ec.participant_indices.clone();
    decoded_from.sort();
    let _ = rank;
    ComboView {
        rank: rank + 1,
        generation: ec.generation,
        trusted: ec.trusted,
        witness_fragment_ids: ec.witness.clone(),
        participants,
        excluded_evidence: ec.evidence.clone(),
        output_digest: ec.output_digest.clone(),
        shard_digests: ec.shard_digests.clone(),
        decoded_from,
    }
}
    pub fn open(data_dir: &std::path::Path) -> Result<Engine> {
        std::fs::create_dir_all(data_dir)?;
        let store = BlockStore::new(data_dir)?;
        let db = Db::open(&data_dir.join("recovery.db").to_string_lossy())?;
        store.clean_stale_staging()?;
        let combo_budget = std::env::var("SR_COMBO_BUDGET")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_COMBO_BUDGET);
        Ok(Engine {
            db,
            store,
            combo_budget,
        })
    }

    pub fn isolated_set(&self) -> Result<HashSet<String>> {
        Ok(self.db.isolated_sources()?.into_iter().collect())
    }

    fn manifest_by_object(&self, object_id: &str) -> Result<Option<(ManifestRow, Manifest)>> {
        let Some(row) = self.db.manifest_for_object(object_id)? else {
            return Ok(None);
        };
        let bytes = std::fs::read(&row.manifest_path)?;
        let manifest: Manifest = serde_json::from_slice(&bytes)?;
        Ok(Some((row, manifest)))
    }

    /// 枚举单个 stripe 的全部可行组合；输出包含参与块、排除证据与重算摘要。
    fn analyze_stripe<'a>(
        &self,
        manifest: &Manifest,
        stripe: u64,
        fragments: &'a [(FragmentRow, Vec<String>)],
        isolated: &HashSet<String>,
    ) -> Result<StripeAnalysis> {
        let k = manifest.codec.k;
        let m = manifest.codec.m;
        let shard_size = manifest.codec.shard_size;
        let current = manifest.current_generation;

        let rows: Vec<&(FragmentRow, Vec<String>)> =
            fragments.iter().filter(|(f, _)| f.stripe as u64 == stripe).collect();

        let mut candidates: Vec<Candidate<'a>> = Vec::new();
        let mut shard_health: BTreeMap<usize, String> = BTreeMap::new();
        for (fragment, sources) in &rows {
            let bytes = std::fs::read(&fragment.blob_path)?;
            let gen = fragment.generation as u64;
            let expected_digest = manifest.expected_digest(gen, stripe, fragment.shard_index as usize);
            let assessed = assess_candidate(
                fragment,
                sources,
                bytes,
                expected_digest,
                shard_size,
                gen == current,
                isolated,
            );
            shard_health
                .entry(fragment.shard_index as usize)
                .and_modify(|h| {
                    if health_rank(&assessed.health) < health_rank(h) {
                        *h = assessed.health.clone();
                    }
                })
                .or_insert_with(|| assessed.health.clone());
            candidates.push(assessed);
        }

        let mut combos: Vec<EvaluatedCombo> = Vec::new();
        let mut rejected: Vec<ExcludedEvidence> = Vec::new();
        let mut evaluated = 0usize;
        let mut budget_exceeded = false;

        let mut generations: Vec<u64> = candidates
            .iter()
            .map(|c| c.fragment.generation as u64)
            .collect();
        generations.sort();
        generations.dedup();

        for generation in generations {
            // 每个 shard 编号的可用候选按 (健康度, 摘要, fragment id) 排序。
            let mut by_shard: BTreeMap<usize, Vec<&Candidate<'a>>> = BTreeMap::new();
            for c in &candidates {
                if c.fragment.generation as u64 == generation && c.eligible {
                    by_shard
                        .entry(c.fragment.shard_index as usize)
                        .or_default()
                        .push(c);
                }
            }
            for list in by_shard.values_mut() {
                list.sort_by(|a, b| {
                    health_rank(&a.health)
                        .cmp(&health_rank(&b.health))
                        .then_with(|| a.fragment.content_digest.cmp(&b.fragment.content_digest))
                        .then_with(|| a.fragment.id.cmp(&b.fragment.id))
                });
            }

            let indices: Vec<usize> = by_shard.keys().copied().collect();
            let group_len = indices.len();
            if group_len < k {
                continue;
            }

            // 先枚举选择哪 k 个不同编号，再为每个编号枚举内容候选。
            for chosen in combinations(&indices, k) {
                let options: Vec<&Vec<&Candidate<'a>>> =
                    chosen.iter().map(|idx| &by_shard[idx]).collect();
                let total: usize = options.iter().map(|v| v.len()).product();
                if evaluated + total > self.combo_budget {
                    budget_exceeded = true;
                    break;
                }
                for combo in 0..total {
                    let mut rem = combo;
                    let mut picks: Vec<&Candidate<'a>> = Vec::new();
                    for opts in &options {
                        let pick = rem % opts.len();
                        rem /= opts.len();
                        picks.push(opts[pick]);
                    }
                    evaluated += 1;
                    let present: Vec<(usize, Vec<u8>)> = picks
                        .iter()
                        .map(|c| (c.fragment.shard_index as usize, c.bytes.clone()))
                        .collect();
                    let decoded = coding::decode(k, m, shard_size, &present);
                    match decoded {
                        Ok(blocks) => {
                            let shard_digests: Vec<String> =
                                blocks.iter().map(|b| sha256_hex(b)).collect();
                            let expected_vec =
                                manifest.stripe_spec(generation, stripe).map(|s| &s.digests);
                            let trusted = expected_vec
                                .map(|d| *d == shard_digests)
                                .unwrap_or(false);
                            let witness: Vec<i64> =
                                picks.iter().map(|c| c.fragment.id).collect();
                            if combos.iter().any(|ec| ec.witness == witness) {
                                continue;
                            }
                            // 同编号未参与的健康候选：记录为被取代证据。
                            let mut evidence = Vec::new();
                            for idx in &chosen {
                                for c in &by_shard[idx] {
                                    if !witness.contains(&c.fragment.id) {
                                        evidence.push(ExcludedEvidence {
                                            fragment_id: c.fragment.id,
                                            shard_index: c.fragment.shard_index as usize,
                                            generation: c.fragment.generation as u64,
                                            content_digest: c.fragment.content_digest.clone(),
                                            sources: c.sources.to_vec(),
                                            reason: EV_SUPERSEDED_CANDIDATE.to_string(),
                                            detail:
                                                "同一编号的另一内容候选，枚举后未进入本组合"
                                                    .to_string(),
                                        });
                                    }
                                }
                            }
                            // 损坏/隔离候选始终作为排除证据列出。
                            for c in &candidates {
                                if c.fragment.generation as u64 == generation {
                                    if let Some(ev) = &c.exclusion {
                                        evidence.push(ev.clone());
                                    }
                                }
                            }
                            evidence.sort_by(|a, b| {
                                a.fragment_id
                                    .cmp(&b.fragment_id)
                                    .then_with(|| a.reason.cmp(&b.reason))
                            });
                            evidence.dedup_by_key(|e| (e.fragment_id, e.reason.clone()));
                            combos.push(EvaluatedCombo {
                                generation,
                                trusted,
                                witness,
                                participants: picks.iter().map(|c| c.fragment.id).collect(),
                                participant_sources: picks
                                    .iter()
                                    .map(|c| c.sources.to_vec())
                                    .collect(),
                                participant_indices: picks
                                    .iter()
                                    .map(|c| c.fragment.shard_index as usize)
                                    .collect(),
                                evidence,
                                output_digest: stripe_output_digest(&blocks),
                                shard_digests,
                                blocks,
                            });
                        }
                        Err(err) => {
                            for c in &picks {
                                rejected.push(ExcludedEvidence {
                                    fragment_id: c.fragment.id,
                                    shard_index: c.fragment.shard_index as usize,
                                    generation: c.fragment.generation as u64,
                                    content_digest: c.fragment.content_digest.clone(),
                                    sources: c.sources.to_vec(),
                                    reason: EV_DECODE_FAILED.to_string(),
                                    detail: format!(
                                        "组合 {:?} 解码不自洽：{err}",
                                        picks
                                            .iter()
                                            .map(|p| p.fragment.shard_index)
                                            .collect::<Vec<_>>()
                                    ),
                                });
                            }
                        }
                    }
                }
            }
            if budget_exceeded {
                break;
            }
        }

        rejected.sort_by_key(|e| (e.fragment_id, e.reason.clone()));
        rejected.dedup_by_key(|e| (e.fragment_id, e.reason.clone()));

        // 可行集合排序：可信优先、当前 generation 优先、证据少优先、参与 id 升序。
        combos.sort_by(|a, b| {
            b.trusted
                .cmp(&a.trusted)
                .then_with(|| b.generation.cmp(&a.generation))
                .then_with(|| a.evidence.len().cmp(&b.evidence.len()))
                .then_with(|| a.witness.cmp(&b.witness))
        });

        let candidate_views = build_candidate_views(candidates);
        let status = if combos.iter().any(|c| c.trusted && c.generation == current) {
            STATUS_VERIFIED
        } else if !combos.is_empty() {
            STATUS_UNTRUSTED
        } else {
            STATUS_UNRECOVERABLE
        };
        let generation = combos.first().map(|c| c.generation);
        let detail = match status {
            STATUS_VERIFIED => "存在与当前 generation 对象摘要完全自洽的重建".to_string(),
            STATUS_UNTRUSTED => {
                "存在数学上自洽的重建，但只能来自旧 generation 或摘要不匹配".to_string()
            }
            _ => {
                if budget_exceeded {
                    format!("可行组合搜索超过预算 {}，未能穷举", self.combo_budget)
                } else {
                    "不足 k 个互异可用编号，或所有候选组合解码失败".to_string()
                }
            }
        };

        Ok(StripeAnalysis {
            stripe,
            status: status.to_string(),
            generation,
            shard_health,
            candidates: candidate_views,
            combos,
            rejected,
            evaluated,
            budget_exceeded,
            detail,
        })
    }
}

struct EvaluatedCombo {
    generation: u64,
    trusted: bool,
    witness: Vec<i64>,
    participants: Vec<i64>,
    participant_sources: Vec<Vec<String>>,
    participant_indices: Vec<usize>,
    evidence: Vec<ExcludedEvidence>,
    output_digest: String,
    shard_digests: Vec<String>,
    blocks: Vec<Vec<u8>>,
}

struct StripeAnalysis {
    stripe: u64,
    status: String,
    generation: Option<u64>,
    shard_health: BTreeMap<usize, String>,
    candidates: Vec<CandidateView>,
    combos: Vec<EvaluatedCombo>,
    rejected: Vec<ExcludedEvidence>,
    evaluated: usize,
    budget_exceeded: bool,
    detail: String,
}

fn build_candidate_views(candidates: Vec<Candidate<'_>>) -> Vec<CandidateView> {
    let mut views: Vec<CandidateView> = candidates
        .into_iter()
        .map(|c| CandidateView {
            fragment_id: c.fragment.id,
            shard_index: c.fragment.shard_index as usize,
            generation: c.fragment.generation as u64,
            content_digest: c.fragment.content_digest,
            claimed_digest: c.fragment.claimed_digest,
            actual_len: c.fragment.actual_len as u64,
            sources: c.sources.to_vec(),
            health: c.health,
            eligible: c.eligible,
            exclusion: c.exclusion,
        })
        .collect();
    views.sort_by_key(|c| {
        (
            c.shard_index,
            health_rank(&c.health),
            c.generation,
            c.fragment_id,
        )
    });
    views
}

fn health_rank(health: &str) -> u8 {
    match health {
        HEALTH_OK => 0,
        HEALTH_GENERATION_STALE => 1,
        HEALTH_DIGEST_MISMATCH => 2,
        HEALTH_LENGTH_MISMATCH => 3,
        HEALTH_SOURCE_ISOLATED => 4,
        _ => 9,
    }
}

/// 返回 n 个元素中所有大小为 k 的下标组合，顺序确定（字典序）。
fn combinations(n: &[usize], k: usize) -> Vec<Vec<usize>> {
    let mut out = Vec::new();
    let mut stack: Vec<usize> = Vec::new();
    fn walk(
        n: &[usize],
        k: usize,
        start: usize,
        stack: &mut Vec<usize>,
        out: &mut Vec<Vec<usize>>,
    ) {
        if stack.len() == k {
            out.push(stack.clone());
            return;
        }
        for i in start..n.len() {
            stack.push(n[i]);
            walk(n, k, i + 1, stack, out);
            stack.pop();
        }
    }
    walk(n, k, 0, &mut stack, &mut out);
    out
}
