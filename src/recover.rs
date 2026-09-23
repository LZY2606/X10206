//! Stripe analysis and recovery: candidate enumeration under generation,
//! per-block digest and stripe constraints, deterministic ordering, bounded
//! search, and per-stripe transactional commits.

use crate::rs::Coder;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

/// Hard cap on enumerated candidate combinations per stripe.
pub const SEARCH_BUDGET: usize = 64;

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(Debug, Clone)]
pub struct Candidate {
    pub shard_id: i64,
    pub idx: usize,
    pub generation: u64,
    pub source_id: i64,
    pub source: String,
    pub bytes: Vec<u8>,
    /// Per-block digest received together with the fragment.
    pub declared_digest: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Participant {
    pub shard_id: i64,
    pub idx: usize,
    pub source: String,
    pub generation: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExcludedEvidence {
    pub shard_id: i64,
    pub idx: usize,
    pub generation: u64,
    pub source: String,
    pub reason: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Combo {
    pub no: usize,
    pub generation: u64,
    /// Shards that actually participated in this reconstruction.
    pub participants: Vec<Participant>,
    pub shard_ids: Vec<i64>,
    pub source_ids: Vec<i64>,
    pub indices: Vec<usize>,
    pub feasible: bool,
    pub reason: String,
    /// Recomputed digests of shards produced by reconstruction.
    pub recomputed: Vec<(usize, String)>,
    /// Digest of concatenated data shards (0..k) for this combo's output.
    pub output_digest: Option<String>,
    /// Human-readable difference vs. the first feasible combo, if any.
    pub difference: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StripeAnalysis {
    pub stripe: usize,
    pub excluded: Vec<ExcludedEvidence>,
    pub combos: Vec<Combo>,
}

impl StripeAnalysis {
    pub fn best_feasible(&self) -> Option<&Combo> {
        self.combos.iter().find(|c| c.feasible)
    }

    /// Distinct feasible outputs (by output digest), deterministically ordered.
    pub fn distinct_outputs(&self) -> Vec<String> {
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for c in &self.combos {
            if c.feasible {
                if let Some(d) = &c.output_digest {
                    if seen.insert(d.clone()) {
                        out.push(d.clone());
                    }
                }
            }
        }
        out
    }
}

#[derive(Debug, Clone)]
pub struct ManifestEntry {
    pub idx: usize,
    pub len: usize,
}

/// Deterministically enumerate candidate combinations for one stripe.
///
/// A combination picks at most one candidate per shard index, all from a
/// single generation. Combinations are ordered by generation (desc), then
/// by the sorted shard-id tuple (asc), and capped by `budget`.
pub fn enumerate_combos(
    candidates: &[Candidate],
    manifest: &HashMap<usize, ManifestEntry>,
    quarantined: &BTreeSet<i64>,
    budget: usize,
) -> (Vec<(Candidate, String)>, Vec<(u64, Vec<Candidate>)>) {
    let mut excluded: Vec<(Candidate, String)> = Vec::new();
    let mut valid: Vec<Candidate> = Vec::new();

    for c in candidates {
        if quarantined.contains(&c.source_id) {
            excluded.push((c.clone(), format!("来源 {} 已被人工隔离", c.source)));
            continue;
        }
        match manifest.get(&c.idx) {
            None => excluded.push((c.clone(), format!("shard 编号 {} 不在 manifest 中", c.idx))),
            Some(entry) => {
                if c.bytes.len() != entry.len {
                    excluded.push((
                        c.clone(),
                        format!(
                            "长度不符: manifest 声明 {} 字节, 实际 {} 字节",
                            entry.len,
                            c.bytes.len()
                        ),
                    ));
                    continue;
                }
                let recomputed = sha256_hex(&c.bytes);
                if recomputed != c.declared_digest {
                    excluded.push((
                        c.clone(),
                        format!(
                            "位损坏证据: 随块摘要 {}..., 重新计算 {}...",
                            &c.declared_digest[..12.min(c.declared_digest.len())],
                            &recomputed[..12]
                        ),
                    ));
                    continue;
                }
                valid.push(c.clone());
            }
        }
    }

    // Group by generation, then by shard index.
    let mut by_gen: BTreeMap<u64, BTreeMap<usize, Vec<Candidate>>> = BTreeMap::new();
    for c in valid {
        by_gen.entry(c.generation).or_default().entry(c.idx).or_default().push(c);
    }

    let mut combos: Vec<(u64, Vec<Candidate>)> = Vec::new();
    // Generation descending.
    for (gen, by_idx) in by_gen.iter().rev() {
        let idxs: Vec<usize> = {
            let mut v: Vec<usize> = by_idx.keys().cloned().collect();
            v.sort_unstable();
            v
        };
        let mut pools: Vec<Vec<Candidate>> = Vec::new();
        for idx in &idxs {
            let mut pool = by_idx[idx].clone();
            pool.sort_by_key(|c| (c.source_id, c.shard_id));
            pools.push(pool);
        }
        // Cartesian product over indices, deterministically ordered.
        let mut acc: Vec<Vec<Candidate>> = vec![Vec::new()];
        for pool in &pools {
            let mut next = Vec::new();
            for prefix in &acc {
                for cand in pool {
                    next.push({
                        let mut v = prefix.clone();
                        v.push(cand.clone());
                        v
                    });
                }
            }
            acc = next;
        }
        acc.sort_by_key(|sel| sel.iter().map(|c| c.shard_id).collect::<Vec<_>>());
        for sel in acc {
            if combos.len() >= budget {
                return (excluded, combos);
            }
            combos.push((*gen, sel));
        }
    }
    (excluded, combos)
}

/// Analyze one stripe: enumerate combos and reconstruct for each. A combo is
/// feasible exactly when it shares one generation, covers >= k indices, its
/// received blocks pass per-block digest + length checks, and the coding
/// matrix yields a reconstruction.
pub fn analyze_stripe(
    stripe: usize,
    candidates: &[Candidate],
    manifest: &HashMap<usize, ManifestEntry>,
    coder: &Coder,
    quarantined: &BTreeSet<i64>,
    budget: usize,
) -> StripeAnalysis {
    let (excluded_raw, raw_combos) = enumerate_combos(candidates, manifest, quarantined, budget);
    let excluded: Vec<ExcludedEvidence> = excluded_raw
        .into_iter()
        .map(|(c, reason)| ExcludedEvidence {
            shard_id: c.shard_id,
            idx: c.idx,
            generation: c.generation,
            source: c.source,
            reason,
        })
        .collect();

    let k = coder.params.k;
    let mut combos: Vec<Combo> = Vec::new();

    for (gen, selection) in raw_combos {
        let indices: Vec<usize> = selection.iter().map(|c| c.idx).collect();
        let shard_ids: Vec<i64> = selection.iter().map(|c| c.shard_id).collect();
        let source_ids: Vec<i64> = selection.iter().map(|c| c.source_id).collect();
        let participants: Vec<Participant> = selection
            .iter()
            .map(|c| Participant {
                shard_id: c.shard_id,
                idx: c.idx,
                source: c.source.clone(),
                generation: c.generation,
            })
            .collect();
        let mut combo = Combo {
            no: 0,
            generation: gen,
            participants,
            shard_ids,
            source_ids,
            indices: indices.clone(),
            feasible: false,
            reason: String::new(),
            recomputed: Vec::new(),
            output_digest: None,
            difference: None,
        };

        if indices.len() < k {
            combo.reason = format!(
                "编号覆盖不足: 仅 {} 个不同编号, 达到恢复下限需要 k={}",
                indices.len(),
                k
            );
            combos.push(combo);
            continue;
        }

        let available: BTreeMap<usize, Vec<u8>> = selection
            .iter()
            .map(|c| (c.idx, c.bytes.clone()))
            .collect();
        match coder.reconstruct(&available) {
            None => {
                combo.reason = "编码矩阵奇异, 无法重建".to_string();
            }
            Some(full) => {
                combo.feasible = true;
                combo.reason = format!(
                    "可行: generation {} 的 {} 个 shard 参与, 满足恢复下限 k={}",
                    gen,
                    indices.len(),
                    k
                );
                let held: BTreeSet<usize> = combo.indices.iter().cloned().collect();
                for (idx, bytes) in &full {
                    if !held.contains(idx) {
                        combo.recomputed.push((*idx, sha256_hex(bytes)));
                    }
                }
                combo.recomputed.sort_by_key(|(idx, _)| *idx);
                let mut data = Vec::new();
                for idx in 0..k {
                    data.extend_from_slice(&full[&idx]);
                }
                combo.output_digest = Some(sha256_hex(&data));
            }
        }
        combos.push(combo);
    }

    for (i, c) in combos.iter_mut().enumerate() {
        c.no = i;
    }

    // Difference markers vs. the first feasible combo.
    let reference = combos
        .iter()
        .find(|c| c.feasible)
        .and_then(|c| c.output_digest.clone());
    if let Some(reference) = reference {
        for c in combos.iter_mut().filter(|c| c.feasible) {
            let d = c.output_digest.clone().unwrap_or_default();
            if d == reference {
                c.difference = Some("与基准可行解输出一致".to_string());
            } else {
                c.difference = Some(format!(
                    "输出与基准可行解不同: 基准 {}..., 本组合 {}...",
                    &reference[..12],
                    &d[..12]
                ));
            }
        }
        if let Some(first) = combos.iter_mut().find(|c| c.feasible) {
            first.difference = Some("基准可行解".to_string());
        }
    }

    StripeAnalysis {
        stripe,
        excluded,
        combos,
    }
}

/// Digest committed over the concatenation of all n shard byte strings in
/// index order. Used to verify committed stripes on resume.
pub fn stripe_commit_digest(shards: &BTreeMap<usize, Vec<u8>>) -> String {
    let mut all = Vec::new();
    for (_idx, bytes) in shards {
        all.extend_from_slice(bytes);
    }
    sha256_hex(&all)
}

pub fn stripe_dir(out_dir: &Path, stripe: usize) -> PathBuf {
    out_dir.join(format!("stripe_{:06}", stripe))
}

pub fn shard_path(out_dir: &Path, stripe: usize, idx: usize) -> PathBuf {
    stripe_dir(out_dir, stripe).join(format!("shard_{:03}.bin", idx))
}

/// Verify a previously committed stripe on disk. Only fully committed
/// stripes (digest matches) may be reused; temp files are never read.
pub fn verify_committed_stripe(
    out_dir: &Path,
    stripe: usize,
    n: usize,
    expected_digest: &str,
) -> bool {
    let mut shards = BTreeMap::new();
    for idx in 0..n {
        let path = shard_path(out_dir, stripe, idx);
        match fs::read(&path) {
            Ok(bytes) => {
                shards.insert(idx, bytes);
            }
            Err(_) => return false,
        }
    }
    stripe_commit_digest(&shards) == expected_digest
}

/// Write all shards of a stripe via temp files + atomic rename, then return
/// the commit digest. Temp files are cleaned up on failure.
pub fn commit_stripe_files(
    out_dir: &Path,
    stripe: usize,
    shards: &BTreeMap<usize, Vec<u8>>,
) -> Result<String, std::io::Error> {
    let dir = stripe_dir(out_dir, stripe);
    fs::create_dir_all(&dir)?;
    let mut written: Vec<PathBuf> = Vec::new();
    let run: Result<(), std::io::Error> = (|| {
        for (idx, bytes) in shards {
            let tmp = dir.join(format!("shard_{:03}.bin.tmp", idx));
            let fin = shard_path(out_dir, stripe, *idx);
            fs::write(&tmp, bytes)?;
            written.push(tmp.clone());
            fs::rename(&tmp, &fin)?;
        }
        Ok(())
    })();
    if let Err(e) = run {
        for tmp in &written {
            let _ = fs::remove_file(tmp);
        }
        return Err(e);
    }
    Ok(stripe_commit_digest(shards))
}

/// Remove stale temp files from an interrupted run; final paths never read
/// `.tmp` files.
pub fn cleanup_temp_files(out_dir: &Path) -> std::io::Result<()> {
    if !out_dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(out_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir()
            && path
                .file_name()
                .map_or(false, |n| n.to_string_lossy().starts_with("stripe_"))
        {
            for f in fs::read_dir(&path)? {
                let f = f?;
                if f.file_name().to_string_lossy().ends_with(".tmp") {
                    fs::remove_file(f.path())?;
                }
            }
        }
    }
    Ok(())
}
