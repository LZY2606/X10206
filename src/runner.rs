//! Store-backed recovery runner: commits per stripe, resumes after
//! interruption by reusing only digest-verified committed stripes.

use crate::recover::{
    self, analyze_stripe, cleanup_temp_files, commit_stripe_files, verify_committed_stripe,
    SEARCH_BUDGET,
};
use crate::rs::Coder;
use crate::store::Store;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, serde::Serialize)]
pub struct StripeOutcome {
    pub stripe: usize,
    /// "reused" | "committed" | "failed"
    pub status: String,
    pub detail: String,
    pub digest: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RecoveryReport {
    pub object_id: i64,
    pub stripes: Vec<StripeOutcome>,
}

impl RecoveryReport {
    pub fn committed_count(&self) -> usize {
        self.stripes
            .iter()
            .filter(|s| s.status == "committed" || s.status == "reused")
            .count()
    }
}

/// Run (or resume) recovery for an object. `max_stripes` limits how many
/// stripes are processed in this run, which models an interrupted process:
/// a later run with no limit resumes from the committed stripes.
pub fn run_recovery(
    store: &Store,
    object_id: i64,
    out_dir: &Path,
    max_stripes: Option<usize>,
) -> RecoveryReport {
    let object = store.get_object(object_id).expect("object not found");
    let coder = Coder::new(object.params);
    let n = coder.n();
    let quarantined = store.quarantined_source_ids();
    let _ = cleanup_temp_files(out_dir);

    let total = store.stripe_count(&object);
    let limit = max_stripes.map_or(total, |l| l.min(total));
    let mut report = RecoveryReport {
        object_id,
        stripes: Vec::new(),
    };

    for stripe in 0..limit {
        // Reuse only committed stripes whose on-disk shards fully verify.
        if let Some(commit) = store.get_commit(object_id, stripe) {
            if verify_committed_stripe(out_dir, stripe, n, &commit.digest) {
                report.stripes.push(StripeOutcome {
                    stripe,
                    status: "reused".to_string(),
                    detail: "已提交 stripe 摘要校验通过, 直接复用".to_string(),
                    digest: Some(commit.digest),
                });
                continue;
            }
            store.delete_commit(object_id, stripe);
        }

        let candidates = store.load_candidates(object_id, stripe);
        let manifest = store.load_manifest(object_id, stripe);
        let analysis = analyze_stripe(
            stripe,
            &candidates,
            &manifest,
            &coder,
            &quarantined,
            SEARCH_BUDGET,
        );
        store.save_analysis(object_id, stripe, &analysis);

        let Some(best) = analysis.best_feasible() else {
            report.stripes.push(StripeOutcome {
                stripe,
                status: "failed".to_string(),
                detail: "无可行候选组合".to_string(),
                digest: None,
            });
            continue;
        };

        let selected: BTreeMap<usize, Vec<u8>> = candidates
            .iter()
            .filter(|c| best.shard_ids.contains(&c.shard_id))
            .map(|c| (c.idx, c.bytes.clone()))
            .collect();
        let full = match coder.reconstruct(&selected) {
            Some(f) => f,
            None => {
                report.stripes.push(StripeOutcome {
                    stripe,
                    status: "failed".to_string(),
                    detail: "重建矩阵奇异".to_string(),
                    digest: None,
                });
                continue;
            }
        };

        match commit_stripe_files(out_dir, stripe, &full) {
            Ok(digest) => {
                let combo_json = serde_json::json!({
                    "combo_no": best.no,
                    "generation": best.generation,
                    "shard_ids": best.shard_ids,
                    "source_ids": best.source_ids,
                    "output_digest": best.output_digest,
                })
                .to_string();
                store.put_commit(object_id, stripe, &digest, &combo_json);
                report.stripes.push(StripeOutcome {
                    stripe,
                    status: "committed".to_string(),
                    detail: format!(
                        "采用组合 #{} (generation {}), 参与 shard: {:?}",
                        best.no, best.generation, best.shard_ids
                    ),
                    digest: Some(digest),
                });
            }
            Err(e) => {
                report.stripes.push(StripeOutcome {
                    stripe,
                    status: "failed".to_string(),
                    detail: format!("磁盘写失败, 本 stripe 未提交: {}", e),
                    digest: None,
                });
            }
        }
    }

    report
}

/// Recompute stripes whose committed combo used a quarantined source.
pub fn recompute_after_quarantine(store: &Store, source_id: i64, data_dir: &Path) -> Vec<i64> {
    let affected = store.commits_using_source(source_id);
    let mut objects: Vec<i64> = affected.iter().map(|(o, _)| *o).collect();
    objects.sort_unstable();
    objects.dedup();
    for (object_id, stripe) in affected {
        store.delete_commit(object_id, stripe);
        let dir = recover::stripe_dir(&object_out_dir(data_dir, object_id), stripe);
        let _ = std::fs::remove_dir_all(&dir);
    }
    for object_id in &objects {
        run_recovery(store, *object_id, &object_out_dir(data_dir, *object_id), None);
    }
    objects
}

pub fn object_out_dir(data_dir: &Path, object_id: i64) -> std::path::PathBuf {
    data_dir.join("objects").join(format!("obj_{}", object_id))
}
