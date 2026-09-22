//! Read models for the web UI: objects, stripes, shard health, candidate
//! combinations and recovery progress.

use std::collections::BTreeMap;

use rusqlite::params;

use crate::db::Db;

#[derive(Clone, Debug, serde::Serialize)]
pub struct ObjectSummary {
    pub object_id: String,
    pub generations: Vec<u64>,
    pub total_stripes: usize,
    pub recovered: usize,
    pub ambiguous: usize,
    pub below_threshold: usize,
    pub budget_exhausted: usize,
    pub failed: usize,
    pub not_attempted: usize,
    pub latest_check_note: String,
    pub latest_check_status: String,
    pub isolated_sources: Vec<String>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct StripeRow {
    pub stripe_index: usize,
    pub status: String,
    pub status_label: String,
    pub ambiguous: bool,
    pub generation: Option<i64>,
    pub note: String,
    pub outcome_count: usize,
    pub active_outcome_id: Option<i64>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ShardHealth {
    pub stripe_index: usize,
    pub shard_index: usize,
    pub generation: i64,
    pub fragment_id: i64,
    pub blob_hash: String,
    pub byte_length: usize,
    pub health: String,
    pub health_label: String,
    pub sources: Vec<String>,
    pub expected_digest: String,
    pub isolated: bool,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct OutcomeView {
    pub outcome_id: i64,
    pub generation: i64,
    pub rank: i64,
    pub feasible: bool,
    pub stripe_digest: String,
    pub all_digests_match: bool,
    pub differences: Vec<String>,
    pub blocks: Vec<OutcomeBlockView>,
    pub evidence: Vec<EvidenceView>,
    pub active: bool,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct OutcomeBlockView {
    pub shard_index: i64,
    pub fragment_id: Option<i64>,
    pub blob_hash: String,
    pub recomputed_digest: String,
    pub expected_digest: String,
    pub matches_expected: bool,
    pub rebuilt: bool,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct EvidenceView {
    pub shard_index: i64,
    pub fragment_id: Option<i64>,
    pub receipt_source: String,
    pub role: String,
    pub reason: String,
    pub reason_label: String,
}

fn status_label(s: &str) -> String {
    use crate::model::StripeStatus::*;
    for v in [NotAttempted, Recovered, Ambiguous, BelowThreshold, BudgetExhausted, Failed] {
        if v.as_str() == s {
            return v.label().to_string();
        }
    }
    s.to_string()
}

pub fn list_objects(db: &Db) -> Vec<ObjectSummary> {
    let conn = db.conn.lock().unwrap();
    let mut objs: Vec<(String, Vec<u64>)> = {
        let mut stmt = conn
            .prepare(
                "SELECT o.object_id, GROUP_CONCAT(g.generation)
                 FROM objects o
                 LEFT JOIN generations g ON g.object_id = o.object_id
                 GROUP BY o.object_id ORDER BY o.object_id",
            )
            .unwrap();
        stmt.query_map([], |r| {
            let id: String = r.get(0)?;
            let gens: Option<String> = r.get(1)?;
            let gens = gens
                .map(|s| s.split(',').filter_map(|x| x.parse::<i64>().ok()).map(|x| x as u64).collect())
                .unwrap_or_default();
            Ok((id, gens))
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
    };

    let mut out = Vec::new();
    for (id, generations) in objs.drain(..) {
        let total_stripes: usize = conn
            .query_row(
                "SELECT COALESCE(MAX(stripe_count),0) FROM generations WHERE object_id=?1",
                params![id],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0) as usize;

        let counts = |status: &str| -> usize {
            conn.query_row(
                "SELECT COUNT(*) FROM stripes WHERE object_id=?1 AND status=?2",
                params![id, status],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0) as usize
        };
        let recovered = counts("recovered");
        let ambiguous = counts("ambiguous");
        let below = counts("below_threshold");
        let budget = counts("budget_exhausted");
        let failed = counts("failed");
        let attempted = recovered + ambiguous + below + budget + failed;
        let not_attempted = total_stripes.saturating_sub(attempted);

        let (latest_check_status, latest_check_note) = conn
            .query_row(
                "SELECT status, note FROM object_checks WHERE object_id=?1
                 ORDER BY id DESC LIMIT 1",
                params![id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .unwrap_or_default();

        let isolated: Vec<String> = {
            let mut stmt = conn
                .prepare("SELECT source FROM isolated_sources WHERE object_id=?1 ORDER BY source")
                .unwrap();
            stmt.query_map(params![id], |r| r.get::<_, String>(0))
                .unwrap()
                .map(|r| r.unwrap())
                .collect()
        };

        out.push(ObjectSummary {
            object_id: id,
            generations,
            total_stripes,
            recovered,
            ambiguous,
            below_threshold: below,
            budget_exhausted: budget,
            failed,
            not_attempted,
            latest_check_note,
            latest_check_status,
            isolated_sources: isolated,
        });
    }
    out
}

pub fn list_stripes(db: &Db, object_id: &str) -> Vec<StripeRow> {
    let total: usize = {
        let conn = db.conn.lock().unwrap();
        conn.query_row(
            "SELECT COALESCE(MAX(stripe_count),0) FROM generations WHERE object_id=?1",
            params![object_id],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0) as usize
    };
    let conn = db.conn.lock().unwrap();
    let mut map: BTreeMap<usize, StripeRow> = BTreeMap::new();
    for i in 0..total {
        map.insert(
            i,
            StripeRow {
                stripe_index: i,
                status: "not_attempted".into(),
                status_label: crate::model::StripeStatus::NotAttempted.label().into(),
                ambiguous: false,
                generation: None,
                note: String::new(),
                outcome_count: 0,
                active_outcome_id: None,
            },
        );
    }
    let mut stmt = conn
        .prepare(
            "SELECT stripe_index, status, ambiguous, generation, note,
                    active_outcome_id,
                    (SELECT COUNT(*) FROM outcomes o
                     WHERE o.object_id = s.object_id AND o.stripe_index = s.stripe_index
                       AND o.feasible = 1)
             FROM stripes s WHERE object_id=?1 ORDER BY stripe_index",
        )
        .unwrap();
    let rows = stmt
        .query_map(params![object_id], |r| {
            Ok((
                r.get::<_, i64>(0)? as usize,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)? != 0,
                r.get::<_, Option<i64>>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, Option<i64>>(5)?,
                r.get::<_, i64>(6)? as usize,
            ))
        })
        .unwrap();
    for r in rows {
        let (idx, status, ambiguous, generation, note, oid, outcome_count) = r.unwrap();
        map.insert(
            idx,
            StripeRow {
                stripe_index: idx,
                status_label: status_label(&status),
                status,
                ambiguous,
                generation,
                note,
                outcome_count,
                active_outcome_id: oid,
            },
        );
    }
    map.into_values().collect()
}

pub fn list_generations(db: &Db, object_id: &str) -> Vec<(i64, i64, i64, i64, i64)> {
    let conn = db.conn.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT generation, data_shards, parity_shards, shard_size, stripe_count
             FROM generations WHERE object_id=?1 ORDER BY generation",
        )
        .unwrap();
    stmt.query_map(params![object_id], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
    })
    .unwrap()
    .map(|r| r.unwrap())
    .collect()
}

pub fn all_sources(db: &Db, object_id: &str) -> Vec<String> {
    let conn = db.conn.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT DISTINCT fr.source
             FROM fragment_receipts fr
             JOIN fragments f ON f.id = fr.fragment_id
             WHERE f.object_id=?1 ORDER BY fr.source",
        )
        .unwrap();
    stmt.query_map(params![object_id], |r| r.get::<_, String>(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
}

pub fn shard_health(db: &Db, object_id: &str) -> Vec<ShardHealth> {
    let isolated = {
        let conn = db.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT source FROM isolated_sources WHERE object_id=?1")
            .unwrap();
        let v: std::collections::BTreeSet<String> = stmt
            .query_map(params![object_id], |r| r.get::<_, String>(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        v
    };
    let conn = db.conn.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT f.stripe_index, f.shard_index, f.generation, f.id, f.blob_hash,
                    f.byte_length, COALESCE(bd.digest,''),
                    (SELECT GROUP_CONCAT(fr.source) FROM fragment_receipts fr
                       WHERE fr.fragment_id = f.id)
             FROM fragments f
             LEFT JOIN block_digests bd
               ON bd.object_id=f.object_id AND bd.generation=f.generation
              AND bd.stripe_index=f.stripe_index AND bd.shard_index=f.shard_index
             WHERE f.object_id=?1
             ORDER BY f.generation, f.stripe_index, f.shard_index, f.id",
        )
        .unwrap();
    let rows = stmt
        .query_map(params![object_id], |r| {
            let sources_raw: Option<String> = r.get(7)?;
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, String>(6)?,
                sources_raw.unwrap_or_default(),
            ))
        })
        .unwrap();
    let mut out = Vec::new();
    for r in rows {
        let (stripe, shard, gen, fid, hash, len, expected, sources_raw) = r.unwrap();
        let sources: Vec<String> = sources_raw
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        let isolated_flag = sources.iter().any(|s| isolated.contains(s));
        let (health, label) = if expected.is_empty() {
            ("unverified", "无摘要")
        } else if format!("sha256:{}", hash) == expected {
            ("good", "健康")
        } else {
            ("corrupt", "损坏")
        };
        out.push(ShardHealth {
            stripe_index: stripe as usize,
            shard_index: shard as usize,
            generation: gen,
            fragment_id: fid,
            blob_hash: hash,
            byte_length: len as usize,
            health: health.into(),
            health_label: label.into(),
            sources,
            expected_digest: expected,
            isolated: isolated_flag,
        });
    }
    out
}

pub fn outcomes_for_stripe(db: &Db, object_id: &str, stripe: usize) -> Vec<OutcomeView> {
    let active_outcome: Option<i64> = {
        let conn = db.conn.lock().unwrap();
        conn.query_row(
            "SELECT active_outcome_id FROM stripes
             WHERE object_id=?1 AND stripe_index=?2",
            params![object_id, stripe as i64],
            |r| r.get::<_, Option<i64>>(0),
        )
        .ok()
        .flatten()
    };
    let conn = db.conn.lock().unwrap();
    let mut outcome_ids: Vec<(i64, i64, i64, i64, String, i64, String)> = {
        let mut stmt = conn
            .prepare(
                "SELECT id, generation, rank, feasible, stripe_digest,
                        all_digests_match, differences_json
                 FROM outcomes WHERE object_id=?1 AND stripe_index=?2
                 ORDER BY recovery_id DESC, rank ASC, id ASC",
            )
            .unwrap();
        stmt.query_map(params![object_id, stripe as i64], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
            ))
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
    };

    let mut views = Vec::new();
    for (id, gen, rank, feasible, digest, all_match, diff_json) in outcome_ids.drain(..) {
        let blocks: Vec<OutcomeBlockView> = {
            let mut stmt = conn
                .prepare(
                    "SELECT shard_index, fragment_id, blob_hash, recomputed_digest,
                            expected_digest, matches_expected, rebuilt
                     FROM outcome_blocks WHERE outcome_id=?1 ORDER BY shard_index",
                )
                .unwrap();
            stmt.query_map(params![id], |r| {
                Ok(OutcomeBlockView {
                    shard_index: r.get(0)?,
                    fragment_id: r.get(1)?,
                    blob_hash: r.get(2)?,
                    recomputed_digest: r.get(3)?,
                    expected_digest: r.get(4)?,
                    matches_expected: r.get::<_, i64>(5)? != 0,
                    rebuilt: r.get::<_, i64>(6)? != 0,
                })
            })
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
        };
        let evidence: Vec<EvidenceView> = {
            let mut stmt = conn
                .prepare(
                    "SELECT shard_index, fragment_id, receipt_source, role, reason
                     FROM outcome_evidence WHERE outcome_id=?1
                     ORDER BY CASE role
                       WHEN 'participant' THEN 0
                       WHEN 'rebuilt' THEN 1
                       WHEN 'excluded_corrupt' THEN 2
                       ELSE 3 END, shard_index, id",
                )
                .unwrap();
            stmt.query_map(params![id], |r| {
                let reason: String = r.get(4)?;
                let label = if reason.is_empty() {
                    String::new()
                } else {
                    serde_json::from_str::<crate::model::ExclusionReason>(&reason)
                        .map(|e| e.label())
                        .unwrap_or(reason.clone())
                };
                Ok(EvidenceView {
                    shard_index: r.get(0)?,
                    fragment_id: r.get(1)?,
                    receipt_source: r.get(2)?,
                    role: r.get(3)?,
                    reason,
                    reason_label: label,
                })
            })
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
        };
        let differences: Vec<String> = serde_json::from_str(&diff_json).unwrap_or_default();
        views.push(OutcomeView {
            outcome_id: id,
            generation: gen,
            rank,
            feasible: feasible != 0,
            stripe_digest: digest,
            all_digests_match: all_match != 0,
            differences,
            blocks,
            evidence,
            active: active_outcome == Some(id),
        });
    }
    views
}

pub fn latest_object_checks(db: &Db, object_id: &str) -> Vec<crate::recovery::ObjectCheckSummary> {
    let recovery_id: Option<i64> = {
        let conn = db.conn.lock().unwrap();
        conn.query_row(
            "SELECT id FROM recoveries WHERE object_id=?1
             ORDER BY id DESC LIMIT 1",
            params![object_id],
            |r| r.get(0),
        )
        .ok()
    };
    let Some(rid) = recovery_id else { return Vec::new() };
    let conn = db.conn.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT generation, status, matching_stripes, stripe_count,
                    object_digest_expected, object_digest_actual, note
             FROM object_checks WHERE recovery_id=?1 ORDER BY generation",
        )
        .unwrap();
    stmt.query_map(params![rid], |r| {
        Ok(crate::recovery::ObjectCheckSummary {
            generation: r.get::<_, i64>(0)? as u64,
            status: r.get(1)?,
            matching_stripes: r.get::<_, i64>(2)? as usize,
            stripe_count: r.get::<_, i64>(3)? as usize,
            object_digest_expected: r.get(4)?,
            object_digest_actual: r.get(5)?,
            note: r.get(6)?,
        })
    })
    .unwrap()
    .map(|r| r.unwrap())
    .collect()
}
