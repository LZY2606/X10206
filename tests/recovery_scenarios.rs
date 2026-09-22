mod common;

use common::{bitflip, Harness};

#[test]
fn single_shard_gap_recovers() {
    // k=3, m=2: one data shard missing, four available.
    let mut h = Harness::new(3, 2, 6, 1);
    let dir = h.make_complete_source_with_gaps(0, |s, idx| !(s == 0 && idx == 2));
    h.import(&dir);
    let report = h.run(false);
    assert_eq!(h.status_of(0), "recovered");
    assert_eq!(report.recovered, 1);
    assert_eq!(h.data_shard_bytes(0, 2), h.all_shards(0)[2]);
}

#[test]
fn multi_shard_gap_parity_only_survives() {
    // Missing data 1,2 and parity 4: survive 0 + parity 3 + parity ... use
    // m=3 so slots 0,3,5 give exactly k=3.
    let mut h = Harness::new(3, 3, 7, 1);
    let dir = h.make_complete_source_with_gaps(0, |s, idx| {
        !(s == 0 && (idx == 1 || idx == 2 || idx == 4))
    });
    h.import(&dir);
    let report = h.run(false);
    assert_eq!(h.status_of(0), "recovered", "{:?}", report.errors);
    for idx in 0..6 {
        assert_eq!(h.data_shard_bytes(0, idx), h.all_shards(0)[idx]);
    }
}

#[test]
fn bit_flipped_candidate_is_excluded_by_digest() {
    // Good shard 1 plus a bit-flipped duplicate shard 1: the corrupt copy is
    // recorded as excluded_corrupt evidence and the good one participates.
    let mut h = Harness::new(3, 2, 6, 1);
    let shards = h.all_shards(0);
    let mut files: Vec<_> = (0..5)
        .filter(|i| *i != 2) // leave a gap so parity is needed
        .map(|i| (0usize, i, shards[i].clone(), None))
        .collect();
    files.push((0, 1, bitflip(&shards[1]), Some("flipped".to_string())));
    let dir = h.make_source(0, &files, |_, _| true);
    h.import(&dir);
    let report = h.run(false);
    assert_eq!(h.status_of(0), "recovered", "{:?}", report.errors);
    assert_eq!(h.data_shard_bytes(0, 2), shards[2]);

    let conn = h.db.conn.lock().unwrap();
    let (reason,): (String,) = conn
        .query_row(
            "SELECT reason FROM outcome_evidence
             WHERE role='excluded_corrupt' AND reason LIKE '%digest_mismatch%' LIMIT 1",
            [],
            |r| Ok((r.get(0)?,)),
        )
        .unwrap();
    assert!(reason.contains("digest_mismatch"));
}

#[test]
fn duplicate_shard_numbers_keep_both_candidates() {
    // Same shard number, two DIFFERENT byte contents from two receipts.
    let mut h = Harness::new(3, 2, 6, 1);
    let shards = h.all_shards(0);
    let files = vec![
        (0usize, 0usize, shards[0].clone(), None),
        (0, 1, shards[1].clone(), None),
        (0, 1, bitflip(&shards[1]), Some("dup".to_string())),
        (0, 3, shards[3].clone(), None),
    ];
    let dir = h.make_source(0, &files, |_, _| true);
    h.import(&dir);
    h.run(false);
    let conn = h.db.conn.lock().unwrap();
    let n: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM fragments WHERE stripe_index=0 AND shard_index=1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 2, "both content candidates must be stored");
}

#[test]
fn boundary_exact_k_shards_succeeds() {
    let mut h = Harness::new(4, 2, 5, 1);
    // Exactly k=4 shards survive.
    let dir = h.make_complete_source_with_gaps(0, |_, idx| idx < 4);
    h.import(&dir);
    let report = h.run(false);
    assert_eq!(h.status_of(0), "recovered", "{:?}", report.errors);
}

#[test]
fn below_threshold_is_reported_not_success() {
    let mut h = Harness::new(3, 2, 5, 1);
    // Only 2 shards: below k.
    let dir = h.make_complete_source_with_gaps(0, |_, idx| idx < 2);
    h.import(&dir);
    let report = h.run(false);
    assert_eq!(h.status_of(0), "below_threshold");
    assert_eq!(report.below_threshold, 1);
    assert_eq!(report.recovered, 0);
}

#[test]
fn multiple_feasible_answers_with_sparse_digests() {
    // A second generation with NO block digests for stripe 0: both the good
    // and the bit-flipped shard-1 candidate yield mathematically feasible
    // (but different) stripes. Both must be retained with a difference note.
    let mut h = Harness::new(3, 2, 6, 1);
    let shards = h.all_shards(0);

    let g0 = h.make_complete_source_with_gaps(0, |s, i| !(s == 0 && i == 2));
    h.import(&g0);

    let files = vec![
        (0usize, 0usize, shards[0].clone(), None),
        (0, 1, shards[1].clone(), Some("good".to_string())),
        (0, 1, bitflip(&shards[1]), Some("alt".to_string())),
        (0, 3, shards[3].clone(), None),
    ];
    // Publish no per-block digests for G1 at all.
    let g1 = h.make_source(1, &files, |_, _| false);
    h.import(&g1);

    let report = h.run(false);
    assert!(h.feasible_count(0) >= 2, "all distinct feasible stripes retained");
    assert_eq!(h.status_of(0), "ambiguous");
    assert!(report.ambiguous >= 1);

    // The distinct outcomes have different stripe digests.
    let conn = h.db.conn.lock().unwrap();
    let digests: i64 = conn
        .query_row(
            "SELECT COUNT(DISTINCT stripe_digest) FROM outcomes
             WHERE object_id=?1 AND stripe_index=0 AND feasible=1",
            rusqlite::params![h.object_id],
            |r| r.get(0),
        )
        .unwrap();
    assert!(digests >= 2);
}

#[test]
fn generation_mixing_partial_write_does_not_corrupt_older_generation() {
    // G0 covers 2 stripes fully; G1 only contains data for stripe 1.
    // Stripe 0 must still recover from G0 even though G1 is below threshold.
    let mut h = Harness::new(3, 2, 6, 2);
    let g0 = h.make_complete_source_with_gaps(0, |s, i| !(s == 0 && (i == 2 || i == 4)));
    // stripe 1 ships complete in G0.
    h.import(&g0);

    let shards1 = h.all_shards(1);
    // G1 manifest covers both stripes but only one shard of stripe 1 ships.
    let files = vec![(1usize, 0usize, shards1[0].clone(), Some("g1".to_string()))];
    let g1 = h.make_source(1, &files, |_, _| true);
    h.import(&g1);

    let report = h.run(false);
    assert_eq!(h.status_of(0), "recovered", "{:?}", report.errors);
    assert_eq!(h.status_of(1), "recovered");
    // The active generation for both stripes is G0; G1's partial stripe 1
    // attempt is retained as below-threshold evidence, not used.
    let conn = h.db.conn.lock().unwrap();
    let gens: Vec<i64> = {
        let mut stmt = conn.prepare(
            "SELECT generation FROM stripes WHERE object_id=?1 ORDER BY stripe_index",
        ).unwrap();
        stmt.query_map(rusqlite::params![h.object_id], |r| r.get::<_, i64>(0))
            .unwrap().map(|r| r.unwrap()).collect()
    };
    drop(conn);
    assert_eq!(gens, vec![0, 0]);
    let conn = h.db.conn.lock().unwrap();
    let g1_infeasible: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM outcomes
             WHERE object_id=?1 AND generation=1 AND feasible=0",
            rusqlite::params![h.object_id],
            |r| r.get(0),
        )
        .unwrap();
    assert!(g1_infeasible >= 1);
}

#[test]
fn enumeration_order_and_budget_are_deterministic() {
    // Two runs on identical inputs must produce identical ordered outcome keys.
    fn keys(h: &Harness) -> Vec<String> {
        let conn = h.db.conn.lock().unwrap();
        let latest: i64 = conn
            .query_row(
                "SELECT MAX(id) FROM recoveries WHERE object_id=?1",
                rusqlite::params![h.object_id],
                |r| r.get(0),
            )
            .unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT stripe_digest FROM outcomes
                 WHERE object_id=?1 AND feasible=1 AND recovery_id=?2
                 ORDER BY stripe_index, rank, stripe_digest",
            )
            .unwrap();
        stmt.query_map(rusqlite::params![h.object_id, latest], |r| r.get::<_, String>(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    let mut h = Harness::new(3, 2, 6, 1);
    let dir = h.make_complete_source_with_gaps(0, |_, i| i != 2);
    h.import(&dir);
    h.run(false);
    let first = keys(&h);
    let second_report = h.run(true);
    let second = keys(&h);
    assert_eq!(first, second);
    assert!(second_report.errors.is_empty());
}

#[test]
fn write_failure_aborts_stripe_without_partial_commit() {
    // Arm one blob write failure: the affected stripe must be marked failed,
    // no active outcome, and staged leftovers swept. After disarming and
    // re-running, recovery succeeds.
    let mut h = Harness::new(3, 2, 6, 1);
    let dir = h.make_complete_source_with_gaps(0, |_, i| i != 2);
    h.import(&dir);

    h.failures.arm_blob_promote_failures(1);
    let report = h.run(false);
    assert!(report.failed >= 1 || !report.errors.is_empty());
    let conn = h.db.conn.lock().unwrap();
    let active: Option<i64> = conn
        .query_row(
            "SELECT active_outcome_id FROM stripes
             WHERE object_id=?1 AND stripe_index=0",
            rusqlite::params![h.object_id],
            |r| r.get(0),
        )
        .unwrap();
    drop(conn);
    assert!(active.is_none(), "no partial commit may be activated");

    // Staging dir is empty after the attempt (swept on next store open).
    let store2 = stripe_recovery_pod::store::BlobStore::open(
        &h.tmp.join("store"),
        h.failures.clone(),
    )
    .unwrap();
    let staged: Vec<_> = std::fs::read_dir(h.tmp.join("store").join("staging"))
        .unwrap()
        .collect();
    assert!(staged.is_empty());

    let report2 = stripe_recovery_pod::recovery::run_recovery(
        &h.db,
        &store2,
        &h.object_id,
        stripe_recovery_pod::recovery::RecoveryOptions { trigger: "retry".into(), force: true },
    );
    assert_eq!(report2.failed, 0, "{:?}", report2.errors);
    assert_eq!(h.status_of(0), "recovered");
}

#[test]
fn interrupted_resume_reuses_only_committed_stripes() {
    // Two stripes; fail on stripe 1 only (arm exactly one failure after
    // stripe 0 has committed). Restart store (sweeps staging) and rerun:
    // stripe 0 is reused without changing its active outcome id, stripe 1
    // then commits.
    let mut h = Harness::new(3, 2, 6, 2);
    let dir = h.make_complete_source_with_gaps(0, |s, i| !(s == 1 && (i == 2 || i == 4)) && !(s == 0 && i == 2));
    h.import(&dir);

    // Stripe 0 needs 2 rebuilt blobs; let those promotes succeed, then fail
    // the first promote belonging to stripe 1. Stripe order is index order.
    h.failures.arm_promote_fail_after(2);
    let report0 = h.run(false);
    assert_eq!(report0.recovered, 1, "{:?}", report0.errors);
    let first_outcome = {
        let conn = h.db.conn.lock().unwrap();
        let v: Option<i64> = conn
            .query_row(
                "SELECT active_outcome_id FROM stripes
                 WHERE object_id=?1 AND stripe_index=0",
                rusqlite::params![h.object_id],
                |r| r.get(0),
            )
            .unwrap();
        v.unwrap()
    };

    // Simulate process restart: reopen the store (sweeps staging) and rerun
    // without force. Both committed stripes must be reused as-is.
    let store2 = stripe_recovery_pod::store::BlobStore::open(
        &h.tmp.join("store"),
        h.failures.clone(),
    )
    .unwrap();
    let report2 = stripe_recovery_pod::recovery::run_recovery(
        &h.db,
        &store2,
        &h.object_id,
        stripe_recovery_pod::recovery::RecoveryOptions { trigger: "resume".into(), force: false },
    );
    assert_eq!(report2.reused, 1);
    assert_eq!(report2.recovered, 1);
    let reused_outcome = {
        let conn = h.db.conn.lock().unwrap();
        let v: Option<i64> = conn
            .query_row(
                "SELECT active_outcome_id FROM stripes
                 WHERE object_id=?1 AND stripe_index=0",
                rusqlite::params![h.object_id],
                |r| r.get(0),
            )
            .unwrap();
        v.unwrap()
    };
    assert_eq!(first_outcome, reused_outcome, "committed stripe is reused, not rebuilt");
    assert_eq!(h.status_of(0), "recovered");
    assert_eq!(h.status_of(1), "recovered");
}

#[test]
fn source_isolation_forces_recompute_without_candidate() {
    // All good shards come from source A; a bit-flipped duplicate comes from
    // source B. Initially A+B are present and recovery succeeds. After
    // isolating source A, only the corrupt B candidate remains for slot 1 and
    // the stripe must fall below threshold.
    let mut h = Harness::new(3, 2, 6, 1);
    let shards = h.all_shards(0);

    let good = h.make_source(
        0,
        &[
            (0usize, 0usize, shards[0].clone(), None),
            (0, 1, shards[1].clone(), None),
            (0, 3, shards[3].clone(), None),
        ],
        |_, _| true,
    );
    h.import(&good);

    let bad = h.make_source(
        0,
        &[(0, 1, bitflip(&shards[1]), Some("bad".to_string()))],
        |_, _| false,
    );
    h.import(&bad);
    assert_eq!(h.run(false).failed, 0);

    let name = good.file_name().unwrap().to_string_lossy().to_string();
    {
        let conn = h.db.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO isolated_sources(object_id, source, isolated_at) VALUES (?1,?2,0)",
            rusqlite::params![h.object_id, name],
        )
        .unwrap();
    }
    let report = h.run(true);
    assert!(report.below_threshold >= 1);
    assert_eq!(h.status_of(0), "below_threshold");
}
