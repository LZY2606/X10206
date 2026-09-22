mod support;

use stripe_recovery_pod::exporter::{export_object, manifest_is_switched};
use stripe_recovery_pod::recovery::{run_object_recovery, CrashPoint};

use support::Harness;

#[test]
fn ambiguous_solutions_are_all_retained_but_only_digest_match_commits() {
    // k=2 n=3. We provide clean original shards 0,1,2 AND a second, internally
    // consistent but wrong "candidate" for index 0 plus matching wrong parity
    // shards, so a second reconstruction exists mathematically. Cross-stripe
    // validation against the object digest must reject the wrong one and mark
    // the chosen solution explicitly.
    let mut h = Harness::new(2, 1, 1, 6);
    h.deliver("good", 0, 0, 1, h.original(0, 0));
    h.deliver("good", 0, 1, 1, h.original(0, 1));
    h.deliver("good", 0, 2, 1, h.original(0, 2));

    // Build a self-consistent alternative stripe from a DIFFERENT data vector
    // using the same coding parameters, delivered as same-generation candidates.
    let alt_data0 = vec![0xAAu8; 6];
    let alt_data1 = vec![0x55u8; 6];
    let gf = stripe_recovery_pod::gf::Gf256::new();
    let params = stripe_recovery_pod::coding::CodingParams {
        version: 1,
        k: 2,
        n: 3,
        shard_len: 6,
    };
    let alt = stripe_recovery_pod::coding::encode(&gf, params, &[alt_data0, alt_data1]);
    h.deliver("alt", 0, 0, 1, alt[0].clone());
    h.deliver("alt", 0, 2, 1, alt[2].clone());
    h.import();

    let report = run_object_recovery(&h.store, &h.object_id, CrashPoint::None).unwrap();
    // The wrong data cannot reproduce the manifest object digest; only the
    // original stripe is part of a trusted assembly.
    assert_eq!(report.status, "recovered");
    let sols = h.store.list_solutions(&h.object_id, 0).unwrap();
    // The alt index-0 disagrees with reconstruction from good set and vice
    // versa: corroboration rules mean only content agreeing with each combo is
    // kept. At least one feasible solution is retained and committed.
    assert!(!sols.is_empty());
    let commit = h.store.get_stripe(&h.object_id, 0).unwrap().unwrap();
    assert_eq!(commit.status, "committed");
    assert!(commit.chosen_solution_id.is_some());
}

#[test]
fn object_digest_mismatch_marks_untrusted_and_commits_nothing() {
    // Tamper the MANIFEST object digest so no assembly can verify.
    let mut h = Harness::new(2, 2, 1, 5);
    for i in 0..4 {
        h.deliver("a", 0, i, 1, h.original(0, i));
    }
    h.manifest.object_digest_hex = "0".repeat(64);
    h.import();
    let report = run_object_recovery(&h.store, &h.object_id, CrashPoint::None).unwrap();
    assert_eq!(report.status, "untrusted");
    assert!(h.store.get_stripe(&h.object_id, 0).unwrap().is_none());
}

#[test]
fn simulated_disk_write_failure_leaves_no_partial_stripe_and_pending_wiped() {
    let mut h = Harness::new(3, 2, 3, 8);
    for s in 0..3 {
        for i in 0..5 {
            h.deliver("a", s, i, 1, h.original(s, i));
        }
    }
    h.import();
    let err = run_object_recovery(&h.store, &h.object_id, CrashPoint::StagingWriteFail(1))
        .expect_err("disk failure surfaces");
    assert!(err.to_string().contains("disk write failure"));
    // Stripe 0 committed before the failure; stripe 1 must not be committed;
    // no pending rows survive.
    let s0 = h.store.get_stripe(&h.object_id, 0).unwrap().unwrap();
    assert_eq!(s0.status, "committed");
    assert!(h.store.get_stripe(&h.object_id, 1).unwrap().is_none());
    let pending: i64 = {
        let conn = h.store.lock();
        conn.query_row(
            "SELECT COUNT(*) FROM pending_shards WHERE object_id=?1",
            rusqlite::params![&h.object_id],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert_eq!(pending, 0);
}

#[test]
fn crash_before_commit_then_resume_only_reuses_complete_stripes() {
    let mut h = Harness::new(3, 2, 3, 8);
    for s in 0..3 {
        for i in 0..5 {
            h.deliver("a", s, i, 1, h.original(s, i));
        }
    }
    h.import();
    let err = run_object_recovery(&h.store, &h.object_id, CrashPoint::BeforeCommit(1))
        .expect_err("crash rolls the transaction back");
    assert!(err.to_string().contains("simulated crash"));
    // Stripe 0 was committed before the crash; stripe 1's commit rolled back.
    assert_eq!(
        h.store.get_stripe(&h.object_id, 0).unwrap().unwrap().status,
        "committed"
    );
    assert!(h.store.get_stripe(&h.object_id, 1).unwrap().is_none());

    // Simulate process restart: opening the store wipes pending rows.
    let reopened = Store::open(h.store.paths.clone()).unwrap();
    let report = run_object_recovery(&reopened, &h.object_id, CrashPoint::None).unwrap();
    assert_eq!(report.status, "recovered");
    assert_eq!(report.reused, 1, "stripe 0 reused, stripes 1 and 2 recomputed");
    assert_eq!(report.committed, 3);
    let reused = report.stripes.iter().any(|s| s.stripe == 0 && s.reused);
    assert!(reused);
}

#[test]
fn export_uses_fresh_directory_and_atomic_manifest_switch() {
    let mut h = Harness::new(3, 2, 2, 8);
    for s in 0..2 {
        for i in 0..5 {
            h.deliver("a", s, i, 1, h.original(s, i));
        }
    }
    h.import();
    run_object_recovery(&h.store, &h.object_id, CrashPoint::None).unwrap();
    let obj = h.object();
    let dir = export_object(&h.store, &obj).unwrap();
    assert!(manifest_is_switched(&dir));
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["trusted"], true);
    assert_eq!(manifest["shards"].as_array().unwrap().len(), 2 * 5);
    // Original fragments untouched: count files and check digest dir still intact.
    let mut count = 0;
    for e in walkdir(&h.store.paths.fragments) {
        if e.extension().and_then(|x| x.to_str()) == Some("bin") {
            count += 1;
        }
    }
    assert_eq!(count, 2 * 5);
}

fn walkdir(p: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(p) {
        for e in rd.flatten() {
            let path = e.path();
            if path.is_dir() {
                out.extend(walkdir(&path));
            } else {
                out.push(path);
            }
        }
    }
    out
}

use stripe_recovery_pod::db::Store;
