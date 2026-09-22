mod support;

use stripe_recovery_pod::recovery::{build_candidates, run_object_recovery, solve_numbered, CrashPoint};
use stripe_recovery_pod::gf::Gf256;
use stripe_recovery_pod::coding::CodingParams;

use support::Harness;

#[test]
fn isolating_a_source_recomputes_affected_stripe() {
    let mut h = Harness::new(3, 2, 2, 8);
    // stripe 0 needs data 0,1 from a and parity 3,4 from b (k=3: 0,1,3).
    h.deliver("a", 0, 0, 1, h.original(0, 0));
    h.deliver("a", 0, 1, 1, h.original(0, 1));
    h.deliver("b", 0, 3, 1, h.original(0, 3));
    h.deliver("b", 0, 4, 1, h.original(0, 4));
    // stripe 1 full set only from b
    for s_only in 0..5 {
        h.deliver("b", 1, s_only, 1, h.original(1, s_only));
    }
    h.import();
    let report = run_object_recovery(&h.store, &h.object_id, CrashPoint::None).unwrap();
    assert_eq!(report.status, "recovered");

    // Isolate source b: stripe 1 loses all shards, stripe 0 loses its parity.
    h.store.set_isolated("b", true, "operator isolation").unwrap();
    let touched = h.store.invalidate_stripes_for_source(&h.object_id, "b").unwrap();
    assert!(touched.contains(&0) && touched.contains(&1));
    let report = run_object_recovery(&h.store, &h.object_id, CrashPoint::None).unwrap();
    assert_eq!(report.status, "unrecoverable");
    assert!(report.failed.contains(&1));

    // Restore b and recovery succeeds again.
    h.store.set_isolated("b", false, "").unwrap();
    let touched = h.store.invalidate_stripes_for_source(&h.object_id, "b").unwrap();
    assert!(!touched.is_empty());
    let report = run_object_recovery(&h.store, &h.object_id, CrashPoint::None).unwrap();
    assert_eq!(report.status, "recovered");
}

#[test]
fn candidate_order_is_deterministic_regardless_of_delivery_order() {
    let mut h1 = Harness::new(3, 2, 1, 8);
    let mut h2 = Harness::new(3, 2, 1, 8);
    // Two sources deliver a duplicated index 0 (same content); reverse order.
    h1.deliver("src-a", 0, 0, 1, h1.original(0, 0));
    h1.deliver("src-b", 0, 0, 1, h1.original(0, 0));
    h1.deliver("src-a", 0, 1, 1, h1.original(0, 1));
    h1.deliver("src-a", 0, 2, 1, h1.original(0, 2));
    h1.deliver("src-b", 0, 4, 1, h1.original(0, 4));

    h2.deliver("src-b", 0, 4, 1, h2.original(0, 4));
    h2.deliver("src-a", 0, 2, 1, h2.original(0, 2));
    h2.deliver("src-a", 0, 1, 1, h2.original(0, 1));
    h2.deliver("src-b", 0, 0, 1, h2.original(0, 0));
    h2.deliver("src-a", 0, 0, 1, h2.original(0, 0));
    h1.import();
    h2.import();

    let gf = Gf256::new();
    let params = CodingParams { version: 1, k: 3, n: 5, shard_len: 8 };
    for h in [&h1, &h2] {
        let obj = h.object();
        let (groups, excluded) = build_candidates(&h.store, &obj, 0);
        let result = solve_numbered(&gf, params, 0, groups, excluded);
        assert_eq!(result.status, "feasible");
        let sig: Vec<(usize, i64, String)> = result.solutions[0]
            .combo
            .iter()
            .map(|c| (c.shard_index, c.fragment_id, c.source.clone()))
            .collect();
        // fragment ids may differ by source order, but the chosen index tuple
        // and chosen source per index must be identical and deterministic.
        let indices: Vec<usize> = sig.iter().map(|(i, _, _)| *i).collect();
        assert_eq!(indices, vec![0, 1, 2]);
        let source0 = &sig[0].2;
        assert_eq!(source0, "src-a", "deterministic source tie-break by name");
    }
}

#[test]
fn search_budget_is_fixed_and_stated() {
    assert_eq!(stripe_recovery_pod::recovery::STRIPE_SEARCH_BUDGET, 256);
    assert_eq!(stripe_recovery_pod::recovery::OBJECT_SEARCH_BUDGET, 256);
}

#[test]
fn demo_seed_recovers_both_objects() {
    let tmp = tempfile::TempDir::new().unwrap();
    let paths = stripe_recovery_pod::db::Paths::new(tmp.path());
    let store = std::sync::Arc::new(stripe_recovery_pod::db::Store::open(paths.clone()).unwrap());
    let ids = stripe_recovery_pod::seed::seed_demo(&paths.incoming).unwrap();
    assert_eq!(ids, vec!["obj-alpha", "obj-beta"]);
    let _ = stripe_recovery_pod::importer::scan_and_import_all(&store).unwrap();
    for id in ids {
        let r = run_object_recovery(&store, &id, CrashPoint::None).unwrap();
        assert_eq!(r.status, "recovered", "{}: {}", id, r.detail);
    }
    // evidence exists for the messy demo scenario
    let ev = store.evidence_for_object("obj-alpha").unwrap();
    let kinds: Vec<&str> = ev.iter().map(|e| e.kind.as_str()).collect();
    assert!(kinds.contains(&"duplicate_index"));
    assert!(kinds.contains(&"generation_mix"));
    assert!(kinds.contains(&"length_mismatch"));
    assert!(kinds.contains(&"digest_mismatch"));
}
