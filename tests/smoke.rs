use stripe_recovery_pod::demo::seed_demo_data;
use stripe_recovery_pod::engine::{recover_object, RunOptions};
use stripe_recovery_pod::export::export_object;
use stripe_recovery_pod::model::StripeStatus;
use stripe_recovery_pod::store::Store;

#[test]
fn smoke_demo_alpha_and_beta() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    seed_demo_data(&store).unwrap();

    let alpha = recover_object(&store, "alpha", RunOptions::default()).unwrap();
    println!(
        "alpha committed={} ambiguous={} infeasible={} reused={}",
        alpha.report.committed, alpha.report.ambiguous, alpha.report.infeasible, alpha.report.reused
    );
    for r in &alpha.report.stripes {
        println!(
            "  stripe {} status={:?} solutions={} truncated={} combos={} resolved={}",
            r.stripe, r.status, r.solutions.len(), r.truncated, r.combos_considered, r.resolved
        );
    }
    assert_eq!(alpha.report.infeasible, 0);
    assert!(alpha.object_bytes.is_some());

    // alpha should export.
    let ex = export_object(&store, "alpha", RunOptions::default()).unwrap();
    println!("alpha export {}", ex.manifest_path);

    let beta = recover_object(&store, "beta", RunOptions::default()).unwrap();
    println!(
        "beta committed={} ambiguous={} infeasible={}",
        beta.report.committed, beta.report.ambiguous, beta.report.infeasible
    );
    for r in &beta.report.stripes {
        println!(
            "  stripe {} status={:?} solutions={}",
            r.stripe, r.status, r.solutions.len()
        );
        for (i, sol) in r.solutions.iter().enumerate() {
            println!(
                "    sol{i} gen={} participants={:?} digest={}",
                sol.generation, sol.participant_ids, sol.stripe_digest
            );
        }
    }
    assert_eq!(beta.report.stripes[0].status, StripeStatus::Ambiguous);
    assert!(beta.object_bytes.is_none());

    // Isolate node-c -> unique.
    store.isolate_source("beta", "node-c").unwrap();
    let beta2 = recover_object(&store, "beta", RunOptions::default()).unwrap();
    assert_eq!(beta2.report.stripes[0].status, StripeStatus::Unique);
    let ex2 = export_object(&store, "beta", RunOptions::default()).unwrap();
    println!("beta export {}", ex2.manifest_path);
}

#[test]
fn alpha_reconstructs_original_bytes_and_records_evidence() {
    use stripe_recovery_pod::digest::object_data_digest;
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    seed_demo_data(&store).unwrap();
    let out = recover_object(&store, "alpha", RunOptions::default()).unwrap();

    // Recompute original from known demo data.
    use stripe_recovery_pod::gf256::Gf256;
    use stripe_recovery_pod::rs::{encode, CodecVersion};
    let gf = Gf256::new();
    let (k, m) = (3, 2);
    let d0 = vec![vec![1u8, 2, 3, 4], vec![5, 6, 7, 8], vec![9, 10, 11, 12]];
    let d1 = vec![vec![20u8, 21, 22, 23], vec![24, 25, 26, 27], vec![28, 29, 30, 31]];
    let c0 = encode(&gf, CodecVersion::V1, k, m, &d0);
    let c1 = encode(&gf, CodecVersion::V1, k, m, &d1);
    let want = object_data_digest(&[c0, c1], k);
    assert_eq!(object_data_digest(&out.committed_shards, k), want);

    // Stripe 0 must exclude the bit-flipped node-b, the length-mismatch
    // node-f, and the stale generation node-e, while using node-a/node-c
    // as data and cross-checking node-d.
    let r0 = &out.report.stripes[0];
    let sol = &r0.solutions[0];
    let exclusion_kinds: Vec<String> = sol
        .exclusions
        .iter()
        .map(|e| serde_json::to_value(e).unwrap()["kind"].as_str().unwrap().to_string())
        .collect();
    assert!(exclusion_kinds.iter().any(|k| k == "digest_mismatch"), "{exclusion_kinds:?}");
    assert!(exclusion_kinds.iter().any(|k| k == "length_mismatch"), "{exclusion_kinds:?}");
    assert!(exclusion_kinds.iter().any(|k| k == "generation_conflict"), "{exclusion_kinds:?}");
    // Exactly k participants; any additional healthy distinct shard is witness.
    assert_eq!(sol.participant_ids.len(), 3);
    assert!(sol.participant_ids.len() + sol.witness_ids.len() <= 5);
}
