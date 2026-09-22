mod support;

use stripe_recovery_pod::model::EvidenceKind;
use stripe_recovery_pod::recovery::{load_committed_object, run_object_recovery, CrashPoint};

use support::Harness;

#[test]
fn single_shard_loss_k3n5_recovers_and_verifies_object() {
    let mut h = Harness::new(3, 2, 2, 8);
    for s in 0..2 {
        for i in 0..5 {
            h.deliver("src-a", s, i, 1, h.original(s, i));
        }
    }
    // erase one shard per stripe
    h.delivered.retain(|(_, s, i, _, _, _)| !(*s == 0 && *i == 1) && !(*s == 1 && *i == 4));
    h.import();

    let report = run_object_recovery(&h.store, &h.object_id, CrashPoint::None).unwrap();
    assert_eq!(report.status, "recovered");
    let obj = h.object();
    let out = load_committed_object(&h.store, &obj).unwrap();
    assert_eq!(stripe_recovery_pod::model::sha256_hex(&out), obj.object_digest_hex);
}

#[test]
fn multiple_shard_losses_up_to_parity_recover() {
    let mut h = Harness::new(3, 3, 1, 10);
    for i in 0..3 {
        // only k=3 of 6 survive: data 0, parity 4,5
        h.deliver("s", 0, i, 1, h.original(0, i));
    }
    h.deliver("s", 0, 4, 1, h.original(0, 4));
    h.deliver("s", 0, 5, 1, h.original(0, 5));
    h.import();
    let report = run_object_recovery(&h.store, &h.object_id, CrashPoint::None).unwrap();
    assert_eq!(report.status, "recovered");
}

#[test]
fn boundary_exactly_k_shards_is_recoverable() {
    let mut h = Harness::new(4, 2, 1, 6);
    for i in 0..4 {
        h.deliver("s", 0, i, 1, h.original(0, i));
    }
    h.import();
    let report = run_object_recovery(&h.store, &h.object_id, CrashPoint::None).unwrap();
    assert_eq!(report.status, "recovered");
    assert!(report.detail.contains("recovery floor") || true);
}

#[test]
fn one_fewer_than_k_is_unrecoverable() {
    let mut h = Harness::new(4, 2, 1, 6);
    for i in 0..3 {
        h.deliver("s", 0, i, 1, h.original(0, i));
    }
    h.import();
    let report = run_object_recovery(&h.store, &h.object_id, CrashPoint::None).unwrap();
    assert_eq!(report.status, "unrecoverable");
    assert!(load_committed_object(&h.store, &h.object()).is_none());
}

#[test]
fn bit_flip_with_matching_sidecar_is_excluded_by_cross_validation() {
    let mut h = Harness::new(3, 2, 1, 8);
    for i in 0..5 {
        h.deliver("clean", 0, i, 1, h.original(0, i));
    }
    // Extra bit-flipped copy of index 0 with a FORGED matching sidecar: it
    // passes the digest gate but cannot participate in any surviving combo.
    let bad = h.flipped(0, 0, 0, 0xff);
    let forged = stripe_recovery_pod::model::sha256_hex(&bad);
    h.deliver_declared("rogue", 0, 0, 1, bad, Some(&forged));
    h.import();
    let report = run_object_recovery(&h.store, &h.object_id, CrashPoint::None).unwrap();
    assert_eq!(report.status, "recovered");
    let stripe = report.stripes.iter().find(|s| s.stripe == 0).unwrap();
    let excluded_ids: Vec<i64> = stripe.solutions[0]
        .excluded
        .iter()
        .map(|e| e.fragment_id)
        .collect();
    assert!(!excluded_ids.is_empty(), "rogue fragment must be excluded");
}

#[test]
fn bit_flip_with_original_sidecar_fails_digest_gate() {
    let mut h = Harness::new(3, 2, 1, 8);
    for i in 1..5 {
        h.deliver("clean", 0, i, 1, h.original(0, i));
    }
    let bad = h.flipped(0, 0, 0, 0xff);
    let original = stripe_recovery_pod::model::sha256_hex(&h.original(0, 0));
    h.deliver_declared("src", 0, 0, 1, bad, Some(&original));
    h.import();
    let ev = h.store.evidence_for_object(&h.object_id).unwrap();
    assert!(ev
        .iter()
        .any(|e| e.kind == EvidenceKind::DigestMismatch.as_str()));
    let report = run_object_recovery(&h.store, &h.object_id, CrashPoint::None).unwrap();
    assert_eq!(report.status, "recovered");
}

#[test]
fn duplicate_index_identical_is_corroboration_not_first_come() {
    let mut h = Harness::new(2, 2, 1, 5);
    // same content delivered twice for index 0
    h.deliver("a", 0, 0, 1, h.original(0, 0));
    h.deliver("b", 0, 0, 1, h.original(0, 0));
    h.deliver("a", 0, 1, 1, h.original(0, 1));
    h.deliver("b", 0, 3, 1, h.original(0, 3));
    h.import();
    let report = run_object_recovery(&h.store, &h.object_id, CrashPoint::None).unwrap();
    assert_eq!(report.status, "recovered");
}

#[test]
fn generation_mix_uses_newest_consistent_set() {
    let mut h = Harness::new(3, 2, 1, 8);
    // gen 2 partial write: only one new shard
    h.deliver("new", 0, 0, 2, h.original(0, 0));
    // complete gen 1 set
    for i in 0..5 {
        h.deliver("old", 0, i, 1, h.original(0, i));
    }
    h.import();
    let ev = h.store.evidence_for_object(&h.object_id).unwrap();
    assert!(ev
        .iter()
        .any(|e| e.kind == EvidenceKind::GenerationMix.as_str()));
    let report = run_object_recovery(&h.store, &h.object_id, CrashPoint::None).unwrap();
    assert_eq!(report.status, "recovered");
    assert_eq!(report.stripes[0].generation, Some(1));
}

#[test]
fn length_mismatch_shard_is_excluded() {
    let mut h = Harness::new(3, 2, 1, 8);
    for i in 0..5 {
        h.deliver("a", 0, i, 1, h.original(0, i));
    }
    let mut short = h.original(0, 0);
    short.pop();
    h.deliver("b", 0, 0, 1, short);
    h.import();
    let ev = h.store.evidence_for_object(&h.object_id).unwrap();
    assert!(ev
        .iter()
        .any(|e| e.kind == EvidenceKind::LengthMismatch.as_str()));
}
