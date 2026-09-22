//! 端到端恢复场景：单/多块缺失、位翻转、重复编号、generation 混合、
//! 边界恢复数、多个可行答案、磁盘写失败、中断续跑。组合排序确定 + 搜索预算。

mod common;

use common::*;
use stripe_capsule::import::import_bundle;
use stripe_capsule::recovery::{run_recovery, Fault, FaultKind, FsSink};
use stripe_capsule::types::lookup_params;

fn run(root: &std::path::Path, storage: &mut stripe_capsule::db::Storage, fault: Option<Fault>) {
    stripe_capsule::recovery::clean_temp_dir(root).unwrap();
    let mut sink = FsSink::new(root).unwrap();
    run_recovery(storage, &mut sink, fault);
}

fn build_simple(
    tmp: &TempDir,
    drops0: &[u32],
    drops1: &[u32],
) -> Vec<Vec<Vec<u8>>> {
    let params = lookup_params("v1").unwrap();
    let s0 = v1_data(10, params.stripe_bytes);
    let s1 = v1_data(40, params.stripe_bytes);
    let p0 = v1_parity(&s0);
    let p1 = v1_parity(&s1);
    let mut b = TestBundle::new(tmp.path(), "node1", "obj", "v1", 2);
    b.set_object_digest(&params, &[s0.clone(), s1.clone()]);
    for (sh, bytes) in s0.iter().enumerate() {
        if !drops0.contains(&(sh as u32)) {
            b.add(0, sh as u32, 1, bytes.clone(), false, 0, false, None);
        }
    }
    for (i, bytes) in p0.iter().enumerate() {
        let sh = params.k as u32 + i as u32;
        if !drops0.contains(&sh) {
            b.add(0, sh, 1, bytes.clone(), false, 0, false, None);
        }
    }
    for (sh, bytes) in s1.iter().enumerate() {
        if !drops1.contains(&(sh as u32)) {
            b.add(1, sh as u32, 1, bytes.clone(), false, 0, false, None);
        }
    }
    for (i, bytes) in p1.iter().enumerate() {
        let sh = params.k as u32 + i as u32;
        if !drops1.contains(&sh) {
            b.add(1, sh, 1, bytes.clone(), false, 0, false, None);
        }
    }
    b.write();
    vec![s0, s1]
}

#[test]
fn single_and_multi_shard_loss_recover_to_trusted() {
    let tmp = TempDir::new("loss");
    let truth = build_simple(&tmp, &[3], &[0, 2]);
    let mut storage = open_storage(tmp.path());
    import_bundle(&mut storage, &tmp.path().join("node1")).unwrap();
    run(tmp.path(), &mut storage, None);

    let obj = object_row(&mut storage, "obj");
    assert_eq!(obj.status, "trusted", "单块与多块缺失应重建成功");
    let stripes = stripe_rows(&mut storage, obj.id);
    assert_eq!(stripes.len(), 2);
    assert!(stripes.iter().all(|s| s.status == "committed"));
    let expect0 = stripe_capsule::hashutil::sha256_hex(&truth[0].concat());
    assert_eq!(stripes[0].output_digest.as_deref(), Some(expect0.as_str()));
}

#[test]
fn boundary_exact_k_shards_recover() {
    // 每 stripe 只剩恰好 k=3 块（含 parity）。
    let tmp = TempDir::new("boundary");
    let _truth = build_simple(&tmp, &[1, 3], &[0, 4]);
    let mut storage = open_storage(tmp.path());
    import_bundle(&mut storage, &tmp.path().join("node1")).unwrap();
    run(tmp.path(), &mut storage, None);
    let obj = object_row(&mut storage, "obj");
    assert_eq!(obj.status, "trusted", "恰好达到恢复下限应可信");
}

#[test]
fn below_threshold_is_unrecoverable() {
    let tmp = TempDir::new("below");
    let _truth = build_simple(&tmp, &[0, 2, 4], &[1, 3]);
    let mut storage = open_storage(tmp.path());
    import_bundle(&mut storage, &tmp.path().join("node1")).unwrap();
    run(tmp.path(), &mut storage, None);
    let obj = object_row(&mut storage, "obj");
    // stripe0 仅 2 块 < k；stripe1 恰好 3 块。
    assert_eq!(obj.status, "unrecoverable");
    let stripes = stripe_rows(&mut storage, obj.id);
    assert_eq!(stripes[0].status, "unrecoverable");
    assert_eq!(stripes[1].status, "committed");
}

#[test]
fn bit_flip_is_detected_and_excluded_with_evidence() {
    let tmp = TempDir::new("bitflip");
    let params = lookup_params("v1").unwrap();
    let s0 = v1_data(10, params.stripe_bytes);
    let p0 = v1_parity(&s0);
    let mut b = TestBundle::new(tmp.path(), "node1", "obj", "v1", 1);
    b.set_object_digest(&params, &[s0.clone()]);
    // d0 传输中位翻转（字节被改，清单仍声明原摘要 => 摘要不符，直接 corrupt）。
    let mut flipped = s0[0].clone();
    flipped[0] ^= 0x01;
    b.add(0, 0, 1, flipped, false, 0, true, None);
    b.add(0, 1, 1, s0[1].clone(), false, 0, false, None);
    b.add(0, 2, 1, s0[2].clone(), false, 0, false, None);
    b.add(0, 3, 1, p0[0].clone(), false, 0, false, None);
    b.add(0, 4, 1, p0[1].clone(), false, 0, false, None);
    b.write();

    let mut storage = open_storage(tmp.path());
    import_bundle(&mut storage, &tmp.path().join("node1")).unwrap();
    run(tmp.path(), &mut storage, None);

    let obj = object_row(&mut storage, "obj");
    assert_eq!(obj.status, "trusted", "坏块应被排除，4 个好块足以重建");
    let stripes = stripe_rows(&mut storage, obj.id);
    let ev = storage.evidence_for_stripe(stripes[0].id).unwrap();
    assert!(ev.iter().any(|e| e.kind == "digest_mismatch"), "位翻转需留摘要证据");
    // 坏碎片健康度
    let frags = storage.list_all_fragments(obj.id).unwrap();
    assert!(frags.iter().any(|f| f.health == "corrupt"));
}

#[test]
fn coding_inconsistent_shard_excluded_by_equations() {
    // 摘要全部"通过"（按篡改后字节生成摘要），但 d0 内容与其它块编码矛盾。
    let tmp = TempDir::new("codingbad");
    let params = lookup_params("v1").unwrap();
    let s0 = v1_data(10, params.stripe_bytes);
    let p0 = v1_parity(&s0);
    let mut tampered = s0[0].clone();
    tampered[3] ^= 0x2a;
    let mut b = TestBundle::new(tmp.path(), "node1", "obj", "v1", 1);
    // 不给对象摘要：防止对象层裁决，专注 stripe 层编码证据。
    b.add(0, 0, 1, tampered, false, 0, false, None);
    b.add(0, 1, 1, s0[1].clone(), false, 0, false, None);
    b.add(0, 2, 1, s0[2].clone(), false, 0, false, None);
    b.add(0, 3, 1, p0[0].clone(), false, 0, false, None);
    b.add(0, 4, 1, p0[1].clone(), false, 0, false, None);
    b.write();

    let mut storage = open_storage(tmp.path());
    import_bundle(&mut storage, &tmp.path().join("node1")).unwrap();
    run(tmp.path(), &mut storage, None);

    let obj = object_row(&mut storage, "obj");
    let stripes = stripe_rows(&mut storage, obj.id);
    assert_eq!(stripes[0].status, "committed");
    let ev = storage.evidence_for_stripe(stripes[0].id).unwrap();
    assert!(
        ev.iter().any(|e| e.kind == "coding_inconsistent"),
        "摘要通过但方程矛盾的块必须作为损坏证据排除"
    );
    let sols = storage.list_solutions(stripes[0].id).unwrap();
    let trusted = sols.iter().find(|s| s.tier == "trusted").unwrap();
    let subset: Vec<i64> = serde_json::from_str(&trusted.chosen_subset).unwrap();
    assert_eq!(subset.len(), 3, "参与计算 shard 需明确列出");
    assert!(!subset.is_empty());
}

#[test]
fn duplicate_shard_numbers_recorded_but_good_copy_recovers() {
    let tmp = TempDir::new("dup");
    let params = lookup_params("v1").unwrap();
    let s0 = v1_data(10, params.stripe_bytes);
    let p0 = v1_parity(&s0);
    let mut b = TestBundle::new(tmp.path(), "node1", "obj", "v1", 1);
    b.set_object_digest(&params, &[s0.clone()]);
    // 同 manifest 中 (stripe0, shard1) 重复：一份位翻转，一份正确（不同文件后缀）。
    b.add(0, 0, 1, s0[0].clone(), false, 0, false, None);
    let mut dup_bad = s0[1].clone();
    dup_bad[0] ^= 0x01;
    b.add(0, 1, 1, dup_bad, false, 0, true, Some(".a"));
    b.add(0, 1, 1, s0[1].clone(), false, 0, false, Some(".b"));
    b.add(0, 2, 1, s0[2].clone(), false, 0, false, None);
    b.add(0, 3, 1, p0[0].clone(), false, 0, false, None);
    b.add(0, 4, 1, p0[1].clone(), false, 0, false, None);
    b.write();

    let mut storage = open_storage(tmp.path());
    import_bundle(&mut storage, &tmp.path().join("node1")).unwrap();
    run(tmp.path(), &mut storage, None);
    let obj = object_row(&mut storage, "obj");
    assert_eq!(obj.status, "trusted");
    let stripes = stripe_rows(&mut storage, obj.id);
    let ev = storage.evidence_for_stripe(stripes[0].id).unwrap();
    assert!(ev.iter().any(|e| e.kind == "duplicate_shard"), "重复编号需记录");
}

#[test]
fn mixed_generation_produces_degraded_or_strict_when_latest_sufficient() {
    let tmp = TempDir::new("genmix");
    let params = lookup_params("v1").unwrap();
    let s0 = v1_data(10, params.stripe_bytes);
    let p0 = v1_parity(&s0);

    // 旧代 gen1：只有 1 块；新代 gen2：恰好 k=3 块。
    let mut old = TestBundle::new(tmp.path(), "old-node", "obj", "v1", 1);
    old.set_object_digest(&params, &[s0.clone()]);
    old.add(0, 0, 1, s0[0].clone(), false, 0, false, None);
    old.write();
    let mut new = TestBundle::new(tmp.path(), "new-node", "obj", "v1", 1);
    new.set_object_digest(&params, &[s0.clone()]);
    new.add(0, 1, 2, s0[1].clone(), false, 0, false, None);
    new.add(0, 2, 2, s0[2].clone(), false, 0, false, None);
    new.add(0, 3, 2, p0[0].clone(), false, 0, false, None);
    new.write();

    let mut storage = open_storage(tmp.path());
    import_bundle(&mut storage, &tmp.path().join("old-node")).unwrap();
    import_bundle(&mut storage, &tmp.path().join("new-node")).unwrap();
    run(tmp.path(), &mut storage, None);

    let obj = object_row(&mut storage, "obj");
    let stripes = stripe_rows(&mut storage, obj.id);
    // 最新代 3 块足够 => trusted 提交；旧代块有 stale_generation 证据。
    assert_eq!(stripes[0].status, "committed");
    let ev = storage.evidence_for_stripe(stripes[0].id).unwrap();
    assert!(ev.iter().any(|e| e.kind == "stale_generation"), "旧代需留痕");
    assert_eq!(obj.status, "trusted");
}

#[test]
fn only_old_generation_available_is_degraded_not_trusted() {
    // 最新代只有 2 块（不足 k），旧代补足 => 只能给出 degraded 保留答案。
    let tmp = TempDir::new("genmix2");
    let params = lookup_params("v1").unwrap();
    let s0 = v1_data(10, params.stripe_bytes);
    let p0 = v1_parity(&s0);
    let mut old = TestBundle::new(tmp.path(), "old-node", "obj", "v1", 1);
    old.add(0, 0, 1, s0[0].clone(), false, 0, false, None);
    old.add(0, 1, 1, s0[1].clone(), false, 0, false, None);
    old.add(0, 2, 1, s0[2].clone(), false, 0, false, None);
    old.write();
    let mut new = TestBundle::new(tmp.path(), "new-node", "obj", "v1", 1);
    new.add(0, 4, 2, p0[1].clone(), false, 0, false, None);
    new.add(0, 3, 2, p0[0].clone(), false, 0, false, None);
    new.write();

    let mut storage = open_storage(tmp.path());
    import_bundle(&mut storage, &tmp.path().join("old-node")).unwrap();
    import_bundle(&mut storage, &tmp.path().join("new-node")).unwrap();
    run(tmp.path(), &mut storage, None);
    let obj = object_row(&mut storage, "obj");
    let stripes = stripe_rows(&mut storage, obj.id);
    assert_eq!(stripes[0].status, "degraded", "混代恢复不得标记 trusted");
    let sols = storage.list_solutions(stripes[0].id).unwrap();
    assert!(sols.iter().any(|s| s.tier == "degraded"));
}

#[test]
fn multiple_feasible_answers_are_both_retained_without_digest() {
    // k=3：d0,d1,d2 中有两块真实数据，d2 位置给两个不同候选；无任何 parity。
    // => 两个候选各自给出一个"方程一致"答案 => ambiguous，保留全部解。
    let tmp = TempDir::new("multi");
    let params = lookup_params("v1").unwrap();
    let s0 = v1_data(10, params.stripe_bytes);
    let mut bogus = s0[2].clone();
    bogus[0] ^= 0x77;
    let mut b = TestBundle::new(tmp.path(), "node1", "obj", "v1", 1);
    b.add(0, 0, 1, s0[0].clone(), false, 0, false, None);
    b.add(0, 1, 1, s0[1].clone(), false, 0, false, None);
    b.add(0, 2, 1, s0[2].clone(), false, 0, false, Some(".real"));
    b.add(0, 2, 1, bogus, false, 0, false, Some(".fake"));
    b.write();

    let mut storage = open_storage(tmp.path());
    import_bundle(&mut storage, &tmp.path().join("node1")).unwrap();
    run(tmp.path(), &mut storage, None);
    let obj = object_row(&mut storage, "obj");
    assert_eq!(obj.status, "ambiguous");
    let stripes = stripe_rows(&mut storage, obj.id);
    assert_eq!(stripes[0].status, "ambiguous");
    let sols = storage.list_solutions(stripes[0].id).unwrap();
    let trusted: Vec<_> = sols.iter().filter(|s| s.tier == "trusted").collect();
    assert_eq!(trusted.len(), 2, "两个不同输出的可行解都必须保留");
    assert_ne!(trusted[0].output_digest, trusted[1].output_digest);
}

#[test]
fn object_digest_breaks_tie_between_feasible_answers() {
    // 同上但提供对象摘要 => 唯一匹配的解被选中提交为 trusted。
    let tmp = TempDir::new("multidig");
    let params = lookup_params("v1").unwrap();
    let s0 = v1_data(10, params.stripe_bytes);
    let mut bogus = s0[2].clone();
    bogus[0] ^= 0x77;
    let mut b = TestBundle::new(tmp.path(), "node1", "obj", "v1", 1);
    b.set_object_digest(&params, &[s0.clone()]);
    b.add(0, 0, 1, s0[0].clone(), false, 0, false, None);
    b.add(0, 1, 1, s0[1].clone(), false, 0, false, None);
    b.add(0, 2, 1, s0[2].clone(), false, 0, false, Some(".real"));
    b.add(0, 2, 1, bogus, false, 0, false, Some(".fake"));
    b.write();

    let mut storage = open_storage(tmp.path());
    import_bundle(&mut storage, &tmp.path().join("node1")).unwrap();
    run(tmp.path(), &mut storage, None);
    let obj = object_row(&mut storage, "obj");
    assert_eq!(obj.status, "trusted", "对象摘要应在多答案中裁决出唯一正确解");
    let stripes = stripe_rows(&mut storage, obj.id);
    assert_eq!(stripes[0].status, "committed");
}

#[test]
fn length_mismatch_blocks_participation_until_fixed() {
    let tmp = TempDir::new("len");
    let params = lookup_params("v1").unwrap();
    let s0 = v1_data(10, params.stripe_bytes);
    let p0 = v1_parity(&s0);
    let mut b = TestBundle::new(tmp.path(), "node1", "obj", "v1", 1);
    // d0 的 manifest 长度被错报（实际字节正确），只剩 4 块 => 仍可恢复，但有证据。
    b.add(0, 0, 1, s0[0].clone(), false, -3, false, None);
    b.add(0, 1, 1, s0[1].clone(), false, 0, false, None);
    b.add(0, 2, 1, s0[2].clone(), false, 0, false, None);
    b.add(0, 3, 1, p0[0].clone(), false, 0, false, None);
    b.add(0, 4, 1, p0[1].clone(), false, 0, false, None);
    b.write();

    let mut storage = open_storage(tmp.path());
    import_bundle(&mut storage, &tmp.path().join("node1")).unwrap();
    run(tmp.path(), &mut storage, None);
    let obj = object_row(&mut storage, "obj");
    let stripes = stripe_rows(&mut storage, obj.id);
    assert_eq!(stripes[0].status, "committed");
    let ev = storage.evidence_for_stripe(stripes[0].id).unwrap();
    assert!(ev.iter().any(|e| e.kind == "length_mismatch"));
}

#[test]
fn disk_write_failure_leaves_stripe_uncommitted_and_recovers_next_run() {
    let tmp = TempDir::new("diskfail");
    let _truth = build_simple(&tmp, &[3], &[4]);
    let mut storage = open_storage(tmp.path());
    import_bundle(&mut storage, &tmp.path().join("node1")).unwrap();

    // 第 1 个 stripe（index 0）落盘时注入写失败。
    run(
        tmp.path(),
        &mut storage,
        Some(Fault { kind: FaultKind::DiskWrite, stripe_seen: 0, fault_after: 0 }),
    );
    let obj = object_row(&mut storage, "obj");
    let stripes = stripe_rows(&mut storage, obj.id);
    assert_eq!(stripes[0].status, "pending", "写失败的 stripe 不得提交");
    assert_eq!(stripes[1].status, "pending", "中断后后续 stripe 也未处理");
    // 临时块必须被清理，最终目录无部分文件。
    let tmpdir = tmp.path().join("recovered").join(".tmp");
    let leftovers: Vec<_> = std::fs::read_dir(&tmpdir).unwrap().filter_map(|e| e.ok()).collect();
    assert!(leftovers.is_empty(), "临时块不得残留被最终读取");
    let s0dir = tmp.path().join("recovered").join("obj").join("s0");
    if s0dir.exists() {
        let promoted: Vec<_> = std::fs::read_dir(&s0dir).unwrap().filter_map(|e| e.ok()).collect();
        assert!(promoted.is_empty(), "未提交 stripe 不得有提升后的输出");
    }

    // 重新运行（无故障）：两个 stripe 均提交成功。
    run(tmp.path(), &mut storage, None);
    let obj = object_row(&mut storage, "obj");
    assert_eq!(obj.status, "trusted");
    let stripes = stripe_rows(&mut storage, obj.id);
    assert!(stripes.iter().all(|s| s.status == "committed"));
}

#[test]
fn interrupted_run_resumes_using_only_committed_stripes() {
    let tmp = TempDir::new("resume");
    let truth = build_simple(&tmp, &[3], &[4]);
    let mut storage = open_storage(tmp.path());
    import_bundle(&mut storage, &tmp.path().join("node1")).unwrap();

    // 第 1 个 stripe 成功，处理第 2 个之前"崩溃"（fault_after=1）。
    run(
        tmp.path(),
        &mut storage,
        Some(Fault { kind: FaultKind::Crash, stripe_seen: 0, fault_after: 1 }),
    );
    let obj = object_row(&mut storage, "obj");
    let stripes = stripe_rows(&mut storage, obj.id);
    assert_eq!(stripes[0].status, "committed");
    assert_eq!(stripes[1].status, "pending");

    // 模拟进程重启：重新打开 DB、清理临时目录、审计已提交 stripe、续跑。
    drop(storage);
    let mut storage2 = open_storage(tmp.path());
    stripe_capsule::recovery::clean_temp_dir(tmp.path()).unwrap();
    {
        let sink = FsSink::new(tmp.path()).unwrap();
        stripe_capsule::recovery::audit_committed(&mut storage2, &sink);
    }
    run(tmp.path(), &mut storage2, None);
    let obj = object_row(&mut storage2, "obj");
    assert_eq!(obj.status, "trusted");
    let stripes = stripe_rows(&mut storage2, obj.id);
    assert!(stripes.iter().all(|s| s.status == "committed"));
    let expect0 = stripe_capsule::hashutil::sha256_hex(&truth[0].concat());
    let expect1 = stripe_capsule::hashutil::sha256_hex(&truth[1].concat());
    assert_eq!(stripes[0].output_digest.as_deref(), Some(expect0.as_str()));
    assert_eq!(stripes[1].output_digest.as_deref(), Some(expect1.as_str()));
}

#[test]
fn committed_stripe_with_missing_output_file_is_recomputed_on_audit() {
    let tmp = TempDir::new("audit");
    let _truth = build_simple(&tmp, &[3], &[4]);
    let mut storage = open_storage(tmp.path());
    import_bundle(&mut storage, &tmp.path().join("node1")).unwrap();
    run(tmp.path(), &mut storage, None);
    // 人为删除一个已提交输出块，模拟崩溃后的不完整提交。
    let f = tmp.path().join("recovered").join("obj").join("s0").join("d0.bin");
    std::fs::remove_file(&f).unwrap();
    {
        let sink = FsSink::new(tmp.path()).unwrap();
        stripe_capsule::recovery::audit_committed(&mut storage, &sink);
    }
    let obj = object_row(&mut storage, "obj");
    let stripes = stripe_rows(&mut storage, obj.id);
    assert_eq!(stripes[0].status, "pending", "文件缺失的 committed stripe 应回退");
    run(tmp.path(), &mut storage, None);
    let obj = object_row(&mut storage, "obj");
    assert_eq!(obj.status, "trusted");
}

#[test]
fn isolating_a_source_recomputes_affected_stripes() {
    let tmp = TempDir::new("isolate");
    let params = lookup_params("v1").unwrap();
    let s0 = v1_data(10, params.stripe_bytes);
    let p0 = v1_parity(&s0);
    // node1：d0,d1,d2（3 data）；node2：p0,p1。隔离 node2 后仍有 3 data 可恢复。
    let mut a = TestBundle::new(tmp.path(), "node1", "obj", "v1", 1);
    a.set_object_digest(&params, &[s0.clone()]);
    a.add(0, 0, 1, s0[0].clone(), false, 0, false, None);
    a.add(0, 1, 1, s0[1].clone(), false, 0, false, None);
    a.add(0, 2, 1, s0[2].clone(), false, 0, false, None);
    a.write();
    let mut b = TestBundle::new(tmp.path(), "node2", "obj", "v1", 1);
    b.set_object_digest(&params, &[s0.clone()]);
    b.add(0, 3, 1, p0[0].clone(), false, 0, false, None);
    b.add(0, 4, 1, p0[1].clone(), false, 0, false, None);
    b.write();

    let mut storage = open_storage(tmp.path());
    import_bundle(&mut storage, &tmp.path().join("node1")).unwrap();
    import_bundle(&mut storage, &tmp.path().join("node2")).unwrap();
    run(tmp.path(), &mut storage, None);
    let obj = object_row(&mut storage, "obj");
    assert_eq!(obj.status, "trusted");

    // 隔离 node1（只有它有 data）=> stripe 不可恢复。
    let sources = storage.list_sources().unwrap();
    let node1 = sources.iter().find(|s| s.name == "node1").unwrap().id;
    let reset = storage.reset_stripes_for_source(node1).unwrap();
    storage.set_source_isolated(node1, true).unwrap();
    assert_eq!(reset.len(), 1);
    run(tmp.path(), &mut storage, None);
    let obj = object_row(&mut storage, "obj");
    assert_eq!(obj.status, "unrecoverable");

    // 取消隔离 => 恢复成功。
    storage.set_source_isolated(node1, false).unwrap();
    storage.reset_stripes_for_source(node1).unwrap();
    run(tmp.path(), &mut storage, None);
    let obj = object_row(&mut storage, "obj");
    assert_eq!(obj.status, "trusted");
}

#[test]
fn enumeration_is_deterministic_across_runs() {
    let tmp = TempDir::new("determ");
    // 多候选歧义场景：两次运行得到完全相同的解序与摘要。
    let params = lookup_params("v1").unwrap();
    let s0 = v1_data(10, params.stripe_bytes);
    let mut bogus2 = s0[2].clone();
    bogus2[0] ^= 0x77;
    let mut bogus1 = s0[1].clone();
    bogus1[0] ^= 0x33;
    let mut b = TestBundle::new(tmp.path(), "node1", "obj", "v1", 1);
    b.add(0, 0, 1, s0[0].clone(), false, 0, false, None);
    b.add(0, 1, 1, s0[1].clone(), false, 0, false, Some(".a"));
    b.add(0, 1, 1, bogus1, false, 0, false, Some(".b"));
    b.add(0, 2, 1, s0[2].clone(), false, 0, false, Some(".a"));
    b.add(0, 2, 1, bogus2, false, 0, false, Some(".b"));
    b.write();

    let sequence_for = |root: &std::path::Path, imported: bool| {
        let mut storage = open_storage(root);
        if !imported {
            import_bundle(&mut storage, &root.join("node1")).unwrap();
        }
        run(root, &mut storage, None);
        let obj = object_row(&mut storage, "obj");
        let stripes = stripe_rows(&mut storage, obj.id);
        storage
            .list_solutions(stripes[0].id)
            .unwrap()
            .into_iter()
            .map(|s| (s.tier, s.generation, s.output_digest))
            .collect::<Vec<_>>()
    };
    let seq1 = sequence_for(tmp.path(), false);
    // 复制来源到第二个目录（全新 DB；不同 fragment id 不影响结果序）。
    let tmp2 = TempDir::new("determ2");
    copy_dir(&tmp.path().join("node1"), &tmp2.path().join("node1"));
    let seq2 = sequence_for(tmp2.path(), false);
    assert_eq!(seq1, seq2, "组合排序必须确定");
    assert!(seq1.len() >= 2);
}

fn copy_dir(from: &std::path::Path, to: &std::path::Path) {
    fn walk(src: &std::path::Path, dst: &std::path::Path, base: &std::path::Path) {
        std::fs::create_dir_all(dst).unwrap();
        for e in std::fs::read_dir(src).unwrap().flatten() {
            let p = e.path();
            let target = dst.join(p.file_name().unwrap());
            if p.is_dir() {
                walk(&p, &target, base);
            } else {
                std::fs::copy(&p, &target).unwrap();
            }
        }
    }
    walk(from, to, from);
}

#[test]
fn export_writes_new_dir_atomic_manifest_and_touchless_sources() {
    let tmp = TempDir::new("export");
    let _truth = build_simple(&tmp, &[3], &[4]);
    let mut storage = open_storage(tmp.path());
    let source_dir = tmp.path().join("node1");
    let before = dir_checksum(&source_dir);
    import_bundle(&mut storage, &source_dir).unwrap();
    run(tmp.path(), &mut storage, None);
    let obj = object_row(&mut storage, "obj");
    let sink = FsSink::new(tmp.path()).unwrap();
    let dir1 = stripe_capsule::export::export_object(&mut storage, &sink, tmp.path(), obj.id).unwrap();
    assert!(dir1.join("manifest.json").exists());
    assert!(!dir1.join("manifest.json.tmp").exists());
    // 再次导出必须是另一个新目录。
    let dir2 = stripe_capsule::export::export_object(&mut storage, &sink, tmp.path(), obj.id).unwrap();
    assert_ne!(dir1, dir2, "导出始终使用新目录");
    let after = dir_checksum(&source_dir);
    assert_eq!(before, after, "原始碎片目录不得被修改");
}

fn dir_checksum(dir: &std::path::Path) -> String {
    let mut files: Vec<String> = Vec::new();
    fn walk(dir: &std::path::Path, out: &mut Vec<String>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else {
                let bytes = std::fs::read(&p).unwrap();
                out.push(format!("{}:{}", p.display(), stripe_capsule::hashutil::sha256_hex(&bytes)));
            }
        }
    }
    walk(dir, &mut files);
    files.sort();
    stripe_capsule::hashutil::sha256_hex(files.join("\n").as_bytes())
}

#[test]
fn search_budget_is_fixed_constant() {
    use stripe_capsule::types::DEFAULT_SEARCH_BUDGET;
    assert_eq!(DEFAULT_SEARCH_BUDGET, 4096);
}
