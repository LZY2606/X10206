#![allow(dead_code)]
#![allow(unused_imports)]
mod common;

use common::*;
use std::collections::BTreeSet;

fn two_stripe_object() -> (Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<u8>) {
    let s0 = vec![vec![10u8, 20, 30, 40], vec![50, 60, 70, 80]];
    let s1 = vec![vec![90, 100, 110, 120], vec![130, 140, 150, 160]];
    let mut object = Vec::new();
    object.extend(s0[0].iter().chain(s0[1].iter()));
    object.extend(s1[0].iter().chain(s1[1].iter()));
    (s0, s1, object)
}

fn build_healthy_bundle(dir: &std::path::Path) -> (Manifest, Vec<u8>) {
    let (s0, s1, object) = two_stripe_object();
    let a0 = encode(&s0);
    let a1 = encode(&s1);
    let manifest = make_manifest("obj", 2, Some(sha256_hex(&object)), Some(object.len()));
    let mut shards = Vec::new();
    for (stripe, all) in [(0, a0), (1, a1)] {
        for sh in 0..4 {
            shards.push(ShardFile::new(
                stripe,
                sh,
                1,
                "node-a",
                all[sh].clone(),
                Some(sha256_hex(&all[sh])),
            ));
        }
    }
    write_bundle(dir, &manifest, &shards);
    (manifest, object)
}

#[test]
fn recovery_and_export_roundtrip() {
    let dir = temp_dir("roundtrip");
    let bundle = dir.join("bundle");
    std::fs::create_dir_all(&bundle).unwrap();
    let (_, object) = build_healthy_bundle(&bundle);
    let store = Store::open(dir.join("store")).unwrap();
    import(&bundle, &store);

    let progress = recovery::run_recovery(&store, "obj", true).unwrap();
    assert_eq!(progress.stripes_total, 2);
    assert_eq!(progress.stripes_rebuilt, 2);

    let result = exporter::export_outcome(&store, "obj", None).unwrap();
    assert!(result.dir.join("manifest.json").exists());
    assert!(!result.dir.join("manifest.json.tmp").exists());
    let exported = std::fs::read(result.dir.join("object.bin")).unwrap();
    assert_eq!(exported, object);
    // 原始碎片未改动：仍可重新读取
    assert!(!store.raw_dir().read_dir().unwrap().next().is_none());
}

#[test]
fn resume_reuses_only_committed_stripes() {
    let dir = temp_dir("resume");
    let bundle = dir.join("bundle");
    std::fs::create_dir_all(&bundle).unwrap();
    build_healthy_bundle(&bundle);
    let store = Store::open(dir.join("store")).unwrap();
    import(&bundle, &store);

    let p1 = recovery::run_recovery(&store, "obj", true).unwrap();
    assert_eq!(p1.stripes_rebuilt, 2);

    // 续跑：两个 stripe 都应复用，不再重建。
    let p2 = recovery::run_recovery(&store, "obj", true).unwrap();
    assert_eq!(p2.stripes_reused, 2);
    assert_eq!(p2.stripes_rebuilt, 0);

    // tmp 目录应为空：临时块不进入最终读取。
    let tmp = store.tmp_dir();
    let leftover: Vec<_> = std::fs::read_dir(&tmp).unwrap().filter_map(|e| e.ok()).collect();
    assert!(leftover.is_empty(), "tmp 中不得残留临时块");
}

#[test]
fn disk_write_failure_then_retry_succeeds() {
    let dir = temp_dir("diskfail");
    let bundle = dir.join("bundle");
    std::fs::create_dir_all(&bundle).unwrap();
    build_healthy_bundle(&bundle);

    // 第一次打开的 store 在临时块写入处失败 100 次（整个恢复必然失败）。
    let fault = CountingFault::new(FaultPoint::WriteTempBlock, 100);
    let store = Store::open_with_fault(dir.join("store-bad"), fault).unwrap();
    import(&bundle, &store);
    let err = recovery::run_recovery(&store, "obj", true);
    assert!(err.is_err(), "磁盘写失败时恢复必须报错，不能只报成功");

    // 不应有任何 stripe 被提交。
    assert!(store.get_stripe_commit("obj", 0).is_none());
    assert!(store.get_stripe_commit("obj", 1).is_none());

    // 全新无故障 store，指向不同目录重新导入并恢复，应成功。
    let store_ok = Store::open(dir.join("store-ok")).unwrap();
    import(&bundle, &store_ok);
    let p = recovery::run_recovery(&store_ok, "obj", true).unwrap();
    assert_eq!(p.stripes_rebuilt, 2);
}

#[test]
fn temp_blocks_never_read_for_final_output() {
    let dir = temp_dir("notmp");
    let bundle = dir.join("bundle");
    std::fs::create_dir_all(&bundle).unwrap();
    build_healthy_bundle(&bundle);
    let store = Store::open(dir.join("store")).unwrap();
    import(&bundle, &store);

    // 未恢复时导出必须失败。
    assert!(exporter::export_outcome(&store, "obj", None).is_err());

    // 人为在 tmp 放假块，恢复后导出也不得读取它。
    let tmp = store.tmp_dir();
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::write(tmp.join("forged.part"), vec![0u8; 4]).unwrap();
    let _ = recovery::run_recovery(&store, "obj", true).unwrap();
    let result = exporter::export_outcome(&store, "obj", None).unwrap();
    let obj = std::fs::read(result.dir.join("object.bin")).unwrap();
    assert_ne!(obj, vec![0u8; obj.len()]);
}

#[test]
fn source_isolation_forces_recompute() {
    // stripe0 只靠 parity2/3 恢复（来自 node-B）；隔离 node-B 后应不可恢复。
    let (s0, s1, object) = two_stripe_object();
    let a0 = encode(&s0);
    let a1 = encode(&s1);
    let manifest = make_manifest("obj", 2, Some(sha256_hex(&object)), Some(object.len()));
    let mut shards = Vec::new();
    // stripe 0：只提供 parity 2、3，来自 node-B（边界恢复）
    for sh in [2usize, 3usize] {
        shards.push(ShardFile::new(
            0,
            sh,
            1,
            "node-B",
            a0[sh].clone(),
            Some(sha256_hex(&a0[sh])),
        ));
    }
    // stripe 1：完整，来自 node-A
    for sh in 0..4 {
        shards.push(ShardFile::new(
            1,
            sh,
            1,
            "node-A",
            a1[sh].clone(),
            Some(sha256_hex(&a1[sh])),
        ));
    }
    let dir = temp_dir("isolate");
    let bundle = dir.join("bundle");
    std::fs::create_dir_all(&bundle).unwrap();
    write_bundle(&bundle, &manifest, &shards);
    let store = Store::open(dir.join("store")).unwrap();
    import(&bundle, &store);

    let p = recovery::run_recovery(&store, "obj", true).unwrap();
    assert_eq!(p.stripes_rebuilt, 2);

    let mut iso = BTreeSet::new();
    iso.insert("node-B".to_string());
    store.set_isolated_sources("obj", &iso).unwrap();
    let err = recovery::run_recovery(&store, "obj", true);
    assert!(err.is_err(), "隔离 node-B 后 stripe0 必须不可恢复");

    // 取消隔离后再次成功
    store.set_isolated_sources("obj", &BTreeSet::new()).unwrap();
    recovery::run_recovery(&store, "obj", true).unwrap();
}

#[test]
fn interruption_midway_then_resume_commits_pending() {
    // 让第一次恢复在第 1 个 stripe 的临时块写入成功后、第 2 个 stripe 写入失败：
    // stripe0 已完整提交，stripe1 未提交；续跑应复用 stripe0、只重建 stripe1。
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc as StdArc;

    struct FailAfter {
        calls: AtomicUsize,
        threshold: usize,
    }
    impl FsFault for FailAfter {
        fn should_fail(&self, point: FaultPoint, _: &std::path::Path) -> bool {
            if point != FaultPoint::WriteTempBlock {
                return false;
            }
            // stripe0 只有缺失块需要临时块；内容寻址已存在的块不再写。
            // 用调用计数：放行前 threshold 次，之后失败。
            self.calls.fetch_add(1, Ordering::SeqCst) + 1 > self.threshold
        }
    }

    let dir = temp_dir("interrupt");
    let bundle = dir.join("bundle");
    std::fs::create_dir_all(&bundle).unwrap();
    build_healthy_bundle(&bundle);

    let fault = StdArc::new(FailAfter {
        calls: AtomicUsize::new(0),
        threshold: 4, // 足够 stripe0 的 4 个输出块，stripe1 首次写即失败
    });
    let store = Store::open_with_fault(dir.join("store"), fault).unwrap();
    import(&bundle, &store);

    let first = recovery::run_recovery(&store, "obj", true);
    assert!(first.is_err(), "模拟中断：第一次恢复应失败");
    // stripe0 已提交（块全部就位），stripe1 未提交。
    assert!(store.get_stripe_commit("obj", 0).is_some());
    assert!(store.get_stripe_commit("obj", 1).is_none());

    // 用无故障方式重新打开同一数据目录续跑。
    let store2 = Store::open(dir.join("store")).unwrap();
    let progress = recovery::run_recovery(&store2, "obj", true).unwrap();
    assert_eq!(progress.stripes_reused, 1, "stripe0 摘要完整应被复用");
    assert_eq!(progress.stripes_rebuilt, 1, "stripe1 应被重建");

    let result = exporter::export_outcome(&store2, "obj", None).unwrap();
    let exported = std::fs::read(result.dir.join("object.bin")).unwrap();
    let (_, _, object) = two_stripe_object();
    assert_eq!(exported, object);
}

#[test]
fn committed_stripe_with_missing_block_is_not_reused() {
    // 人为删除 stripe0 的一个最终块：摘要完整性校验应失败并触发重建。
    let dir = temp_dir("corruptblock");
    let bundle = dir.join("bundle");
    std::fs::create_dir_all(&bundle).unwrap();
    build_healthy_bundle(&bundle);
    let store = Store::open(dir.join("store")).unwrap();
    import(&bundle, &store);
    recovery::run_recovery(&store, "obj", true).unwrap();

    // 删除 stripe0 首选解 shard0 的物理块。
    let (sid, analysis_json) = store.get_stripe_commit("obj", 0).unwrap();
    let analysis: stripe_recovery_cabin::model::StripeAnalysis =
        serde_json::from_str(&analysis_json).unwrap();
    let digest = store
        .solution_block_digest("obj", 0, &sid, 0)
        .unwrap();
    let path = store.blocks_dir().join(format!("{}.bin", digest));
    let _ = std::fs::remove_file(&path);

    let progress = recovery::run_recovery(&store, "obj", true).unwrap();
    assert_eq!(progress.stripes_reused, 1, "stripe1 仍可复用");
    assert_eq!(progress.stripes_rebuilt, 1, "缺块的 stripe0 必须重建");
    let _ = analysis;
}
