#![allow(dead_code)]
#![allow(unused_imports)]
mod common;

use common::*;
use std::collections::BTreeSet;

fn sample_data() -> Vec<Vec<u8>> {
    vec![vec![10, 20, 30, 40], vec![50, 60, 70, 80]]
}

fn digest_list(shards: &[Vec<u8>]) -> Vec<String> {
    shards.iter().map(|b| sha256_hex(b)).collect()
}

#[test]
fn single_and_multi_missing_recover() {
    let data = sample_data();
    let all = encode(&data);
    let dig = digest_list(&all);

    // 单块缺失：缺 shard1
    let mut manifest = make_manifest("obj", 1, None, None);
    let shards = vec![
        ShardFile::new(0, 0, 1, "a", all[0].clone(), Some(dig[0].clone())),
        ShardFile::new(0, 2, 1, "a", all[2].clone(), Some(dig[2].clone())),
        ShardFile::new(0, 3, 1, "a", all[3].clone(), Some(dig[3].clone())),
    ];
    let dir = temp_dir("single");
    write_bundle(&dir, &manifest, &shards);
    let store = Store::open(dir.join("store")).unwrap();
    import(&dir, &store);
    let frags = load_frags(&store, "obj");
    let a = analyze(&manifest, &frags, &BTreeSet::new());
    assert_eq!(a[0].health, StripeHealth::Healthy);
    assert_eq!(a[0].solutions[0].shards, all);
    assert!(a[0].solutions[0].participants.iter().any(|p| p.shard == 2));

    // 多块缺失：只剩 2、3（两块 parity）
    manifest.stripe_count = 1;
    let shards = vec![
        ShardFile::new(0, 2, 1, "a", all[2].clone(), Some(dig[2].clone())),
        ShardFile::new(0, 3, 1, "a", all[3].clone(), Some(dig[3].clone())),
    ];
    let dir = temp_dir("multi");
    write_bundle(&dir, &manifest, &shards);
    let store = Store::open(dir.join("store")).unwrap();
    import(&dir, &store);
    let frags = load_frags(&store, "obj");
    let a = analyze(&manifest, &frags, &BTreeSet::new());
    assert_eq!(a[0].solutions[0].shards, all);
}

#[test]
fn bitflip_excluded_by_digest_and_redundancy() {
    let data = sample_data();
    let all = encode(&data);
    let dig = digest_list(&all);

    let mut bad = all[1].clone();
    bad[0] ^= 0xff; // 位翻转
    let shards = vec![
        ShardFile::new(0, 0, 1, "a", all[0].clone(), Some(dig[0].clone())),
        // 损坏块，但登记的是"正确"摘要 -> 摘要不符
        ShardFile::new(0, 1, 1, "b", bad, Some(dig[1].clone())),
        ShardFile::new(0, 2, 1, "a", all[2].clone(), Some(dig[2].clone())),
        ShardFile::new(0, 3, 1, "a", all[3].clone(), Some(dig[3].clone())),
    ];
    let manifest = make_manifest("obj", 1, None, None);
    let dir = temp_dir("bitflip");
    write_bundle(&dir, &manifest, &shards);
    let store = Store::open(dir.join("store")).unwrap();
    import(&dir, &store);
    let frags = load_frags(&store, "obj");
    let a = analyze(&manifest, &frags, &BTreeSet::new());

    assert!(a[0]
        .global_excluded
        .iter()
        .any(|e| e.reason == ExcludeReason::DigestMismatch && e.shard == 1));
    assert_eq!(a[0].solutions.len(), 1);
    assert_eq!(a[0].solutions[0].shards, all);
    // 损坏块绝不出现在参与者里
    assert!(a[0].solutions[0].participants.iter().all(|p| p.shard != 1 || p.source != "b"));
}

#[test]
fn duplicate_shard_numbers_picks_deterministic_candidate() {
    let data = sample_data();
    let all = encode(&data);
    let dig = digest_list(&all);

    // shard1 有两个内容候选：一个正确（g2，node-new），一个损坏（g1，node-old，无摘要）。
    let mut alt = all[1].clone();
    alt[3] ^= 0x01;
    let shards = vec![
        ShardFile::new(0, 0, 1, "a", all[0].clone(), Some(dig[0].clone())),
        ShardFile::new(0, 2, 1, "a", all[2].clone(), Some(dig[2].clone())),
        ShardFile::new(0, 3, 1, "a", all[3].clone(), Some(dig[3].clone())),
        ShardFile::new(0, 1, 1, "node-old", alt, None).with_suffix("old"),
        ShardFile::new(0, 1, 2, "node-new", all[1].clone(), Some(dig[1].clone()))
            .with_suffix("new"),
    ];
    let manifest = make_manifest("obj", 1, None, None);
    let dir = temp_dir("dup");
    write_bundle(&dir, &manifest, &shards);
    let store = Store::open(dir.join("store")).unwrap();
    import(&dir, &store);
    let frags = load_frags(&store, "obj");
    let a1 = analyze(&manifest, &frags, &BTreeSet::new());
    let a2 = analyze(&manifest, &frags, &BTreeSet::new());
    // 两次枚举顺序完全一致
    assert_eq!(
        a1[0].solutions.iter().map(|s| s.solution_id.clone()).collect::<Vec<_>>(),
        a2[0].solutions.iter().map(|s| s.solution_id.clone()).collect::<Vec<_>>()
    );
    let top = &a1[0].solutions[0];
    assert_eq!(top.shards, all);
    let p1 = top.participants.iter().find(|p| p.shard == 1).unwrap();
    assert_eq!(p1.source, "node-new");
    assert_eq!(p1.generation, 2);
    // 旧候选在冗余核对中被排除并留下证据
    assert!(top
        .excluded
        .iter()
        .chain(a1[0].global_excluded.iter())
        .any(|e| e.source == "node-old"));
}

#[test]
fn generation_mix_resolved_by_object_digest() {
    let new_data = sample_data();
    let old_data = vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8]];
    let new_all = encode(&new_data);
    let old_all = encode(&old_data);
    let new_dig = digest_list(&new_all);
    let old_dig = digest_list(&old_all);

    // 部分写：shard0=g2 新，shard1=g1 旧，parity2=g2 新，parity3=g1 旧。
    let shards = vec![
        ShardFile::new(0, 0, 2, "a", new_all[0].clone(), Some(new_dig[0].clone())),
        ShardFile::new(0, 1, 1, "b", old_all[1].clone(), Some(old_dig[1].clone())),
        ShardFile::new(0, 2, 2, "c", new_all[2].clone(), Some(new_dig[2].clone())),
        ShardFile::new(0, 3, 1, "d", old_all[3].clone(), Some(old_dig[3].clone())),
    ];
    let object: Vec<u8> = new_data.iter().flatten().copied().collect();
    let manifest = make_manifest("obj", 1, Some(sha256_hex(&object)), Some(object.len()));
    let dir = temp_dir("genmix");
    write_bundle(&dir, &manifest, &shards);
    let store = Store::open(dir.join("store")).unwrap();
    import(&dir, &store);
    let frags = load_frags(&store, "obj");
    let analyses = analyze(&manifest, &frags, &BTreeSet::new());

    // 部分写场景：旧代（g1）自洽解存在；混杂组合因与同代已验证块冲突而被淘汰，
    // 跨 stripe 组装时对象摘要唯一裁定为新代内容。
    assert!(analyses[0].solutions.iter().all(|s| !s.mixed_generation));
    assert!(analyses[0].solutions.iter().any(|s| s.generations == vec![1u64]));
    let outcomes = assemble_outcomes(&manifest, &analyses, DEFAULT_OBJECT_BUDGET).unwrap();
    // 对象摘要裁定后只剩"新"对象
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].bytes, object);
    assert_eq!(outcomes[0].digest_matches_manifest, Some(true));
}

#[test]
fn boundary_exactly_k_available_recovers() {
    let data = sample_data();
    let all = encode(&data);
    let dig = digest_list(&all);
    let shards = vec![
        ShardFile::new(0, 0, 1, "a", all[0].clone(), Some(dig[0].clone())),
        ShardFile::new(0, 3, 1, "a", all[3].clone(), Some(dig[3].clone())),
    ];
    let manifest = make_manifest("obj", 1, None, None);
    let dir = temp_dir("boundary");
    write_bundle(&dir, &manifest, &shards);
    let store = Store::open(dir.join("store")).unwrap();
    import(&dir, &store);
    let frags = load_frags(&store, "obj");
    let a = analyze(&manifest, &frags, &BTreeSet::new());
    assert_eq!(a[0].solutions[0].shards, all);

    // 少于 k：不可恢复
    let shards = vec![ShardFile::new(0, 0, 1, "a", all[0].clone(), Some(dig[0].clone()))];
    let dir2 = temp_dir("below");
    write_bundle(&dir2, &manifest, &shards);
    let store2 = Store::open(dir2.join("store")).unwrap();
    import(&dir2, &store2);
    let frags2 = load_frags(&store2, "obj");
    let a2 = analyze(&manifest, &frags2, &BTreeSet::new());
    assert_eq!(a2[0].health, StripeHealth::BelowThreshold);
    assert!(a2[0].solutions.is_empty());
}

#[test]
fn multiple_feasible_answers_without_object_digest() {
    // 两个不同 stripe，每个 stripe 都存在"已验证正确解"与"未验证但自洽的替代解"。
    // 构造：shard0/1/2 已验证 => 正确解；shard3 放一个与正确值不同且无摘要的块，
    // 用 {0,1,3} 可解出另一个"自洽"答案，因没有对象摘要，两个结果都保留。
    let data = sample_data();
    let all = encode(&data);
    let dig = digest_list(&all);

    // 恰好 k 个数据块：shard0 只有一份，shard1 有两个来源、同代、各自摘要自洽但内容不同。
    // 没有 parity 冗余、也没有对象摘要，两个 stripe 数据解都可行且必须全部保留。
    let mut alt1 = all[1].clone();
    alt1[0] ^= 0x55;
    let shards = vec![
        ShardFile::new(0, 0, 1, "a", all[0].clone(), Some(dig[0].clone())),
        ShardFile::new(0, 1, 1, "a", all[1].clone(), Some(dig[1].clone())),
        ShardFile::new(0, 1, 1, "z", alt1.clone(), Some(sha256_hex(&alt1)))
            .with_suffix("alt"),
    ];
    let manifest = make_manifest("obj", 1, None, None);
    let dir = temp_dir("multians");
    write_bundle(&dir, &manifest, &shards);
    let store = Store::open(dir.join("store")).unwrap();
    import(&dir, &store);
    let frags = load_frags(&store, "obj");
    let analyses = analyze(&manifest, &frags, &BTreeSet::new());

    // 应保留多个可行解（正确解与用 alt3 解出的替代解）
    assert!(analyses[0].solutions.len() >= 2);
    let outcomes = assemble_outcomes(&manifest, &analyses, DEFAULT_OBJECT_BUDGET).unwrap();
    assert!(outcomes.len() >= 2);
    let correct: Vec<u8> = data.iter().flatten().copied().collect();
    assert!(outcomes.iter().any(|o| o.bytes == correct));
    assert!(outcomes.iter().any(|o| o.bytes != correct));
    // 排序确定：两次结果 id 序列一致
    let ids1: Vec<String> = outcomes.iter().map(|o| o.outcome_id.clone()).collect();
    let analyses2 = analyze(&manifest, &frags, &BTreeSet::new());
    let outcomes2 = assemble_outcomes(&manifest, &analyses2, DEFAULT_OBJECT_BUDGET).unwrap();
    let ids2: Vec<String> = outcomes2.iter().map(|o| o.outcome_id.clone()).collect();
    assert_eq!(ids1, ids2);
}

#[test]
fn length_mismatch_marked_as_evidence() {
    let data = sample_data();
    let all = encode(&data);
    let mut wrong_len = all[2].clone();
    wrong_len.push(9);
    let shards = vec![
        ShardFile::new(0, 0, 1, "a", all[0].clone(), Some(sha256_hex(&all[0]))),
        ShardFile::new(0, 1, 1, "a", all[1].clone(), Some(sha256_hex(&all[1]))),
        ShardFile::new(0, 2, 1, "a", wrong_len, None),
    ];
    let manifest = make_manifest("obj", 1, None, None);
    let dir = temp_dir("len");
    write_bundle(&dir, &manifest, &shards);
    let store = Store::open(dir.join("store")).unwrap();
    import(&dir, &store);
    let frags = load_frags(&store, "obj");
    let a = analyze(&manifest, &frags, &BTreeSet::new());
    assert!(a[0]
        .global_excluded
        .iter()
        .any(|e| e.reason == ExcludeReason::LengthMismatch && e.shard == 2));
}
