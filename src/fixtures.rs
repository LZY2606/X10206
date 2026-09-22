//! 小有限域演示 fixture：在 data/sources 下生成三个对象的多个来源舱，
//! 覆盖单/多块缺失、位翻转、重复编号、generation 混杂、边界恢复、多个可行答案。

use std::fs;
use std::path::Path;

use crate::gf::{Gf256, DEFAULT_POLY};
use crate::hashutil::sha256_hex;
use crate::types::{coding_registry, CodingParams};
use serde::Serialize;

#[derive(Serialize)]
struct ManifestOut {
    object_id: String,
    object_digest: Option<String>,
    coding_version: String,
    declared_len: Option<u64>,
    stripe_count: u32,
    fragments: Vec<FragEntry>,
}

#[derive(Serialize, Clone)]
struct FragEntry {
    shard: u32,
    stripe: u32,
    generation: u32,
    length: u64,
    digest: String,
    file: String,
}

struct Bundle {
    source: String,
    object_id: String,
    object_digest: Option<String>,
    params_version: String,
    declared_len: Option<u64>,
    stripe_count: u32,
    entries: Vec<(FragEntry, Vec<u8>)>,
}

impl Bundle {
    fn new(source: &str, object_id: &str, version: &str, stripe_count: u32) -> Self {
        Bundle {
            source: source.into(),
            object_id: object_id.into(),
            object_digest: None,
            params_version: version.into(),
            declared_len: None,
            stripe_count,
            entries: Vec::new(),
        }
    }

    fn add(&mut self, stripe: u32, shard: u32, gen: u32, data: Vec<u8>) {
        let file = format!("shards/s{stripe}.sh{shard}.g{gen}.bin");
        self.add_named(stripe, shard, gen, data, file);
    }

    fn add_named(&mut self, stripe: u32, shard: u32, gen: u32, data: Vec<u8>, file: String) {
        let digest = sha256_hex(&data);
        let length = data.len() as u64;
        self.entries.push((
            FragEntry { shard, stripe, generation: gen, length, digest, file: file.clone() },
            data,
        ));
    }

    fn write(&self, root: &Path) {
        let dir = root.join(&self.source);
        fs::create_dir_all(dir.join("shards")).unwrap();
        for (e, data) in &self.entries {
            fs::write(dir.join(&e.file), data).unwrap();
        }
        let manifest = ManifestOut {
            object_id: self.object_id.clone(),
            object_digest: self.object_digest.clone(),
            coding_version: self.params_version.clone(),
            declared_len: self.declared_len,
            stripe_count: self.stripe_count,
            fragments: self.entries.iter().map(|(e, _)| e.clone()).collect(),
        };
        fs::write(
            dir.join("manifest.json"),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();
    }
}

fn params(version: &str) -> CodingParams {
    coding_registry().into_iter().find(|p| p.version == version).unwrap()
}

fn stripe_data(params: &CodingParams, seed: u8) -> Vec<Vec<u8>> {
    (0..params.k)
        .map(|j| {
            (0..params.stripe_bytes)
                .map(|b| seed.wrapping_add(j * 31).wrapping_add((b as u8) * 7))
                .collect()
        })
        .collect()
}

fn encode(params: &CodingParams, data: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let gf = Gf256::new(params.poly);
    gf.encode_parity(params.k, params.m, data)
}

pub fn create_demo_fixtures(root: &Path) {
    let sources = root.join("sources");
    fs::create_dir_all(&sources).unwrap();
    if sources.read_dir().unwrap().next().is_some() {
        return; // 已有数据，不覆盖
    }
    build_object_a(&sources);
    build_object_b(&sources);
    build_object_c(&sources);
}

// 对象 A：v1(k=3,m=2)，2 个 stripe。单块缺失 + 位翻转坏块 + 重复编号。
fn build_object_a(sources: &Path) {
    let p = params("v1");
    let mut s0data = stripe_data(&p, 10);
    s0data[0][2] ^= 0x55; // 让内容更"随机"（无实际意义，仅种子差异）
    let s0 = stripe_data(&p, 10);
    let s1 = stripe_data(&p, 40);
    let p0 = encode(&p, &s0);
    let p1 = encode(&p, &s1);

    let object_len = (p.k as usize * p.stripe_bytes * 2) as u64;
    let mut blocks = Vec::new();
    for d in &s0 { blocks.push(d.clone()); }
    for d in &s1 { blocks.push(d.clone()); }

    let digest = crate::hashutil::sha256_concat(&blocks, Some(object_len as usize));

    // 主来源：stripe0 缺 d0；stripe1 缺 p0（sh3），其余都在。
    let mut main = Bundle::new("A-field-node-01", "telemetry-A", "v1", 2);
    main.object_digest = Some(digest.clone());
    main.declared_len = Some(object_len);
    // stripe 0
    main.add(0, 1, 1, s0[1].clone());
    main.add(0, 2, 1, s0[2].clone());
    main.add(0, 3, 1, p0[0].clone());
    main.add(0, 4, 1, p0[1].clone());
    // stripe 1
    main.add(1, 0, 1, s1[0].clone());
    main.add(1, 1, 1, s1[1].clone());
    main.add(1, 2, 1, s1[2].clone());
    main.add(1, 4, 1, p1[1].clone());
    main.write(sources);

    // 备来源：提供缺失的 d0，但同 manifest 内 shard 编号重复（正确副本 + 位翻转副本）。
    let mut backup = Bundle::new("A-field-node-02", "telemetry-A", "v1", 2);
    backup.object_digest = Some(digest);
    backup.declared_len = Some(object_len);
    let mut flipped = s0[0].clone();
    flipped[0] ^= 0x01; // 位翻转：摘要不符，直接判 corrupt
    backup.add(0, 0, 1, flipped); // 重复编号条目 1（坏）
    backup.add(0, 0, 1, s0[0].clone()); // 重复编号条目 2（好）
    // stripe1 缺的 p0 也由备来源补齐
    backup.add(1, 3, 1, p1[0].clone());
    backup.write(sources);
}

// 对象 B：v1(k=3,m=2)，3 个 stripe，generation 混杂 + 恰好下限 + 不可恢复。
fn build_object_b(sources: &Path) {
    let p = params("v1");
    let s0 = stripe_data(&p, 70);
    let s1 = stripe_data(&p, 90);
    let s2 = stripe_data(&p, 110);
    let p0 = encode(&p, &s0);
    let p1 = encode(&p, &s1);
    let p2 = encode(&p, &s2);

    let object_len = (p.k as usize * p.stripe_bytes * 3) as u64;
    let mut blocks = Vec::new();
    for stripe_blocks in [&s0, &s1, &s2] {
        for d in stripe_blocks {
            blocks.push(d.clone());
        }
    }
    let digest = crate::hashutil::sha256_concat(&blocks, Some(object_len as usize));

    // 旧代来源（gen 1）：stripe0 有 2 个 data + 1 parity（恰好下限）。
    let mut old = Bundle::new("B-old-tape", "image-B", "v1", 3);
    old.object_digest = Some(digest.clone());
    old.declared_len = Some(object_len);
    old.add(0, 0, 1, s0[0].clone());
    old.add(0, 2, 1, s0[2].clone());
    old.add(0, 3, 1, p0[0].clone());
    // stripe1 旧代残留
    old.add(1, 0, 1, s1[0].clone());
    // stripe2 旧代残留（之后未被新代覆盖足够数量）
    old.add(2, 0, 1, s2[0].clone());
    old.write(sources);

    // 新代来源（gen 2，部分写入）：
    // stripe0 新代只有 1 块 -> 最新代位置不足 k，但旧代恰好 3 块 => 只有 degraded 可行
    //   （旧代内容恰好正确，degraded 解可人工核对）。
    // stripe1 新代 3 块（d1,d2,p1）+ 旧代 d0 => 新代不足 k，但混代全部恰好一致。
    // stripe2 新代仅 1 块 + 旧代 1 块 => 不可恢复。
    let mut new = Bundle::new("B-new-node", "image-B", "v1", 3);
    new.object_digest = Some(digest);
    new.declared_len = Some(object_len);
    new.add(0, 4, 2, p0[1].clone());
    new.add(1, 1, 2, s1[1].clone());
    new.add(1, 2, 2, s1[2].clone());
    new.add(1, 4, 2, p1[1].clone());
    new.add(2, 3, 2, p2[0].clone());
    new.write(sources);
}

// 对象 C：v2(k=4,m=3)，1 个 stripe，无对象摘要，同一 shard 两个内容候选 =>
// 在恰好下限时产生两个可行答案，页面显示 ambiguous 与差异。
fn build_object_c(sources: &Path) {
    let p = params("v2");
    let s0 = stripe_data(&p, 200);

    // 真相数据 d0..d3（无 parity 进入来源 => 两个 d3 候选都无法被证伪）。
    // 来源一只有 d0,d1,d2（3 块 < k=4，缺一块）。
    let mut src1 = Bundle::new("C-lab-alpha", "puzzle-C", "v2", 1);
    src1.add(0, 0, 1, s0[0].clone());
    src1.add(0, 1, 1, s0[1].clone());
    src1.add(0, 2, 1, s0[2].clone());
    src1.write(sources);

    // 来源二对缺失的 d3 给出两个候选：正确的与伪造的；没有 parity 可以证伪。
    let mut bogus = s0[3].clone();
    bogus[5] ^= 0x7f;
    let mut src2 = Bundle::new("C-lab-beta", "puzzle-C", "v2", 1);
    src2.add_named(0, 3, 1, s0[3].clone(), "shards/s0.sh3.g1.bin".into());
    src2.add_named(0, 3, 1, bogus, "shards/s0.sh3.g1.cand2.bin".into());
    src2.write(sources);
}

#[allow(dead_code)]
fn default_poly_used() -> u16 {
    DEFAULT_POLY
}
