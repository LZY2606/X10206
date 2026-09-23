//! 演示 fixture：GF(16)、k=3、m=2、3 条 stripe，覆盖
//! 缺失、位翻转、重复编号、generation 混杂、边界恢复数（恰好 3 块）。

use std::fs;
use std::path::Path;

use stripe_recovery_bay::coding::{encode, CodingParams};
use stripe_recovery_bay::field::Field;
use stripe_recovery_bay::import;
use stripe_recovery_bay::manifest::{
    CodingSpec, DigestRef, ImportManifest, ShardEntry, IMPORT_MANIFEST_VERSION,
};
use stripe_recovery_bay::model::{object_digest_hex, sha256_hex};
use stripe_recovery_bay::store::Store;
use stripe_recovery_bay::model::FaultGate;
use std::sync::Arc;

pub fn seed_demo(data_dir: &str) -> std::io::Result<()> {
    let dir = Path::new(data_dir).join("inbox").join("demo-batch");
    fs::create_dir_all(&dir)?;
    let f = Field::gf16();
    let params = CodingParams { field_bits: 4, k: 3, m: 2, shard_size: 8 };

    let stripe_data: Vec<Vec<Vec<u8>>> = vec![
        vec![vec![1, 2, 3, 4, 5, 6, 7, 8], vec![9, 10, 11, 12, 13, 14, 15, 1], vec![2, 4, 6, 8, 10, 12, 14, 1]],
        vec![vec![3, 3, 3, 3, 7, 7, 7, 7], vec![1, 1, 2, 2, 3, 3, 4, 4], vec![15, 14, 13, 12, 11, 10, 9, 8]],
        vec![vec![8, 7, 6, 5, 4, 3, 2, 1], vec![10, 10, 10, 10, 10, 10, 10, 10], vec![5, 5, 6, 6, 7, 7, 8, 8]],
    ];
    let mut grid = Vec::new();
    for d in &stripe_data {
        let p = encode(&f, d, 2);
        let mut full = d.clone();
        full.extend(p);
        grid.push(full);
    }
    let object_digest = object_digest_hex(&grid);

    let mut shards = Vec::new();
    let mut add = |shards: &mut Vec<ShardEntry>,
                   file: String,
                   stripe: usize,
                   slot: usize,
                   gen: i64,
                   source: &str,
                   bytes: &[u8],
                   with_digest: bool| {
        let digest = if with_digest {
            Some(DigestRef { alg: "sha256".into(), value: sha256_hex(bytes) })
        } else {
            None
        };
        shards.push(ShardEntry {
            file,
            stripe,
            slot,
            generation: gen,
            source: source.into(),
            digest,
        });
    };

    // stripe 0：slot 0,1,2 数据块齐全（恰好下限），来自三个来源；缺两块校验。
    for slot in 0..3 {
        let name = format!("s0-slot{slot}.bin");
        fs::write(dir.join(&name), &grid[0][slot])?;
        add(&mut shards, name, 0, slot, 1, &format!("node-{}", ['A', 'B', 'C'][slot]), &grid[0][slot], true);
    }

    // stripe 1：4 块（>下限），其中 slot4 位翻转 => 枚举时矛盾证据；正确子集仍可恢复。
    let present = [0usize, 1, 2, 4];
    for &slot in &present {
        let name = format!("s1-slot{slot}.bin");
        let mut bytes = grid[1][slot].clone();
        if slot == 4 {
            bytes[0] ^= 0b1;
        }
        fs::write(dir.join(&name), &bytes)?;
        // 故意不提供被翻转块的摘要，模拟“收到但完整性未知”。
        add(&mut shards, name, 1, slot, 1, "node-B", &bytes, slot != 4);
    }
    // 同一 slot1 的重复编号：旧 generation 2 的另一份内容（部分写残留）。
    let stale = vec![9u8, 9, 9, 9, 9, 9, 9, 9];
    fs::write(dir.join("s1-slot1-gen2.bin"), &stale)?;
    add(&mut shards, "s1-slot1-gen2.bin".into(), 1, 1, 2, "node-A", &stale, true);

    // stripe 2：slot 0,1,2,3 四块，恰好需要 3；全部同代且正确。
    for slot in 0..4 {
        let name = format!("s2-slot{slot}.bin");
        fs::write(dir.join(&name), &grid[2][slot])?;
        add(&mut shards, name, 2, slot, 1, "node-C", &grid[2][slot], true);
    }
    // slot3 再来一份重复内容（同摘要，重复编号但无分歧）。
    fs::write(dir.join("s2-slot3-dup.bin"), &grid[2][3])?;
    add(&mut shards, "s2-slot3-dup.bin".into(), 2, 3, 1, "node-A", &grid[2][3], true);

    let manifest = ImportManifest {
        manifest_version: IMPORT_MANIFEST_VERSION.into(),
        object_id: "demo-object".into(),
        object_digest: Some(DigestRef { alg: "sha256".into(), value: object_digest }),
        coding: CodingSpec { field: "gf16".into(), k: 3, m: 2, shard_size: 8 },
        stripes: 3,
        shards,
    };
    fs::write(
        dir.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )?;

    let fault: Arc<FaultGate> = FaultGate::new();
    let store = Store::open(data_dir, fault)?;
    let report = import::import_batch(&store, &dir)?;
    println!(
        "演示对象导入完成：{} 个 shard，{} 条证据",
        report.shards_imported, report.evidence
    );
    Ok(())
}
