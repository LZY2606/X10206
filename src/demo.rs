//! 内置演示 fixture（gf16, k=2, m=2, 3 个 stripe）：
//! - stripe 0：编号 2/3 恰好达到恢复下限（两块 parity 恢复）；
//! - stripe 1：shard1 发生位翻转、另有同编号未验证候选，重建后与冗余核对；
//! - stripe 2：部分写造成 generation 混杂（g1/g2），对象摘要裁定正确组合。

use crate::coding::Coding;
use crate::gf::Field;
use crate::importer::{import_bundle, ImportReport};
use crate::model::{sha256_hex, Manifest};
use crate::store::Store;
use std::collections::BTreeSet;
use std::path::Path;

pub fn demo_manifest(object_digest: String, object_length: usize) -> Manifest {
    Manifest {
        object_id: "demo-object".into(),
        codec_version: 1,
        field: "gf16".into(),
        k: 2,
        m: 2,
        stripe_length: 4,
        stripe_count: 3,
        object_length: Some(object_length),
        object_digest: Some(object_digest),
    }
}

pub fn build_demo_bytes() -> Vec<Vec<Vec<u8>>> {
    // 3 个 stripe，每个 2 个 data shard，每 shard 4 字节。
    vec![
        vec![
            vec![0x12, 0x34, 0x56, 0x78],
            vec![0x9a, 0xbc, 0xde, 0xf0],
        ],
        vec![
            vec![0x11, 0x22, 0x33, 0x44],
            vec![0x55, 0x66, 0x77, 0x88],
        ],
        vec![
            vec![0xab, 0xcd, 0xef, 0x01],
            vec![0x23, 0x45, 0x67, 0x89],
        ],
    ]
}

struct Written {
    stripe: usize,
    shard: usize,
    generation: u64,
    name: String,
    source: String,
    bytes: Vec<u8>,
    digest: Option<String>,
}

pub fn seed_demo(store: &Store, data_dir: &Path) -> Result<ImportReport, String> {
    if let Some(json) = store.get_manifest_json("demo-object")? {
        let _: Manifest = serde_json::from_str(&json).map_err(|e| e.to_string())?;
        return Ok(ImportReport {
            object_id: "demo-object".into(),
            fragment_count: 0,
            sources: BTreeSet::new(),
            warnings: vec!["demo 已存在，跳过生成".into()],
        });
    }

    let coding = Coding::new(Field::Gf16, 2, 2)?;
    let data = build_demo_bytes();
    let mut all_shards: Vec<Vec<Vec<u8>>> = Vec::new();
    let mut object = Vec::new();
    for stripe_data in &data {
        let shards = coding.encode_bytes(stripe_data);
        for d in stripe_data {
            object.extend_from_slice(d);
        }
        all_shards.push(shards);
    }
    let object_digest = sha256_hex(&object);
    let manifest = demo_manifest(object_digest, object.len());

    let bundle = data_dir.join("bundles").join("demo-bundle");
    let shards_dir = bundle.join("shards");
    std::fs::create_dir_all(&shards_dir).map_err(|e| e.to_string())?;
    std::fs::write(
        bundle.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .map_err(|e| e.to_string())?;

    let mut writes: Vec<Written> = Vec::new();

    // stripe 0：只保留 parity 2、3（边界恢复）。
    for sh in [2usize, 3usize] {
        let bytes = all_shards[0][sh].clone();
        let name = format!("s0_sh{sh}_g1");
        writes.push(Written {
            stripe: 0,
            shard: sh,
            generation: 1,
            source: "node-A".into(),
            bytes: bytes.clone(),
            digest: Some(sha256_hex(&bytes)),
            name,
        });
    }

    // stripe 1：shard0 正确；shard1 位翻转（带错误登记摘要=真实摘要，制造摘要不符）；
    // shard2 正确；另有同编号 shard1 的未验证候选（无摘要边车），字节也损坏。
    {
        let b0 = all_shards[1][0].clone();
        writes.push(Written {
            stripe: 1, shard: 0, generation: 1, source: "node-A".into(),
            bytes: b0.clone(), digest: Some(sha256_hex(&b0)), name: "s1_sh0_g1".into(),
        });
        let mut bad = all_shards[1][1].clone();
        bad[2] ^= 0xff;
        writes.push(Written {
            stripe: 1, shard: 1, generation: 1, source: "node-B".into(),
            bytes: bad.clone(),
            digest: Some(sha256_hex(&all_shards[1][1])),
            name: "s1_sh1_g1".into(),
        });
        let b2 = all_shards[1][2].clone();
        writes.push(Written {
            stripe: 1, shard: 2, generation: 1, source: "node-C".into(),
            bytes: b2.clone(), digest: Some(sha256_hex(&b2)), name: "s1_sh2_g1".into(),
        });
        let mut alt = all_shards[1][1].clone();
        alt[0] ^= 0x0f;
        writes.push(Written {
            stripe: 1, shard: 1, generation: 1, source: "node-D".into(),
            bytes: alt, digest: None, name: "s1_sh1_g1-alt".into(),
        });
    }

    // stripe 2：g2 部分写——shard0 是新的，shard1 没更新（g1），parity 2 是 g2、parity3 是 g1。
    // 旧代数据 stripe_data 不同于新代，用来演示 generation 混杂被对象摘要裁定。
    let old_data = vec![vec![0x01u8, 0x02, 0x03, 0x04], vec![0x05, 0x06, 0x07, 0x08]];
    let old_shards = coding.encode_bytes(&old_data);
    let new = &all_shards[2];
    let mixed: [(usize, u64, &'static str, Vec<u8>); 4] = [
        (0, 2, "node-A", new[0].clone()),
        (1, 1, "node-B", old_shards[1].clone()),
        (2, 2, "node-C", new[2].clone()),
        (3, 1, "node-D", old_shards[3].clone()),
    ];
    for (sh, g, src, bytes) in mixed {
        let name = format!("s2_sh{sh}_g{g}");
        writes.push(Written {
            stripe: 2,
            shard: sh,
            generation: g,
            source: src.into(),
            bytes: bytes.clone(),
            digest: Some(sha256_hex(&bytes)),
            name,
        });
    }

    for w in &writes {
        let bin = shards_dir.join(format!("{}.bin", w.name));
        std::fs::write(&bin, &w.bytes).map_err(|e| e.to_string())?;
        if let Some(d) = &w.digest {
            std::fs::write(shards_dir.join(format!("{}.digest", w.name)), d)
                .map_err(|e| e.to_string())?;
        }
        let meta = serde_json::json!({ "source": w.source });
        std::fs::write(
            shards_dir.join(format!("{}.meta.json", w.name)),
            meta.to_string().into_bytes(),
        )
        .map_err(|e| e.to_string())?;
    }

    import_bundle(store, &bundle)
}
