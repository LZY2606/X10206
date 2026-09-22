//! 演示夹具：用小有限域（GF256, k=3/m=2）生成两组对象，覆盖各类故障。
//! 仅在 inbox 为空时写入，绝不改动已有碎片。

use crate::digest::{object_digest, sha256_hex};
use crate::gf256::{encode_with_parity, Field};
use crate::importer::block_filename;
use crate::model::{ObjectManifest, ShardKind};
use std::collections::BTreeMap;
use std::path::Path;

fn pseudo_byte(stripe: usize, shard: usize, pos: usize, gen: u64) -> u8 {
    let v = (stripe * 31 + shard * 7 + pos * 3 + 1) as u64;
    ((v.wrapping_mul(1103515245).wrapping_add(12345 + gen * 7919)) >> 8) as u8
}

fn data_stripe(stripe: usize, k: usize, block_len: usize, gen: u64) -> Vec<Vec<u8>> {
    (0..k)
        .map(|shard| {
            (0..block_len)
                .map(|pos| pseudo_byte(stripe, shard, pos, gen))
                .collect()
        })
        .collect()
}

struct BlockFile {
    stripe: usize,
    shard: usize,
    gen: u64,
    source: String,
    bytes: Vec<u8>,
    attached: Option<String>, // 写入随附 .digest 的内容
}

fn write_block(root: &Path, object_id: &str, b: &BlockFile) -> std::io::Result<()> {
    let name = block_filename(object_id, b.stripe, b.shard, b.gen, &b.source);
    let path = root.join(&name);
    std::fs::write(&path, &b.bytes)?;
    if let Some(d) = &b.attached {
        std::fs::write(path.with_extension("bin.digest"), format!("{d}  {name}\n"))?;
    }
    Ok(())
}

pub fn ensure_demo_fixture(inbox: &Path) -> std::io::Result<()> {
    let marker = inbox.join(".demo-ready");
    if marker.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(inbox)?;

    let field = Field::new();

    // ---------------- 对象 1：可信可恢复（k=3, m=2, L=4, 4 stripe） ----------------
    let obj1 = "obj-demo-trusted";
    let (k1, m1, l1, sc1) = (3usize, 2usize, 4usize, 4usize);
    let object_len1 = sc1 * k1 * l1 - 2; // 46：测试尾部截断

    let mut all_stripes: Vec<Vec<Vec<u8>>> = Vec::new();
    for s in 0..sc1 {
        all_stripes.push(encode_with_parity(&field, k1, m1, &data_stripe(s, k1, l1, 1)));
    }
    // stripe3 使用 gen2 数据（部分写后的新代数）
    let stripe3_gen2 = encode_with_parity(&field, k1, m1, &data_stripe(sc1 - 1, k1, l1, 2));
    all_stripes[sc1 - 1] = stripe3_gen2;

    let mut block_digests: BTreeMap<usize, BTreeMap<usize, String>> = BTreeMap::new();
    for (s, blocks) in all_stripes.iter().enumerate() {
        for (i, bytes) in blocks.iter().enumerate() {
            block_digests.entry(s).or_default().insert(i, sha256_hex(bytes));
        }
    }
    let mut flat: Vec<Vec<u8>> = Vec::new();
    for blocks in &all_stripes {
        for i in 0..k1 {
            flat.push(blocks[i].clone());
        }
    }
    let obj_digest1 = object_digest(&flat, object_len1);

    let manifest1 = ObjectManifest {
        object_id: obj1.into(),
        codec_version: 1,
        k: k1,
        m: m1,
        block_len: l1,
        stripe_count: sc1,
        object_len: object_len1,
        object_digest: Some(obj_digest1),
        block_digests,
    };
    // 导入器按 manifest.json 文件名识别：对象清单放到独立子目录。
    let dir1 = inbox.join(obj1);
    std::fs::create_dir_all(&dir1)?;
    std::fs::write(
        dir1.join("manifest.json"),
        serde_json::to_string_pretty(&manifest1).unwrap(),
    )?;

    let mut files: Vec<BlockFile> = Vec::new();

    // stripe0：单块缺失（shard3 校验丢失）；shard0 带随附摘要；另放一个长度不符的 shard4 候选
    for i in [0usize, 1, 2, 4] {
        let attached = if i == 0 { Some(sha256_hex(&all_stripes[0][i])) } else { None };
        files.push(BlockFile {
            stripe: 0,
            shard: i,
            gen: 1,
            source: "node-a".into(),
            bytes: all_stripes[0][i].clone(),
            attached,
        });
    }
    files.push(BlockFile {
        stripe: 0,
        shard: 4,
        gen: 1,
        source: "node-badlen".into(),
        bytes: vec![0, 1, 2], // 长度与 block_len 不符
        attached: None,
    });

    // stripe1：边界恢复数——恰好 k=3 块可用，缺 shard0(data) 与 shard4(parity)
    for i in [1usize, 2, 3] {
        files.push(BlockFile {
            stripe: 1,
            shard: i,
            gen: 1,
            source: "node-a".into(),
            bytes: all_stripes[1][i].clone(),
            attached: None,
        });
    }

    // stripe2：同编号两个内容候选（node-a 正确 / node-b 位翻转且随附正确摘要），
    // shard1 另有同内容重复候选（node-c），shard4 缺失。
    files.push(BlockFile {
        stripe: 2,
        shard: 0,
        gen: 1,
        source: "node-a".into(),
        bytes: all_stripes[2][0].clone(),
        attached: None,
    });
    let mut flipped = all_stripes[2][0].clone();
    flipped[1] ^= 0x5a;
    files.push(BlockFile {
        stripe: 2,
        shard: 0,
        gen: 1,
        source: "node-b".into(),
        bytes: flipped,
        attached: Some(sha256_hex(&all_stripes[2][0])),
    });
    for i in [1usize, 2, 3] {
        files.push(BlockFile {
            stripe: 2,
            shard: i,
            gen: 1,
            source: "node-a".into(),
            bytes: all_stripes[2][i].clone(),
            attached: None,
        });
    }
    files.push(BlockFile {
        stripe: 2,
        shard: 1,
        gen: 1,
        source: "node-c".into(),
        bytes: all_stripes[2][1].clone(),
        attached: None,
    });

    // stripe3：generation 混杂。数据 0,1,2 与校验 4 为 gen2；
    // shard3 同时残留 gen1 旧内容（部分写）和 gen2 新内容。
    for i in [0usize, 1, 2, 4] {
        files.push(BlockFile {
            stripe: 3,
            shard: i,
            gen: 2,
            source: "node-new".into(),
            bytes: all_stripes[3][i].clone(),
            attached: None,
        });
    }
    let stripe3_gen1 = encode_with_parity(&field, k1, m1, &data_stripe(3, k1, l1, 1));
    files.push(BlockFile {
        stripe: 3,
        shard: 3,
        gen: 1,
        source: "node-old".into(),
        bytes: stripe3_gen1[3].clone(),
        attached: None,
    });
    files.push(BlockFile {
        stripe: 3,
        shard: 3,
        gen: 2,
        source: "node-new".into(),
        bytes: all_stripes[3][3].clone(),
        attached: None,
    });

    for b in &files {
        write_block(&dir1, obj1, b)?;
    }
    let _ = ShardKind::Data;

    // ---------------- 对象 2：无摘要、多可行答案 + 低于恢复下限 ----------------
    let obj2 = "obj-demo-ambiguous";
    let (k2, m2, l2, sc2) = (2usize, 1usize, 3usize, 2usize);
    let manifest2 = ObjectManifest {
        object_id: obj2.into(),
        codec_version: 1,
        k: k2,
        m: m2,
        block_len: l2,
        stripe_count: sc2,
        object_len: sc2 * k2 * l2,
        object_digest: None,
        block_digests: BTreeMap::new(), // 无任何块摘要：不同内容候选无法被摘要甄别
    };
    let dir2 = inbox.join(obj2);
    std::fs::create_dir_all(&dir2)?;
    std::fs::write(
        dir2.join("manifest.json"),
        serde_json::to_string_pretty(&manifest2).unwrap(),
    )?;

    let world_a = encode_with_parity(
        &field,
        k2,
        m2,
        &vec![vec![10, 20, 30], vec![40, 50, 60]],
    );
    let world_b = encode_with_parity(
        &field,
        k2,
        m2,
        &vec![vec![11, 22, 33], vec![44, 55, 66]],
    );
    // stripe0：shard0/shard1 各有两个来源的内容候选，shard2 缺失 -> 4 个可行重建、内容分歧
    let mut files2 = vec![
        BlockFile { stripe: 0, shard: 0, gen: 1, source: "src-alpha".into(), bytes: world_a[0].clone(), attached: None },
        BlockFile { stripe: 0, shard: 0, gen: 1, source: "src-beta".into(),  bytes: world_b[0].clone(), attached: None },
        BlockFile { stripe: 0, shard: 1, gen: 1, source: "src-alpha".into(), bytes: world_a[1].clone(), attached: None },
        BlockFile { stripe: 0, shard: 1, gen: 1, source: "src-beta".into(),  bytes: world_b[1].clone(), attached: None },
    ];
    // stripe1：全部缺失 -> 低于恢复下限，不可恢复（无文件）
    for b in &files2 {
        write_block(&dir2, obj2, b)?;
    }
    files2.clear();

    std::fs::write(marker, "generated\n")?;
    Ok(())
}
