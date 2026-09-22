//! 演示 fixture 生成：在 data/input 下构造离线碎片目录（含全部棘手场景），
//! 并导入到 chamber。原始源文件生成后不再修改。

use crate::commit::{sha256_hex, stripe_digest};
use crate::db::Store;
use crate::gf::GfField;
use crate::import::import_manifest;
use crate::model::{EncodingParamsV1, ObjectManifestV1, ShardSidecarV1};
use std::collections::BTreeMap;
use std::path::Path;

fn write_shard(
    dir: &Path,
    object_id: &str,
    stripe: usize,
    shard: usize,
    gen: u64,
    source: &str,
    bytes: &[u8],
    digest: bool,
) -> std::io::Result<()> {
    let safe_src: String = source
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let name = format!("shard-{:02}-{:02}-g{}-{}.bin", stripe, shard, gen, safe_src);
    std::fs::write(dir.join(&name), bytes)?;
    if digest {
        let sc = ShardSidecarV1::new(object_id, stripe, shard, gen, source, Some(sha256_hex(bytes)));
        std::fs::write(dir.join(format!("{name}.sidecar.json")), serde_json::to_vec_pretty(&sc)?)?;
    } else {
        // 无摘要 sidecar（只有来源/generation）
        let sc = ShardSidecarV1::new(object_id, stripe, shard, gen, source, None);
        std::fs::write(dir.join(format!("{name}.sidecar.json")), serde_json::to_vec_pretty(&sc)?)?;
    }
    Ok(())
}

fn manifest_path(dir: &Path) -> std::path::PathBuf {
    dir.join("manifest.json")
}

/// object-alpha：GF(2^4), k=2, m=2, 2 stripe, 4 符号。
/// stripe 0：单块缺失（恰达下限）+ 同编号重复来源。
/// stripe 1：位翻转（摘要不符）、长度不符、纯 gen 冲突给出两个不同可行解、
///           以及恰好 k 个健康候选的边界恢复。
pub fn build_alpha(base: &Path) -> std::io::Result<()> {
    let dir = base.join("object-alpha");
    if manifest_path(&dir).exists() {
        return Ok(());
    }
    std::fs::create_dir_all(&dir)?;
    let params = EncodingParamsV1::v1(2, 2, 4);
    let field = GfField::new(4).unwrap();
    let len = 4;

    let d0: Vec<Vec<u8>> = vec![vec![1, 2, 3, 4], vec![9, 10, 11, 12]];
    let all0 = field.encode(2, 2, &d0).unwrap();

    // stripe 0: 缺 position 3；position 0 有两个来源（重复编号，内容相同）。
    write_shard(&dir, "object-alpha", 0, 0, 1, "node-a", &all0[0], true)?;
    write_shard(&dir, "object-alpha", 0, 0, 1, "node-b", &all0[0], true)?;
    write_shard(&dir, "object-alpha", 0, 1, 1, "node-a", &all0[1], true)?;
    write_shard(&dir, "object-alpha", 0, 2, 1, "node-c", &all0[2], false)?; // 无摘要

    // stripe 1: 用两套不同的数据内容制造纯 generation 冲突（部分写）。
    let old: Vec<Vec<u8>> = vec![vec![1, 1, 1, 1], vec![2, 2, 2, 2]];
    let old_all = field.encode(2, 2, &old).unwrap();
    let new: Vec<Vec<u8>> = vec![vec![3, 3, 3, 3], vec![4, 4, 4, 4]];
    let new_all = field.encode(2, 2, &new).unwrap();
    let expected_digest_new = stripe_digest(&new_all);

    // 旧 stripe（gen1，node-a）凑成完整一套：pos0、pos1 为干净候选，pos2 被位翻转。
    // 新 stripe（gen2，node-b/node-c）凑成 pos0、pos1、pos3 三个干净候选。
    // 于是恰好存在两个纯 generation 可行答案，输出不同。
    write_shard(&dir, "object-alpha", 1, 0, 1, "node-a", &old_all[0], true)?;
    write_shard(&dir, "object-alpha", 1, 1, 1, "node-a", &old_all[1], true)?;
    write_shard(&dir, "object-alpha", 1, 0, 2, "node-b", &new_all[0], true)?;
    write_shard(&dir, "object-alpha", 1, 1, 2, "node-b", &new_all[1], true)?;
    write_shard(&dir, "object-alpha", 1, 3, 2, "node-c", &new_all[3], true)?;
    // position 2：旧 gen1 内容 + 被位翻转，但 sidecar 声称的是旧内容正确摘要 -> 摘要不符
    let mut flipped = old_all[2].clone();
    flipped[0] ^= 0x7;
    let sc = ShardSidecarV1::new(
        "object-alpha",
        1,
        2,
        1,
        "node-d",
        Some(sha256_hex(&old_all[2])),
    );
    std::fs::write(dir.join("shard-01-02-g1-node-d.bin"), &flipped)?;
    std::fs::write(
        dir.join("shard-01-02-g1-node-d.bin.sidecar.json"),
        serde_json::to_vec_pretty(&sc)?,
    )?;
    // 再放一个长度不符的额外块（编号越界在导入层被拒，这里借用合法编号的第二来源）
    let short = vec![5u8, 6, 7];
    let sc = ShardSidecarV1::new("object-alpha", 1, 3, 2, "node-e", Some(sha256_hex(&short)));
    std::fs::write(dir.join("shard-01-03-g2-node-e.bin"), &short)?;
    std::fs::write(
        dir.join("shard-01-03-g2-node-e.bin.sidecar.json"),
        serde_json::to_vec_pretty(&sc)?,
    )?;

    let mut stripe_digests = BTreeMap::new();
    stripe_digests.insert(0usize, stripe_digest(&all0));
    stripe_digests.insert(1usize, expected_digest_new);
    let manifest = ObjectManifestV1 {
        version: "object-manifest/v1".into(),
        object_id: "object-alpha".into(),
        params,
        stripe_len: len,
        stripe_count: 2,
        stripe_digests,
        object_digest: None,
    };
    std::fs::write(
        manifest_path(&dir),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(())
}

/// object-beta：GF(2^4), k=2, m=1, 1 stripe。
/// generation 混杂的部分写：pos0 为新 gen2，pos1 为旧 gen1（内容混合但恰成一个码词），
/// manifest stripe 摘要对应这套混合结果 -> 混杂解排榜首。
pub fn build_beta(base: &Path) -> std::io::Result<()> {
    let dir = base.join("object-beta");
    if manifest_path(&dir).exists() {
        return Ok(());
    }
    std::fs::create_dir_all(&dir)?;
    let params = EncodingParamsV1::v1(2, 1, 4);
    let field = GfField::new(4).unwrap();
    let len = 3;

    let old: Vec<Vec<u8>> = vec![vec![6, 6, 6], vec![8, 8, 8]];
    let old_all = field.encode(2, 1, &old).unwrap();
    // 混合 stripe：新 data0 + 旧 data1，重算 parity -> 自洽码词
    let new_d0 = vec![13u8, 13, 13];
    let mixed_data = vec![new_d0.clone(), old[1].clone()];
    let mixed_all = field.encode(2, 1, &mixed_data).unwrap();
    let mixed_digest = stripe_digest(&mixed_all);

    write_shard(&dir, "object-beta", 0, 0, 2, "node-a", &new_d0, true)?;
    write_shard(&dir, "object-beta", 0, 1, 1, "node-b", &old_all[1], true)?;
    write_shard(&dir, "object-beta", 0, 2, 1, "node-c", &old_all[2], true)?; // 旧 parity，与混合码词矛盾，将被本解排除

    let mut stripe_digests = BTreeMap::new();
    stripe_digests.insert(0usize, mixed_digest);
    let manifest = ObjectManifestV1 {
        version: "object-manifest/v1".into(),
        object_id: "object-beta".into(),
        params,
        stripe_len: len,
        stripe_count: 1,
        stripe_digests,
        object_digest: None,
    };
    std::fs::write(manifest_path(&dir), serde_json::to_vec_pretty(&manifest)?)?;
    Ok(())
}

/// object-gamma：GF(2^8), k=3, m=2, 1 stripe, 32 字节，全部健康（生产参数冒烟）。
pub fn build_gamma(base: &Path) -> std::io::Result<()> {
    let dir = base.join("object-gamma");
    if manifest_path(&dir).exists() {
        return Ok(());
    }
    std::fs::create_dir_all(&dir)?;
    let params = EncodingParamsV1::v1(3, 2, 8);
    let field = GfField::new(8).unwrap();
    let len = 32;
    let data: Vec<Vec<u8>> = (0..3)
        .map(|j| (0..len).map(|t| ((j * 73 + t * 7) & 0xff) as u8).collect())
        .collect();
    let all = field.encode(3, 2, &data).unwrap();
    for p in 0..5 {
        // 缺 position 4：恰好 k+? —— 给 4 个候选，缺 1 块
        if p == 4 {
            continue;
        }
        write_shard(&dir, "object-gamma", 0, p, 1, "node-a", &all[p], true)?;
    }
    let mut stripe_digests = BTreeMap::new();
    stripe_digests.insert(0usize, stripe_digest(&all));
    let manifest = ObjectManifestV1 {
        version: "object-manifest/v1".into(),
        object_id: "object-gamma".into(),
        params,
        stripe_len: len,
        stripe_count: 1,
        stripe_digests,
        object_digest: None,
    };
    std::fs::write(manifest_path(&dir), serde_json::to_vec_pretty(&manifest)?)?;
    Ok(())
}

pub fn seed_demo(store: &Store, base: &Path) -> std::io::Result<()> {
    build_alpha(base)?;
    build_beta(base)?;
    build_gamma(base)?;
    for name in ["object-alpha", "object-beta", "object-gamma"] {
        import_manifest(store, &base.join(name).join("manifest.json"))?;
    }
    Ok(())
}
