//! 演示用小有限域 fixture：构造确定性对象、编码并投递带各种故障的碎片。

use crate::coding;
use crate::digest::sha256_hex;
use crate::importer::inbox_dir;
use crate::model::{
    CodecParams, GenPlan, Manifest, StripeSpec, MANIFEST_KIND, MANIFEST_VERSION,
};
use anyhow::Result;
use std::path::Path;

fn pad_data(data: &[u8], shard_size: usize) -> (Vec<Vec<u8>>, u64) {
    let stripe_bytes = shard_size;
    let stripes = data.len().div_ceil(stripe_bytes);
    let mut padded = vec![0u8; stripes * shard_size];
    padded[..data.len()].copy_from_slice(data);
    let blocks = padded
        .chunks(shard_size)
        .map(|c| c.to_vec())
        .collect::<Vec<_>>();
    (blocks, data.len() as u64)
}

fn data_block(label: u8, shard_size: usize) -> Vec<u8> {
    (0..shard_size)
        .map(|b| label.wrapping_mul(31).wrapping_add((b % 13) as u8))
        .collect()
}

fn write_frag(
    inbox: &Path,
    source: &str,
    object: &str,
    generation: u64,
    stripe: u64,
    index: usize,
    bytes: &[u8],
    digest_override: Option<&str>,
) -> Result<()> {
    let dir = inbox.join(source);
    std::fs::create_dir_all(&dir)?;
    let claimed = digest_override
        .map(|d| format!("__{d}"))
        .unwrap_or_default();
    let path = dir.join(format!(
        "{object}__g{generation}_s{stripe}_i{index}{claimed}.frag"
    ));
    std::fs::write(&path, bytes)?;
    Ok(())
}

fn write_manifest(inbox: &Path, source: &str, manifest: &Manifest) -> Result<()> {
    let dir = inbox.join(source);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.manifest.json", manifest.object_id));
    std::fs::write(&path, serde_json::to_vec_pretty(manifest)?)?;
    Ok(())
}

fn build_manifest(
    object_id: &str,
    object_digest: &str,
    object_size: u64,
    k: usize,
    m: usize,
    shard_size: usize,
    current_generation: u64,
    generations: Vec<(u64, Vec<Vec<Vec<u8>>>)>,
) -> Manifest {
    let gen_plans = generations
        .into_iter()
        .map(|(generation, stripes)| GenPlan {
            generation,
            stripe_digests: stripes
                .iter()
                .enumerate()
                .map(|(stripe, shards)| StripeSpec {
                    stripe: stripe as u64,
                    digests: shards.iter().map(|s| sha256_hex(s)).collect(),
                })
                .collect(),
        })
        .collect();
    Manifest {
        manifest_kind: MANIFEST_KIND.to_string(),
        manifest_version: MANIFEST_VERSION.to_string(),
        object_id: object_id.to_string(),
        object_size,
        object_digest: object_digest.to_string(),
        codec: CodecParams {
            codec: coding::CODEC_RS_V1.to_string(),
            k,
            m,
            shard_size,
        },
        current_generation,
        generations: gen_plans,
    }
}

fn encoded_stripes(k: usize, m: usize, data: &[Vec<u8>], shard_size: usize) -> Vec<Vec<Vec<u8>>> {
    data.iter()
        .map(|d| {
            let blocks = coding::encode(k, m, shard_size, &[d.clone()]);
            // data 只是单列：encode 需要 k 个数据块，这里直接在调用处展开。
            blocks
        })
        .collect()
}

/// 在空 inbox 中生成 alpha / bravo / charlie 三组演示对象。
pub fn seed_demo_inbox(data_dir: &Path) -> Result<bool> {
    let inbox = inbox_dir(data_dir);
    if inbox.exists() && std::fs::read_dir(&inbox)?.next().is_some() {
        return Ok(false);
    }
    std::fs::create_dir_all(&inbox)?;
    seed_alpha(&inbox)?;
    seed_bravo(&inbox)?;
    seed_charlie(&inbox)?;
    Ok(true)
}

fn stripe_encode(k: usize, m: usize, shard_size: usize, data: &[Vec<u8>]) -> Vec<Vec<Vec<u8>>> {
    data.chunks(k)
        .map(|row| {
            let mut row = row.to_vec();
            while row.len() < k {
                row.push(vec![0u8; shard_size]);
            }
            coding::encode(k, m, shard_size, &row)
        })
        .collect()
}

fn seed_alpha(inbox: &Path) -> Result<()> {
    // alpha: k=2 m=2 sh=8，3 个 stripe；对象末尾不足一扇区，验证截断导出。
    let (k, m, sh) = (2, 2, 8);
    let d0 = data_block(1, sh);
    let d1 = data_block(2, sh);
    let d2 = data_block(3, sh);
    let d3 = data_block(4, sh);
    let d4 = data_block(5, sh);
    let d5 = data_block(6, sh);
    let mut object_bytes = Vec::new();
    for d in [&d0, &d1, &d2, &d3, &d4, &d5] {
        object_bytes.extend_from_slice(d);
    }
    object_bytes.truncate(44);
    let (padded, size) = pad_data(&object_bytes, sh * k);
    let mut flat: Vec<u8> = padded.concat();
    flat.truncate(6 * sh);
    let data: Vec<Vec<u8>> = flat.chunks(sh).map(|c| c.to_vec()).collect();
    let stripes = stripe_encode(k, m, sh, &data);
    let manifest = build_manifest(
        "alpha",
        &sha256_hex(&object_bytes),
        size,
        k,
        m,
        sh,
        1,
        vec![(1, stripes.clone())],
    );
    write_manifest(inbox, "source-a", &manifest)?;

    // stripe 0：编号 0 有两个内容候选（含位翻转），编号 1、2 健康；
    // 健康组合 (1,2) 与 (0,1,2 中) 多解，位翻转组合必须解码失败。
    write_frag(inbox, "source-a", "alpha", 1, 0, 0, &stripes[0][0], None)?;
    let mut flipped = stripes[0][0].clone();
    flipped[0] ^= 0x01;
    write_frag(inbox, "source-b", "alpha", 1, 0, 0, &flipped, None)?;
    write_frag(inbox, "source-a", "alpha", 1, 0, 1, &stripes[0][1], None)?;
    write_frag(inbox, "source-b", "alpha", 1, 0, 2, &stripes[0][2], None)?;

    // stripe 1：单块缺失（编号 1 缺席），由 0、2、3 任意两个恢复。
    write_frag(inbox, "source-a", "alpha", 1, 1, 0, &stripes[1][0], None)?;
    write_frag(inbox, "source-a", "alpha", 1, 1, 2, &stripes[1][2], None)?;
    write_frag(inbox, "source-b", "alpha", 1, 1, 3, &stripes[1][3], None)?;

    // stripe 2：恰好达到恢复下限，仅余两块校验。
    write_frag(inbox, "source-a", "alpha", 1, 2, 2, &stripes[2][2], None)?;
    write_frag(inbox, "source-b", "alpha", 1, 2, 3, &stripes[2][3], None)?;
    Ok(())
}

fn seed_bravo(inbox: &Path) -> Result<()> {
    // bravo: k=3 m=2 sh=6；重复编号、manifest 长度不符、边界恢复数。
    let (k, m, sh) = (3, 2, 6);
    let data: Vec<Vec<u8>> = (1..=6).map(|label| data_block(label, sh)).collect();
    let object_bytes = data.concat();
    let stripes = stripe_encode(k, m, sh, &data);
    let manifest = build_manifest(
        "bravo",
        &sha256_hex(&object_bytes),
        object_bytes.len() as u64,
        k,
        m,
        sh,
        1,
        vec![(1, stripes.clone())],
    );
    write_manifest(inbox, "source-b", &manifest)?;

    // stripe 0：编号 1 出现两次（重复送达，同内容不同来源）。
    write_frag(inbox, "source-a", "bravo", 1, 0, 0, &stripes[0][0], None)?;
    write_frag(inbox, "source-a", "bravo", 1, 0, 1, &stripes[0][1], None)?;
    write_frag(inbox, "source-b", "bravo", 1, 0, 1, &stripes[0][1], None)?;
    write_frag(inbox, "source-b", "bravo", 1, 0, 2, &stripes[0][2], None)?;

    // stripe 1：恰好 k 块且含 2 块校验；另有一块长度不符（多 1 字节）。
    write_frag(inbox, "source-a", "bravo", 1, 1, 0, &stripes[1][0], None)?;
    write_frag(inbox, "source-a", "bravo", 1, 1, 3, &stripes[1][3], None)?;
    write_frag(inbox, "source-b", "bravo", 1, 1, 4, &stripes[1][4], None)?;
    let mut truncated = stripes[1][1].clone();
    truncated.push(0x7e);
    write_frag(inbox, "source-b", "bravo", 1, 1, 1, &truncated, None)?;
    Ok(())
}

fn seed_charlie(inbox: &Path) -> Result<()> {
    // charlie: k=2 m=2 sh=5；部分写造成 generation 混杂：
    // stripe 0 已在 g2 重写完成，stripe 1 只有旧 g1 内容，对象整体不可信、禁止导出。
    let (k, m, sh) = (2, 2, 5);
    let g1: Vec<Vec<u8>> = (1..=4).map(|label| data_block(label, sh)).collect();
    let g2: Vec<Vec<u8>> = (7..=10).map(|label| data_block(label, sh)).collect();
    let s_g1 = stripe_encode(k, m, sh, &g1);
    let s_g2 = stripe_encode(k, m, sh, &g2);
    let object_bytes = g2.concat();
    let manifest = build_manifest(
        "charlie",
        &sha256_hex(&object_bytes),
        object_bytes.len() as u64,
        k,
        m,
        sh,
        2,
        vec![(1, s_g1.clone()), (2, s_g2.clone())],
    );
    write_manifest(inbox, "source-a", &manifest)?;

    // stripe 0：当前 generation，三块足够，含一块位翻转。
    write_frag(inbox, "source-a", "charlie", 2, 0, 0, &s_g2[0][0], None)?;
    write_frag(inbox, "source-b", "charlie", 2, 0, 1, &s_g2[0][1], None)?;
    write_frag(inbox, "source-a", "charlie", 2, 0, 2, &s_g2[0][2], None)?;
    let mut flipped = s_g2[0][3].clone();
    flipped[2] ^= 0x80;
    write_frag(inbox, "source-b", "charlie", 2, 0, 3, &flipped, None)?;

    // stripe 1：只到了旧 generation g1（部分写）。
    write_frag(inbox, "source-a", "charlie", 1, 1, 0, &s_g1[1][0], None)?;
    write_frag(inbox, "source-b", "charlie", 1, 1, 2, &s_g1[1][2], None)?;
    Ok(())
}

#[allow(dead_code)]
fn ensure_encoded_link(k: usize, m: usize, shard_size: usize) {
    let _ = encoded_stripes(k, m, &[vec![0u8; 1]], shard_size);
}
