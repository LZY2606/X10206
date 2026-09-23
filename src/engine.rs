//! 恢复编排：按 stripe 提交、中断复用、来源隔离、原子导出。
use crate::ec::EcParams;
use crate::recover::{
    enumerate_stripe, sha256_hex, ShardCandidate, StripeReport, DEFAULT_BUDGET,
};
use crate::store::{Manifest, ManifestShard, Res, Store};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() || "-_.".contains(c) || (c as u32) > 127 {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// 对一个对象执行恢复。逐 stripe：先尝试复用摘要完整的已提交结果，
/// 否则枚举候选、重建、写临时块、提交。临时块绝不参与最终读取。
pub fn recover_object(store: &Store, object_id: i64, budget: usize) -> Res<Vec<StripeReport>> {
    let obj = store.object(object_id)?;
    let params = EcParams {
        k: obj.k,
        m: obj.m,
        version: obj.ec_version,
    };
    let mut reports = Vec::new();
    for stripe in 0..obj.stripes {
        if let Some((digest, bytes, _sources)) = store.committed(object_id, stripe)? {
            if sha256_hex(&bytes) == digest {
                reports.push(StripeReport::reused(stripe, &digest));
                continue;
            }
            // 摘要不完整的已提交记录不可信，删除后重算。
            store.delete_committed(object_id, stripe)?;
        }
        let rows = store.shards_for(object_id, stripe, true)?;
        let manifest = store.manifest_digests(object_id, stripe)?;
        // 同 (编号, generation, 摘要) 的碎片合并为一个候选，来源归集。
        let mut merged: BTreeMap<(u32, u64, String), ShardCandidate> = BTreeMap::new();
        for r in rows {
            merged
                .entry((r.index, r.generation, r.digest.clone()))
                .and_modify(|c: &mut ShardCandidate| {
                    if !c.sources.contains(&r.source) {
                        c.sources.push(r.source.clone());
                        c.sources.sort();
                    }
                })
                .or_insert(ShardCandidate {
                    index: r.index,
                    generation: r.generation,
                    sources: vec![r.source.clone()],
                    digest: r.digest,
                    bytes: r.bytes,
                });
        }
        let candidates: Vec<ShardCandidate> = merged.into_values().collect();
        let mut report = enumerate_stripe(&params, obj.shard_len, stripe, &candidates, &manifest, budget);
        if let Some(best) = report.reconstructions.first() {
            match commit_stripe(store, object_id, stripe, &best.result_digest, &best.data, best) {
                Ok(()) => report.committed = true,
                Err(e) => report.note = Some(format!("提交失败: {}", e)),
            }
        }
        reports.push(report);
    }
    Ok(reports)
}

fn commit_stripe(
    store: &Store,
    object_id: i64,
    stripe: u32,
    digest: &str,
    data: &[u8],
    best: &crate::recover::Reconstruction,
) -> Res<()> {
    // 先写临时块，再提交；崩溃时临时块残留但不会参与最终读取。
    let tmp = store.base.join("tmp");
    std::fs::create_dir_all(&tmp).map_err(|e| format!("临时目录不可用: {}", e))?;
    let part = tmp.join(format!("obj{}-stripe{}.part", object_id, stripe));
    std::fs::write(&part, data).map_err(|e| format!("临时块写入失败: {}", e))?;
    let mut sources: Vec<String> = best
        .sets
        .first()
        .map(|s| s.iter().flat_map(|r| r.sources.clone()).collect())
        .unwrap_or_default();
    sources.sort();
    sources.dedup();
    store.commit_stripe(object_id, stripe, digest, data, &sources.join(","))?;
    let _ = std::fs::remove_file(&part);
    Ok(())
}

/// 导出到新目录，清单原子切换；原始碎片不改动。
pub fn export_object(store: &Store, object_id: i64) -> Res<PathBuf> {
    let obj = store.object(object_id)?;
    let committed = store.committed_stripes(object_id)?;
    if committed.len() != obj.stripes as usize {
        return Err(format!(
            "已提交 stripe {}/{}，无法导出",
            committed.len(),
            obj.stripes
        ));
    }
    let mut data = Vec::new();
    let mut stripe_digests = Vec::new();
    for (stripe, digest, bytes) in &committed {
        if sha256_hex(bytes) != digest {
            return Err(format!("stripe {} 的已提交摘要不完整，拒绝导出", stripe));
        }
        data.extend_from_slice(bytes);
        stripe_digests.push(digest.clone());
    }
    let dir = store.base.join("export").join(sanitize(&obj.name));
    std::fs::create_dir_all(&dir).map_err(|e| format!("导出目录创建失败: {}", e))?;

    let obj_tmp = dir.join("object.bin.tmp");
    std::fs::write(&obj_tmp, &data).map_err(|e| format!("导出写入失败: {}", e))?;
    std::fs::rename(&obj_tmp, dir.join("object.bin")).map_err(|e| format!("导出切换失败: {}", e))?;

    let manifest_entries: Vec<serde_json::Value> = store
        .manifest_all(object_id)?
        .into_iter()
        .map(|(stripe, idx, kind, digest)| {
            serde_json::json!({"stripe": stripe, "index": idx, "kind": kind, "sha256": digest})
        })
        .collect();
    let export_manifest = serde_json::json!({
        "name": obj.name,
        "k": obj.k, "m": obj.m, "shard_len": obj.shard_len,
        "stripes": obj.stripes, "ec_version": obj.ec_version,
        "object_sha256": sha256_hex(&data),
        "stripe_digests": stripe_digests,
        "source_manifest": manifest_entries,
    });
    let man_tmp = dir.join("manifest.json.tmp");
    std::fs::write(&man_tmp, serde_json::to_vec_pretty(&export_manifest).unwrap())
        .map_err(|e| format!("清单写入失败: {}", e))?;
    // 原子清单切换：rename 同目录替换。
    std::fs::rename(&man_tmp, dir.join("manifest.json")).map_err(|e| format!("清单切换失败: {}", e))?;
    Ok(dir)
}

/// 隔离/解除隔离一个来源；隔离时删除受其影响的已提交 stripe。
pub fn set_quarantine(store: &Store, source: &str, on: bool) -> Res<Vec<(i64, u32)>> {
    store.set_quarantine(source, on)?;
    if on {
        store.drop_committed_with_source(source)
    } else {
        Ok(Vec::new())
    }
}

/// 演示数据：健康 stripe + 含位翻转/重复编号/generation 混杂的可恢复 stripe。
pub fn seed_demo(store: &Store) -> Res<i64> {
    for o in store.list_objects()? {
        if o.name == "演示对象" {
            return Ok(o.id);
        }
    }
    let k = 3usize;
    let m = 2usize;
    let shard_len = 16usize;
    let stripes = 2u32;
    let params = EcParams { k, m, version: 1 };
    let mut manifest_shards = Vec::new();
    let mut encoded: Vec<Vec<Vec<u8>>> = Vec::new();
    for stripe in 0..stripes {
        let data: Vec<Vec<u8>> = (0..k)
            .map(|i| {
                (0..shard_len)
                    .map(|j| (stripe * 7 + i as u32 * 13 + j as u32 * 5 + 3) as u8)
                    .collect()
            })
            .collect();
        let full = crate::ec::encode(&params, &data);
        for (idx, shard) in full.iter().enumerate() {
            manifest_shards.push(ManifestShard {
                stripe,
                index: idx as u32,
                kind: if idx < k { "data".into() } else { "parity".into() },
                sha256: sha256_hex(shard),
            });
        }
        encoded.push(full);
    }
    let id = store.create_object(&Manifest {
        name: "演示对象".into(),
        k,
        m,
        shard_len,
        stripes,
        ec_version: 1,
        shards: manifest_shards,
    })?;
    let put = |stripe: u32, index: u32, gen: u64, source: &str, bytes: &[u8]| -> Res<()> {
        store.add_shard(id, stripe, index, gen, source, &sha256_hex(bytes), bytes)
    };
    // stripe 0：完整健康。
    for (idx, shard) in encoded[0].iter().enumerate() {
        put(0, idx as u32, 1, "alpha", shard)?;
    }
    // stripe 1：idx3/idx4 缺失（恰好处于恢复下限），idx0 有一份位翻转副本，
    // idx1 有两个来源的相同副本，idx2 混入一个 generation=2 的串代块。
    put(1, 0, 1, "alpha", &encoded[1][0])?;
    let mut flipped = encoded[1][0].clone();
    flipped[3] ^= 0x01;
    put(1, 0, 1, "beta", &flipped)?;
    put(1, 1, 1, "alpha", &encoded[1][1])?;
    put(1, 1, 1, "beta", &encoded[1][1])?;
    put(1, 2, 1, "alpha", &encoded[1][2])?;
    let stray: Vec<u8> = (0..shard_len).map(|j| (j as u8).wrapping_mul(41).wrapping_add(9)).collect();
    put(1, 2, 2, "gamma", &stray)?;
    Ok(id)
}

pub fn default_budget() -> usize {
    DEFAULT_BUDGET
}
