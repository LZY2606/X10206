//! 导入 manifest / data shard / parity shard / 每块摘要。
//! 原始字节写入 fragments 目录（永不改动），数据库记录来源与声明/实际摘要。

use crate::digest::sha256_hex;
use crate::model::*;
use crate::store::Store;

use std::path::PathBuf;

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct IngestReport {
    pub source_id: i64,
    pub ingest_seq: i64,
    pub versions: usize,
    pub shards_received: usize,
    pub bad_hex: usize,
    pub out_of_range: usize,
    pub warnings: Vec<String>,
}

pub fn ingest(store: &Store, req: &IngestRequest) -> rusqlite::Result<IngestReport> {
    let mut report = IngestReport::default();
    let seq = store.next_ingest_seq()?;
    report.ingest_seq = seq;
    let source_id = store.insert_source(&req.source, &req.received_at, seq)?;
    report.source_id = source_id;

    store.upsert_object(&req.manifest.object_id, req.manifest.current_generation as i64)?;

    for v in &req.manifest.versions {
        store.upsert_manifest_version(v, &req.manifest.object_id)?;
        for (s, row) in v.shard_digests.iter().enumerate() {
            for (h, dig) in row.iter().enumerate() {
                store.upsert_expectation(
                    &req.manifest.object_id,
                    v.generation as i64,
                    s as i64,
                    h as i64,
                    dig,
                )?;
            }
        }
        report.versions += 1;
        store.ensure_stripe(&req.manifest.object_id, 0, v.stripe_count)?;
    }

    let mut conn = store.conn.lock().unwrap();
    let tx = conn.transaction()?;
    let mut order: i64 = 0;
    for (stripe_idx, row) in req.shards.iter().enumerate() {
        for (shard_idx, hex_bytes) in row {
            order += 1;
            let bytes = match hex::decode(hex_bytes) {
                Ok(b) => b,
                Err(_) => {
                    report.bad_hex += 1;
                    report.warnings.push(format!(
                        "stripe {stripe_idx} shard {shard_idx}: 非法十六进制，已忽略"
                    ));
                    continue;
                }
            };
            // 选择 generation：导入时碎片归属清单当前 generation（旧版本碎片通过同一来源再次导入）。
            let gen = req.manifest.current_generation as i64;
            let version = req.manifest.versions.iter().find(|v| v.generation as i64 == gen);
            let Some(version) = version else {
                report.warnings.push(format!(
                    "stripe {stripe_idx} shard {shard_idx}: 当前 generation {gen} 无对应清单版本，已忽略"
                ));
                continue;
            };
            if shard_idx as i64 >= version.k + version.m {
                report.out_of_range += 1;
                report.warnings.push(format!(
                    "stripe {stripe_idx} shard {shard_idx}: 超出 k+m={}，已忽略",
                    version.k + version.m
                ));
                continue;
            }
            if stripe_idx as i64 >= version.stripe_count as i64 {
                report.out_of_range += 1;
                report.warnings.push(format!(
                    "stripe {stripe_idx}: 超出 stripe_count={}，已忽略",
                    version.stripe_count
                ));
                continue;
            }
            let actual = sha256_hex(&bytes);
            let claim_key = format!("{stripe_idx}:{shard_idx}");
            let claimed = req
                .claimed_digests
                .get(&claim_key)
                .cloned()
                .or_else(|| {
                    version.shard_digests.get(stripe_idx).and_then(|r| r.get(*shard_idx)).cloned()
                })
                .unwrap_or_else(|| actual.clone());

            // 保存原始字节：内容寻址，绝不覆盖。
            let fname = format!(
                "{}.g{}.s{}.h{}.{}.bin",
                safe(&req.manifest.object_id),
                gen,
                stripe_idx,
                shard_idx,
                &actual[..16]
            );
            let rel = PathBuf::from("fragments").join(fname);
            let abs = store.data_dir.join(&rel);
            if !abs.exists() {
                std::fs::write(&abs, &bytes).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
            }
            let exists: Option<i64> = tx
                .query_row(
                    "SELECT id FROM fragments WHERE object_id=?1 AND generation=?2 AND stripe_idx=?3
                     AND shard_idx=?4 AND source_id=?5 AND actual_digest=?6",
                    rusqlite::params![
                        req.manifest.object_id,
                        gen,
                        stripe_idx as i64,
                        *shard_idx as i64,
                        source_id,
                        actual
                    ],
                    |r| r.get(0),
                )
                .ok()
                .flatten();
            if exists.is_none() {
                tx.execute(
                    "INSERT INTO fragments(object_id,generation,stripe_idx,shard_idx,source_id,length,
                         claimed_digest,actual_digest,byte_path,receive_order)
                     VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                    rusqlite::params![
                        req.manifest.object_id,
                        gen,
                        stripe_idx as i64,
                        *shard_idx as i64,
                        source_id,
                        bytes.len() as i64,
                        claimed,
                        actual,
                        rel.to_string_lossy(),
                        order
                    ],
                )?;
            }
            report.shards_received += 1;
        }
    }
    tx.commit()?;
    drop(conn);
    Ok(report)
}

fn safe(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}
