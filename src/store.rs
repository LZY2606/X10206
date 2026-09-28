//! SQLite 存储：原始碎片字节、来源、manifest 期望摘要、staging/committed 分离。

use crate::digest::sha256_hex;
use crate::model::{
    shard_len, stripe_count, Evidence, ManifestJson, ShardImportJson, VariantResult,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rusqlite::{params, Connection};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    quarantined INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS objects (
    object_id TEXT PRIMARY KEY,
    size INTEGER NOT NULL,
    stripe_size INTEGER NOT NULL,
    k INTEGER NOT NULL,
    m INTEGER NOT NULL,
    version INTEGER NOT NULL,
    stripe_count INTEGER NOT NULL,
    manifest_json TEXT NOT NULL,
    imported_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS stripe_manifest (
    object_id TEXT NOT NULL,
    stripe INTEGER NOT NULL,
    expected_json TEXT NOT NULL,
    PRIMARY KEY (object_id, stripe)
);
CREATE TABLE IF NOT EXISTS shards (
    id INTEGER PRIMARY KEY,
    object_id TEXT NOT NULL,
    stripe INTEGER NOT NULL,
    shard_index INTEGER NOT NULL,
    generation INTEGER NOT NULL,
    source_id INTEGER NOT NULL,
    bytes BLOB NOT NULL,
    len INTEGER NOT NULL,
    expected_len INTEGER NOT NULL,
    claimed_digest TEXT NOT NULL,
    actual_digest TEXT NOT NULL,
    status TEXT NOT NULL,
    imported_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS staging_shards (
    object_id TEXT NOT NULL,
    stripe INTEGER NOT NULL,
    variant_no INTEGER NOT NULL,
    shard_index INTEGER NOT NULL,
    bytes BLOB NOT NULL,
    digest TEXT NOT NULL,
    reconstructed INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS stripe_commits (
    object_id TEXT NOT NULL,
    stripe INTEGER NOT NULL,
    committed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    variant_count INTEGER NOT NULL,
    PRIMARY KEY (object_id, stripe)
);
CREATE TABLE IF NOT EXISTS recovery_variants (
    id INTEGER PRIMARY KEY,
    object_id TEXT NOT NULL,
    stripe INTEGER NOT NULL,
    variant_no INTEGER NOT NULL,
    generation INTEGER NOT NULL,
    status TEXT NOT NULL,
    participants_json TEXT NOT NULL,
    excluded_json TEXT NOT NULL,
    diffs_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS output_shards (
    object_id TEXT NOT NULL,
    stripe INTEGER NOT NULL,
    variant_no INTEGER NOT NULL,
    shard_index INTEGER NOT NULL,
    bytes BLOB NOT NULL,
    digest TEXT NOT NULL,
    reconstructed INTEGER NOT NULL,
    PRIMARY KEY (object_id, stripe, variant_no, shard_index)
);
"#;

pub struct Store {
    pub conn: Connection,
    pub root: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct ObjectMeta {
    pub object_id: String,
    pub size: u64,
    pub stripe_size: u64,
    pub k: usize,
    pub m: usize,
    pub version: u32,
    pub stripe_count: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ObjectRow {
    #[serde(flatten)]
    pub meta: ObjectMeta,
    pub stripes_committed: u32,
    pub shards_total: u32,
    pub shards_bad: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceRow {
    pub id: i64,
    pub name: String,
    pub quarantined: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ShardRow {
    pub id: i64,
    pub stripe: u32,
    pub shard_index: u32,
    pub generation: u64,
    pub source_id: i64,
    pub source_name: String,
    pub source_quarantined: bool,
    pub len: usize,
    pub expected_len: usize,
    pub claimed_digest: String,
    pub actual_digest: String,
    pub status: String,
}

pub struct ShardRec {
    pub row: ShardRow,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OutputDigestRow {
    pub shard_index: u32,
    pub digest: String,
    pub reconstructed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct VariantRow {
    pub variant_no: u32,
    pub generation: u64,
    pub status: String,
    pub participants: Vec<i64>,
    pub excluded: Vec<Evidence>,
    pub diffs: Vec<String>,
    pub outputs: Vec<OutputDigestRow>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StripeDetail {
    pub index: u32,
    pub committed: bool,
    pub committed_at: Option<String>,
    pub expected_len: usize,
    pub shards: Vec<ShardRow>,
    pub variants: Vec<VariantRow>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ObjectDetail {
    #[serde(flatten)]
    pub meta: ObjectMeta,
    pub stripes: Vec<StripeDetail>,
}

impl Store {
    pub fn open(root: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(root).map_err(|e| format!("创建数据目录失败: {e}"))?;
        std::fs::create_dir_all(root.join("export"))
            .map_err(|e| format!("创建导出目录失败: {e}"))?;
        let conn = Connection::open(root.join("app.db"))
            .map_err(|e| format!("打开 SQLite 失败: {e}"))?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .map_err(|e| e.to_string())?;
        conn.execute_batch(SCHEMA).map_err(|e| e.to_string())?;
        let mut store = Self {
            conn,
            root: root.to_path_buf(),
        };
        // 中断恢复：临时块一律丢弃，绝不能被最终读取。
        store
            .conn
            .execute_batch("DELETE FROM staging_shards;")
            .map_err(|e| e.to_string())?;
        Ok(store)
    }

    pub fn get_or_create_source(&mut self, name: &str) -> Result<i64, String> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO sources(name) VALUES (?1)",
                params![name],
            )
            .map_err(|e| e.to_string())?;
        self.conn
            .query_row("SELECT id FROM sources WHERE name=?1", params![name], |r| {
                r.get(0)
            })
            .map_err(|e| e.to_string())
    }

    pub fn import_manifest(&mut self, json_text: &str) -> Result<String, String> {
        let manifest: ManifestJson =
            serde_json::from_str(json_text).map_err(|e| format!("manifest JSON 解析失败: {e}"))?;
        if manifest.object_id.trim().is_empty() {
            return Err("object_id 为空".into());
        }
        let count = stripe_count(manifest.size, manifest.stripe_size);
        if count == 0 {
            return Err("对象大小或 stripe_size 非法".into());
        }
        if manifest.stripes.len() != count as usize {
            return Err(format!(
                "manifest stripe 数量 {} 与对象大小推导出的 {count} 不符",
                manifest.stripes.len()
            ));
        }
        let k = manifest.encoding.data_shards;
        let m = manifest.encoding.parity_shards;
        if k == 0 || m == 0 || k + m > 256 {
            return Err(format!("非法编码参数 k={k} m={m}"));
        }
        self.conn
            .execute(
                "INSERT OR REPLACE INTO objects(object_id,size,stripe_size,k,m,version,stripe_count,manifest_json)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    manifest.object_id,
                    manifest.size as i64,
                    manifest.stripe_size as i64,
                    k as i64,
                    m as i64,
                    manifest.encoding.version,
                    count,
                    json_text,
                ],
            )
            .map_err(|e| e.to_string())?;
        self.conn
            .execute(
                "DELETE FROM stripe_manifest WHERE object_id=?1",
                params![manifest.object_id],
            )
            .map_err(|e| e.to_string())?;
        for stripe in &manifest.stripes {
            self.conn
                .execute(
                    "INSERT INTO stripe_manifest(object_id,stripe,expected_json) VALUES (?1,?2,?3)",
                    params![
                        manifest.object_id,
                        stripe.index,
                        serde_json::to_string(&stripe.shard_digests).unwrap(),
                    ],
                )
                .map_err(|e| e.to_string())?;
        }
        Ok(manifest.object_id)
    }

    pub fn import_shard(&mut self, json_text: &str) -> Result<(i64, String), String> {
        let req: ShardImportJson =
            serde_json::from_str(json_text).map_err(|e| format!("shard JSON 解析失败: {e}"))?;
        if req.shard_index as usize >= self.object_meta(&req.object_id)?.k
            + self.object_meta(&req.object_id)?.m
        {
            return Err("shard_index 超出 k+m 范围".into());
        }
        let bytes = STANDARD
            .decode(req.data_b64.as_bytes())
            .map_err(|e| format!("base64 解码失败: {e}"))?;
        let meta = self.object_meta(&req.object_id)?;
        let expected_len = shard_len(meta.size, meta.stripe_size, meta.k, req.stripe);
        let actual = sha256_hex(&bytes);
        let mut problems = Vec::new();
        if bytes.len() != expected_len {
            problems.push(format!(
                "长度与 manifest 不符（实际 {}，期望 {}）",
                bytes.len(),
                expected_len
            ));
        }
        if actual != req.digest.trim().to_lowercase() {
            problems.push("声明摘要与重算摘要不一致（疑似位翻转/损坏）".to_string());
        }
        let expected = self.expected_digests(&req.object_id, req.stripe)?;
        if let Some(want) = expected.get(&req.shard_index) {
            if want != &actual {
                problems.push("内容摘要与 manifest 期望不一致（同编号存在其它内容候选）".to_string());
            }
        }
        let status = if problems.is_empty() {
            "ok".to_string()
        } else {
            problems.join("；")
        };
        let source_id = self.get_or_create_source(&req.source)?;
        self.conn
            .execute(
                "INSERT INTO shards(object_id,stripe,shard_index,generation,source_id,bytes,len,expected_len,claimed_digest,actual_digest,status)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                params![
                    req.object_id,
                    req.stripe,
                    req.shard_index,
                    req.generation as i64,
                    source_id,
                    bytes,
                    bytes.len() as i64,
                    expected_len as i64,
                    req.digest.trim().to_lowercase(),
                    actual,
                    status,
                ],
            )
            .map_err(|e| e.to_string())?;
        let id = self.conn.last_insert_rowid();
        Ok((id, status))
    }

    pub fn object_meta(&self, object_id: &str) -> Result<ObjectMeta, String> {
        self.conn
            .query_row(
                "SELECT object_id,size,stripe_size,k,m,version,stripe_count FROM objects WHERE object_id=?1",
                params![object_id],
                |r| {
                    Ok(ObjectMeta {
                        object_id: r.get(0)?,
                        size: r.get::<_, i64>(1)? as u64,
                        stripe_size: r.get::<_, i64>(2)? as u64,
                        k: r.get::<_, i64>(3)? as usize,
                        m: r.get::<_, i64>(4)? as usize,
                        version: r.get::<_, i64>(5)? as u32,
                        stripe_count: r.get::<_, i64>(6)? as u32,
                    })
                },
            )
            .map_err(|_| format!("对象不存在: {object_id}（请先导入 manifest）"))
    }

    pub fn expected_digests(
        &self,
        object_id: &str,
        stripe: u32,
    ) -> Result<HashMap<u32, String>, String> {
        let text: Option<String> = self
            .conn
            .query_row(
                "SELECT expected_json FROM stripe_manifest WHERE object_id=?1 AND stripe=?2",
                params![object_id, stripe],
                |r| r.get(0),
            )
            .ok()
            .flatten();
        let mut map = HashMap::new();
        if let Some(text) = text {
            let parsed: HashMap<String, String> =
                serde_json::from_str(&text).map_err(|e| e.to_string())?;
            for (k, v) in parsed {
                if let Ok(idx) = k.parse::<u32>() {
                    map.insert(idx, v.trim().to_lowercase());
                }
            }
        }
        Ok(map)
    }

    pub fn stripe_shards(&self, object_id: &str, stripe: u32) -> Result<Vec<ShardRec>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT s.id,s.stripe,s.shard_index,s.generation,s.source_id,src.name,src.quarantined,
                        s.len,s.expected_len,s.claimed_digest,s.actual_digest,s.status,s.bytes
                 FROM shards s JOIN sources src ON src.id=s.source_id
                 WHERE s.object_id=?1 AND s.stripe=?2 ORDER BY s.id",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![object_id, stripe], |r| {
                let bytes: Vec<u8> = r.get(12)?;
                Ok(ShardRec {
                    row: ShardRow {
                        id: r.get(0)?,
                        stripe: r.get(1)?,
                        shard_index: r.get(2)?,
                        generation: r.get::<_, i64>(3)? as u64,
                        source_id: r.get(4)?,
                        source_name: r.get(5)?,
                        source_quarantined: r.get::<_, i64>(6)? != 0,
                        len: r.get::<_, i64>(7)? as usize,
                        expected_len: r.get::<_, i64>(8)? as usize,
                        claimed_digest: r.get(9)?,
                        actual_digest: r.get(10)?,
                        status: r.get(11)?,
                    },
                    bytes,
                })
            })
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    pub fn list_objects(&self) -> Result<Vec<ObjectRow>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT o.object_id,o.size,o.stripe_size,o.k,o.m,o.version,o.stripe_count,
                        (SELECT count(*) FROM stripe_commits c WHERE c.object_id=o.object_id),
                        (SELECT count(*) FROM shards s WHERE s.object_id=o.object_id),
                        (SELECT count(*) FROM shards s WHERE s.object_id=o.object_id AND s.status!='ok')
                 FROM objects o ORDER BY o.object_id",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| {
                let meta = ObjectMeta {
                    object_id: r.get(0)?,
                    size: r.get::<_, i64>(1)? as u64,
                    stripe_size: r.get::<_, i64>(2)? as u64,
                    k: r.get::<_, i64>(3)? as usize,
                    m: r.get::<_, i64>(4)? as usize,
                    version: r.get::<_, i64>(5)? as u32,
                    stripe_count: r.get::<_, i64>(6)? as u32,
                };
                Ok(ObjectRow {
                    meta,
                    stripes_committed: r.get::<_, i64>(7)? as u32,
                    shards_total: r.get::<_, i64>(8)? as u32,
                    shards_bad: r.get::<_, i64>(9)? as u32,
                })
            })
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    pub fn list_sources(&self) -> Result<Vec<SourceRow>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT id,name,quarantined FROM sources ORDER BY id")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| {
                Ok(SourceRow {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    quarantined: r.get::<_, i64>(2)? != 0,
                })
            })
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    pub fn set_quarantined(&mut self, source_id: i64, value: bool) -> Result<(), String> {
        let affected = self
            .conn
            .execute(
                "UPDATE sources SET quarantined=?2 WHERE id=?1",
                params![source_id, value as i64],
            )
            .map_err(|e| e.to_string())?;
        if affected == 0 {
            return Err(format!("来源不存在: {source_id}"));
        }
        Ok(())
    }

    pub fn shard_ids_for_source(&self, source_id: i64) -> Result<HashSet<i64>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM shards WHERE source_id=?1")
            .map_err(|e| e.to_string())?;
        let ids = stmt
            .query_map(params![source_id], |r| r.get::<_, i64>(0))
            .map_err(|e| e.to_string())?;
        let mut set = HashSet::new();
        for id in ids {
            set.insert(id.map_err(|e| e.to_string())?);
        }
        Ok(set)
    }

    /// 列出已提交 variant 使用了给定 shard 集合的 (object, stripe)。
    pub fn committed_stripes_using(
        &self,
        shard_ids: &HashSet<i64>,
    ) -> Result<Vec<(String, u32)>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT object_id,stripe,participants_json FROM recovery_variants ORDER BY object_id,stripe,variant_no",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u32, r.get::<_, String>(2)?))
            })
            .map_err(|e| e.to_string())?;
        let mut seen = HashSet::new();
        let mut affected = Vec::new();
        for row in rows {
            let (object_id, stripe, json_text) = row.map_err(|e| e.to_string())?;
            let participants: Vec<i64> =
                serde_json::from_str(&json_text).map_err(|e| e.to_string())?;
            if participants.iter().any(|p| shard_ids.contains(p))
                && seen.insert((object_id.clone(), stripe))
            {
                affected.push((object_id, stripe));
            }
        }
        Ok(affected)
    }

    pub fn delete_commit(&mut self, object_id: &str, stripe: u32) -> Result<(), String> {
        self.conn
            .execute(
                "DELETE FROM output_shards WHERE object_id=?1 AND stripe=?2",
                params![object_id, stripe],
            )
            .map_err(|e| e.to_string())?;
        self.conn
            .execute(
                "DELETE FROM recovery_variants WHERE object_id=?1 AND stripe=?2",
                params![object_id, stripe],
            )
            .map_err(|e| e.to_string())?;
        self.conn
            .execute(
                "DELETE FROM stripe_commits WHERE object_id=?1 AND stripe=?2",
                params![object_id, stripe],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// 只有提交存在且首选 variant 的全部输出摘要完整时才允许复用。
    pub fn is_committed_complete(
        &self,
        object_id: &str,
        stripe: u32,
    ) -> Result<bool, String> {
        let total = {
            let meta = self.object_meta(object_id)?;
            meta.k + meta.m
        };
        let committed: i64 = self
            .conn
            .query_row(
                "SELECT count(*) FROM stripe_commits WHERE object_id=?1 AND stripe=?2",
                params![object_id, stripe],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        if committed == 0 {
            return Ok(false);
        }
        let complete: i64 = self
            .conn
            .query_row(
                "SELECT count(*) FROM output_shards
                 WHERE object_id=?1 AND stripe=?2 AND variant_no=0
                   AND digest IS NOT NULL AND length(digest)=64",
                params![object_id, stripe],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        Ok(complete as usize == total)
    }

    pub fn committed_at(&self, object_id: &str, stripe: u32) -> Option<String> {
        self.conn
            .query_row(
                "SELECT committed_at FROM stripe_commits WHERE object_id=?1 AND stripe=?2",
                params![object_id, stripe],
                |r| r.get(0),
            )
            .ok()
    }

    pub fn staging_count(&self) -> Result<i64, String> {
        self.conn
            .query_row("SELECT count(*) FROM staging_shards", [], |r| r.get(0))
            .map_err(|e| e.to_string())
    }

    /// 恢复结果先落 staging（临时块），再在单个事务里切换到 committed 表。
    pub fn commit_stripe(
        &mut self,
        object_id: &str,
        stripe: u32,
        variants: &[VariantResult],
        excluded: &[Evidence],
    ) -> Result<(), String> {
        if variants.is_empty() {
            return Err("没有可提交的 variant".into());
        }
        self.conn
            .execute(
                "DELETE FROM staging_shards WHERE object_id=?1 AND stripe=?2",
                params![object_id, stripe],
            )
            .map_err(|e| e.to_string())?;
        for (vno, variant) in variants.iter().enumerate() {
            for output in &variant.outputs {
                self.conn
                    .execute(
                        "INSERT INTO staging_shards(object_id,stripe,variant_no,shard_index,bytes,digest,reconstructed)
                         VALUES (?1,?2,?3,?4,?5,?6,?7)",
                        params![
                            object_id,
                            stripe,
                            vno as i64,
                            output.shard_index,
                            output.bytes,
                            output.digest,
                            output.reconstructed as i64,
                        ],
                    )
                    .map_err(|e| e.to_string())?;
            }
        }
        let tx = self.conn.transaction().map_err(|e| e.to_string())?;
        tx.execute(
            "DELETE FROM output_shards WHERE object_id=?1 AND stripe=?2",
            params![object_id, stripe],
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "DELETE FROM recovery_variants WHERE object_id=?1 AND stripe=?2",
            params![object_id, stripe],
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "DELETE FROM stripe_commits WHERE object_id=?1 AND stripe=?2",
            params![object_id, stripe],
        )
        .map_err(|e| e.to_string())?;
        let excluded_json = serde_json::to_string(excluded).unwrap();
        for (vno, variant) in variants.iter().enumerate() {
            tx.execute(
                "INSERT INTO recovery_variants(object_id,stripe,variant_no,generation,status,participants_json,excluded_json,diffs_json)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    object_id,
                    stripe,
                    vno as i64,
                    variant.generation as i64,
                    variant.status,
                    serde_json::to_string(&variant.participants).unwrap(),
                    excluded_json,
                    serde_json::to_string(&variant.diffs).unwrap(),
                ],
            )
            .map_err(|e| e.to_string())?;
        }
        tx.execute(
            "INSERT INTO output_shards(object_id,stripe,variant_no,shard_index,bytes,digest,reconstructed)
             SELECT object_id,stripe,variant_no,shard_index,bytes,digest,reconstructed
             FROM staging_shards WHERE object_id=?1 AND stripe=?2",
            params![object_id, stripe],
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO stripe_commits(object_id,stripe,variant_count) VALUES (?1,?2,?3)",
            params![object_id, stripe, variants.len() as i64],
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "DELETE FROM staging_shards WHERE object_id=?1 AND stripe=?2",
            params![object_id, stripe],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(())
    }

    /// 导出/最终读取只允许从 committed 表取首选 variant。
    pub fn primary_outputs(
        &self,
        object_id: &str,
        stripe: u32,
    ) -> Result<Vec<(u32, Vec<u8>, String)>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT shard_index,bytes,digest FROM output_shards
                 WHERE object_id=?1 AND stripe=?2 AND variant_no=0 ORDER BY shard_index",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![object_id, stripe], |r| {
                Ok((r.get::<_, i64>(0)? as u32, r.get::<_, Vec<u8>>(1)?, r.get::<_, String>(2)?))
            })
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    pub fn object_detail(&self, object_id: &str) -> Result<ObjectDetail, String> {
        let meta = self.object_meta(object_id)?;
        let mut stripes = Vec::new();
        for index in 0..meta.stripe_count {
            let expected_len = shard_len(meta.size, meta.stripe_size, meta.k, index);
            let shards = self
                .stripe_shards(object_id, index)?
                .into_iter()
                .map(|r| r.row)
                .collect();
            let committed_at = self.committed_at(object_id, index);
            let variants = if committed_at.is_some() {
                self.variant_rows(object_id, index)?
            } else {
                Vec::new()
            };
            stripes.push(StripeDetail {
                index,
                committed: committed_at.is_some(),
                committed_at,
                expected_len,
                shards,
                variants,
            });
        }
        Ok(ObjectDetail { meta, stripes })
    }

    fn variant_rows(&self, object_id: &str, stripe: u32) -> Result<Vec<VariantRow>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT variant_no,generation,status,participants_json,excluded_json,diffs_json
                 FROM recovery_variants WHERE object_id=?1 AND stripe=?2 ORDER BY variant_no",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![object_id, stripe], |r| {
                Ok((
                    r.get::<_, i64>(0)? as u32,
                    r.get::<_, i64>(1)? as u64,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            let (variant_no, generation, status, participants_json, excluded_json, diffs_json) =
                row.map_err(|e| e.to_string())?;
            let participants: Vec<i64> =
                serde_json::from_str(&participants_json).map_err(|e| e.to_string())?;
            let excluded: Vec<Evidence> =
                serde_json::from_str(&excluded_json).map_err(|e| e.to_string())?;
            let diffs: Vec<String> =
                serde_json::from_str(&diffs_json).map_err(|e| e.to_string())?;
            let mut outputs = Vec::new();
            let mut o_stmt = self
                .conn
                .prepare(
                    "SELECT shard_index,digest,reconstructed FROM output_shards
                     WHERE object_id=?1 AND stripe=?2 AND variant_no=?3 ORDER BY shard_index",
                )
                .map_err(|e| e.to_string())?;
            let o_rows = o_stmt
                .query_map(params![object_id, stripe, variant_no], |r| {
                    Ok(OutputDigestRow {
                        shard_index: r.get::<_, i64>(0)? as u32,
                        digest: r.get(1)?,
                        reconstructed: r.get::<_, i64>(2)? != 0,
                    })
                })
                .map_err(|e| e.to_string())?;
            for o in o_rows {
                outputs.push(o.map_err(|e| e.to_string())?);
            }
            out.push(VariantRow {
                variant_no,
                generation,
                status,
                participants,
                excluded,
                diffs,
                outputs,
            });
        }
        Ok(out)
    }
}
