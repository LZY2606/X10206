//! SQLite + 文件系统持久层。
//!
//! 原始字节不可变地保存在 `shards/`；已提交 stripe 的重建块仅出现在
//! `committed/<object>/<stripe>/`。临时文件写入 `tmp/`，且最终读取路径
//! 永不包含 `tmp/`。导入的原始碎片保存在 `imports/`，全程只读不改动。

use anyhow::{anyhow, bail, Context, Result};
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const SCHEMA_VERSION: i64 = 1;

#[derive(Clone)]
pub struct Store {
    pub root: PathBuf,
    pub db_path: PathBuf,
    /// 测试专用：令下一次提交块写入失败（用后即清零）。
    pub fail_next_block_write: Arc<Mutex<bool>>,
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

impl Store {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        for sub in ["shards", "committed", "exports", "imports", "tmp", "db"] {
            std::fs::create_dir_all(root.join(sub))
                .with_context(|| format!("创建目录 {sub} 失败"))?;
        }
        let db_path = root.join("db").join("cab.sqlite");
        let store = Self {
            root,
            db_path,
            fail_next_block_write: Arc::new(Mutex::new(false)),
        };
        {
            let mut conn = store.connect()?;
            store.init_schema(&mut conn)?;
            store.recover_pending(&mut conn)?;
        }
        Ok(store)
    }

    pub fn connect(&self) -> Result<Connection> {
        let conn = Connection::open(&self.db_path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "busy_timeout", 5000i64)?;
        Ok(conn)
    }

    pub fn shards_dir(&self) -> PathBuf {
        self.root.join("shards")
    }
    pub fn committed_dir(&self) -> PathBuf {
        self.root.join("committed")
    }
    pub fn exports_dir(&self) -> PathBuf {
        self.root.join("exports")
    }
    pub fn imports_dir(&self) -> PathBuf {
        self.root.join("imports")
    }
    pub fn tmp_dir(&self) -> PathBuf {
        self.root.join("tmp")
    }

    fn init_schema(&self, conn: &mut Connection) -> Result<()> {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS objects (
                object_id       TEXT PRIMARY KEY,
                manifest_digest TEXT NOT NULL,
                manifest_json   TEXT NOT NULL,
                total_size      INTEGER NOT NULL,
                stripe_count    INTEGER NOT NULL,
                object_digest   TEXT NOT NULL,
                isolated_sources TEXT NOT NULL DEFAULT '[]',
                imported_at_ms  INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS receipts (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                object_id       TEXT NOT NULL REFERENCES objects(object_id),
                stripe_index    INTEGER NOT NULL,
                shard_index     INTEGER NOT NULL,
                generation      INTEGER NOT NULL,
                source          TEXT NOT NULL,
                payload_digest  TEXT NOT NULL,
                expected_digest TEXT,
                observed_len    INTEGER NOT NULL,
                expected_len    INTEGER NOT NULL,
                length_ok       INTEGER NOT NULL,
                digest_ok       INTEGER NOT NULL,
                blob_path       TEXT NOT NULL,
                received_at_ms  INTEGER NOT NULL,
                UNIQUE(object_id, stripe_index, shard_index, generation, payload_digest)
            );
            CREATE INDEX IF NOT EXISTS idx_receipts_lookup
                ON receipts(object_id, stripe_index);
            CREATE TABLE IF NOT EXISTS stripes (
                object_id     TEXT NOT NULL REFERENCES objects(object_id),
                stripe_index  INTEGER NOT NULL,
                status        TEXT NOT NULL,
                analysis_json TEXT NOT NULL,
                chosen_rank   INTEGER,
                committed     INTEGER NOT NULL DEFAULT 0,
                committed_at_ms INTEGER,
                PRIMARY KEY(object_id, stripe_index)
            );
            CREATE TABLE IF NOT EXISTS committed_blocks (
                object_id    TEXT NOT NULL,
                stripe_index INTEGER NOT NULL,
                shard_index  INTEGER NOT NULL,
                generation   INTEGER NOT NULL,
                blob_path    TEXT NOT NULL,
                shard_digest TEXT NOT NULL,
                from_receipt_id INTEGER,
                PRIMARY KEY(object_id, stripe_index, shard_index)
            );
            CREATE TABLE IF NOT EXISTS jobs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                kind        TEXT NOT NULL,
                object_id   TEXT,
                status      TEXT NOT NULL,
                progress    REAL NOT NULL DEFAULT 0,
                message     TEXT NOT NULL DEFAULT '',
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL
            );
            "#,
        )?;
        let version: i64 = conn
            .query_row(
                "SELECT value FROM meta WHERE key='schema_version'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(SCHEMA_VERSION);
        if version != SCHEMA_VERSION {
            bail!("schema 版本不兼容：数据库 {version}，程序 {SCHEMA_VERSION}");
        }
        conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?1)",
            params![SCHEMA_VERSION.to_string()],
        )?;
        Ok(())
    }

    /// 崩溃 / 中断恢复：把停留在 rebuilding 的 stripe 复位为 pending，
    /// 已 committed 的 stripe 一律复用，不重新计算。
    fn recover_pending(&self, conn: &mut Connection) -> Result<()> {
        // committed=1 但块目录缺失（极端情况）时也复位为 pending。
        let mut suspect: Vec<(String, i64)> = Vec::new();
        {
            let mut stmt =
                conn.prepare("SELECT object_id, stripe_index FROM stripes")?;
            let rows = stmt.query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
            })?;
            for row in rows {
                let (object_id, stripe_index) = row?;
                let dir = self.committed_dir().join(&object_id).join(stripe_index.to_string());
                if !dir.is_dir() {
                    suspect.push((object_id, stripe_index));
                }
            }
        }
        for (object_id, stripe_index) in suspect {
            conn.execute(
                "UPDATE stripes SET committed=0, committed_at_ms=NULL, status='pending'
                 WHERE object_id=?1 AND stripe_index=?2",
                params![object_id, stripe_index],
            )?;
            conn.execute(
                "DELETE FROM committed_blocks WHERE object_id=?1 AND stripe_index=?2",
                params![object_id, stripe_index],
            )?;
        }
        // 清理任何遗留临时块（最终读取从不经过 tmp/）。
        let tmp = self.tmp_dir();
        if tmp.is_dir() {
            for entry in std::fs::read_dir(&tmp)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    let _ = std::fs::remove_dir_all(&path);
                } else {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
        Ok(())
    }
}

/// 一个已提交块的信息（用于导出与页面展示）。
#[derive(Debug, Clone)]
pub struct CommittedBlock {
    pub shard_index: usize,
    pub generation: u64,
    pub blob_path: PathBuf,
    pub shard_digest: String,
    pub from_receipt_id: Option<i64>,
}

impl Store {
    /// 把原始接收到的字节不可变地写入 shards 目录。
    /// 路径按内容寻址：同内容复用，绝不覆盖。
    pub fn write_received_blob(&self, digest_hex: &str, bytes: &[u8]) -> Result<PathBuf> {
        let rel = Path::new(&digest_hex[0..2]).join(format!("{digest_hex}.bin"));
        let full = self.shards_dir().join(&rel);
        if !full.exists() {
            let tmp_dir = self.tmp_dir().join("ingest");
            std::fs::create_dir_all(&tmp_dir)?;
            let tmp = tmp_dir.join(format!("{digest_hex}.tmp.{}", std::process::id()));
            std::fs::write(&tmp, bytes).with_context(|| "写入接收分片失败")?;
            std::fs::create_dir_all(full.parent().unwrap())?;
            std::fs::rename(&tmp, &full).with_context(|| "接收分片落位失败")?;
        }
        Ok(PathBuf::from("shards").join(rel))
    }

    /// 原子写入一个待提交块到 tmp 暂存区；调用方随后用 commit_blocks 提交。
    pub fn stage_block(
        &self,
        object_id: &str,
        stripe_index: usize,
        shard_index: usize,
        bytes: &[u8],
    ) -> Result<PathBuf> {
        if *self.fail_next_block_write.lock().unwrap() {
            *self.fail_next_block_write.lock().unwrap() = false;
            return Err(anyhow!("注入故障：模拟磁盘写失败（块 {shard_index}）"));
        }
        let dir = self
            .tmp_dir()
            .join("staging")
            .join(object_id)
            .join(stripe_index.to_string());
        std::fs::create_dir_all(&dir)?;
        let tmp = dir.join(format!("shard-{shard_index:04}.tmp"));
        std::fs::write(&tmp, bytes).with_context(|| "写入临时块失败")?;
        Ok(tmp)
    }

    /// 提交一条 stripe：暂存块原子落位 + 数据库事务。
    ///
    /// 只有块文件与事务同时完成，stripe 才标记 committed；
    /// 中断后未提交块随 tmp/ 清理，不会被最终读取。
    pub fn commit_stripe(
        &self,
        conn: &mut Connection,
        object_id: &str,
        stripe_index: usize,
        status: &str,
        analysis_json: &str,
        chosen_rank: Option<i64>,
        blocks: &[(usize, u64, PathBuf, String, Option<i64>)],
    ) -> Result<()> {
        let tx = conn.transaction()?;
        let out_dir = self
            .committed_dir()
            .join(object_id)
            .join(stripe_index.to_string());
        std::fs::create_dir_all(&out_dir)?;
        for (shard_index, _gen, staged, _digest, _receipt) in blocks {
            let dest = out_dir.join(format!("shard-{shard_index:04}.bin"));
            std::fs::rename(staged, &dest).with_context(|| {
                format!("提交块 {shard_index} 落位失败（stripe {stripe_index}）")
            })?;
        }
        let rel_dir = PathBuf::from("committed")
            .join(object_id)
            .join(stripe_index.to_string());
        tx.execute(
            "INSERT INTO stripes(object_id, stripe_index, status, analysis_json,
                 chosen_rank, committed, committed_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6)
             ON CONFLICT(object_id, stripe_index) DO UPDATE SET
                 status=excluded.status,
                 analysis_json=excluded.analysis_json,
                 chosen_rank=excluded.chosen_rank,
                 committed=1,
                 committed_at_ms=excluded.committed_at_ms",
            params![
                object_id,
                stripe_index as i64,
                status,
                analysis_json,
                chosen_rank,
                now_ms()
            ],
        )?;
        tx.execute(
            "DELETE FROM committed_blocks WHERE object_id=?1 AND stripe_index=?2",
            params![object_id, stripe_index as i64],
        )?;
        for (shard_index, generation, _staged, digest, receipt_id) in blocks {
            let blob_path = rel_dir.join(format!("shard-{shard_index:04}.bin"));
            tx.execute(
                "INSERT INTO committed_blocks
                    (object_id, stripe_index, shard_index, generation, blob_path,
                     shard_digest, from_receipt_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    object_id,
                    stripe_index as i64,
                    *shard_index as i64,
                    *generation as i64,
                    blob_path.to_string_lossy(),
                    digest,
                    receipt_id,
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// 仅保存分析结果（不可恢复 / intact 提交、隔离重算等）。
    pub fn save_analysis(
        &self,
        conn: &mut Connection,
        object_id: &str,
        stripe_index: usize,
        status: &str,
        analysis_json: &str,
        chosen_rank: Option<i64>,
        committed: bool,
    ) -> Result<()> {
        conn.execute(
            "INSERT INTO stripes(object_id, stripe_index, status, analysis_json,
                 chosen_rank, committed, committed_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(object_id, stripe_index) DO UPDATE SET
                 status=excluded.status,
                 analysis_json=excluded.analysis_json,
                 chosen_rank=excluded.chosen_rank,
                 committed=excluded.committed,
                 committed_at_ms=excluded.committed_at_ms",
            params![
                object_id,
                stripe_index as i64,
                status,
                analysis_json,
                chosen_rank,
                committed as i64,
                if committed { Some(now_ms()) } else { None },
            ],
        )?;
        Ok(())
    }

    /// 列出已提交块（导出 / 最终读取唯一合法来源之一）。
    pub fn committed_blocks(
        &self,
        conn: &mut Connection,
        object_id: &str,
        stripe_index: usize,
    ) -> Result<Vec<CommittedBlock>> {
        let mut stmt = conn.prepare(
            "SELECT shard_index, generation, blob_path, shard_digest, from_receipt_id
             FROM committed_blocks
             WHERE object_id=?1 AND stripe_index=?2
             ORDER BY shard_index",
        )?;
        let rows = stmt.query_map(params![object_id, stripe_index as i64], |r| {
            Ok(CommittedBlock {
                shard_index: r.get::<_, i64>(0)? as usize,
                generation: r.get::<_, i64>(1)? as u64,
                blob_path: PathBuf::from(r.get::<_, String>(2)?),
                shard_digest: r.get::<_, String>(3)?,
                from_receipt_id: r.get::<_, Option<i64>>(4)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            let mut block = row?;
            block.blob_path = self.root.join(&block.blob_path);
            out.push(block);
        }
        Ok(out)
    }
}

#[derive(Debug, Clone)]
pub struct ObjectRow {
    pub object_id: String,
    pub manifest_digest: String,
    pub manifest_json: String,
    pub total_size: usize,
    pub stripe_count: usize,
    pub object_digest: String,
    pub isolated_sources: Vec<String>,
    pub imported_at_ms: i64,
}

#[derive(Debug, Clone)]
pub struct ReceiptRow {
    pub id: i64,
    pub object_id: String,
    pub stripe_index: usize,
    pub shard_index: usize,
    pub generation: u64,
    pub source: String,
    pub payload_digest: String,
    pub expected_digest: Option<String>,
    pub observed_len: usize,
    pub expected_len: usize,
    pub length_ok: bool,
    pub digest_ok: bool,
    pub blob_rel: String,
}

impl ReceiptRow {
    pub fn health(&self, n: usize) -> &'static str {
        if self.shard_index >= n {
            "bad_index"
        } else if !self.length_ok {
            "bad_length"
        } else if !self.digest_ok {
            "bad_digest"
        } else {
            "good"
        }
    }
    pub fn blob_path(root: &Path, rel: &str) -> PathBuf {
        root.join(rel)
    }
}

#[derive(Debug, Clone)]
pub struct StripeRow {
    pub stripe_index: usize,
    pub status: String,
    pub analysis_json: String,
    pub chosen_rank: Option<i64>,
    pub committed: bool,
}

impl Store {
    pub fn upsert_object(
        &self,
        conn: &mut Connection,
        object_id: &str,
        manifest_digest: &str,
        manifest_json: &str,
        total_size: usize,
        stripe_count: usize,
        object_digest: &str,
    ) -> Result<bool> {
        let existed = conn
            .query_row(
                "SELECT 1 FROM objects WHERE object_id=?1",
                params![object_id],
                |_| Ok(()),
            )
            .is_ok();
        conn.execute(
            "INSERT INTO objects(object_id, manifest_digest, manifest_json, total_size,
                 stripe_count, object_digest, imported_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(object_id) DO UPDATE SET
                 manifest_digest=excluded.manifest_digest,
                 manifest_json=excluded.manifest_json,
                 total_size=excluded.total_size,
                 stripe_count=excluded.stripe_count,
                 object_digest=excluded.object_digest",
            params![
                object_id,
                manifest_digest,
                manifest_json,
                total_size as i64,
                stripe_count as i64,
                object_digest,
                now_ms()
            ],
        )?;
        Ok(existed)
    }

    pub fn insert_receipt(&self, conn: &mut Connection, r: &ReceiptRow) -> Result<()> {
        conn.execute(
            "INSERT OR IGNORE INTO receipts
                (object_id, stripe_index, shard_index, generation, source,
                 payload_digest, expected_digest, observed_len, expected_len,
                 length_ok, digest_ok, blob_path, received_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                r.object_id,
                r.stripe_index as i64,
                r.shard_index as i64,
                r.generation as i64,
                r.source,
                r.payload_digest,
                r.expected_digest,
                r.observed_len as i64,
                r.expected_len as i64,
                r.length_ok as i64,
                r.digest_ok as i64,
                r.blob_rel,
                now_ms(),
            ],
        )?;
        Ok(())
    }

    pub fn list_objects(&self, conn: &Connection) -> Result<Vec<ObjectRow>> {
        let mut stmt = conn.prepare(
            "SELECT object_id, manifest_digest, manifest_json, total_size, stripe_count,
                    object_digest, isolated_sources, imported_at_ms
             FROM objects ORDER BY object_id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(ObjectRow {
                object_id: r.get(0)?,
                manifest_digest: r.get(1)?,
                manifest_json: r.get(2)?,
                total_size: r.get::<_, i64>(3)? as usize,
                stripe_count: r.get::<_, i64>(4)? as usize,
                object_digest: r.get(5)?,
                isolated_sources: serde_json::from_str(&r.get::<_, String>(6)?)
                    .unwrap_or_default(),
                imported_at_ms: r.get(7)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn get_object(&self, conn: &Connection, object_id: &str) -> Result<Option<ObjectRow>> {
        Ok(self.list_objects(conn)?.into_iter().find(|o| o.object_id == object_id))
    }

    pub fn receipts_for_stripe(
        &self,
        conn: &Connection,
        object_id: &str,
        stripe_index: usize,
    ) -> Result<Vec<ReceiptRow>> {
        let mut stmt = conn.prepare(
            "SELECT id, object_id, stripe_index, shard_index, generation, source,
                    payload_digest, expected_digest, observed_len, expected_len,
                    length_ok, digest_ok, blob_path
             FROM receipts
             WHERE object_id=?1 AND stripe_index=?2
             ORDER BY shard_index, generation DESC, id",
        )?;
        let rows = stmt.query_map(
            params![object_id, stripe_index as i64],
            |r| {
                Ok(ReceiptRow {
                    id: r.get(0)?,
                    object_id: r.get(1)?,
                    stripe_index: r.get::<_, i64>(2)? as usize,
                    shard_index: r.get::<_, i64>(3)? as usize,
                    generation: r.get::<_, i64>(4)? as u64,
                    source: r.get(5)?,
                    payload_digest: r.get(6)?,
                    expected_digest: r.get(7)?,
                    observed_len: r.get::<_, i64>(8)? as usize,
                    expected_len: r.get::<_, i64>(9)? as usize,
                    length_ok: r.get::<_, i64>(10)? != 0,
                    digest_ok: r.get::<_, i64>(11)? != 0,
                    blob_rel: r.get(12)?,
                })
            },
        )?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn list_stripes(&self, conn: &Connection, object_id: &str) -> Result<Vec<StripeRow>> {
        let mut stmt = conn.prepare(
            "SELECT stripe_index, status, analysis_json, chosen_rank, committed
             FROM stripes WHERE object_id=?1 ORDER BY stripe_index",
        )?;
        let rows = stmt.query_map(params![object_id], |r| {
            Ok(StripeRow {
                stripe_index: r.get::<_, i64>(0)? as usize,
                status: r.get(1)?,
                analysis_json: r.get(2)?,
                chosen_rank: r.get(3)?,
                committed: r.get::<_, i64>(4)? != 0,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn set_isolated_sources(
        &self,
        conn: &mut Connection,
        object_id: &str,
        sources: &[String],
    ) -> Result<()> {
        let json = serde_json::to_string(sources)?;
        let affected = conn.execute(
            "UPDATE objects SET isolated_sources=?1 WHERE object_id=?2",
            params![json, object_id],
        )?;
        if affected == 0 {
            bail!("对象 {object_id} 不存在");
        }
        Ok(())
    }
}
