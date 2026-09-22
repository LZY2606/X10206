//! SQLite 持久层：导入记录、候选块、排除证据、枚举方案、stripe 提交、来源隔离。

use rusqlite::{params, Connection};
use std::sync::Mutex;

pub struct Db {
    pub conn: Mutex<Connection>,
}

pub const SCHEMA: &str = r#"
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS objects (
    object_id      TEXT PRIMARY KEY,
    manifest_json  TEXT NOT NULL,
    codec_version  INTEGER NOT NULL,
    k              INTEGER NOT NULL,
    m              INTEGER NOT NULL,
    block_len      INTEGER NOT NULL,
    stripe_count   INTEGER NOT NULL,
    object_len     INTEGER NOT NULL,
    object_digest  TEXT,
    imported_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 接收到的原始碎片：同一 (stripe, shard) 允许多个候选（不同 generation / 内容 / 来源）。
CREATE TABLE IF NOT EXISTS raw_blocks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id       TEXT NOT NULL REFERENCES objects(object_id),
    stripe          INTEGER NOT NULL,
    shard           INTEGER NOT NULL,
    generation      INTEGER NOT NULL,
    source          TEXT NOT NULL,
    origin_path     TEXT NOT NULL,
    bytes           BLOB NOT NULL,
    recalculated    TEXT NOT NULL,           -- 重新计算的 sha256
    attached_digest TEXT,                   -- 随附 .digest
    kind            TEXT NOT NULL,          -- data | parity
    UNIQUE(object_id, stripe, shard, generation, source, recalculated)
);
CREATE INDEX IF NOT EXISTS idx_raw ON raw_blocks(object_id, stripe, shard);

-- 导入/解析阶段的异常证据。
CREATE TABLE IF NOT EXISTS import_warnings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id   TEXT,
    scope       TEXT NOT NULL,             -- global | object
    kind        TEXT NOT NULL,             -- duplicate_index | length_mismatch | unknown_object | bad_filename | ...
    detail      TEXT NOT NULL,
    origin_path TEXT NOT NULL
);

-- 每个 stripe 的分析结果快照。
CREATE TABLE IF NOT EXISTS stripe_reports (
    object_id        TEXT NOT NULL,
    stripe           INTEGER NOT NULL,
    status           TEXT NOT NULL,        -- unrecoverable | recovered | already_complete
    feasible_count   INTEGER NOT NULL,
    chosen_count     INTEGER NOT NULL,
    inspected_combos INTEGER NOT NULL,
    truncated        INTEGER NOT NULL,     -- 是否触发搜索预算
    trusted          INTEGER NOT NULL,     -- 提交内容是否全部通过摘要校验
    committed        INTEGER NOT NULL,     -- 是否已提交
    committed_gen    INTEGER,
    content_diverge  INTEGER NOT NULL,     -- 可行方案重建内容是否存在差异
    updated_at       TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (object_id, stripe)
);

-- 枚举到的可行方案（全量保留，最多存储上限由恢复层决定）。
CREATE TABLE IF NOT EXISTS plans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id    TEXT NOT NULL,
    stripe       INTEGER NOT NULL,
    rank         INTEGER NOT NULL,         -- 确定性排序名次（0 起）
    generation   INTEGER NOT NULL,        -- 方案采用的 generation
    uniform_gen  INTEGER NOT NULL,
    participants TEXT NOT NULL,           -- JSON: [{shard, raw_block_id, source, generation}]
    missing      TEXT NOT NULL,           -- JSON: [shard,...]
    outputs      TEXT NOT NULL,           -- JSON: {shard: {recomputed, expected, digest_ok}}
    trust_ok     INTEGER NOT NULL,        -- 可核对摘要全部一致
    content_sig  TEXT NOT NULL,           -- 重建缺失块内容签名（识别多答案差异）
    UNIQUE(object_id, stripe, rank)
);

-- 分析某方案时被排除的损坏/冲突证据。
CREATE TABLE IF NOT EXISTS exclusions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id    TEXT NOT NULL,
    stripe       INTEGER NOT NULL,
    plan_rank    INTEGER,                 -- NULL 表示条带级预排除
    raw_block_id INTEGER,
    shard        INTEGER,
    reason       TEXT NOT NULL,            -- length_mismatch | digest_mismatch | bitflip_crosscheck | gen_mix ...
    detail       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_excl ON exclusions(object_id, stripe);

-- 已提交 stripe 的重建块（仅在摘要完整且全部通过时写入）。
CREATE TABLE IF NOT EXISTS committed_blocks (
    object_id  TEXT NOT NULL,
    stripe     INTEGER NOT NULL,
    shard      INTEGER NOT NULL,
    generation INTEGER NOT NULL,
    bytes      BLOB NOT NULL,
    recomputed TEXT NOT NULL,
    PRIMARY KEY (object_id, stripe, shard)
);

CREATE TABLE IF NOT EXISTS commits (
    object_id      TEXT NOT NULL,
    stripe         INTEGER NOT NULL,
    generation     INTEGER NOT NULL,
    content_sig    TEXT NOT NULL,
    PRIMARY KEY (object_id, stripe)
);

-- 人工隔离的接收来源：重算时该来源块不可参与。
CREATE TABLE IF NOT EXISTS isolated_sources (
    object_id TEXT NOT NULL,
    source    TEXT NOT NULL,
    PRIMARY KEY (object_id, source)
);
"#;

impl Db {
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Db {
            conn: Mutex::new(conn),
        })
    }

    pub fn open_in_memory() -> rusqlite::Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Db {
            conn: Mutex::new(conn),
        })
    }

    pub fn upsert_object(&self, manifest_json: &str, m: &crate::model::ObjectManifest) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO objects(object_id, manifest_json, codec_version, k, m, block_len,
                                 stripe_count, object_len, object_digest)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)
             ON CONFLICT(object_id) DO UPDATE SET
                manifest_json=excluded.manifest_json,
                codec_version=excluded.codec_version,
                k=excluded.k, m=excluded.m, block_len=excluded.block_len,
                stripe_count=excluded.stripe_count, object_len=excluded.object_len,
                object_digest=excluded.object_digest",
            params![
                m.object_id,
                manifest_json,
                m.codec_version,
                m.k as i64,
                m.m as i64,
                m.block_len as i64,
                m.stripe_count as i64,
                m.object_len as i64,
                m.object_digest,
            ],
        )?;
        Ok(())
    }

    pub fn insert_warning(
        &self,
        object_id: Option<&str>,
        scope: &str,
        kind: &str,
        detail: &str,
        origin: &str,
    ) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO import_warnings(object_id, scope, kind, detail, origin_path)
             VALUES (?1,?2,?3,?4,?5)",
            params![object_id, scope, kind, detail, origin],
        )?;
        Ok(())
    }

    pub fn insert_raw_block(
        &self,
        b: &crate::model::ReceivedBlock,
        kind: &str,
        recalculated: &str,
    ) -> rusqlite::Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO raw_blocks
                (object_id, stripe, shard, generation, source, origin_path, bytes,
                 recalculated, attached_digest, kind)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                b.object_id,
                b.stripe as i64,
                b.shard as i64,
                b.generation as i64,
                b.source,
                b.origin_path,
                b.bytes,
                recalculated,
                b.attached_digest,
                kind,
            ],
        )?;
        let id = conn.last_insert_rowid();
        Ok(id)
    }

    pub fn list_objects(&self) -> rusqlite::Result<Vec<ObjectRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT object_id, codec_version, k, m, block_len, stripe_count, object_len, object_digest
             FROM objects ORDER BY object_id",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(ObjectRow {
                    object_id: r.get(0)?,
                    codec_version: r.get(1)?,
                    k: r.get::<_, i64>(2)? as usize,
                    m: r.get::<_, i64>(3)? as usize,
                    block_len: r.get::<_, i64>(4)? as usize,
                    stripe_count: r.get::<_, i64>(5)? as usize,
                    object_len: r.get::<_, i64>(6)? as usize,
                    object_digest: r.get(7)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn get_manifest_json(&self, object_id: &str) -> rusqlite::Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT manifest_json FROM objects WHERE object_id=?1",
            [object_id],
            |r| r.get(0),
        )
        .optional()
    }

    pub fn isolated_sources(&self, object_id: &str) -> rusqlite::Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT source FROM isolated_sources WHERE object_id=?1 ORDER BY source")?;
        let v = stmt
            .query_map([object_id], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(v)
    }

    pub fn set_source_isolated(&self, object_id: &str, source: &str, isolate: bool) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        if isolate {
            conn.execute(
                "INSERT OR IGNORE INTO isolated_sources(object_id, source) VALUES (?1,?2)",
                params![object_id, source],
            )?;
        } else {
            conn.execute(
                "DELETE FROM isolated_sources WHERE object_id=?1 AND source=?2",
                params![object_id, source],
            )?;
        }
        Ok(())
    }

    pub fn list_sources(&self, object_id: &str) -> rusqlite::Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT DISTINCT source FROM raw_blocks WHERE object_id=?1 ORDER BY source",
        )?;
        let v = stmt
            .query_map([object_id], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(v)
    }
}

#[derive(Debug, Clone)]
pub struct ObjectRow {
    pub object_id: String,
    pub codec_version: u32,
    pub k: usize,
    pub m: usize,
    pub block_len: usize,
    pub stripe_count: usize,
    pub object_len: usize,
    pub object_digest: Option<String>,
}

/// rusqlite 0.32 自带 optional 扩展。
use rusqlite::OptionalExtension;
