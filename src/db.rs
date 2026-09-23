//! SQLite 持久层：对象、碎片候选、条带、重建结果、恢复任务、来源隔离。

use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

#[derive(Debug, Clone, serde::Serialize)]
pub struct ObjectRow {
    pub object_id: String,
    pub object_len: u64,
    pub object_digest: Option<String>,
    pub coding_version: u32,
    pub data_shards: u32,
    pub parity_shards: u32,
    pub stripe_size: u32,
    pub stripe_count: u32,
    pub imported_at: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FragmentRow {
    pub id: i64,
    pub object_id: String,
    pub stripe_index: u32,
    pub shard_index: u32,
    pub generation: u64,
    pub source: String,
    pub file_path: String,
    pub declared_len: Option<u64>,
    pub declared_digest: Option<String>,
    pub artifact_digest: String,
    pub len: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StripeRow {
    pub object_id: String,
    pub stripe_index: u32,
    /// pending | healthy | committed | ambiguous | unrecoverable | failed
    pub status: String,
    pub message: Option<String>,
    pub processed_at: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ReconstructionRow {
    pub id: i64,
    pub job_id: i64,
    pub object_id: String,
    pub stripe_index: u32,
    pub participant_ids: String,
    pub excluded_evidence: String,
    pub block_digests: String,
    pub result_digest: String,
    pub object_digest_match: Option<bool>,
    pub chosen: bool,
    pub ambiguous: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct JobRow {
    pub id: i64,
    pub status: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub total_stripes: u32,
    pub done_stripes: u32,
    pub message: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct JobStripeRow {
    pub job_id: i64,
    pub stripe_index: u32,
    pub status: String,
    pub message: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SourceRow {
    pub id: i64,
    pub object_id: String,
    pub name: String,
    pub isolated: bool,
}

#[derive(Clone)]
pub struct Database {
    pub conn: std::sync::Mutex<Connection>,
}

pub fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}

const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS objects (
    object_id        TEXT PRIMARY KEY,
    object_len       INTEGER NOT NULL,
    object_digest    TEXT,
    coding_version   INTEGER NOT NULL,
    data_shards      INTEGER NOT NULL,
    parity_shards    INTEGER NOT NULL,
    stripe_size      INTEGER NOT NULL,
    stripe_count     INTEGER NOT NULL,
    imported_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sources (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id  TEXT NOT NULL REFERENCES objects(object_id),
    name       TEXT NOT NULL,
    isolated   INTEGER NOT NULL DEFAULT 0,
    UNIQUE(object_id, name)
);

CREATE TABLE IF NOT EXISTS fragments (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id        TEXT NOT NULL REFERENCES objects(object_id),
    stripe_index     INTEGER NOT NULL,
    shard_index      INTEGER NOT NULL,
    generation       INTEGER NOT NULL,
    source           TEXT NOT NULL,
    file_path        TEXT NOT NULL,
    declared_len     INTEGER,
    declared_digest  TEXT,
    artifact_digest  TEXT NOT NULL,
    len              INTEGER NOT NULL,
    imported_at      TEXT NOT NULL,
    UNIQUE(object_id, stripe_index, shard_index, generation, source, artifact_digest, declared_digest)
);
CREATE INDEX IF NOT EXISTS idx_frag_lookup
    ON fragments(object_id, stripe_index, shard_index);

CREATE TABLE IF NOT EXISTS stripes (
    object_id     TEXT NOT NULL REFERENCES objects(object_id),
    stripe_index  INTEGER NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending',
    message       TEXT,
    processed_at  TEXT,
    PRIMARY KEY(object_id, stripe_index)
);

CREATE TABLE IF NOT EXISTS reconstructions (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id                INTEGER NOT NULL,
    object_id             TEXT NOT NULL REFERENCES objects(object_id),
    stripe_index          INTEGER NOT NULL,
    participant_ids       TEXT NOT NULL,
    excluded_evidence     TEXT NOT NULL,
    block_digests         TEXT NOT NULL,
    result_digest         TEXT NOT NULL,
    object_digest_match  INTEGER,
    chosen                INTEGER NOT NULL DEFAULT 0,
    ambiguous             INTEGER NOT NULL DEFAULT 0,
    created_at            TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rec_stripe
    ON reconstructions(object_id, stripe_index);

CREATE TABLE IF NOT EXISTS jobs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    status         TEXT NOT NULL,
    started_at     TEXT NOT NULL,
    finished_at    TEXT,
    total_stripes  INTEGER NOT NULL,
    done_stripes   INTEGER NOT NULL DEFAULT 0,
    message        TEXT
);

CREATE TABLE IF NOT EXISTS job_stripes (
    job_id        INTEGER NOT NULL REFERENCES jobs(id),
    stripe_index  INTEGER NOT NULL,
    status        TEXT NOT NULL,
    message       TEXT,
    PRIMARY KEY(job_id, stripe_index)
);

CREATE TABLE IF NOT EXISTS exports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id       TEXT NOT NULL,
    dir             TEXT NOT NULL,
    status          TEXT NOT NULL,
    block_count     INTEGER NOT NULL DEFAULT 0,
    object_digest   TEXT,
    digest_matches  INTEGER,
    message         TEXT,
    created_at      TEXT NOT NULL
);
"#;

fn row_to_fragment(r: &rusqlite::Row) -> rusqlite::Result<FragmentRow> {
    Ok(FragmentRow {
        id: r.get(0)?,
        object_id: r.get(1)?,
        stripe_index: r.get::<_, i64>(2)? as u32,
        shard_index: r.get::<_, i64>(3)? as u32,
        generation: r.get::<_, i64>(4)? as u64,
        source: r.get(5)?,
        file_path: r.get(6)?,
        declared_len: r.get::<_, Option<i64>>(7)?.map(|v| v as u64),
        declared_digest: r.get(8)?,
        artifact_digest: r.get(9)?,
        len: r.get::<_, i64>(10)? as u64,
    })
}

impl Database {
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Database {
            conn: std::sync::Mutex::new(conn),
        })
    }

    /// 内存库（测试用）。
    pub fn open_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Database {
            conn: std::sync::Mutex::new(conn),
        })
    }

    pub fn upsert_object(&self, o: &ObjectRow) -> anyhow::Result<()> {
        let db = self.conn.lock().unwrap();
        db.execute(
            "INSERT INTO objects(object_id, object_len, object_digest, coding_version,
                data_shards, parity_shards, stripe_size, stripe_count, imported_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)
             ON CONFLICT(object_id) DO UPDATE SET
                object_len=excluded.object_len,
                object_digest=COALESCE(excluded.object_digest, objects.object_digest),
                coding_version=excluded.coding_version,
                data_shards=excluded.data_shards,
                parity_shards=excluded.parity_shards,
                stripe_size=excluded.stripe_size,
                stripe_count=excluded.stripe_count,
                imported_at=excluded.imported_at",
            params![
                o.object_id,
                o.object_len,
                o.object_digest,
                o.coding_version,
                o.data_shards,
                o.parity_shards,
                o.stripe_size,
                o.stripe_count,
                o.imported_at
            ],
        )?;
        Ok(())
    }

    pub fn list_objects(&self) -> anyhow::Result<Vec<ObjectRow>> {
        let db = self.conn.lock().unwrap();
        let mut stmt = db.prepare(
            "SELECT object_id, object_len, object_digest, coding_version, data_shards,
                    parity_shards, stripe_size, stripe_count, imported_at
             FROM objects ORDER BY object_id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(ObjectRow {
                object_id: r.get(0)?,
                object_len: r.get::<_, i64>(1)? as u64,
                object_digest: r.get(2)?,
                coding_version: r.get::<_, i64>(3)? as u32,
                data_shards: r.get::<_, i64>(4)? as u32,
                parity_shards: r.get::<_, i64>(5)? as u32,
                stripe_size: r.get::<_, i64>(6)? as u32,
                stripe_count: r.get::<_, i64>(7)? as u32,
                imported_at: r.get(8)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn get_object(&self, object_id: &str) -> anyhow::Result<Option<ObjectRow>> {
        let db = self.conn.lock().unwrap();
        db.query_row(
            "SELECT object_id, object_len, object_digest, coding_version, data_shards,
                    parity_shards, stripe_size, stripe_count, imported_at
             FROM objects WHERE object_id = ?1",
            params![object_id],
            |r| {
                Ok(ObjectRow {
                    object_id: r.get(0)?,
                    object_len: r.get::<_, i64>(1)? as u64,
                    object_digest: r.get(2)?,
                    coding_version: r.get::<_, i64>(3)? as u32,
                    data_shards: r.get::<_, i64>(4)? as u32,
                    parity_shards: r.get::<_, i64>(5)? as u32,
                    stripe_size: r.get::<_, i64>(6)? as u32,
                    stripe_count: r.get::<_, i64>(7)? as u32,
                    imported_at: r.get(8)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn insert_source_if_absent(&self, object_id: &str, name: &str) -> anyhow::Result<()> {
        let db = self.conn.lock().unwrap();
        db.execute(
            "INSERT OR IGNORE INTO sources(object_id, name) VALUES (?1, ?2)",
            params![object_id, name],
        )?;
        Ok(())
    }

    pub fn list_sources(&self, object_id: &str) -> anyhow::Result<Vec<SourceRow>> {
        let db = self.conn.lock().unwrap();
        let mut stmt = db.prepare(
            "SELECT id, object_id, name, isolated FROM sources
             WHERE object_id = ?1 ORDER BY name",
        )?;
        let rows = stmt.query_map(params![object_id], |r| {
            Ok(SourceRow {
                id: r.get(0)?,
                object_id: r.get(1)?,
                name: r.get(2)?,
                isolated: r.get::<_, i64>(3)? != 0,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn isolated_sources(
        &self,
        object_id: &str,
    ) -> anyhow::Result<std::collections::HashSet<String>> {
        Ok(self
            .list_sources(object_id)?
            .into_iter()
            .filter(|s| s.isolated)
            .map(|s| s.name)
            .collect())
    }

    pub fn set_source_isolated(
        &self,
        object_id: &str,
        name: &str,
        isolated: bool,
    ) -> anyhow::Result<bool> {
        let db = self.conn.lock().unwrap();
        let n = db.execute(
            "UPDATE sources SET isolated = ?1 WHERE object_id = ?2 AND name = ?3",
            params![isolated as i64, object_id, name],
        )?;
        Ok(n > 0)
    }

    pub fn insert_fragment(&self, f: &FragmentRow) -> anyhow::Result<i64> {
        let db = self.conn.lock().unwrap();
        db.execute(
            "INSERT OR IGNORE INTO fragments(object_id, stripe_index, shard_index, generation,
                source, file_path, declared_len, declared_digest, artifact_digest, len, imported_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                f.object_id,
                f.stripe_index,
                f.shard_index,
                f.generation as i64,
                f.source,
                f.file_path,
                f.declared_len.map(|v| v as i64),
                f.declared_digest,
                f.artifact_digest,
                f.len as i64,
                now()
            ],
        )?;
        Ok(db.last_insert_rowid())
    }

    pub fn list_fragments(&self, object_id: &str) -> anyhow::Result<Vec<FragmentRow>> {
        let db = self.conn.lock().unwrap();
        let mut stmt = db.prepare(
            "SELECT id, object_id, stripe_index, shard_index, generation, source, file_path,
                    declared_len, declared_digest, artifact_digest, len
             FROM fragments WHERE object_id = ?1
             ORDER BY stripe_index, shard_index, generation DESC, id",
        )?;
        let rows = stmt.query_map(params![object_id], row_to_fragment)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn ensure_stripe(&self, object_id: &str, stripe_index: u32) -> anyhow::Result<()> {
        let db = self.conn.lock().unwrap();
        db.execute(
            "INSERT OR IGNORE INTO stripes(object_id, stripe_index) VALUES (?1, ?2)",
            params![object_id, stripe_index],
        )?;
        Ok(())
    }

    pub fn list_stripes(&self, object_id: &str) -> anyhow::Result<Vec<StripeRow>> {
        let db = self.conn.lock().unwrap();
        let mut stmt = db.prepare(
            "SELECT object_id, stripe_index, status, message, processed_at
             FROM stripes WHERE object_id = ?1 ORDER BY stripe_index",
        )?;
        let rows = stmt.query_map(params![object_id], |r| {
            Ok(StripeRow {
                object_id: r.get(0)?,
                stripe_index: r.get::<_, i64>(1)? as u32,
                status: r.get(2)?,
                message: r.get(3)?,
                processed_at: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn get_stripe(
        &self,
        object_id: &str,
        stripe_index: u32,
    ) -> anyhow::Result<Option<StripeRow>> {
        Ok(self
            .list_stripes(object_id)?
            .into_iter()
            .find(|s| s.stripe_index == stripe_index))
    }

    /// 重算：清空条带旧重建结果并回到 pending（committed 文件由恢复层清理）。
    pub fn reset_stripe(&self, object_id: &str, stripe_index: u32) -> anyhow::Result<()> {
        let mut db = self.conn.lock().unwrap();
        let tx = db.transaction()?;
        tx.execute(
            "DELETE FROM reconstructions WHERE object_id = ?1 AND stripe_index = ?2",
            params![object_id, stripe_index],
        )?;
        tx.execute(
            "UPDATE stripes SET status='pending', message=NULL, processed_at=NULL
             WHERE object_id=?1 AND stripe_index=?2",
            params![object_id, stripe_index],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn set_stripe_status(
        &self,
        object_id: &str,
        stripe_index: u32,
        status: &str,
        message: Option<&str>,
    ) -> anyhow::Result<()> {
        let db = self.conn.lock().unwrap();
        db.execute(
            "UPDATE stripes SET status=?1, message=?2, processed_at=?3
             WHERE object_id=?4 AND stripe_index=?5",
            params![status, message, now(), object_id, stripe_index],
        )?;
        Ok(())
    }

    pub fn insert_reconstruction(&self, r: &ReconstructionRow) -> anyhow::Result<i64> {
        let db = self.conn.lock().unwrap();
        db.execute(
            "INSERT INTO reconstructions(job_id, object_id, stripe_index, participant_ids,
                excluded_evidence, block_digests, result_digest, object_digest_match,
                chosen, ambiguous, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                r.job_id,
                r.object_id,
                r.stripe_index,
                r.participant_ids,
                r.excluded_evidence,
                r.block_digests,
                r.result_digest,
                r.object_digest_match,
                r.chosen as i64,
                r.ambiguous as i64,
                now()
            ],
        )?;
        Ok(db.last_insert_rowid())
    }

    pub fn list_reconstructions(
        &self,
        object_id: &str,
        stripe_index: u32,
    ) -> anyhow::Result<Vec<ReconstructionRow>> {
        let db = self.conn.lock().unwrap();
        let mut stmt = db.prepare(
            "SELECT id, job_id, object_id, stripe_index, participant_ids, excluded_evidence,
                    block_digests, result_digest, object_digest_match, chosen, ambiguous, created_at
             FROM reconstructions WHERE object_id=?1 AND stripe_index=?2 ORDER BY id",
        )?;
        let rows = stmt.query_map(params![object_id, stripe_index], |r| {
            Ok(ReconstructionRow {
                id: r.get(0)?,
                job_id: r.get(1)?,
                object_id: r.get(2)?,
                stripe_index: r.get::<_, i64>(3)? as u32,
                participant_ids: r.get(4)?,
                excluded_evidence: r.get(5)?,
                block_digests: r.get(6)?,
                result_digest: r.get(7)?,
                object_digest_match: r.get::<_, Option<i64>>(8)?.map(|v| v != 0),
                chosen: r.get::<_, i64>(9)? != 0,
                ambiguous: r.get::<_, i64>(10)? != 0,
                created_at: r.get(11)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn set_reconstruction_object_match(
        &self,
        id: i64,
        matches: bool,
    ) -> anyhow::Result<()> {
        let db = self.conn.lock().unwrap();
        db.execute(
            "UPDATE reconstructions SET object_digest_match=?1 WHERE id=?2",
            params![matches as i64, id],
        )?;
        Ok(())
    }

    pub fn mark_chosen_reconstruction(&self, id: i64) -> anyhow::Result<()> {
        let db = self.conn.lock().unwrap();
        db.execute(
            "UPDATE reconstructions SET chosen=1, ambiguous=0 WHERE id=?1",
            params![id],
        )?;
        Ok(())
    }

    pub fn create_job(&self, total_stripes: u32) -> anyhow::Result<i64> {
        let db = self.conn.lock().unwrap();
        db.execute(
            "INSERT INTO jobs(status, started_at, total_stripes) VALUES ('running', ?1, ?2)",
            params![now(), total_stripes],
        )?;
        Ok(db.last_insert_rowid())
    }

    pub fn upsert_job_stripe(
        &self,
        job_id: i64,
        stripe_index: u32,
        status: &str,
        message: Option<&str>,
    ) -> anyhow::Result<()> {
        let db = self.conn.lock().unwrap();
        db.execute(
            "INSERT INTO job_stripes(job_id, stripe_index, status, message)
             VALUES (?1,?2,?3,?4)
             ON CONFLICT(job_id, stripe_index) DO UPDATE SET
                status=excluded.status, message=excluded.message",
            params![job_id, stripe_index, status, message],
        )?;
        Ok(())
    }

    pub fn job_progress(&self, job_id: i64, done: u32) -> anyhow::Result<()> {
        let db = self.conn.lock().unwrap();
        db.execute(
            "UPDATE jobs SET done_stripes=?1 WHERE id=?2",
            params![done, job_id],
        )?;
        Ok(())
    }

    pub fn finish_job(&self, job_id: i64, status: &str, message: Option<&str>) -> anyhow::Result<()> {
        let db = self.conn.lock().unwrap();
        db.execute(
            "UPDATE jobs SET status=?1, finished_at=?2, message=?3 WHERE id=?4",
            params![status, now(), message, job_id],
        )?;
        Ok(())
    }

    pub fn get_job(&self, job_id: i64) -> anyhow::Result<Option<JobRow>> {
        let db = self.conn.lock().unwrap();
        db.query_row(
            "SELECT id, status, started_at, finished_at, total_stripes, done_stripes, message
             FROM jobs WHERE id=?1",
            params![job_id],
            |r| {
                Ok(JobRow {
                    id: r.get(0)?,
                    status: r.get(1)?,
                    started_at: r.get(2)?,
                    finished_at: r.get(3)?,
                    total_stripes: r.get::<_, i64>(4)? as u32,
                    done_stripes: r.get::<_, i64>(5)? as u32,
                    message: r.get(6)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn latest_job(&self) -> anyhow::Result<Option<JobRow>> {
        let db = self.conn.lock().unwrap();
        db.query_row(
            "SELECT id, status, started_at, finished_at, total_stripes, done_stripes, message
             FROM jobs ORDER BY id DESC LIMIT 1",
            [],
            |r| {
                Ok(JobRow {
                    id: r.get(0)?,
                    status: r.get(1)?,
                    started_at: r.get(2)?,
                    finished_at: r.get(3)?,
                    total_stripes: r.get::<_, i64>(4)? as u32,
                    done_stripes: r.get::<_, i64>(5)? as u32,
                    message: r.get(6)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn list_job_stripes(&self, job_id: i64) -> anyhow::Result<Vec<JobStripeRow>> {
        let db = self.conn.lock().unwrap();
        let mut stmt = db.prepare(
            "SELECT job_id, stripe_index, status, message FROM job_stripes
             WHERE job_id=?1 ORDER BY stripe_index",
        )?;
        let rows = stmt.query_map(params![job_id], |r| {
            Ok(JobStripeRow {
                job_id: r.get(0)?,
                stripe_index: r.get::<_, i64>(1)? as u32,
                status: r.get(2)?,
                message: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// 中断恢复：把上次中断遗留的 running 任务标记为 interrupted。
    pub fn mark_interrupted_jobs(&self) -> anyhow::Result<u32> {
        let db = self.conn.lock().unwrap();
        let n = db.execute(
            "UPDATE jobs SET status='interrupted', finished_at=?1,
                message='进程中断，已提交 stripe 可在下次任务复用'
             WHERE status='running'",
            params![now()],
        )?;
        Ok(n as u32)
    }

    pub fn record_export(
        &self,
        object_id: &str,
        dir: &str,
        status: &str,
        block_count: u32,
        object_digest: Option<&str>,
        digest_matches: Option<bool>,
        message: Option<&str>,
    ) -> anyhow::Result<i64> {
        let db = self.conn.lock().unwrap();
        db.execute(
            "INSERT INTO exports(object_id, dir, status, block_count, object_digest,
                digest_matches, message, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                object_id,
                dir,
                status,
                block_count,
                object_digest,
                digest_matches,
                message,
                now()
            ],
        )?;
        Ok(db.last_insert_rowid())
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ExportRow {
    pub id: i64,
    pub object_id: String,
    pub dir: String,
    pub status: String,
    pub block_count: u32,
    pub object_digest: Option<String>,
    pub digest_matches: Option<bool>,
    pub message: Option<String>,
    pub created_at: String,
}

impl Database {
    pub fn get_fragment(&self, id: i64) -> anyhow::Result<Option<FragmentRow>> {
        let db = self.conn.lock().unwrap();
        db.query_row(
            "SELECT id, object_id, stripe_index, shard_index, generation, source, file_path,
                    declared_len, declared_digest, artifact_digest, len
             FROM fragments WHERE id = ?1",
            params![id],
            row_to_fragment,
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn chosen_reconstruction(
        &self,
        object_id: &str,
        stripe_index: u32,
    ) -> anyhow::Result<Option<ReconstructionRow>> {
        Ok(self
            .list_reconstructions(object_id, stripe_index)?
            .into_iter()
            .find(|r| r.chosen))
    }

    pub fn finish_export(
        &self,
        id: i64,
        status: &str,
        block_count: u32,
        object_digest: Option<&str>,
        digest_matches: Option<bool>,
        message: Option<&str>,
    ) -> anyhow::Result<()> {
        let db = self.conn.lock().unwrap();
        db.execute(
            "UPDATE exports SET status=?1, block_count=?2, object_digest=?3,
                digest_matches=?4, message=?5 WHERE id=?6",
            params![
                status,
                block_count,
                object_digest,
                digest_matches,
                message,
                id
            ],
        )?;
        Ok(())
    }

    pub fn list_exports(&self, object_id: &str) -> anyhow::Result<Vec<ExportRow>> {
        let db = self.conn.lock().unwrap();
        let mut stmt = db.prepare(
            "SELECT id, object_id, dir, status, block_count, object_digest, digest_matches,
                    message, created_at
             FROM exports WHERE object_id=?1 ORDER BY id DESC",
        )?;
        let rows = stmt.query_map(params![object_id], |r| {
            Ok(ExportRow {
                id: r.get(0)?,
                object_id: r.get(1)?,
                dir: r.get(2)?,
                status: r.get(3)?,
                block_count: r.get::<_, i64>(4)? as u32,
                object_digest: r.get(5)?,
                digest_matches: r.get::<_, Option<i64>>(6)?.map(|v| v != 0),
                message: r.get(7)?,
                created_at: r.get(8)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn latest_job(&self) -> anyhow::Result<Option<JobRow>> {
        let db = self.conn.lock().unwrap();
        db.query_row(
            "SELECT id, status, started_at, finished_at, total_stripes, done_stripes, message
             FROM jobs ORDER BY id DESC LIMIT 1",
            [],
            |r| {
                Ok(JobRow {
                    id: r.get(0)?,
                    status: r.get(1)?,
                    started_at: r.get(2)?,
                    finished_at: r.get(3)?,
                    total_stripes: r.get::<_, i64>(4)? as u32,
                    done_stripes: r.get::<_, i64>(5)? as u32,
                    message: r.get(6)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
    }
}
