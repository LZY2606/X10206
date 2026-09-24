//! SQLite 持久层：导入记录、来源隔离、stripe 提交与导出清单。

use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use std::sync::Mutex;

pub struct Db {
    pub conn: Mutex<Connection>,
}

#[derive(Debug, Clone)]
pub struct ManifestRow {
    pub id: i64,
    pub object_id: String,
    pub current_generation: i64,
    pub manifest_path: String,
    pub received_from: String,
}

#[derive(Debug, Clone)]
pub struct FragmentRow {
    pub id: i64,
    pub object_id: String,
    pub stripe: i64,
    pub shard_index: i64,
    pub generation: i64,
    pub content_digest: String,
    pub claimed_digest: Option<String>,
    pub actual_len: i64,
    pub blob_path: String,
}

impl Db {
    pub fn open(path: &str) -> Result<Db> {
        let conn = Connection::open(path).context("open sqlite")?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Db {
            conn: Mutex::new(conn),
        })
    }

    pub fn next_id(&self, name: &str) -> Result<i64> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let next: i64 = tx
            .query_row(
                "SELECT next_value FROM seq_counters WHERE counter_name = ?1",
                params![name],
                |r| r.get(0),
            )
            .unwrap_or(1);
        tx.execute(
            "INSERT INTO seq_counters(counter_name, next_value) VALUES (?1, ?2)
             ON CONFLICT(counter_name) DO UPDATE SET next_value = ?2",
            params![name, next + 1],
        )?;
        tx.commit()?;
        Ok(next)
    }

    pub fn insert_manifest(
        &self,
        object_id: &str,
        current_generation: i64,
        manifest_path: &str,
        received_from: &str,
    ) -> Result<i64> {
        let id = self.next_id("manifest")?;
        self.conn.lock().unwrap().execute(
            "INSERT INTO manifests(id, object_id, current_generation, manifest_path, received_from)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, object_id, current_generation, manifest_path, received_from],
        )?;
        Ok(id)
    }

    pub fn manifest_for_object(&self, object_id: &str) -> Result<Option<ManifestRow>> {
        let mut stmt = self.conn.lock().unwrap().prepare(
            "SELECT id, object_id, current_generation, manifest_path, received_from
             FROM manifests WHERE object_id = ?1 ORDER BY id",
        )?;
        let mut rows = stmt.query(params![object_id])?;
        match rows.next()? {
            None => Ok(None),
            Some(r) => Ok(Some(ManifestRow {
                id: r.get(0)?,
                object_id: r.get(1)?,
                current_generation: r.get(2)?,
                manifest_path: r.get(3)?,
                received_from: r.get(4)?,
            })),
        }
    }

    pub fn list_manifests(&self) -> Result<Vec<ManifestRow>> {
        let mut stmt = self.conn.lock().unwrap().prepare(
            "SELECT id, object_id, current_generation, manifest_path, received_from
             FROM manifests ORDER BY id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(ManifestRow {
                id: r.get(0)?,
                object_id: r.get(1)?,
                current_generation: r.get(2)?,
                manifest_path: r.get(3)?,
                received_from: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS seq_counters (
    counter_name TEXT PRIMARY KEY,
    next_value INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS manifests (
    id INTEGER PRIMARY KEY,
    object_id TEXT NOT NULL,
    current_generation INTEGER NOT NULL,
    manifest_path TEXT NOT NULL,
    received_from TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS fragments (
    id INTEGER PRIMARY KEY,
    object_id TEXT NOT NULL,
    stripe INTEGER NOT NULL,
    shard_index INTEGER NOT NULL,
    generation INTEGER NOT NULL,
    content_digest TEXT NOT NULL,
    claimed_digest TEXT,
    actual_len INTEGER NOT NULL,
    blob_path TEXT NOT NULL,
    UNIQUE(object_id, stripe, shard_index, generation, content_digest)
);
CREATE TABLE IF NOT EXISTS fragment_receipts (
    fragment_id INTEGER NOT NULL REFERENCES fragments(id) ON DELETE CASCADE,
    received_from TEXT NOT NULL,
    PRIMARY KEY (fragment_id, received_from)
);
CREATE TABLE IF NOT EXISTS isolated_sources (
    source TEXT PRIMARY KEY,
    isolated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS stripe_commits (
    id INTEGER PRIMARY KEY,
    object_id TEXT NOT NULL,
    stripe INTEGER NOT NULL,
    generation INTEGER NOT NULL,
    object_digest TEXT NOT NULL,
    combo_index INTEGER NOT NULL,
    output_digest TEXT NOT NULL,
    commit_path TEXT NOT NULL,
    isolated_snapshot TEXT NOT NULL,
    UNIQUE(object_id, stripe)
);
CREATE TABLE IF NOT EXISTS exports (
    id INTEGER PRIMARY KEY,
    object_id TEXT NOT NULL,
    export_path TEXT NOT NULL,
    object_digest TEXT NOT NULL,
    exported_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS recovery_runs (
    id INTEGER PRIMARY KEY,
    object_id TEXT NOT NULL,
    status TEXT NOT NULL,
    stripes_total INTEGER NOT NULL,
    stripes_committed INTEGER NOT NULL,
    started_at TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at TEXT
);
"#;

impl Db {
    /// 写入碎片及其接收来源；内容重复时只补充来源，返回碎片 id。
    pub fn upsert_fragment(
        &self,
        object_id: &str,
        stripe: i64,
        shard_index: i64,
        generation: i64,
        content_digest: &str,
        claimed_digest: Option<&str>,
        actual_len: i64,
        blob_path: &str,
        received_from: &str,
    ) -> Result<i64> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let existing: Option<i64> = tx
            .query_row(
                "SELECT id FROM fragments
                 WHERE object_id=?1 AND stripe=?2 AND shard_index=?3
                   AND generation=?4 AND content_digest=?5",
                params![object_id, stripe, shard_index, generation, content_digest],
                |r| r.get(0),
            )
            .ok();
        let id = match existing {
            Some(id) => id,
            None => {
                let id = Self::next_id_locked(&tx, "fragment")?;
                tx.execute(
                    "INSERT INTO fragments(id, object_id, stripe, shard_index, generation,
                        content_digest, claimed_digest, actual_len, blob_path)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    params![
                        id, object_id, stripe, shard_index, generation,
                        content_digest, claimed_digest, actual_len, blob_path
                    ],
                )?;
                id
            }
        };
        tx.execute(
            "INSERT OR IGNORE INTO fragment_receipts(fragment_id, received_from)
             VALUES (?1, ?2)",
            params![id, received_from],
        )?;
        tx.commit()?;
        Ok(id)
    }

    fn next_id_locked(
        tx: &rusqlite::Transaction<'_>,
        name: &str,
    ) -> Result<i64> {
        let next: i64 = tx
            .query_row(
                "SELECT next_value FROM seq_counters WHERE counter_name = ?1",
                params![name],
                |r| r.get(0),
            )
            .unwrap_or(1);
        tx.execute(
            "INSERT INTO seq_counters(counter_name, next_value) VALUES (?1, ?2)
             ON CONFLICT(counter_name) DO UPDATE SET next_value = ?2",
            params![name, next + 1],
        )?;
        Ok(next)
    }

    pub fn fragments_for_object(
        &self,
        object_id: &str,
    ) -> Result<Vec<(FragmentRow, Vec<String>)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, object_id, stripe, shard_index, generation,
                    content_digest, claimed_digest, actual_len, blob_path
             FROM fragments WHERE object_id = ?1
             ORDER BY stripe, shard_index, generation, id",
        )?;
        let fragments: Vec<FragmentRow> = stmt
            .query_map(params![object_id], |r| {
                Ok(FragmentRow {
                    id: r.get(0)?,
                    object_id: r.get(1)?,
                    stripe: r.get(2)?,
                    shard_index: r.get(3)?,
                    generation: r.get(4)?,
                    content_digest: r.get(5)?,
                    claimed_digest: r.get(6)?,
                    actual_len: r.get(7)?,
                    blob_path: r.get(8)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(stmt);
        let mut out = Vec::new();
        for f in fragments {
            let mut src_stmt = conn.prepare(
                "SELECT received_from FROM fragment_receipts
                 WHERE fragment_id = ?1 ORDER BY received_from",
            )?;
            let sources: Vec<String> = src_stmt
                .query_map(params![f.id], |r| r.get(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            out.push((f, sources));
        }
        Ok(out)
    }

    pub fn set_isolated(&self, source: &str, isolated: bool) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        if isolated {
            conn.execute(
                "INSERT OR IGNORE INTO isolated_sources(source) VALUES (?1)",
                params![source],
            )?;
        } else {
            conn.execute(
                "DELETE FROM isolated_sources WHERE source = ?1",
                params![source],
            )?;
        }
        Ok(())
    }

    pub fn isolated_sources(&self) -> Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT source FROM isolated_sources ORDER BY source")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn upsert_commit(
        &self,
        object_id: &str,
        stripe: i64,
        generation: i64,
        object_digest: &str,
        combo_index: i64,
        output_digest: &str,
        commit_path: &str,
        isolated_snapshot: &str,
    ) -> Result<i64> {
        let id = self.next_id("stripe_commit")?;
        self.conn.lock().unwrap().execute(
            "INSERT INTO stripe_commits(id, object_id, stripe, generation, object_digest,
                combo_index, output_digest, commit_path, isolated_snapshot)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(object_id, stripe) DO UPDATE SET
                generation=excluded.generation,
                object_digest=excluded.object_digest,
                combo_index=excluded.combo_index,
                output_digest=excluded.output_digest,
                commit_path=excluded.commit_path,
                isolated_snapshot=excluded.isolated_snapshot",
            params![
                id, object_id, stripe, generation, object_digest,
                combo_index, output_digest, commit_path, isolated_snapshot
            ],
        )?;
        Ok(id)
    }

    #[derive(Debug, Clone)]
    pub struct CommitRow {
        pub id: i64,
        pub stripe: i64,
        pub generation: i64,
        pub object_digest: String,
        pub combo_index: i64,
        pub output_digest: String,
        pub commit_path: String,
        pub isolated_snapshot: String,
    }

    pub fn commits_for_object(&self, object_id: &str) -> Result<Vec<CommitRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, stripe, generation, object_digest, combo_index, output_digest,
                    commit_path, isolated_snapshot
             FROM stripe_commits WHERE object_id = ?1 ORDER BY stripe",
        )?;
        let rows = stmt.query_map(params![object_id], |r| {
            Ok(CommitRow {
                id: r.get(0)?,
                stripe: r.get(1)?,
                generation: r.get(2)?,
                object_digest: r.get(3)?,
                combo_index: r.get(4)?,
                output_digest: r.get(5)?,
                commit_path: r.get(6)?,
                isolated_snapshot: r.get(7)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn delete_commit(&self, object_id: &str, stripe: i64) -> Result<Option<String>> {
        let path: Option<String> = {
            let conn = self.conn.lock().unwrap();
            conn.query_row(
                "SELECT commit_path FROM stripe_commits
                 WHERE object_id=?1 AND stripe=?2",
                params![object_id, stripe],
                |r| r.get(0),
            )
            .ok()
        };
        self.conn.lock().unwrap().execute(
            "DELETE FROM stripe_commits WHERE object_id=?1 AND stripe=?2",
            params![object_id, stripe],
        )?;
        Ok(path)
    }

    pub fn record_export(
        &self,
        object_id: &str,
        export_path: &str,
        object_digest: &str,
    ) -> Result<i64> {
        let id = self.next_id("export")?;
        self.conn.lock().unwrap().execute(
            "INSERT INTO exports(id, object_id, export_path, object_digest)
             VALUES (?1, ?2, ?3, ?4)",
            params![id, object_id, export_path, object_digest],
        )?;
        Ok(id)
    }

    pub fn list_exports(&self, object_id: &str) -> Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT export_path FROM exports WHERE object_id=?1 ORDER BY id",
        )?;
        let rows = stmt.query_map(params![object_id], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn start_run(&self, object_id: &str, total: i64) -> Result<i64> {
        let id = self.next_id("recovery_run")?;
        self.conn.lock().unwrap().execute(
            "INSERT INTO recovery_runs(id, object_id, status, stripes_total, stripes_committed)
             VALUES (?1, ?2, 'running', ?3, 0)",
            params![id, object_id, total],
        )?;
        Ok(id)
    }

    pub fn finish_run(&self, run_id: i64, status: &str, committed: i64) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "UPDATE recovery_runs SET status=?2, stripes_committed=?3,
                finished_at=datetime('now') WHERE id=?1",
            params![run_id, status, committed],
        )?;
        Ok(())
    }
}
