//! SQLite persistence for manifests, received shards, runs and commits.
//!
//! The database stores metadata and provenance only; original shard bytes
//! live untouched under `received/` while rebuilt bytes live under
//! `staging/` or `committed/`.

use crate::model::{Manifest, RunStatus, ShardHealth, StripeState};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub struct BayDb {
    pub path: PathBuf,
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone)]
pub struct ObjectRow {
    pub object_id: String,
    pub codec_version: u8,
    pub k: u8,
    pub m: u8,
    pub stripe_count: u32,
    pub object_digest: String,
}

#[derive(Debug, Clone)]
pub struct ShardRow {
    pub id: i64,
    pub object_id: String,
    pub stripe_index: u32,
    pub shard_index: u8,
    pub generation: i64,
    pub content_sha256: String,
    pub sidecar_sha256: Option<String>,
    pub length_bytes: i64,
    pub source: String,
    pub health: String,
    pub blob_path: String,
    pub received_at: String,
}

#[derive(Debug, Clone)]
pub struct RunRow {
    pub id: i64,
    pub object_id: String,
    pub status: String,
    pub reason: Option<String>,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub budget: i64,
}

#[derive(Debug, Clone)]
pub struct CommitRow {
    pub id: i64,
    pub object_id: String,
    pub stripe_index: u32,
    pub run_id: i64,
    pub generation: i64,
    pub solution_index: i64,
    pub digest_matches: bool,
    pub content_digest: String,
    pub object_digest_at_commit: String,
    pub dir: String,
    pub pointer: i64,
    pub committed_at: String,
    pub valid: bool,
    pub superseded_reason: Option<String>,
}

fn now_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    // Deterministic enough for audit ordering; UI does not rely on wall clock.
    format!("{secs:010}")
}

const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS objects (
    object_id      TEXT PRIMARY KEY,
    codec_version  INTEGER NOT NULL,
    k              INTEGER NOT NULL,
    m              INTEGER NOT NULL,
    stripe_count   INTEGER NOT NULL,
    object_digest  TEXT NOT NULL,
    manifest_json  TEXT NOT NULL,
    imported_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sources (
    name       TEXT PRIMARY KEY,
    isolated   INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS shards (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id      TEXT NOT NULL REFERENCES objects(object_id),
    stripe_index   INTEGER NOT NULL,
    shard_index    INTEGER NOT NULL,
    generation     INTEGER NOT NULL,
    content_sha256 TEXT NOT NULL,
    sidecar_sha256 TEXT,
    length_bytes   INTEGER NOT NULL,
    source         TEXT NOT NULL,
    health         TEXT NOT NULL,
    blob_path      TEXT NOT NULL,
    received_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_shards_loc ON shards(object_id, stripe_index, shard_index);
CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id   TEXT NOT NULL REFERENCES objects(object_id),
    status      TEXT NOT NULL,
    reason      TEXT,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    budget      INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS stripe_runs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id       INTEGER NOT NULL REFERENCES runs(id),
    object_id    TEXT NOT NULL,
    stripe_index INTEGER NOT NULL,
    state        TEXT NOT NULL,
    detail       TEXT,
    UNIQUE(run_id, stripe_index)
);
CREATE TABLE IF NOT EXISTS stripe_commits (
    id                        INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id                 TEXT NOT NULL,
    stripe_index              INTEGER NOT NULL,
    run_id                    INTEGER NOT NULL,
    generation                INTEGER NOT NULL,
    solution_index            INTEGER NOT NULL,
    digest_matches            INTEGER NOT NULL,
    content_digest            TEXT NOT NULL,
    object_digest_at_commit   TEXT NOT NULL,
    dir                       TEXT NOT NULL,
    pointer                   INTEGER NOT NULL,
    committed_at              TEXT NOT NULL,
    valid                     INTEGER NOT NULL DEFAULT 1,
    superseded_reason         TEXT
);
CREATE INDEX IF NOT EXISTS idx_commits_lookup
    ON stripe_commits(object_id, stripe_index, valid);
CREATE TABLE IF NOT EXISTS solutions (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id          TEXT NOT NULL,
    stripe_index       INTEGER NOT NULL,
    run_id             INTEGER,
    solution_index     INTEGER NOT NULL,
    generation         INTEGER NOT NULL,
    digest_match       INTEGER NOT NULL,
    content_digest     TEXT NOT NULL,
    chosen_indices     TEXT NOT NULL,
    chosen_shard_ids   TEXT NOT NULL,
    involved_shard_ids TEXT NOT NULL,
    excluded_evidence  TEXT NOT NULL,
    recomputed_digests TEXT NOT NULL,
    created_at         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_solutions_lookup ON solutions(object_id, stripe_index, run_id);
CREATE TABLE IF NOT EXISTS exports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id   TEXT NOT NULL,
    dir         TEXT NOT NULL,
    manifest_at TEXT NOT NULL,
    ok          INTEGER NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    kind      TEXT NOT NULL,
    object_id TEXT,
    message   TEXT NOT NULL
);
"#;

impl BayDb {
    pub fn open(path: &Path) -> rusqlite::Result<BayDb> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "foreign_keys", "on")?;
        conn.execute_batch(SCHEMA)?;
        Ok(BayDb { path: path.to_path_buf(), conn: Mutex::new(conn) })
    }

    pub fn in_memory() -> rusqlite::Result<BayDb> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "foreign_keys", "on")?;
        conn.execute_batch(SCHEMA)?;
        Ok(BayDb { path: PathBuf::from(":memory:"), conn: Mutex::new(conn) })
    }

    pub fn event(&self, kind: &str, object_id: Option<&str>, message: &str) {
        let c = self.conn.lock().unwrap();
        let _ = c.execute(
            "INSERT INTO events(ts, kind, object_id, message) VALUES (?1,?2,?3,?4)",
            params![now_iso(), kind, object_id, message],
        );
    }
}

impl BayDb {
    pub fn insert_object_if_absent(&self, manifest: &Manifest) -> rusqlite::Result<bool> {
        let mut c = self.conn.lock().unwrap();
        let tx = c.transaction()?;
        let exists: bool = tx
            .query_row(
                "SELECT 1 FROM objects WHERE object_id = ?1",
                params![manifest.object_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if exists {
            tx.rollback()?;
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO objects(object_id, codec_version, k, m, stripe_count,
             object_digest, manifest_json, imported_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                manifest.object_id,
                manifest.codec_version,
                manifest.k,
                manifest.m,
                manifest.stripe_count,
                manifest.object_digest,
                serde_json::to_string(manifest).unwrap(),
                now_iso()
            ],
        )?;
        tx.commit()?;
        Ok(true)
    }

    pub fn list_objects(&self) -> rusqlite::Result<Vec<ObjectRow>> {
        let c = self.conn.lock().unwrap();
        let mut stmt = c.prepare(
            "SELECT object_id, codec_version, k, m, stripe_count, object_digest
             FROM objects ORDER BY object_id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(ObjectRow {
                object_id: r.get(0)?,
                codec_version: r.get(1)?,
                k: r.get(2)?,
                m: r.get(3)?,
                stripe_count: r.get(4)?,
                object_digest: r.get(5)?,
            })
        })?;
        rows.collect()
    }

    pub fn get_manifest(&self, object_id: &str) -> rusqlite::Result<Option<Manifest>> {
        let c = self.conn.lock().unwrap();
        let s: Option<String> = c
            .query_row(
                "SELECT manifest_json FROM objects WHERE object_id = ?1",
                params![object_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(s.and_then(|j| serde_json::from_str(&j).ok()))
    }

    pub fn touch_source(&self, name: &str) -> rusqlite::Result<()> {
        let c = self.conn.lock().unwrap();
        c.execute(
            "INSERT INTO sources(name, isolated, updated_at) VALUES (?1, 0, ?2)
             ON CONFLICT(name) DO UPDATE SET updated_at = excluded.updated_at",
            params![name, now_iso()],
        )?;
        Ok(())
    }

    pub fn list_sources(&self) -> rusqlite::Result<Vec<(String, bool)>> {
        let c = self.conn.lock().unwrap();
        let mut stmt = c.prepare("SELECT name, isolated FROM sources ORDER BY name")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? != 0)))?;
        rows.map(|r| r.map(|(n, i)| (n, i))).collect()
    }

    pub fn set_source_isolated(&self, name: &str, isolated: bool) -> rusqlite::Result<bool> {
        let c = self.conn.lock().unwrap();
        let n = c.execute(
            "UPDATE sources SET isolated = ?2, updated_at = ?3 WHERE name = ?1",
            params![name, isolated as i64, now_iso()],
        )?;
        Ok(n > 0)
    }

    pub fn isolated_sources(&self) -> rusqlite::Result<std::collections::HashSet<String>> {
        Ok(self.list_sources()?.into_iter().filter(|(_, i)| *i).map(|(n, _)| n).collect())
    }

    pub fn insert_shard(
        &self,
        object_id: &str,
        stripe_index: u32,
        shard_index: u8,
        generation: i64,
        content_sha256: &str,
        sidecar_sha256: Option<&str>,
        length_bytes: i64,
        source: &str,
        health: ShardHealth,
        blob_path: &str,
    ) -> rusqlite::Result<i64> {
        let c = self.conn.lock().unwrap();
        c.execute(
            "INSERT INTO shards(object_id, stripe_index, shard_index, generation,
             content_sha256, sidecar_sha256, length_bytes, source, health, blob_path, received_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                object_id,
                stripe_index,
                shard_index,
                generation,
                content_sha256,
                sidecar_sha256,
                length_bytes,
                source,
                health.as_str(),
                blob_path,
                now_iso()
            ],
        )?;
        Ok(c.last_insert_rowid())
    }

    pub fn shards_for_object(&self, object_id: &str) -> rusqlite::Result<Vec<ShardRow>> {
        let c = self.conn.lock().unwrap();
        let mut stmt = c.prepare(
            "SELECT id, object_id, stripe_index, shard_index, generation, content_sha256,
                    sidecar_sha256, length_bytes, source, health, blob_path, received_at
             FROM shards WHERE object_id = ?1
             ORDER BY stripe_index, shard_index, id",
        )?;
        let rows = stmt.query_map(params![object_id], |r| {
            Ok(ShardRow {
                id: r.get(0)?,
                object_id: r.get(1)?,
                stripe_index: r.get::<_, i64>(2)? as u32,
                shard_index: r.get::<_, i64>(3)? as u8,
                generation: r.get(4)?,
                content_sha256: r.get(5)?,
                sidecar_sha256: r.get(6)?,
                length_bytes: r.get(7)?,
                source: r.get(8)?,
                health: r.get(9)?,
                blob_path: r.get(10)?,
                received_at: r.get(11)?,
            })
        })?;
        rows.collect()
    }
}

impl BayDb {
    pub fn start_run(&self, object_id: &str, budget: u64) -> rusqlite::Result<i64> {
        let c = self.conn.lock().unwrap();
        c.execute(
            "INSERT INTO runs(object_id, status, started_at, budget) VALUES (?1, 'running', ?2, ?3)",
            params![object_id, now_iso(), budget as i64],
        )?;
        Ok(c.last_insert_rowid())
    }

    pub fn finish_run(&self, run_id: i64, status: RunStatus, reason: Option<&str>) -> rusqlite::Result<()> {
        let c = self.conn.lock().unwrap();
        c.execute(
            "UPDATE runs SET status = ?2, reason = ?3, finished_at = ?4 WHERE id = ?1",
            params![run_id, status.as_str(), reason, now_iso()],
        )?;
        Ok(())
    }

    pub fn latest_run(&self, object_id: &str) -> rusqlite::Result<Option<RunRow>> {
        let c = self.conn.lock().unwrap();
        c.query_row(
            "SELECT id, object_id, status, reason, started_at, finished_at, budget
             FROM runs WHERE object_id = ?1 ORDER BY id DESC LIMIT 1",
            params![object_id],
            |r| {
                Ok(RunRow {
                    id: r.get(0)?,
                    object_id: r.get(1)?,
                    status: r.get(2)?,
                    reason: r.get(3)?,
                    started_at: r.get(4)?,
                    finished_at: r.get(5)?,
                    budget: r.get(6)?,
                })
            },
        )
        .optional()
    }

    pub fn upsert_stripe_run(
        &self,
        run_id: i64,
        object_id: &str,
        stripe_index: u32,
        state: StripeState,
        detail: &str,
    ) -> rusqlite::Result<()> {
        let c = self.conn.lock().unwrap();
        c.execute(
            "INSERT INTO stripe_runs(run_id, object_id, stripe_index, state, detail)
             VALUES (?1,?2,?3,?4,?5)
             ON CONFLICT(run_id, stripe_index)
             DO UPDATE SET state = excluded.state, detail = excluded.detail",
            params![run_id, object_id, stripe_index, state.as_str(), detail],
        )?;
        Ok(())
    }

    pub fn insert_commit(
        &self,
        object_id: &str,
        stripe_index: u32,
        run_id: i64,
        generation: i64,
        solution_index: i64,
        digest_matches: bool,
        content_digest: &str,
        object_digest_at_commit: &str,
        dir: &str,
        pointer: i64,
    ) -> rusqlite::Result<i64> {
        let c = self.conn.lock().unwrap();
        c.execute(
            "INSERT INTO stripe_commits(object_id, stripe_index, run_id, generation,
             solution_index, digest_matches, content_digest, object_digest_at_commit,
             dir, pointer, committed_at, valid)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,1)",
            params![
                object_id, stripe_index, run_id, generation, solution_index,
                digest_matches as i64, content_digest, object_digest_at_commit,
                dir, pointer, now_iso()
            ],
        )?;
        Ok(c.last_insert_rowid())
    }

    pub fn invalidate_commit(&self, commit_id: i64, reason: &str) -> rusqlite::Result<()> {
        let c = self.conn.lock().unwrap();
        c.execute(
            "UPDATE stripe_commits SET valid = 0, superseded_reason = ?2 WHERE id = ?1",
            params![commit_id, reason],
        )?;
        Ok(())
    }

    pub fn valid_commit(&self, object_id: &str, stripe_index: u32) -> rusqlite::Result<Option<CommitRow>> {
        let c = self.conn.lock().unwrap();
        c.query_row(
            "SELECT id, object_id, stripe_index, run_id, generation, solution_index,
                    digest_matches, content_digest, object_digest_at_commit, dir, pointer,
                    committed_at, valid, superseded_reason
             FROM stripe_commits WHERE object_id = ?1 AND stripe_index = ?2 AND valid = 1
             ORDER BY pointer DESC LIMIT 1",
            params![object_id, stripe_index],
            commit_row_from_sql,
        )
        .optional()
    }

    pub fn list_commits(&self, object_id: &str) -> rusqlite::Result<Vec<CommitRow>> {
        let c = self.conn.lock().unwrap();
        let mut stmt = c.prepare(
            "SELECT id, object_id, stripe_index, run_id, generation, solution_index,
                    digest_matches, content_digest, object_digest_at_commit, dir, pointer,
                    committed_at, valid, superseded_reason
             FROM stripe_commits WHERE object_id = ?1
             ORDER BY stripe_index, pointer",
        )?;
        let rows = stmt.query_map(params![object_id], commit_row_from_sql)?;
        rows.collect()
    }

    pub fn next_commit_pointer(&self, object_id: &str, stripe_index: u32) -> rusqlite::Result<i64> {
        let c = self.conn.lock().unwrap();
        let max: Option<i64> = c.query_row(
            "SELECT MAX(pointer) FROM stripe_commits WHERE object_id = ?1 AND stripe_index = ?2",
            params![object_id, stripe_index],
            |r| r.get(0),
        )?;
        Ok(max.unwrap_or(0) + 1)
    }

    pub fn insert_solution(
        &self,
        object_id: &str,
        stripe_index: u32,
        run_id: Option<i64>,
        solution_index: i64,
        generation: i64,
        digest_match: bool,
        content_digest: &str,
        chosen_indices: &str,
        chosen_shard_ids: &str,
        involved_shard_ids: &str,
        excluded_evidence: &str,
        recomputed_digests: &str,
    ) -> rusqlite::Result<i64> {
        let c = self.conn.lock().unwrap();
        c.execute(
            "INSERT INTO solutions(object_id, stripe_index, run_id, solution_index, generation,
             digest_match, content_digest, chosen_indices, chosen_shard_ids, involved_shard_ids,
             excluded_evidence, recomputed_digests, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                object_id, stripe_index, run_id, solution_index, generation,
                digest_match as i64, content_digest, chosen_indices, chosen_shard_ids,
                involved_shard_ids, excluded_evidence, recomputed_digests, now_iso()
            ],
        )?;
        Ok(c.last_insert_rowid())
    }

    pub fn solutions_for_stripe(
        &self,
        object_id: &str,
        stripe_index: u32,
        run_id: Option<i64>,
    ) -> rusqlite::Result<Vec<serde_json::Value>> {
        let c = self.conn.lock().unwrap();
        let mut stmt = c.prepare(
            "SELECT solution_index, generation, digest_match, content_digest, chosen_indices,
                    chosen_shard_ids, involved_shard_ids, excluded_evidence, recomputed_digests
             FROM solutions WHERE object_id = ?1 AND stripe_index = ?2
             AND (?3 IS NULL OR run_id = ?3)
             ORDER BY solution_index",
        )?;
        let rows = stmt.query_map(params![object_id, stripe_index, run_id], |r| {
            Ok(serde_json::json!({
                "solution_index": r.get::<_, i64>(0)?,
                "generation": r.get::<_, i64>(1)?,
                "digest_match": r.get::<_, i64>(2)? != 0,
                "content_digest": r.get::<_, String>(3)?,
                "chosen_indices": r.get::<_, String>(4)?,
                "chosen_shard_ids": r.get::<_, String>(5)?,
                "involved_shard_ids": r.get::<_, String>(6)?,
                "excluded_evidence": r.get::<_, String>(7)?,
                "recomputed_digests": r.get::<_, String>(8)?,
            }))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
    }

    pub fn record_export(&self, object_id: &str, dir: &str, manifest_at: &str, ok: bool) -> rusqlite::Result<()> {
        let c = self.conn.lock().unwrap();
        c.execute(
            "INSERT INTO exports(object_id, dir, manifest_at, ok, created_at)
             VALUES (?1,?2,?3,?4,?5)",
            params![object_id, dir, manifest_at, ok as i64, now_iso()],
        )?;
        Ok(())
    }

    pub fn recent_events(&self, limit: i64) -> rusqlite::Result<Vec<(String, String, Option<String>, String)>> {
        let c = self.conn.lock().unwrap();
        let mut stmt = c.prepare(
            "SELECT ts, kind, object_id, message FROM events ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get(2)?, r.get::<_, String>(3)?))
        })?;
        rows.collect()
    }

    pub fn clear_run_solutions(&self, run_id: i64) -> rusqlite::Result<()> {
        let c = self.conn.lock().unwrap();
        c.execute("DELETE FROM solutions WHERE run_id = ?1", params![run_id])?;
        Ok(())
    }
}

fn commit_row_from_sql(r: &rusqlite::Row<'_>) -> rusqlite::Result<CommitRow> {
    Ok(CommitRow {
        id: r.get(0)?,
        object_id: r.get(1)?,
        stripe_index: r.get::<_, i64>(2)? as u32,
        run_id: r.get(3)?,
        generation: r.get(4)?,
        solution_index: r.get(5)?,
        digest_matches: r.get::<_, i64>(6)? != 0,
        content_digest: r.get(7)?,
        object_digest_at_commit: r.get(8)?,
        dir: r.get(9)?,
        pointer: r.get(10)?,
        committed_at: r.get(11)?,
        valid: r.get::<_, i64>(12)? != 0,
        superseded_reason: r.get(13)?,
    })
}
