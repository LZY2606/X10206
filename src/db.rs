//! SQLite persistence: manifests, received fragments, analyses, solutions,
//! per-stripe commits, recovery runs, isolation state and export records.

use std::path::Path;

use anyhow::Context;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;

pub const SCHEMA_VERSION: i64 = 1;

pub fn open(data_dir: &Path) -> anyhow::Result<Connection> {
    std::fs::create_dir_all(data_dir).context("creating data dir")?;
    let path = data_dir.join("srp.sqlite");
    let mut conn = Connection::open(&path).with_context(|| format!("opening {}", path.display()))?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "busy_timeout", 5_000)?;
    migrate(&mut conn)?;
    Ok(conn)
}

pub fn migrate(conn: &mut Connection) -> anyhow::Result<()> {
    let tx = conn.transaction()?;
    tx.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS schema_meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS objects (
            object_id          TEXT PRIMARY KEY,
            coding_version     TEXT NOT NULL,
            data_shards        INTEGER NOT NULL,
            parity_shards      INTEGER NOT NULL,
            shard_length       INTEGER NOT NULL,
            stripe_count       INTEGER NOT NULL,
            current_generation INTEGER NOT NULL,
            object_digests     TEXT NOT NULL,
            manifest_digest    TEXT NOT NULL,
            manifest_blob      TEXT NOT NULL,
            imported_at        INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS stripes (
            object_id          TEXT NOT NULL REFERENCES objects(object_id),
            stripe             INTEGER NOT NULL,
            generation         INTEGER NOT NULL,
            data_digests       TEXT NOT NULL,
            shard_digests      TEXT NOT NULL,
            PRIMARY KEY (object_id, stripe)
        );

        CREATE TABLE IF NOT EXISTS fragments (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            object_id       TEXT NOT NULL REFERENCES objects(object_id),
            stripe          INTEGER NOT NULL,
            shard_index     INTEGER NOT NULL,
            source          TEXT NOT NULL,
            generation      INTEGER NOT NULL,
            claimed_digest  TEXT NOT NULL,
            actual_digest   TEXT NOT NULL,
            length          INTEGER NOT NULL,
            blob_digest     TEXT NOT NULL,
            received_at     TEXT NOT NULL,
            claim_ok        INTEGER NOT NULL,
            UNIQUE (object_id, stripe, shard_index, source, generation, actual_digest)
        );

        CREATE TABLE IF NOT EXISTS isolated_sources (
            object_id  TEXT NOT NULL REFERENCES objects(object_id),
            source     TEXT NOT NULL,
            isolated_at INTEGER NOT NULL,
            PRIMARY KEY (object_id, source)
        );

        CREATE TABLE IF NOT EXISTS analyses (
            object_id          TEXT NOT NULL REFERENCES objects(object_id),
            stripe             INTEGER NOT NULL,
            analyzed_at        INTEGER NOT NULL,
            analyzed_revision INTEGER NOT NULL,
            search_budget      INTEGER NOT NULL,
            combos_checked     INTEGER NOT NULL,
            budget_exhausted   INTEGER NOT NULL,
            feasible_count     INTEGER NOT NULL,
            PRIMARY KEY (object_id, stripe)
        );

        CREATE TABLE IF NOT EXISTS solutions (
            object_id     TEXT NOT NULL,
            stripe        INTEGER NOT NULL,
            rank          INTEGER NOT NULL,
            generation    INTEGER NOT NULL,
            member_ids    TEXT NOT NULL,
            indices       TEXT NOT NULL,
            data_digest   TEXT NOT NULL,
            witness_count INTEGER NOT NULL,
            witnesses     TEXT NOT NULL,
            excluded_ids  TEXT NOT NULL,
            report        TEXT NOT NULL,
            PRIMARY KEY (object_id, stripe, rank),
            FOREIGN KEY (object_id, stripe) REFERENCES stripes(object_id, stripe)
        );

        CREATE TABLE IF NOT EXISTS excluded_evidence (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            object_id   TEXT NOT NULL,
            stripe      INTEGER NOT NULL,
            rank        INTEGER,
            fragment_id INTEGER NOT NULL REFERENCES fragments(id),
            reason      TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS recovery_runs (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            object_id    TEXT NOT NULL REFERENCES objects(object_id),
            started_at   INTEGER NOT NULL,
            finished_at  INTEGER,
            status       TEXT NOT NULL,
            revision     INTEGER NOT NULL,
            last_stripe  INTEGER
        );

        CREATE TABLE IF NOT EXISTS stripe_commit (
            object_id    TEXT NOT NULL,
            stripe       INTEGER NOT NULL,
            run_id       INTEGER NOT NULL REFERENCES recovery_runs(id),
            generation   INTEGER NOT NULL,
            committed_at INTEGER NOT NULL,
            revision     INTEGER NOT NULL,
            report       TEXT NOT NULL,
            PRIMARY KEY (object_id, stripe)
        );

        CREATE TABLE IF NOT EXISTS recovered_shards (
            object_id    TEXT NOT NULL,
            stripe       INTEGER NOT NULL,
            shard_index  INTEGER NOT NULL,
            generation   INTEGER NOT NULL,
            blob_digest  TEXT NOT NULL,
            committed_at INTEGER NOT NULL,
            PRIMARY KEY (object_id, stripe, shard_index)
        );

        CREATE TABLE IF NOT EXISTS exports (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            object_id     TEXT NOT NULL REFERENCES objects(object_id),
            path          TEXT NOT NULL,
            manifest_path TEXT NOT NULL,
            created_at    INTEGER NOT NULL,
            stripes       INTEGER NOT NULL,
            verified      INTEGER NOT NULL
        );
        "#,
    )?;
    tx.execute(
        "INSERT OR IGNORE INTO schema_meta(key, value) VALUES ('version', ?1)",
        params![SCHEMA_VERSION.to_string()],
    )?;
    tx.commit()?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct ObjectRow {
    pub object_id: String,
    pub coding_version: String,
    pub data_shards: i64,
    pub parity_shards: i64,
    pub shard_length: i64,
    pub stripe_count: i64,
    pub current_generation: i64,
    pub object_digests: String,
    pub manifest_digest: String,
    pub manifest_blob: String,
    pub imported_at: i64,
}

pub fn list_objects(conn: &Connection) -> anyhow::Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT object_id FROM objects ORDER BY object_id")?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

pub fn get_object(conn: &Connection, object_id: &str) -> anyhow::Result<Option<ObjectRow>> {
    conn.query_row(
        "SELECT object_id, coding_version, data_shards, parity_shards, shard_length,
                stripe_count, current_generation, object_digests, manifest_digest,
                manifest_blob, imported_at
         FROM objects WHERE object_id = ?1",
        params![object_id],
        |r| {
            Ok(ObjectRow {
                object_id: r.get(0)?,
                coding_version: r.get(1)?,
                data_shards: r.get(2)?,
                parity_shards: r.get(3)?,
                shard_length: r.get(4)?,
                stripe_count: r.get(5)?,
                current_generation: r.get(6)?,
                object_digests: r.get(7)?,
                manifest_digest: r.get(8)?,
                manifest_blob: r.get(9)?,
                imported_at: r.get(10)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

#[derive(Debug, Clone)]
pub struct StripeRow {
    pub stripe: u32,
    pub generation: u64,
    pub data_digests: String,
    pub shard_digests: String,
}

pub fn list_stripes(conn: &Connection, object_id: &str) -> anyhow::Result<Vec<StripeRow>> {
    let mut stmt = conn.prepare(
        "SELECT stripe, generation, data_digests, shard_digests
         FROM stripes WHERE object_id = ?1 ORDER BY stripe",
    )?;
    let rows = stmt.query_map(params![object_id], |r| {
        Ok(StripeRow {
            stripe: r.get::<_, i64>(0)? as u32,
            generation: r.get::<_, i64>(1)? as u64,
            data_digests: r.get(2)?,
            shard_digests: r.get(3)?,
        })
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

#[derive(Debug, Clone)]
pub struct FragmentRow {
    pub id: i64,
    pub stripe: u32,
    pub shard_index: u32,
    pub source: String,
    pub generation: u64,
    pub claimed_digest: String,
    pub actual_digest: String,
    pub length: usize,
    pub blob_digest: String,
    pub received_at: String,
    pub claim_ok: bool,
}

pub fn list_fragments(conn: &Connection, object_id: &str, stripe: u32) -> anyhow::Result<Vec<FragmentRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, stripe, shard_index, source, generation, claimed_digest,
                actual_digest, length, blob_digest, received_at, claim_ok
         FROM fragments
         WHERE object_id = ?1 AND stripe = ?2
         ORDER BY shard_index, generation, source, actual_digest, id",
    )?;
    let rows = stmt.query_map(params![object_id, stripe as i64], |r| {
        Ok(FragmentRow {
            id: r.get(0)?,
            stripe: r.get::<_, i64>(1)? as u32,
            shard_index: r.get::<_, i64>(2)? as u32,
            source: r.get(3)?,
            generation: r.get::<_, i64>(4)? as u64,
            claimed_digest: r.get(5)?,
            actual_digest: r.get(6)?,
            length: r.get::<_, i64>(7)? as usize,
            blob_digest: r.get(8)?,
            received_at: r.get(9)?,
            claim_ok: r.get::<_, i64>(10)? != 0,
        })
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

pub fn list_all_fragments(conn: &Connection, object_id: &str) -> anyhow::Result<Vec<FragmentRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, stripe, shard_index, source, generation, claimed_digest,
                actual_digest, length, blob_digest, received_at, claim_ok
         FROM fragments
         WHERE object_id = ?1
         ORDER BY stripe, shard_index, generation, source, actual_digest, id",
    )?;
    let rows = stmt.query_map(params![object_id], |r| {
        Ok(FragmentRow {
            id: r.get(0)?,
            stripe: r.get::<_, i64>(1)? as u32,
            shard_index: r.get::<_, i64>(2)? as u32,
            source: r.get(3)?,
            generation: r.get::<_, i64>(4)? as u64,
            claimed_digest: r.get(5)?,
            actual_digest: r.get(6)?,
            length: r.get::<_, i64>(7)? as usize,
            blob_digest: r.get(8)?,
            received_at: r.get(9)?,
            claim_ok: r.get::<_, i64>(10)? != 0,
        })
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

pub fn fragment_by_id(conn: &Connection, object_id: &str, id: i64) -> anyhow::Result<Option<FragmentRow>> {
    conn.query_row(
        "SELECT id, stripe, shard_index, source, generation, claimed_digest,
                actual_digest, length, blob_digest, received_at, claim_ok
         FROM fragments WHERE object_id = ?1 AND id = ?2",
        params![object_id, id],
        |r| {
            Ok(FragmentRow {
                id: r.get(0)?,
                stripe: r.get::<_, i64>(1)? as u32,
                shard_index: r.get::<_, i64>(2)? as u32,
                source: r.get(3)?,
                generation: r.get::<_, i64>(4)? as u64,
                claimed_digest: r.get(5)?,
                actual_digest: r.get(6)?,
                length: r.get::<_, i64>(7)? as usize,
                blob_digest: r.get(8)?,
                received_at: r.get(9)?,
                claim_ok: r.get::<_, i64>(10)? != 0,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

pub fn isolated_sources(conn: &Connection, object_id: &str) -> anyhow::Result<Vec<String>> {
    let mut stmt =
        conn.prepare("SELECT source FROM isolated_sources WHERE object_id = ?1 ORDER BY source")?;
    let rows = stmt.query_map(params![object_id], |r| r.get::<_, String>(0))?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

pub fn distinct_sources(conn: &Connection, object_id: &str) -> anyhow::Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT source FROM fragments WHERE object_id = ?1 ORDER BY source",
    )?;
    let rows = stmt.query_map(params![object_id], |r| r.get::<_, String>(0))?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

pub fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

pub fn json_get<T: serde::de::DeserializeOwned>(s: &str) -> anyhow::Result<T> {
    serde_json::from_str::<T>(s).with_context(|| format!("bad json in db: {s}"))
}

pub fn json_put<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap_or(Value::Null.to_string())
}
