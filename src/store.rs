//! SQLite persistence and blob storage paths.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use rusqlite::Connection;
use serde::Serialize;
use serde_json::Value;

use crate::model::{CandidateRow, ObjectRow, PlanRow, StripeRow};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Clone)]
pub struct Store {
    pub db_path: PathBuf,
    pub blobs_dir: PathBuf,
    pub exports_dir: PathBuf,
    pub tmp_dir: PathBuf,
}

/// Fault injection knobs used by the disk-failure and crash tests.
#[derive(Clone, Debug, Default, Serialize)]
pub struct FailureInjection {
    /// Fail every Nth staging write (0 disables); counted per process call.
    pub fail_staging_write: bool,
    /// Simulate a crash after the staging blob is written but before commit.
    pub crash_before_commit: bool,
}

const SCHEMA: &str = r#"
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS objects (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  coding_version TEXT NOT NULL,
  k INTEGER NOT NULL,
  m INTEGER NOT NULL,
  data_len INTEGER NOT NULL,
  object_digest TEXT,
  status TEXT NOT NULL,
  excluded_sources TEXT NOT NULL DEFAULT '[]',
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS stripes (
  id TEXT PRIMARY KEY,
  object_id TEXT NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
  stripe_index INTEGER NOT NULL,
  shard_len INTEGER NOT NULL,
  data_len INTEGER NOT NULL,
  expected_digest TEXT,
  recovered_digest TEXT,
  status TEXT NOT NULL,
  committed INTEGER NOT NULL DEFAULT 0,
  commit_id TEXT,
  ambiguous INTEGER NOT NULL DEFAULT 0,
  budget_exceeded INTEGER NOT NULL DEFAULT 0,
  detail TEXT NOT NULL DEFAULT '',
  updated_at INTEGER NOT NULL,
  UNIQUE(object_id, stripe_index)
);
CREATE TABLE IF NOT EXISTS candidates (
  id TEXT PRIMARY KEY,
  stripe_id TEXT NOT NULL REFERENCES stripes(id) ON DELETE CASCADE,
  shard_index INTEGER NOT NULL,
  source TEXT NOT NULL,
  generation INTEGER NOT NULL,
  received_at INTEGER NOT NULL,
  length INTEGER NOT NULL,
  claimed_digest TEXT,
  recomputed_digest TEXT NOT NULL,
  digest_ok INTEGER NOT NULL,
  length_ok INTEGER NOT NULL,
  usable INTEGER NOT NULL,
  blob_path TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS plans (
  id TEXT PRIMARY KEY,
  stripe_id TEXT NOT NULL REFERENCES stripes(id) ON DELETE CASCADE,
  rank INTEGER NOT NULL,
  participants_json TEXT NOT NULL,
  output_digest TEXT NOT NULL,
  verifies INTEGER NOT NULL,
  generation_coherent INTEGER NOT NULL,
  selected INTEGER NOT NULL DEFAULT 0,
  evidence_json TEXT NOT NULL,
  output_blob TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS commits (
  id TEXT PRIMARY KEY,
  stripe_id TEXT NOT NULL UNIQUE REFERENCES stripes(id) ON DELETE CASCADE,
  plan_id TEXT NOT NULL,
  output_digest TEXT NOT NULL,
  output_blob TEXT NOT NULL,
  committed_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_candidates_stripe ON candidates(stripe_id);
CREATE INDEX IF NOT EXISTS idx_plans_stripe ON plans(stripe_id);
"#;

impl Store {
    pub fn new(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref();
        let blobs_dir = root.join("blobs");
        let exports_dir = root.join("exports");
        let tmp_dir = root.join("tmp");
        for d in [&blobs_dir, &exports_dir, &tmp_dir] {
            std::fs::create_dir_all(d).with_context(|| format!("create {}", d.display()))?;
        }
        let store = Self {
            db_path: root.join("pod.db"),
            blobs_dir,
            exports_dir,
            tmp_dir,
        };
        let mut conn = store.connect()?;
        store.migrate(&mut conn)?;
        Ok(store)
    }

    pub fn connect(&self) -> Result<Connection> {
        let conn = Connection::open(&self.db_path)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "busy_timeout", 5000)?;
        Ok(conn)
    }

    fn migrate(&self, conn: &mut Connection) -> Result<()> {
        conn.execute_batch(SCHEMA)?;
        let v: i64 = conn
            .query_row(
                "SELECT CAST(value AS INTEGER) FROM meta WHERE key='schema_version'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if v == 0 {
            conn.execute(
                "INSERT INTO meta(key,value) VALUES('schema_version',?1)",
                [SCHEMA_VERSION.to_string()],
            )?;
        } else if v as u32 != SCHEMA_VERSION {
            return Err(anyhow!("unsupported schema version {v}"));
        }
        Ok(())
    }

    /// Remove staging leftovers from an interrupted process.
    pub fn sweep_tmp(&self) -> Result<()> {
        if self.tmp_dir.exists() {
            for ent in std::fs::read_dir(&self.tmp_dir)? {
                let p = ent?.path();
                if p.is_dir() {
                    std::fs::remove_dir_all(&p).ok();
                } else {
                    std::fs::remove_file(&p).ok();
                }
            }
        }
        Ok(())
    }
}

pub fn bool_to_i64(b: bool) -> i64 {
    b as i64
}
pub fn i64_to_bool(i: i64) -> bool {
    i != 0
}

pub fn read_objects(conn: &Connection) -> Result<Vec<ObjectRow>> {
    let mut stmt = conn.prepare(
        "SELECT id,name,coding_version,k,m,data_len,object_digest,status,created_at
         FROM objects ORDER BY created_at, id",
    )?;
    let rows = stmt.query_map([], row_to_object)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

pub fn read_object(conn: &Connection, id: &str) -> Result<Option<ObjectRow>> {
    let mut stmt = conn.prepare(
        "SELECT id,name,coding_version,k,m,data_len,object_digest,status,created_at
         FROM objects WHERE id=?1",
    )?;
    let mut it = stmt.query_map([id], row_to_object)?;
    Ok(match it.next() {
        Some(r) => Some(r?),
        None => None,
    })
}

fn row_to_object(r: &rusqlite::Row<'_>) -> rusqlite::Result<ObjectRow> {
    Ok(ObjectRow {
        id: r.get(0)?,
        name: r.get(1)?,
        coding_version: r.get(2)?,
        k: r.get(3)?,
        m: r.get(4)?,
        data_len: r.get(5)?,
        object_digest: r.get(6)?,
        status: r.get(7)?,
        created_at: r.get(8)?,
    })
}

pub fn read_stripes(conn: &Connection, object_id: &str) -> Result<Vec<StripeRow>> {
    let mut stmt = conn.prepare(
        "SELECT id,object_id,stripe_index,shard_len,data_len,expected_digest,
                recovered_digest,status,committed,commit_id,ambiguous,budget_exceeded,
                detail,updated_at
         FROM stripes WHERE object_id=?1 ORDER BY stripe_index",
    )?;
    let rows = stmt.query_map([object_id], row_to_stripe)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

pub fn read_stripe_by_id(conn: &Connection, id: &str) -> Result<Option<StripeRow>> {
    let mut stmt = conn.prepare(
        "SELECT id,object_id,stripe_index,shard_len,data_len,expected_digest,
                recovered_digest,status,committed,commit_id,ambiguous,budget_exceeded,
                detail,updated_at
         FROM stripes WHERE id=?1",
    )?;
    let mut it = stmt.query_map([id], row_to_stripe)?;
    Ok(match it.next() {
        Some(r) => Some(r?),
        None => None,
    })
}

#[allow(clippy::too_many_arguments)]
fn row_to_stripe(r: &rusqlite::Row<'_>) -> rusqlite::Result<StripeRow> {
    Ok(StripeRow {
        id: r.get(0)?,
        object_id: r.get(1)?,
        stripe_index: r.get(2)?,
        shard_len: r.get(3)?,
        data_len: r.get(4)?,
        expected_digest: r.get(5)?,
        recovered_digest: r.get(6)?,
        status: r.get(7)?,
        committed: i64_to_bool(r.get(8)?),
        commit_id: r.get(9)?,
        ambiguous: i64_to_bool(r.get(10)?),
        budget_exceeded: i64_to_bool(r.get(11)?),
        detail: r.get(12)?,
        updated_at: r.get(13)?,
    })
}

pub fn read_candidates(conn: &Connection, stripe_id: &str) -> Result<Vec<CandidateRow>> {
    let mut stmt = conn.prepare(
        "SELECT id,stripe_id,shard_index,source,generation,received_at,length,
                claimed_digest,recomputed_digest,digest_ok,length_ok,usable,blob_path
         FROM candidates WHERE stripe_id=?1
         ORDER BY shard_index, source, generation, id",
    )?;
    let rows = stmt.query_map([stripe_id], |r| {
        Ok(CandidateRow {
            id: r.get(0)?,
            stripe_id: r.get(1)?,
            shard_index: r.get(2)?,
            source: r.get(3)?,
            generation: r.get(4)?,
            received_at: r.get(5)?,
            length: r.get(6)?,
            claimed_digest: r.get(7)?,
            recomputed_digest: r.get(8)?,
            digest_ok: i64_to_bool(r.get(9)?),
            length_ok: i64_to_bool(r.get(10)?),
            usable: i64_to_bool(r.get(11)?),
            blob_path: r.get(12)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

pub fn read_plans(conn: &Connection, stripe_id: &str) -> Result<Vec<PlanRow>> {
    let mut stmt = conn.prepare(
        "SELECT id,stripe_id,rank,participants_json,output_digest,verifies,
                generation_coherent,selected,evidence_json,output_blob
         FROM plans WHERE stripe_id=?1 ORDER BY rank, output_digest, id",
    )?;
    let rows = stmt.query_map([stripe_id], |r| {
        let participants_json: String = r.get(3)?;
        let evidence_json: String = r.get(8)?;
        Ok(PlanRow {
            id: r.get(0)?,
            stripe_id: r.get(1)?,
            rank: r.get(2)?,
            participants: serde_json::from_str(&participants_json).unwrap_or_default(),
            output_digest: r.get(4)?,
            verifies: i64_to_bool(r.get(5)?),
            generation_coherent: i64_to_bool(r.get(6)?),
            selected: i64_to_bool(r.get(7)?),
            evidence: serde_json::from_str(&evidence_json).unwrap_or_default(),
            output_blob: r.get(9)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

pub fn read_excluded_sources(conn: &Connection, object_id: &str) -> Result<Vec<String>> {
    let raw: Option<String> = conn.query_row(
        "SELECT excluded_sources FROM objects WHERE id=?1",
        [object_id],
        |r| r.get(0),
    )?;
    Ok(serde_json::from_str(&raw.unwrap_or_else(|| "[]".to_string())).unwrap_or_default())
}

pub fn write_excluded_sources(
    conn: &Connection,
    object_id: &str,
    sources: &[String],
) -> Result<()> {
    let raw = serde_json::to_string(sources)?;
    conn.execute(
        "UPDATE objects SET excluded_sources=?1 WHERE id=?2",
        (raw, object_id),
    )?;
    Ok(())
}

pub fn json_value(conn: &Connection, key: &str) -> Result<Option<Value>> {
    let raw: Option<String> =
        conn.query_row("SELECT value FROM meta WHERE key=?1", [key], |r| r.get(0))?;
    Ok(match raw {
        Some(s) => Some(serde_json::from_str(&s)?),
        None => None,
    })
}

pub fn set_json_value(conn: &Connection, key: &str, value: &Value) -> Result<()> {
    let raw = serde_json::to_string(value)?;
    conn.execute(
        "INSERT INTO meta(key,value) VALUES(?1,?2)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, raw),
    )?;
    Ok(())
}
