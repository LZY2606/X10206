//! SQLite persistence: imported shards keep raw bytes and their source;
//! recovery state is committed per stripe so interrupted runs can resume.

use crate::recover::{Candidate, ManifestEntry, StripeAnalysis};
use crate::rs::CodingParams;
use rusqlite::{params, Connection};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

pub struct Store {
    pub conn: Mutex<Connection>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ObjectRow {
    pub id: i64,
    pub name: String,
    pub params: CodingParams,
    pub total_len: u64,
    pub object_digest: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SourceRow {
    pub id: i64,
    pub name: String,
    pub quarantined: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CommitRow {
    pub stripe: usize,
    pub digest: String,
    pub combo_json: String,
    pub committed_at: String,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS objects(
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  coding_version INTEGER NOT NULL,
  k INTEGER NOT NULL,
  m INTEGER NOT NULL,
  shard_size INTEGER NOT NULL,
  total_len INTEGER NOT NULL,
  object_digest TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS sources(
  id INTEGER PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  quarantined INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS shards(
  id INTEGER PRIMARY KEY,
  object_id INTEGER NOT NULL,
  stripe INTEGER NOT NULL,
  idx INTEGER NOT NULL,
  generation INTEGER NOT NULL,
  source_id INTEGER NOT NULL,
  bytes BLOB NOT NULL,
  digest TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS manifest_entries(
  object_id INTEGER NOT NULL,
  stripe INTEGER NOT NULL,
  idx INTEGER NOT NULL,
  len INTEGER NOT NULL,
  PRIMARY KEY(object_id, stripe, idx)
);
CREATE TABLE IF NOT EXISTS stripe_commits(
  object_id INTEGER NOT NULL,
  stripe INTEGER NOT NULL,
  digest TEXT NOT NULL,
  combo_json TEXT NOT NULL,
  committed_at TEXT NOT NULL,
  PRIMARY KEY(object_id, stripe)
);
CREATE TABLE IF NOT EXISTS stripe_analyses(
  object_id INTEGER NOT NULL,
  stripe INTEGER NOT NULL,
  analysis_json TEXT NOT NULL,
  PRIMARY KEY(object_id, stripe)
);
";

impl Store {
    pub fn open(path: &Path) -> std::io::Result<Store> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        conn.execute_batch(SCHEMA)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        Ok(Store {
            conn: Mutex::new(conn),
        })
    }

    pub fn open_memory() -> Store {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        Store {
            conn: Mutex::new(conn),
        }
    }

    pub fn create_object(
        &self,
        name: &str,
        params: &CodingParams,
        total_len: u64,
        object_digest: &str,
    ) -> i64 {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO objects(name, coding_version, k, m, shard_size, total_len, object_digest)
             VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                name,
                params.version as i64,
                params.k as i64,
                params.m as i64,
                params.shard_size as i64,
                total_len as i64,
                object_digest
            ],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    pub fn ensure_source(&self, name: &str) -> i64 {
        let conn = self.conn.lock().unwrap();
        conn.execute("INSERT OR IGNORE INTO sources(name) VALUES(?1)", params![name])
            .unwrap();
        conn.query_row("SELECT id FROM sources WHERE name=?1", params![name], |r| {
            r.get(0)
        })
        .unwrap()
    }

    pub fn add_manifest_entry(
        &self,
        object_id: i64,
        stripe: usize,
        entry: &ManifestEntry,
    ) {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO manifest_entries(object_id, stripe, idx, len)
             VALUES(?1,?2,?3,?4)",
            params![object_id, stripe as i64, entry.idx as i64, entry.len as i64],
        )
        .unwrap();
    }

    /// Store a received shard: raw bytes plus the source it came from.
    pub fn add_shard(
        &self,
        object_id: i64,
        stripe: usize,
        idx: usize,
        generation: u64,
        source_id: i64,
        bytes: &[u8],
    ) -> i64 {
        let digest = crate::recover::sha256_hex(bytes);
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO shards(object_id, stripe, idx, generation, source_id, bytes, digest)
             VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                object_id,
                stripe as i64,
                idx as i64,
                generation as i64,
                source_id,
                bytes,
                digest
            ],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    pub fn list_objects(&self) -> Vec<ObjectRow> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, name, coding_version, k, m, shard_size, total_len, object_digest
                 FROM objects ORDER BY id",
            )
            .unwrap();
        stmt.query_map([], |r| {
            Ok(ObjectRow {
                id: r.get(0)?,
                name: r.get(1)?,
                params: CodingParams {
                    version: r.get::<_, i64>(2)? as u32,
                    k: r.get::<_, i64>(3)? as usize,
                    m: r.get::<_, i64>(4)? as usize,
                    shard_size: r.get::<_, i64>(5)? as usize,
                },
                total_len: r.get::<_, i64>(6)? as u64,
                object_digest: r.get(7)?,
            })
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
    }

    pub fn get_object(&self, id: i64) -> Option<ObjectRow> {
        self.list_objects().into_iter().find(|o| o.id == id)
    }

    pub fn list_sources(&self) -> Vec<SourceRow> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id, name, quarantined FROM sources ORDER BY id")
            .unwrap();
        stmt.query_map([], |r| {
            Ok(SourceRow {
                id: r.get(0)?,
                name: r.get(1)?,
                quarantined: r.get::<_, i64>(2)? != 0,
            })
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
    }

    pub fn set_quarantine(&self, source_id: i64, quarantined: bool) {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE sources SET quarantined=?1 WHERE id=?2",
            params![quarantined as i64, source_id],
        )
        .unwrap();
    }

    pub fn quarantined_source_ids(&self) -> std::collections::BTreeSet<i64> {
        self.list_sources()
            .into_iter()
            .filter(|s| s.quarantined)
            .map(|s| s.id)
            .collect()
    }

    pub fn stripe_count(&self, object: &ObjectRow) -> usize {
        let per = (object.params.k * object.params.shard_size) as u64;
        ((object.total_len + per - 1) / per).max(1) as usize
    }

    pub fn load_candidates(&self, object_id: i64, stripe: usize) -> Vec<Candidate> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT s.id, s.idx, s.generation, s.source_id, src.name, s.bytes, s.digest
                 FROM shards s JOIN sources src ON src.id = s.source_id
                 WHERE s.object_id=?1 AND s.stripe=?2
                 ORDER BY s.id",
            )
            .unwrap();
        stmt.query_map(params![object_id, stripe as i64], |r| {
            Ok(Candidate {
                shard_id: r.get(0)?,
                idx: r.get::<_, i64>(1)? as usize,
                generation: r.get::<_, i64>(2)? as u64,
                source_id: r.get(3)?,
                source: r.get(4)?,
                bytes: r.get(5)?,
                declared_digest: r.get(6)?,
            })
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
    }

    pub fn load_manifest(
        &self,
        object_id: i64,
        stripe: usize,
    ) -> HashMap<usize, ManifestEntry> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT idx, len FROM manifest_entries
                 WHERE object_id=?1 AND stripe=?2",
            )
            .unwrap();
        stmt.query_map(params![object_id, stripe as i64], |r| {
            Ok((
                r.get::<_, i64>(0)? as usize,
                ManifestEntry {
                    idx: r.get::<_, i64>(0)? as usize,
                    len: r.get::<_, i64>(1)? as usize,
                },
            ))
        })
        .unwrap()
        .collect::<Result<HashMap<_, _>, _>>()
        .unwrap()
    }

    pub fn get_commit(&self, object_id: i64, stripe: usize) -> Option<CommitRow> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT stripe, digest, combo_json, committed_at FROM stripe_commits
             WHERE object_id=?1 AND stripe=?2",
            params![object_id, stripe as i64],
            |r| {
                Ok(CommitRow {
                    stripe: r.get::<_, i64>(0)? as usize,
                    digest: r.get(1)?,
                    combo_json: r.get(2)?,
                    committed_at: r.get(3)?,
                })
            },
        )
        .ok()
    }

    pub fn list_commits(&self, object_id: i64) -> Vec<CommitRow> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT stripe, digest, combo_json, committed_at FROM stripe_commits
                 WHERE object_id=?1 ORDER BY stripe",
            )
            .unwrap();
        stmt.query_map(params![object_id], |r| {
            Ok(CommitRow {
                stripe: r.get::<_, i64>(0)? as usize,
                digest: r.get(1)?,
                combo_json: r.get(2)?,
                committed_at: r.get(3)?,
            })
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
    }

    pub fn put_commit(&self, object_id: i64, stripe: usize, digest: &str, combo_json: &str) {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO stripe_commits(object_id, stripe, digest, combo_json, committed_at)
             VALUES(?1,?2,?3,?4, datetime('now'))",
            params![object_id, stripe as i64, digest, combo_json],
        )
        .unwrap();
    }

    pub fn delete_commit(&self, object_id: i64, stripe: usize) {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM stripe_commits WHERE object_id=?1 AND stripe=?2",
            params![object_id, stripe as i64],
        )
        .unwrap();
    }

    pub fn save_analysis(&self, object_id: i64, stripe: usize, analysis: &StripeAnalysis) {
        let json = serde_json::to_string(analysis).unwrap();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO stripe_analyses(object_id, stripe, analysis_json)
             VALUES(?1,?2,?3)",
            params![object_id, stripe as i64, json],
        )
        .unwrap();
    }

    pub fn load_analysis(&self, object_id: i64, stripe: usize) -> Option<StripeAnalysis> {
        let conn = self.conn.lock().unwrap();
        let json: String = conn
            .query_row(
                "SELECT analysis_json FROM stripe_analyses WHERE object_id=?1 AND stripe=?2",
                params![object_id, stripe as i64],
                |r| r.get(0),
            )
            .ok()?;
        serde_json::from_str(&json).ok()
    }

    /// Stripes whose committed combo used the given source (for quarantine
    /// recomputation).
    pub fn commits_using_source(&self, source_id: i64) -> Vec<(i64, usize)> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT object_id, stripe, combo_json FROM stripe_commits")
            .unwrap();
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)? as usize,
                    r.get::<_, String>(2)?,
                ))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        rows.into_iter()
            .filter(|(_, _, json)| {
                serde_json::from_str::<serde_json::Value>(json)
                    .ok()
                    .and_then(|v| {
                        v.get("source_ids").and_then(|s| s.as_array()).map(|a| {
                            a.iter().any(|x| x.as_i64() == Some(source_id))
                        })
                    })
                    .unwrap_or(false)
            })
            .map(|(o, s, _)| (o, s))
            .collect()
    }
}
