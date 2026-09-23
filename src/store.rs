//! SQLite persistence. Recovery commits are per-stripe transactions; temp
//! blocks live in a separate table that final reads never touch.

use crate::model::*;
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::Mutex;

pub struct Store {
    conn: Mutex<Connection>,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS objects(
  object_id TEXT PRIMARY KEY,
  manifest_json TEXT NOT NULL,
  imported_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS shards(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  object_id TEXT NOT NULL,
  idx INTEGER NOT NULL,
  generation INTEGER NOT NULL,
  source TEXT NOT NULL,
  bytes BLOB NOT NULL,
  digest TEXT NOT NULL,
  health TEXT NOT NULL DEFAULT 'ok'
);
CREATE TABLE IF NOT EXISTS stripes(
  object_id TEXT NOT NULL,
  stripe_no INTEGER NOT NULL,
  status TEXT NOT NULL,               -- pending | committed
  committed_digest TEXT,              -- digest of committed alternatives json
  alternatives_json TEXT NOT NULL DEFAULT '[]',
  PRIMARY KEY(object_id, stripe_no)
);
-- Temp blocks produced mid-recovery. Never read by export/final assembly.
CREATE TABLE IF NOT EXISTS temp_blocks(
  object_id TEXT NOT NULL,
  stripe_no INTEGER NOT NULL,
  idx INTEGER NOT NULL,
  data BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS quarantine(
  source TEXT PRIMARY KEY,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS runs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  object_id TEXT NOT NULL,
  status TEXT NOT NULL,               -- completed | interrupted | failed
  note TEXT NOT NULL DEFAULT '',
  started_at TEXT NOT NULL DEFAULT (datetime('now')),
  finished_at TEXT
);
";

impl Store {
    pub fn open(path: &Path) -> rusqlite::Result<Store> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).ok();
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Store { conn: Mutex::new(conn) })
    }

    pub fn open_memory() -> rusqlite::Result<Store> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Store { conn: Mutex::new(conn) })
    }

    pub fn put_manifest(&self, m: &Manifest) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO objects(object_id, manifest_json) VALUES(?1, ?2)
             ON CONFLICT(object_id) DO UPDATE SET manifest_json=excluded.manifest_json",
            params![m.object_id, serde_json::to_string(m).unwrap()],
        )?;
        Ok(())
    }

    pub fn get_manifest(&self, object_id: &str) -> rusqlite::Result<Option<Manifest>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT manifest_json FROM objects WHERE object_id=?1")?;
        let mut rows = stmt.query(params![object_id])?;
        Ok(match rows.next()? {
            Some(row) => {
                let j: String = row.get(0)?;
                Some(serde_json::from_str(&j).expect("manifest json"))
            }
            None => None,
        })
    }

    pub fn list_objects(&self) -> rusqlite::Result<Vec<Manifest>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT manifest_json FROM objects ORDER BY object_id")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        Ok(rows
            .filter_map(|r| r.ok())
            .map(|j| serde_json::from_str(&j).expect("manifest json"))
            .collect())
    }

    pub fn add_shard(
        &self,
        object_id: &str,
        idx: usize,
        generation: u64,
        source: &str,
        bytes: &[u8],
    ) -> rusqlite::Result<i64> {
        let conn = self.conn.lock().unwrap();
        let digest = sha256_hex(bytes);
        conn.execute(
            "INSERT INTO shards(object_id, idx, generation, source, bytes, digest)
             VALUES(?1,?2,?3,?4,?5,?6)",
            params![object_id, idx as i64, generation as i64, source, bytes, digest],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn shards_for(&self, object_id: &str) -> rusqlite::Result<Vec<ShardRecord>> {
        let conn = self.conn.lock().unwrap();
        let quarantined = self.quarantined_sources_locked(&conn)?;
        let mut stmt = conn.prepare(
            "SELECT id, object_id, idx, generation, source, bytes, digest, health
             FROM shards WHERE object_id=?1
             ORDER BY idx, generation DESC, digest, source, id",
        )?;
        let rows = stmt.query_map(params![object_id], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, Vec<u8>>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, String>(7)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (id, oid, idx, gen, source, bytes, digest, health) = r?;
            let mut h = ShardHealth::from_str(&health);
            if h == ShardHealth::Ok && quarantined.contains(&source) {
                h = ShardHealth::Quarantined;
            }
            out.push(ShardRecord {
                id,
                object_id: oid,
                idx: idx as usize,
                generation: gen as u64,
                source,
                bytes,
                digest,
                health: h,
            });
        }
        Ok(out)
    }

    pub fn set_shard_health(&self, shard_id: i64, health: ShardHealth) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE shards SET health=?1 WHERE id=?2",
            params![health.as_str(), shard_id],
        )?;
        Ok(())
    }

    fn quarantined_sources_locked(&self, conn: &Connection) -> rusqlite::Result<Vec<String>> {
        let mut stmt = conn.prepare("SELECT source FROM quarantine ORDER BY source")?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn quarantined_sources(&self) -> rusqlite::Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        self.quarantined_sources_locked(&conn)
    }

    pub fn quarantine_source(&self, source: &str) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO quarantine(source) VALUES(?1)",
            params![source],
        )?;
        Ok(())
    }

    pub fn unquarantine_source(&self, source: &str) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM quarantine WHERE source=?1", params![source])?;
        Ok(())
    }

    /// Reset all stripes of an object to pending (used before a fresh run).
    pub fn reset_stripes(&self, object_id: &str) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM stripes WHERE object_id=?1",
            params![object_id],
        )?;
        conn.execute(
            "DELETE FROM temp_blocks WHERE object_id=?1",
            params![object_id],
        )?;
        Ok(())
    }

    /// Reset a single stripe back to pending (used by quarantine recompute).
    pub fn reset_stripe(&self, object_id: &str, stripe_no: usize) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM stripes WHERE object_id=?1 AND stripe_no=?2",
            params![object_id, stripe_no as i64],
        )?;
        conn.execute(
            "DELETE FROM temp_blocks WHERE object_id=?1 AND stripe_no=?2",
            params![object_id, stripe_no as i64],
        )?;
        Ok(())
    }

    /// Drop leftover temp blocks (crash recovery). Temp blocks are never
    /// read by final assembly; this just keeps the chamber tidy.
    pub fn clear_temp_blocks(&self, object_id: &str) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM temp_blocks WHERE object_id=?1",
            params![object_id],
        )?;
        Ok(())
    }

    pub fn add_temp_block(
        &self,
        object_id: &str,
        stripe_no: usize,
        idx: usize,
        data: &[u8],
    ) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO temp_blocks(object_id, stripe_no, idx, data) VALUES(?1,?2,?3,?4)",
            params![object_id, stripe_no as i64, idx as i64, data],
        )?;
        Ok(())
    }

    pub fn temp_block_count(&self, object_id: &str) -> rusqlite::Result<usize> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT COUNT(*) FROM temp_blocks WHERE object_id=?1",
            params![object_id],
            |r| r.get::<_, i64>(0),
        )
        .map(|c| c as usize)
    }

    /// Atomically commit one stripe: alternatives + digest, single transaction.
    pub fn commit_stripe(
        &self,
        object_id: &str,
        stripe_no: usize,
        alternatives: &[StripeAlternative],
    ) -> rusqlite::Result<()> {
        let json = serde_json::to_string(alternatives).unwrap();
        let digest = sha256_hex(json.as_bytes());
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO stripes(object_id, stripe_no, status, committed_digest, alternatives_json)
             VALUES(?1,?2,'committed',?3,?4)
             ON CONFLICT(object_id, stripe_no) DO UPDATE SET
               status='committed', committed_digest=excluded.committed_digest,
               alternatives_json=excluded.alternatives_json",
            params![object_id, stripe_no as i64, digest, json],
        )?;
        // Any temp blocks for this stripe become garbage once committed.
        tx.execute(
            "DELETE FROM temp_blocks WHERE object_id=?1 AND stripe_no=?2",
            params![object_id, stripe_no as i64],
        )?;
        tx.commit()
    }

    /// Load committed stripes whose stored digest still verifies. Anything
    /// else is treated as uncommitted and will be recomputed.
    pub fn committed_stripes(&self, object_id: &str) -> rusqlite::Result<Vec<StripeState>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT stripe_no, committed_digest, alternatives_json FROM stripes
             WHERE object_id=?1 AND status='committed' ORDER BY stripe_no",
        )?;
        let rows = stmt.query_map(params![object_id], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (no, digest, json) = r?;
            // Only reuse stripes whose digest is complete and verifies.
            let verified = match &digest {
                Some(d) => *d == sha256_hex(json.as_bytes()),
                None => false,
            };
            if verified {
                let alternatives: Vec<StripeAlternative> =
                    serde_json::from_str(&json).unwrap_or_default();
                out.push(StripeState {
                    stripe_no: no as usize,
                    status: "committed".into(),
                    committed_digest: digest,
                    alternatives,
                });
            }
        }
        Ok(out)
    }

    pub fn stripe_states(&self, object_id: &str, stripe_count: usize) -> rusqlite::Result<Vec<StripeState>> {
        let committed = self.committed_stripes(object_id)?;
        let mut out = Vec::with_capacity(stripe_count);
        for no in 0..stripe_count {
            if let Some(s) = committed.iter().find(|s| s.stripe_no == no) {
                out.push(s.clone());
            } else {
                out.push(StripeState {
                    stripe_no: no,
                    status: "pending".into(),
                    committed_digest: None,
                    alternatives: Vec::new(),
                });
            }
        }
        Ok(out)
    }

    pub fn start_run(&self, object_id: &str) -> rusqlite::Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO runs(object_id, status) VALUES(?1, 'running')",
            params![object_id],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn finish_run(&self, run_id: i64, status: &str, note: &str) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE runs SET status=?1, note=?2, finished_at=datetime('now') WHERE id=?3",
            params![status, note, run_id],
        )?;
        Ok(())
    }

    pub fn sources(&self) -> rusqlite::Result<Vec<(String, bool)>> {
        let conn = self.conn.lock().unwrap();
        let quarantined = self.quarantined_sources_locked(&conn)?;
        let mut stmt = conn.prepare("SELECT DISTINCT source FROM shards ORDER BY source")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        Ok(rows
            .filter_map(|r| r.ok())
            .map(|s| {
                let q = quarantined.contains(&s);
                (s, q)
            })
            .collect())
    }
}
