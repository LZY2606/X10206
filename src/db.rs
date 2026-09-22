//! SQLite persistence: objects, imported shards, and per-stripe commits.

use std::path::Path;

use anyhow::Context;
use rusqlite::{params, Connection, OptionalExtension};

use crate::model::{Manifest, ObjectRow, ShardRow, StripeRow};

pub struct Db {
    pub conn: Connection,
}

impl Db {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create data dir {}", parent.display()))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("open database {}", path.display()))?;
        let db = Self { conn };
        db.init()?;
        Ok(db)
    }

    pub fn open_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn };
        db.init()?;
        Ok(db)
    }

    fn init(&self) -> anyhow::Result<()> {
        self.conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS objects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                profile_version INTEGER NOT NULL,
                k INTEGER NOT NULL,
                m INTEGER NOT NULL,
                shard_size INTEGER NOT NULL,
                stripe_count INTEGER NOT NULL,
                object_digest TEXT,
                manifest_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS shards (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                object_id INTEGER NOT NULL REFERENCES objects(id),
                stripe INTEGER NOT NULL,
                shard_index INTEGER NOT NULL,
                generation INTEGER NOT NULL,
                source TEXT NOT NULL,
                claimed_digest TEXT NOT NULL,
                actual_digest TEXT NOT NULL,
                length INTEGER NOT NULL,
                data BLOB NOT NULL,
                quarantined INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_shards_obj_stripe
                ON shards(object_id, stripe);
            CREATE TABLE IF NOT EXISTS stripes (
                object_id INTEGER NOT NULL REFERENCES objects(id),
                stripe INTEGER NOT NULL,
                state TEXT NOT NULL,
                result_json TEXT,
                digest TEXT,
                committed_at TEXT,
                PRIMARY KEY (object_id, stripe)
            );
            ",
        )?;
        Ok(())
    }

    pub fn insert_object(&self, manifest: &Manifest) -> anyhow::Result<i64> {
        let tx = self.conn.unchecked_transaction()?;
        let manifest_json = serde_json::to_string(manifest)?;
        tx.execute(
            "INSERT INTO objects
             (name, profile_version, k, m, shard_size, stripe_count, object_digest, manifest_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                manifest.name,
                manifest.profile_version,
                manifest.k as i64,
                manifest.m as i64,
                manifest.shard_size as i64,
                manifest.stripe_count as i64,
                manifest.object_digest,
                manifest_json,
            ],
        )?;
        let object_id = tx.last_insert_rowid();
        for stripe in 0..manifest.stripe_count {
            tx.execute(
                "INSERT INTO stripes (object_id, stripe, state) VALUES (?1, ?2, 'pending')",
                params![object_id, stripe as i64],
            )?;
        }
        tx.commit()?;
        Ok(object_id)
    }

    pub fn list_objects(&self) -> anyhow::Result<Vec<ObjectRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, profile_version, k, m, shard_size, stripe_count,
                    object_digest, manifest_json
             FROM objects ORDER BY id",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(ObjectRow {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    profile_version: r.get::<_, i64>(2)? as u32,
                    k: r.get::<_, i64>(3)? as usize,
                    m: r.get::<_, i64>(4)? as usize,
                    shard_size: r.get::<_, i64>(5)? as usize,
                    stripe_count: r.get::<_, i64>(6)? as usize,
                    object_digest: r.get(7)?,
                    manifest_json: r.get(8)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn get_object(&self, id: i64) -> anyhow::Result<Option<ObjectRow>> {
        Ok(self
            .list_objects()?
            .into_iter()
            .find(|o| o.id == id))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_shard(
        &self,
        object_id: i64,
        stripe: usize,
        shard_index: usize,
        generation: i64,
        source: &str,
        claimed_digest: &str,
        actual_digest: &str,
        data: &[u8],
    ) -> anyhow::Result<i64> {
        self.conn.execute(
            "INSERT INTO shards
             (object_id, stripe, shard_index, generation, source,
              claimed_digest, actual_digest, length, data)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                object_id,
                stripe as i64,
                shard_index as i64,
                generation,
                source,
                claimed_digest,
                actual_digest,
                data.len() as i64,
                data,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn list_shards(&self, object_id: i64) -> anyhow::Result<Vec<ShardRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, object_id, stripe, shard_index, generation, source,
                    claimed_digest, actual_digest, length, quarantined
             FROM shards WHERE object_id = ?1
             ORDER BY stripe, shard_index, generation, id",
        )?;
        let rows = stmt
            .query_map(params![object_id], |r| {
                Ok(ShardRow {
                    id: r.get(0)?,
                    object_id: r.get(1)?,
                    stripe: r.get::<_, i64>(2)? as usize,
                    shard_index: r.get::<_, i64>(3)? as usize,
                    generation: r.get(4)?,
                    source: r.get(5)?,
                    claimed_digest: r.get(6)?,
                    actual_digest: r.get(7)?,
                    length: r.get::<_, i64>(8)? as usize,
                    quarantined: r.get::<_, i64>(9)? != 0,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn shard_bytes(&self, shard_id: i64) -> anyhow::Result<Vec<u8>> {
        let data: Vec<u8> = self.conn.query_row(
            "SELECT data FROM shards WHERE id = ?1",
            params![shard_id],
            |r| r.get(0),
        )?;
        Ok(data)
    }

    pub fn get_stripe(&self, object_id: i64, stripe: usize) -> anyhow::Result<Option<StripeRow>> {
        self.conn
            .query_row(
                "SELECT stripe, state, result_json, digest, committed_at
                 FROM stripes WHERE object_id = ?1 AND stripe = ?2",
                params![object_id, stripe as i64],
                |r| {
                    Ok(StripeRow {
                        stripe: r.get::<_, i64>(0)? as usize,
                        state: r.get(1)?,
                        result_json: r.get(2)?,
                        digest: r.get(3)?,
                        committed_at: r.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn list_stripes(&self, object_id: i64) -> anyhow::Result<Vec<StripeRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT stripe, state, result_json, digest, committed_at
             FROM stripes WHERE object_id = ?1 ORDER BY stripe",
        )?;
        let rows = stmt
            .query_map(params![object_id], |r| {
                Ok(StripeRow {
                    stripe: r.get::<_, i64>(0)? as usize,
                    state: r.get(1)?,
                    result_json: r.get(2)?,
                    digest: r.get(3)?,
                    committed_at: r.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Commit a stripe result atomically. Only committed rows whose stored
    /// digest matches the result payload are ever reused later.
    pub fn commit_stripe(
        &self,
        object_id: i64,
        stripe: usize,
        result_json: &str,
        digest: &str,
    ) -> anyhow::Result<()> {
        self.conn.execute(
            "UPDATE stripes SET state = 'committed', result_json = ?3, digest = ?4,
                committed_at = datetime('now')
             WHERE object_id = ?1 AND stripe = ?2",
            params![object_id, stripe as i64, result_json, digest],
        )?;
        Ok(())
    }

    pub fn reset_stripe(&self, object_id: i64, stripe: usize) -> anyhow::Result<()> {
        self.conn.execute(
            "UPDATE stripes SET state = 'pending', result_json = NULL,
                digest = NULL, committed_at = NULL
             WHERE object_id = ?1 AND stripe = ?2",
            params![object_id, stripe as i64],
        )?;
        Ok(())
    }

    /// Quarantine every shard received from `source`; returns affected ids.
    pub fn quarantine_source(&self, object_id: i64, source: &str) -> anyhow::Result<usize> {
        let n = self.conn.execute(
            "UPDATE shards SET quarantined = 1
             WHERE object_id = ?1 AND source = ?2",
            params![object_id, source],
        )?;
        Ok(n)
    }
}
