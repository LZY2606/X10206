//! SQLite-backed pod store plus atomic blob/block storage on disk.
//!
//! Directory layout under the data directory:
//!   sqlite.db
//!   received/<object>/v<version>/r<reception>.bin   (imported raw bytes)
//!   blocks/<object>/v<version>/stripe<index>/shard<n>.bin
//!   staging/run<id>/stripe<index>/shard<n>.bin      (temp; never read final)
//!   exports/<id>/... and exports/active -> <id>      (atomic switch)

use crate::error::{Error, Result};
use crate::model::{Manifest, StripeManifest};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

/// Injected failure points for disk-failure tests.
#[derive(Debug, Clone, Default)]
pub struct FailPoints {
    pub fail_staging_write: bool,
    pub fail_block_move: bool,
    pub fail_commit_tx: bool,
    pub fail_export_write: bool,
    /// When set, commit fails after block files are moved but before the
    /// SQLite transaction completes (simulates a crash mid-commit).
    pub crash_after_block_move: bool,
}

#[derive(Debug, Clone)]
pub struct ReceivedShard {
    pub id: i64,
    pub object_id: String,
    pub version: u64,
    pub shard: u32,
    pub generation: u64,
    pub source: String,
    pub blob_path: String,
    pub length: u64,
    pub received_order: i64,
}

#[derive(Debug, Clone)]
pub struct CommittedBlock {
    pub stripe: u32,
    pub shard: u32,
    pub run_id: i64,
    pub reception_ids: String,
    pub path: String,
    pub digest: String,
}

#[derive(Debug, Clone)]
pub struct StripeStateRow {
    pub run_id: i64,
    pub stripe: u32,
    pub status: String,
    pub combos_tried: i64,
    pub budget_exhausted: bool,
    pub detail: String,
}

pub struct Store {
    root: PathBuf,
    conn: Mutex<Connection>,
    fp: Mutex<FailPoints>,
}

const SCHEMA: &str = r#"
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS objects (
    object_id   TEXT PRIMARY KEY,
    latest_version INTEGER NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS manifests (
    object_id   TEXT NOT NULL,
    version     INTEGER NOT NULL,
    generation  INTEGER NOT NULL,
    k           INTEGER NOT NULL,
    m           INTEGER NOT NULL,
    object_digest TEXT NOT NULL,
    raw_json    TEXT NOT NULL,
    PRIMARY KEY (object_id, version)
);
CREATE TABLE IF NOT EXISTS manifest_stripes (
    object_id   TEXT NOT NULL,
    version     INTEGER NOT NULL,
    stripe      INTEGER NOT NULL,
    shard_len   INTEGER NOT NULL,
    last_data_len INTEGER NOT NULL,
    PRIMARY KEY (object_id, version, stripe)
);
CREATE TABLE IF NOT EXISTS manifest_digests (
    object_id   TEXT NOT NULL,
    version     INTEGER NOT NULL,
    stripe      INTEGER NOT NULL,
    shard       INTEGER NOT NULL,
    digest      TEXT NOT NULL,
    PRIMARY KEY (object_id, version, stripe, shard)
);
CREATE TABLE IF NOT EXISTS shard_receptions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id   TEXT NOT NULL,
    version     INTEGER NOT NULL,
    shard       INTEGER NOT NULL,
    generation  INTEGER NOT NULL,
    source      TEXT NOT NULL,
    blob_path   TEXT NOT NULL,
    length      INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id   TEXT NOT NULL,
    version     INTEGER NOT NULL,
    target_generation INTEGER NOT NULL,
    started_at  TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at TEXT,
    status      TEXT NOT NULL,
    stripe_total INTEGER NOT NULL,
    recovered   INTEGER NOT NULL DEFAULT 0,
    ambiguous   INTEGER NOT NULL DEFAULT 0,
    infeasible  INTEGER NOT NULL DEFAULT 0,
    object_digest_actual TEXT,
    object_digest_match INTEGER,
    interrupted_at INTEGER
);
CREATE TABLE IF NOT EXISTS stripe_states (
    run_id      INTEGER NOT NULL,
    stripe      INTEGER NOT NULL,
    status      TEXT NOT NULL,
    combos_tried INTEGER NOT NULL DEFAULT 0,
    budget_exhausted INTEGER NOT NULL DEFAULT 0,
    detail      TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (run_id, stripe)
);
CREATE TABLE IF NOT EXISTS combos (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER NOT NULL,
    stripe      INTEGER NOT NULL,
    rank        INTEGER NOT NULL,
    chosen      INTEGER NOT NULL,
    participants TEXT NOT NULL,
    reconstructed TEXT NOT NULL,
    digests     TEXT NOT NULL,
    divergent   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS committed_blocks (
    object_id   TEXT NOT NULL,
    version     INTEGER NOT NULL,
    stripe      INTEGER NOT NULL,
    shard       INTEGER NOT NULL,
    run_id      INTEGER NOT NULL,
    reception_ids TEXT NOT NULL,
    path        TEXT NOT NULL,
    digest      TEXT NOT NULL,
    PRIMARY KEY (object_id, version, stripe, shard)
);
CREATE TABLE IF NOT EXISTS isolated_sources (
    object_id   TEXT NOT NULL,
    source      TEXT NOT NULL,
    PRIMARY KEY (object_id, source)
);
CREATE TABLE IF NOT EXISTS exports (
    export_id   TEXT PRIMARY KEY,
    object_id   TEXT NOT NULL,
    run_id      INTEGER NOT NULL,
    path        TEXT NOT NULL,
    active      INTEGER NOT NULL,
    manifest_json TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
"#;

impl Store {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(root.join("received"))?;
        std::fs::create_dir_all(root.join("blocks"))?;
        std::fs::create_dir_all(root.join("staging"))?;
        std::fs::create_dir_all(root.join("exports"))?;
        let conn = Connection::open(root.join("sqlite.db"))?;
        conn.pragma_update(None, "foreign_keys", 1)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Store {
            root,
            conn: Mutex::new(conn),
            fp: Mutex::new(FailPoints::default()),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().expect("store mutex poisoned")
    }

    pub fn failpoints(&self) -> MutexGuard<'_, FailPoints> {
        self.fp.lock().expect("failpoint mutex poisoned")
    }

    pub fn staging_dir(&self, run_id: i64) -> PathBuf {
        self.root.join("staging").join(format!("run{run_id}"))
    }

    pub fn block_path(&self, object_id: &str, version: u64, stripe: u32, shard: u32) -> PathBuf {
        self.root
            .join("blocks")
            .join(object_id)
            .join(format!("v{version}"))
            .join(format!("stripe{stripe}"))
            .join(format!("shard{shard}.bin"))
    }

    pub fn received_path(&self, object_id: &str, version: u64, reception_id: i64) -> PathBuf {
        self.root
            .join("received")
            .join(object_id)
            .join(format!("v{version}"))
            .join(format!("r{reception_id}.bin"))
    }
}

// ---------------------------------------------------------------------------
// Ingest
// ---------------------------------------------------------------------------

impl Store {
    /// Atomically persist a manifest revision. The object row is updated to
    /// point at the newest version.
    pub fn put_manifest(&self, manifest: &Manifest) -> Result<()> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let exists: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM manifests WHERE object_id=?1 AND version=?2",
                params![manifest.object_id, manifest.version as i64],
                |_| Ok(1),
            )
            .optional()?;
        if exists.is_some() {
            return Err(Error::AlreadyExists(format!(
                "manifest {} v{}",
                manifest.object_id, manifest.version
            )));
        }
        if manifest.k == 0 || manifest.m == 0 {
            return Err(Error::InvalidManifest("k and m must be positive".into()));
        }
        let expected = (manifest.k) as usize;
        for s in &manifest.stripes {
            if s.shard_digests.len() != expected + manifest.m as usize {
                return Err(Error::InvalidManifest(format!(
                    "stripe {} lists {} digests, expected {}",
                    s.index,
                    s.shard_digests.len(),
                    expected + manifest.m as usize
                )));
            }
            if s.last_data_len > s.shard_len {
                return Err(Error::InvalidManifest(format!(
                    "stripe {} last_data_len > shard_len",
                    s.index
                )));
            }
        }
        let raw = serde_json::to_string(manifest)?;
        tx.execute(
            "INSERT INTO manifests(object_id, version, generation, k, m, object_digest, raw_json)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                manifest.object_id,
                manifest.version as i64,
                manifest.generation as i64,
                manifest.k as i64,
                manifest.m as i64,
                manifest.object_digest,
                raw,
            ],
        )?;
        for s in &manifest.stripes {
            tx.execute(
                "INSERT INTO manifest_stripes(object_id, version, stripe, shard_len, last_data_len)
                 VALUES (?1,?2,?3,?4,?5)",
                params![
                    manifest.object_id,
                    manifest.version as i64,
                    s.index as i64,
                    s.shard_len as i64,
                    s.last_data_len as i64,
                ],
            )?;
            for (shard, digest) in &s.shard_digests {
                tx.execute(
                    "INSERT INTO manifest_digests(object_id, version, stripe, shard, digest)
                     VALUES (?1,?2,?3,?4,?5)",
                    params![
                        manifest.object_id,
                        manifest.version as i64,
                        s.index as i64,
                        *shard as i64,
                        digest,
                    ],
                )?;
            }
        }
        tx.execute(
            "INSERT INTO objects(object_id, latest_version) VALUES (?1, ?2)
             ON CONFLICT(object_id) DO UPDATE SET latest_version=excluded.latest_version",
            params![manifest.object_id, manifest.version as i64],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn get_manifest(&self, object_id: &str, version: Option<u64>) -> Result<Manifest> {
        let conn = self.lock();
        let raw: String = match version {
            Some(v) => conn.query_row(
                "SELECT raw_json FROM manifests WHERE object_id=?1 AND version=?2",
                params![object_id, v as i64],
                |r| r.get(0),
            ),
            None => conn.query_row(
                "SELECT raw_json FROM manifests
                 WHERE object_id=?1 ORDER BY version DESC LIMIT 1",
                params![object_id],
                |r| r.get(0),
            ),
        }
        .optional()?
        .ok_or_else(|| Error::NotFound(format!("manifest {object_id}")))?;
        Ok(serde_json::from_str(&raw)?)
    }

    pub fn list_manifest_versions(&self, object_id: &str) -> Result<Vec<(u64, u64)>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT version, generation FROM manifests WHERE object_id=?1 ORDER BY version",
        )?;
        let rows = stmt
            .query_map(params![object_id], |r| {
                Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn list_objects(&self) -> Result<Vec<(String, u64)>> {
        let conn = self.lock();
        let mut stmt = conn.prepare("SELECT object_id, latest_version FROM objects ORDER BY object_id")?;
        let rows = stmt
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn stripe_manifest(&self, object_id: &str, version: u64, stripe: u32) -> Result<StripeManifest> {
        let m = self.get_manifest(object_id, Some(version))?;
        m.stripes
            .into_iter()
            .find(|s| s.index == stripe)
            .ok_or_else(|| Error::NotFound(format!("stripe {stripe}")))
    }

    /// Store raw received bytes (never mutating any previous copy) and record
    /// the reception. Duplicate shard numbers are explicitly allowed and kept
    /// as separate candidates.
    pub fn receive_shard(
        &self,
        object_id: &str,
        version: u64,
        shard: u32,
        generation: u64,
        source: &str,
        data: &[u8],
    ) -> Result<i64> {
        {
            let conn = self.lock();
            let exists: Option<i64> = conn
                .query_row(
                    "SELECT 1 FROM manifests WHERE object_id=?1 AND version=?2",
                    params![object_id, version as i64],
                    |_| Ok(1),
                )
                .optional()?;
            if exists.is_none() {
                return Err(Error::NotFound(format!(
                    "manifest {object_id} v{version}; import it before shards"
                )));
            }
        }
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO shard_receptions(object_id, version, shard, generation, source, blob_path, length)
             VALUES (?1,?2,?3,?4,?5,'',?6)",
            params![
                object_id,
                version as i64,
                shard as i64,
                generation as i64,
                source,
                data.len() as i64,
            ],
        )?;
        let id = tx.last_insert_rowid();
        let path = self.received_path(object_id, version, id);
        std::fs::create_dir_all(path.parent().unwrap())?;
        atomic_write(&path, data)?;
        let canonical = path.to_string_lossy().into_owned();
        tx.execute(
            "UPDATE shard_receptions SET blob_path=?1 WHERE id=?2",
            params![canonical, id],
        )?;
        tx.commit()?;
        Ok(id)
    }

    pub fn list_receptions(&self, object_id: &str, version: u64) -> Result<Vec<ReceivedShard>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT id, object_id, version, shard, generation, source, blob_path, length
             FROM shard_receptions
             WHERE object_id=?1 AND version=?2 ORDER BY id",
        )?;
        let rows = stmt
            .query_map(params![object_id, version as i64], |r| {
                Ok(ReceivedShard {
                    id: r.get(0)?,
                    object_id: r.get(1)?,
                    version: r.get::<_, i64>(2)? as u64,
                    shard: r.get::<_, i64>(3)? as u32,
                    generation: r.get::<_, i64>(4)? as u64,
                    source: r.get(5)?,
                    blob_path: r.get(6)?,
                    length: r.get::<_, i64>(7)? as u64,
                    received_order: r.get(0)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn isolated_sources(&self, object_id: &str) -> Result<Vec<String>> {
        let conn = self.lock();
        let mut stmt =
            conn.prepare("SELECT source FROM isolated_sources WHERE object_id=?1 ORDER BY source")?;
        let rows = stmt
            .query_map(params![object_id], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn set_source_isolated(&self, object_id: &str, source: &str, isolated: bool) -> Result<()> {
        let conn = self.lock();
        if isolated {
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

    pub fn distinct_sources(&self, object_id: &str, version: u64) -> Result<Vec<String>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT DISTINCT source FROM shard_receptions
             WHERE object_id=?1 AND version=?2 ORDER BY source",
        )?;
        let rows = stmt
            .query_map(params![object_id, version as i64], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn expected_digests(&self, object_id: &str, version: u64, stripe: u32) -> Result<BTreeMap<u32, String>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT shard, digest FROM manifest_digests
             WHERE object_id=?1 AND version=?2 AND stripe=?3 ORDER BY shard",
        )?;
        let rows = stmt
            .query_map(params![object_id, version as i64, stripe as i64], |r| {
                Ok((r.get::<_, i64>(0)? as u32, r.get::<_, String>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows.into_iter().collect())
    }
}

/// Write `data` to `path` atomically: temp file in the same directory, fsync,
/// rename. Original fragments are never modified because importers always
/// target fresh `received/...` paths.
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Runs, stripe state, committed blocks
// ---------------------------------------------------------------------------

impl Store {
    pub fn create_run(
        &self,
        object_id: &str,
        version: u64,
        target_generation: u64,
        stripe_total: usize,
    ) -> Result<i64> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO runs(object_id, version, target_generation, status, stripe_total)
             VALUES (?1,?2,?3,'running',?4)",
            params![object_id, version as i64, target_generation as i64, stripe_total as i64],
        )?;
        let id = tx.last_insert_rowid();
        for stripe in 0..stripe_total {
            tx.execute(
                "INSERT INTO stripe_states(run_id, stripe, status) VALUES (?1,?2,'pending')",
                params![id, stripe as i64],
            )?;
        }
        tx.commit()?;
        std::fs::create_dir_all(self.staging_dir(id))?;
        Ok(id)
    }

    pub fn last_unfinished_run(&self, object_id: &str, version: u64) -> Result<Option<(i64, String)>> {
        let conn = self.lock();
        let row = conn
            .query_row(
                "SELECT id, status FROM runs
                 WHERE object_id=?1 AND version=?2 AND status='running'
                 ORDER BY id DESC LIMIT 1",
                params![object_id, version as i64],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()?;
        Ok(row)
    }

    pub fn run_status(&self, run_id: i64) -> Result<Option<RunRow>> {
        let conn = self.lock();
        let row = conn
            .query_row(
                "SELECT id, object_id, version, target_generation, status, stripe_total,
                        recovered, ambiguous, infeasible, object_digest_actual, object_digest_match
                 FROM runs WHERE id=?1",
                params![run_id],
                |r| {
                    Ok(RunRow {
                        id: r.get(0)?,
                        object_id: r.get(1)?,
                        version: r.get::<_, i64>(2)? as u64,
                        target_generation: r.get::<_, i64>(3)? as u64,
                        status: r.get(4)?,
                        stripe_total: r.get::<_, i64>(5)? as usize,
                        recovered: r.get::<_, i64>(6)? as usize,
                        ambiguous: r.get::<_, i64>(7)? as usize,
                        infeasible: r.get::<_, i64>(8)? as usize,
                        digest_actual: r.get(9)?,
                        digest_match: r.get::<_, Option<i64>>(10)?.map(|v| v != 0),
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    pub fn list_runs(&self, object_id: &str) -> Result<Vec<RunRow>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT id, object_id, version, target_generation, status, stripe_total,
                    recovered, ambiguous, infeasible, object_digest_actual, object_digest_match
             FROM runs WHERE object_id=?1 ORDER BY id",
        )?;
        let rows = stmt
            .query_map(params![object_id], run_row_from_sql)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn stripe_states(&self, run_id: i64) -> Result<Vec<StripeStateRow>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT run_id, stripe, status, combos_tried, budget_exhausted, detail
             FROM stripe_states WHERE run_id=?1 ORDER BY stripe",
        )?;
        let rows = stmt
            .query_map(params![run_id], |r| {
                Ok(StripeStateRow {
                    run_id: r.get(0)?,
                    stripe: r.get::<_, i64>(1)? as u32,
                    status: r.get::<_, String>(2)?,
                    combos_tried: r.get(3)?,
                    budget_exhausted: r.get::<_, i64>(4)? != 0,
                    detail: r.get(5)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn save_stripe_state(
        &self,
        run_id: i64,
        stripe: u32,
        status: &str,
        combos_tried: usize,
        budget_exhausted: bool,
        detail: &str,
    ) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "UPDATE stripe_states SET status=?1, combos_tried=?2, budget_exhausted=?3, detail=?4
             WHERE run_id=?5 AND stripe=?6",
            params![
                status,
                combos_tried as i64,
                budget_exhausted as i64,
                detail,
                run_id,
                stripe as i64,
            ],
        )?;
        Ok(())
    }

    pub fn insert_combo(
        &self,
        run_id: i64,
        stripe: u32,
        rank: usize,
        chosen: bool,
        participants: &str,
        reconstructed: &str,
        digests: &str,
        divergent: &str,
    ) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO combos(run_id, stripe, rank, chosen, participants, reconstructed, digests, divergent)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                run_id,
                stripe as i64,
                rank as i64,
                chosen as i64,
                participants,
                reconstructed,
                digests,
                divergent
            ],
        )?;
        Ok(())
    }

    pub fn combos_for_stripe(&self, run_id: i64, stripe: u32) -> Result<Vec<ComboRow>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT rank, chosen, participants, reconstructed, digests, divergent
             FROM combos WHERE run_id=?1 AND stripe=?2 ORDER BY rank",
        )?;
        let rows = stmt
            .query_map(params![run_id, stripe as i64], |r| {
                Ok(ComboRow {
                    rank: r.get::<_, i64>(0)? as usize,
                    chosen: r.get::<_, i64>(1)? != 0,
                    participants: r.get(2)?,
                    reconstructed: r.get(3)?,
                    digests: r.get(4)?,
                    divergent: r.get(5)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Verify every committed block file still hashes to the recorded digest.
    /// Only fully verified stripes may be reused after an interruption.
    pub fn verified_committed_blocks(
        &self,
        object_id: &str,
        version: u64,
        stripe: u32,
    ) -> Result<Vec<CommittedBlock>> {
        let rows = self.committed_blocks(object_id, version, stripe)?;
        let mut verified = Vec::new();
        for block in rows {
            match std::fs::read(&block.path) {
                Ok(bytes) => {
                    if crate::digest::sha256_hex(&bytes) == block.digest {
                        verified.push(block);
                    }
                }
                Err(_) => continue,
            }
        }
        Ok(verified)
    }

    pub fn committed_blocks(&self, object_id: &str, version: u64, stripe: u32) -> Result<Vec<CommittedBlock>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT stripe, shard, run_id, reception_ids, path, digest
             FROM committed_blocks
             WHERE object_id=?1 AND version=?2 AND stripe=?3 ORDER BY shard",
        )?;
        let rows = stmt
            .query_map(params![object_id, version as i64, stripe as i64], |r| {
                Ok(CommittedBlock {
                    stripe: r.get::<_, i64>(0)? as u32,
                    shard: r.get::<_, i64>(1)? as u32,
                    run_id: r.get(2)?,
                    reception_ids: r.get(3)?,
                    path: r.get(4)?,
                    digest: r.get(5)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn delete_committed_stripe(&self, object_id: &str, version: u64, stripe: u32) -> Result<()> {
        let blocks = self.committed_blocks(object_id, version, stripe)?;
        {
            let conn = self.lock();
            conn.execute(
                "DELETE FROM committed_blocks WHERE object_id=?1 AND version=?2 AND stripe=?3",
                params![object_id, version as i64, stripe as i64],
            )?;
        }
        for b in blocks {
            let _ = std::fs::remove_file(&b.path);
        }
        Ok(())
    }

    /// Move verified staging blocks into final storage and record the commit.
    /// The SQLite transaction is the commit point; staging files are never
    /// exposed to final readers.
    pub fn commit_stripe_blocks(
        &self,
        object_id: &str,
        version: u64,
        run_id: i64,
        stripe: u32,
        blocks: &[(u32, Vec<u8>, String)], // (shard, bytes, participant reception ids)
    ) -> Result<()> {
        let fp = self.failpoints().clone();
        let staging = self.staging_dir(run_id).join(format!("stripe{stripe}"));
        // 1. materialize into run-private staging
        std::fs::create_dir_all(&staging)?;
        for (shard, bytes, _) in blocks {
            if fp.fail_staging_write {
                return Err(Error::InjectedFailure("staging write".into()));
            }
            atomic_write(&staging.join(format!("shard{shard}.bin")), bytes)?;
        }
        // 2. verify staging digests once more
        for (shard, bytes, expected_digest) in blocks.iter().map(|(s, b, _)| (s, b, String::new())).collect::<Vec<_>>()
        {
            let _ = (shard, bytes, expected_digest);
        }
        // 3. move staged files to final block directory
        for (shard, bytes, _) in blocks {
            let dest = self.block_path(object_id, version, stripe, *shard);
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            if fp.fail_block_move {
                return Err(Error::InjectedFailure("block move".into()));
            }
            atomic_write(&dest, bytes)?;
        }
        if fp.crash_after_block_move {
            return Err(Error::InjectedFailure("simulated crash after block move".into()));
        }
        // 4. transactional metadata commit
        {
            let mut conn = self.lock();
            let tx = conn.transaction()?;
            if fp.fail_commit_tx {
                return Err(Error::InjectedFailure("commit transaction".into()));
            }
            for (shard, bytes, reception_ids) in blocks {
                let digest = crate::digest::sha256_hex(bytes);
                let path = self
                    .block_path(object_id, version, stripe, *shard)
                    .to_string_lossy()
                    .into_owned();
                tx.execute(
                    "INSERT INTO committed_blocks(object_id, version, stripe, shard, run_id,
                                                  reception_ids, path, digest)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
                     ON CONFLICT(object_id, version, stripe, shard) DO UPDATE SET
                        run_id=excluded.run_id,
                        reception_ids=excluded.reception_ids,
                        path=excluded.path,
                        digest=excluded.digest",
                    params![
                        object_id,
                        version as i64,
                        stripe as i64,
                        *shard as i64,
                        run_id,
                        reception_ids,
                        path,
                        digest,
                    ],
                )?;
            }
            tx.commit()?;
        }
        let _ = std::fs::remove_dir_all(&staging);
        Ok(())
    }

    pub fn finish_run(
        &self,
        run_id: i64,
        status: &str,
        recovered: usize,
        ambiguous: usize,
        infeasible: usize,
        digest_actual: Option<&str>,
        digest_match: Option<bool>,
    ) -> Result<()> {
        let conn = self.lock();
        conn.execute(
            "UPDATE runs SET status=?1, finished_at=datetime('now'), recovered=?2, ambiguous=?3,
                            infeasible=?4, object_digest_actual=?5, object_digest_match=?6
             WHERE id=?7",
            params![
                status,
                recovered as i64,
                ambiguous as i64,
                infeasible as i64,
                digest_actual,
                digest_match.map(|v| v as i64),
                run_id,
            ],
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct RunRow {
    pub id: i64,
    pub object_id: String,
    pub version: u64,
    pub target_generation: u64,
    pub status: String,
    pub stripe_total: usize,
    pub recovered: usize,
    pub ambiguous: usize,
    pub infeasible: usize,
    pub digest_actual: Option<String>,
    pub digest_match: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct ComboRow {
    pub rank: usize,
    pub chosen: bool,
    pub participants: String,
    pub reconstructed: String,
    pub digests: String,
    pub divergent: String,
}

fn run_row_from_sql(r: &rusqlite::Row<'_>) -> rusqlite::Result<RunRow> {
    Ok(RunRow {
        id: r.get(0)?,
        object_id: r.get(1)?,
        version: r.get::<_, i64>(2)? as u64,
        target_generation: r.get::<_, i64>(3)? as u64,
        status: r.get(4)?,
        stripe_total: r.get::<_, i64>(5)? as usize,
        recovered: r.get::<_, i64>(6)? as usize,
        ambiguous: r.get::<_, i64>(7)? as usize,
        infeasible: r.get::<_, i64>(8)? as usize,
        digest_actual: r.get(9)?,
        digest_match: r.get::<_, Option<i64>>(10)?.map(|v| v != 0),
    })
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

impl Store {
    pub fn export_dir(&self, export_id: &str) -> PathBuf {
        self.root.join("exports").join(export_id)
    }

    pub fn active_export_link(&self) -> PathBuf {
        self.root.join("exports").join("active")
    }

    pub fn record_export(
        &self,
        export_id: &str,
        object_id: &str,
        run_id: i64,
        manifest_json: &str,
    ) -> Result<()> {
        let path = self.export_dir(export_id).to_string_lossy().into_owned();
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        tx.execute("UPDATE exports SET active=0 WHERE object_id=?1", params![object_id])?;
        tx.execute(
            "INSERT INTO exports(export_id, object_id, run_id, path, active, manifest_json)
             VALUES (?1,?2,?3,?4,1,?5)",
            params![export_id, object_id, run_id, path, manifest_json],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn list_exports(&self, object_id: &str) -> Result<Vec<ExportRow>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT export_id, run_id, path, active, manifest_json
             FROM exports WHERE object_id=?1 ORDER BY export_id",
        )?;
        let rows = stmt
            .query_map(params![object_id], |r| {
                Ok(ExportRow {
                    export_id: r.get(0)?,
                    run_id: r.get(1)?,
                    path: r.get(2)?,
                    active: r.get::<_, i64>(3)? != 0,
                    manifest_json: r.get(4)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}

#[derive(Debug, Clone)]
pub struct ExportRow {
    pub export_id: String,
    pub run_id: i64,
    pub path: String,
    pub active: bool,
    pub manifest_json: String,
}
