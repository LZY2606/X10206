//! SQLite metadata store plus content-addressed immutable blob storage.
//!
//! Layout under the data root:
//!   pod.db                 - metadata (WAL mode)
//!   blobs/aa/bbcc...       - original received bytes and rebuilt bytes,
//!                            keyed by sha256 (never modified in place)
//!   staging/<job>/...      - temp blocks; never read by final code paths
//!   inbox/                 - import area (manifests + blocks)
//!   export/                - export snapshots + LATEST pointer

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;

use crate::digest::sha256_hex;

#[derive(Debug)]
pub enum StoreError {
    Io(String),
    Sql(rusqlite::Error),
    Fault(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Io(s) => write!(f, "io error: {s}"),
            StoreError::Sql(e) => write!(f, "sqlite error: {e}"),
            StoreError::Fault(s) => write!(f, "injected fault: {s}"),
        }
    }
}
impl std::error::Error for StoreError {}
impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        StoreError::Io(e.to_string())
    }
}
impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Sql(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailMode {
    None,
    /// The Nth *staging* block write fails with a simulated disk error.
    WriteAfterN(u64),
    /// Process aborts after N stripes have been committed.
    KillAfterN(u64),
}

pub struct Store {
    pub root: PathBuf,
    pub db: Mutex<Connection>,
    pub fault: Mutex<(FailMode, u64)>,
}

impl Store {
    pub fn open(root: impl AsRef<Path>) -> Result<Store, StoreError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("blobs"))?;
        fs::create_dir_all(root.join("staging"))?;
        fs::create_dir_all(root.join("inbox"))?;
        fs::create_dir_all(root.join("export"))?;
        let db = Connection::open(root.join("pod.db"))?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA foreign_keys=ON;
             PRAGMA synchronous=NORMAL;",
        )?;
        migrate(&db)?;
        Ok(Store {
            root,
            db: Mutex::new(db),
            fault: Mutex::new((FailMode::None, 0)),
        })
    }

    pub fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    pub fn set_fault(&self, mode: FailMode) {
        *self.fault.lock().unwrap() = (mode, 0);
    }

    pub fn fault_mode(&self) -> FailMode {
        self.fault.lock().unwrap().0
    }

    /// Store an immutable blob. Never fails from fault injection.
    pub fn blob_put(&self, bytes: &[u8]) -> Result<String, StoreError> {
        let hash = sha256_hex(bytes);
        let rel = format!("blobs/{}/{}", &hash[0..2], &hash[2..]);
        let path = self.root.join(&rel);
        if path.exists() {
            return Ok(rel);
        }
        fs::create_dir_all(path.parent().unwrap())?;
        let tmp = self.root.join("blobs").join(format!(".tmp-{hash}"));
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &path)?;
        Ok(rel)
    }

    pub fn blob_read(&self, rel: &str) -> Result<Vec<u8>, StoreError> {
        let p = self.root.join(rel);
        Ok(fs::read(p)?)
    }

    pub fn blob_exists(&self, rel: &str) -> bool {
        self.root.join(rel).exists()
    }

    /// Write a *temporary* block for a job's staging directory. These
    /// files are never part of any final read path. Subject to injected
    /// disk-write failures so crash semantics can be exercised.
    pub fn staging_write(
        &self,
        job_id: &str,
        name: &str,
        bytes: &[u8],
    ) -> Result<PathBuf, StoreError> {
        let mut fault = self.fault.lock().unwrap();
        fault.1 += 1;
        let fire = match fault.0 {
            FailMode::WriteAfterN(n) => fault.1 >= n,
            _ => false,
        };
        if fire {
            return Err(StoreError::Fault(format!(
                "simulated disk write failure at staging block {name}"
            )));
        }
        drop(fault);

        let dir = self.root.join("staging").join(job_id);
        fs::create_dir_all(&dir)?;
        let p = dir.join(name);
        let mut f = fs::File::create(&p)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(p)
    }

    /// Called by the engine between stripes; returns true when the
    /// simulated process interruption must fire.
    pub fn kill_check(&self, committed: u64) -> bool {
        match self.fault.lock().unwrap().0 {
            FailMode::KillAfterN(n) => committed >= n,
            _ => false,
        }
    }

    pub fn setting_get(&self, key: &str) -> Option<String> {
        self.db
            .lock()
            .unwrap()
            .query_row(
                "SELECT value FROM settings WHERE key=?1",
                params![key],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .unwrap_or(None)
    }
    pub fn setting_set(&self, key: &str, value: &str) {
        self.db
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO settings(key,value) VALUES(?1,?2)
                 ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                params![key, value],
            )
            .unwrap();
    }
}

fn migrate(db: &Connection) -> Result<(), StoreError> {
    db.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS objects (
            object_id TEXT PRIMARY KEY,
            current_generation INTEGER NOT NULL,
            length_consistent INTEGER NOT NULL,
            object_digest TEXT,
            object_digest_verified INTEGER
        );
        CREATE TABLE IF NOT EXISTS manifests (
            object_id TEXT NOT NULL,
            generation INTEGER NOT NULL,
            code_version INTEGER NOT NULL,
            k INTEGER NOT NULL,
            m INTEGER NOT NULL,
            shard_size INTEGER NOT NULL,
            object_size INTEGER NOT NULL,
            object_digest TEXT NOT NULL,
            geometry_consistent INTEGER NOT NULL,
            json TEXT NOT NULL,
            PRIMARY KEY (object_id, generation)
        );
        CREATE TABLE IF NOT EXISTS sources (
            source TEXT PRIMARY KEY,
            isolated INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS shards (
            block_uid INTEGER PRIMARY KEY AUTOINCREMENT,
            shard_id TEXT NOT NULL,
            object_id TEXT NOT NULL,
            generation INTEGER NOT NULL,
            stripe_idx INTEGER NOT NULL,
            row INTEGER NOT NULL,
            code_version INTEGER NOT NULL,
            size INTEGER NOT NULL,
            sidecar_digest TEXT,
            computed_digest TEXT NOT NULL,
            block_ok INTEGER NOT NULL,
            exclude_reason TEXT,
            blob TEXT NOT NULL,
            source TEXT NOT NULL,
            received_seq INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS jobs (
            job_id TEXT PRIMARY KEY,
            scope_object TEXT,
            started_at INTEGER NOT NULL,
            finished_at INTEGER,
            status TEXT NOT NULL,
            total_stripes INTEGER NOT NULL DEFAULT 0,
            committed INTEGER NOT NULL DEFAULT 0,
            failed INTEGER NOT NULL DEFAULT 0,
            note TEXT
        );
        CREATE TABLE IF NOT EXISTS job_stripes (
            job_id TEXT NOT NULL,
            object_id TEXT NOT NULL,
            generation INTEGER NOT NULL,
            stripe_idx INTEGER NOT NULL,
            state TEXT NOT NULL,
            PRIMARY KEY (job_id, object_id, generation, stripe_idx)
        );
        CREATE TABLE IF NOT EXISTS stripe_answers (
            object_id TEXT NOT NULL,
            generation INTEGER NOT NULL,
            stripe_idx INTEGER NOT NULL,
            rank_seq INTEGER NOT NULL,
            data_digest TEXT NOT NULL,
            trust TEXT NOT NULL,
            is_recoverable INTEGER NOT NULL,
            used_rows TEXT NOT NULL,
            used_blocks TEXT NOT NULL,
            participating TEXT NOT NULL,
            excluded_evidence TEXT NOT NULL,
            row_digests TEXT NOT NULL,
            blobs TEXT NOT NULL,
            data_len INTEGER NOT NULL,
            object_digest_match INTEGER,
            produced_job TEXT NOT NULL,
            committed_at INTEGER NOT NULL,
            PRIMARY KEY (object_id, generation, stripe_idx, rank_seq)
        );
        CREATE INDEX IF NOT EXISTS idx_shards_lookup
            ON shards(object_id, generation, stripe_idx);
        ",
    )?;
    // Migration aid for older dev databases.
    let cols: u64 = db.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('stripe_answers') WHERE name='object_digest_match'",
        [],
        |r| r.get(0),
    ).unwrap_or(0);
    if cols == 0 {
        db.execute_batch("ALTER TABLE stripe_answers ADD COLUMN object_digest_match INTEGER;").ok();
    }
    let _ = Value::Null;
    Ok(())
}
