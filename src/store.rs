//! SQLite-backed persistence plus a content-addressed blob store.
//!
//! Original fragments are stored read-only under `blobs/`; reconstructed
//! blocks are written to `work/<run>/` during a run and only promoted into
//! `committed/<object>/` after the stripe commits. Committed blocks are
//! verified on every later run, so interrupted runs never expose temp data.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rusqlite::Connection;

use crate::digest::sha256_hex;
use crate::model::Manifest;

#[derive(Debug, Clone, Default)]
pub struct FaultPoints {
    pub fail_commit_write: bool,
    pub fail_export_write: bool,
}

#[derive(Clone)]
pub struct Store {
    pub root: PathBuf,
    pub db: Arc<Mutex<Connection>>,
    pub faults: Arc<Mutex<FaultPoints>>,
}

#[derive(Debug, Clone)]
pub struct ReceiptRow {
    pub id: i64,
    pub object_id: String,
    pub stripe: i64,
    pub shard: i64,
    pub generation: i64,
    pub source: String,
    pub claimed_digest: String,
    pub actual_digest: String,
    pub length: i64,
    pub blob_path: String,
}

#[derive(Debug, Clone)]
pub struct CommittedRow {
    pub resolved: bool,
    pub object_id: String,
    pub stripe: i64,
    pub codec_version: i64,
    pub generation: i64,
    pub status: String,
    pub solution_count: i64,
    pub participant_ids: String,
    pub witness_ids: String,
    pub exclusions_json: String,
    pub stripe_digest: String,
    pub data_digest: String,
    pub blob_path: String,
    pub run_id: String,
}

impl Store {
    pub fn open(root: impl AsRef<Path>) -> std::io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("blobs"))?;
        fs::create_dir_all(root.join("work"))?;
        fs::create_dir_all(root.join("committed"))?;
        fs::create_dir_all(root.join("exports"))?;
        let db_path = root.join("pod.sqlite");
        let conn = Connection::open(db_path).map_err(io_err)?;
        conn.pragma_update(None, "journal_mode", "WAL").map_err(io_err)?;
        conn.pragma_update(None, "foreign_keys", "ON").map_err(io_err)?;
        conn.execute_batch(SCHEMA).map_err(io_err)?;
        Ok(Store {
            root,
            db: Arc::new(Mutex::new(conn)),
            faults: Arc::new(Mutex::new(FaultPoints::default())),
        })
    }

    /// Lock the SQLite connection (engine deletes stale committed rows).
    pub fn db_lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.db.lock().unwrap()
    }

    pub fn set_faults(&self, faults: FaultPoints) {
        *self.faults.lock().unwrap() = faults;
    }

    pub fn faults(&self) -> FaultPoints {
        self.faults.lock().unwrap().clone()
    }

    // ----- manifests -----

    pub fn upsert_manifest(&self, m: &Manifest) -> rusqlite::Result<()> {
        let conn = self.db.lock().unwrap();
        conn.execute(
            "INSERT INTO objects(object_id, codec_version, k, m, stripe_count,
                 shard_len, object_digest, generation)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
             ON CONFLICT(object_id) DO UPDATE SET
                 codec_version=excluded.codec_version,
                 k=excluded.k, m=excluded.m, stripe_count=excluded.stripe_count,
                 shard_len=excluded.shard_len,
                 object_digest=COALESCE(excluded.object_digest, objects.object_digest),
                 generation=excluded.generation",
            rusqlite::params![
                m.object_id,
                m.codec_version,
                m.k as i64,
                m.m as i64,
                m.stripe_count as i64,
                m.shard_len as i64,
                m.object_digest,
                m.generation,
            ],
        )?;
        Ok(())
    }

    pub fn get_manifest(&self, object_id: &str) -> rusqlite::Result<Option<Manifest>> {
        let conn = self.db.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT object_id, codec_version, k, m, stripe_count, shard_len,
                    object_digest, generation
             FROM objects WHERE object_id=?1",
        )?;
        let mut rows = stmt.query(rusqlite::params![object_id])?;
        match rows.next()? {
            None => Ok(None),
            Some(r) => Ok(Some(Manifest {
                object_id: r.get(0)?,
                codec_version: r.get(1)?,
                k: r.get::<_, i64>(2)? as usize,
                m: r.get::<_, i64>(3)? as usize,
                stripe_count: r.get::<_, i64>(4)? as usize,
                shard_len: r.get::<_, i64>(5)? as usize,
                object_digest: r.get(6)?,
                generation: r.get(7)?,
            })),
        }
    }

    pub fn list_objects(&self) -> rusqlite::Result<Vec<String>> {
        let conn = self.db.lock().unwrap();
        let mut stmt = conn.prepare("SELECT object_id FROM objects ORDER BY object_id")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        rows.collect()
    }

    // ----- receipts (original fragments, immutable) -----

    pub fn insert_receipt(
        &self,
        object_id: &str,
        stripe: usize,
        shard: usize,
        generation: i64,
        source: &str,
        claimed_digest: &str,
        actual_digest: &str,
        length: usize,
        bytes: &[u8],
    ) -> rusqlite::Result<i64> {
        // Content-addressed original blob: identical bytes dedupe, but every
        // receipt (including duplicate-numbered candidates) is retained.
        let rel = format!("blobs/{}", actual_digest);
        let path = self.root.join(&rel);
        if !path.exists() {
            atomic_write(&path, bytes).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        }
        let conn = self.db.lock().unwrap();
        conn.execute(
            "INSERT INTO receipts(object_id, stripe, shard, generation, source,
                 claimed_digest, actual_digest, length, blob_path)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            rusqlite::params![
                object_id,
                stripe as i64,
                shard as i64,
                generation,
                source,
                claimed_digest,
                actual_digest,
                length as i64,
                rel,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn list_receipts(&self, object_id: &str) -> rusqlite::Result<Vec<ReceiptRow>> {
        let conn = self.db.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, object_id, stripe, shard, generation, source,
                    claimed_digest, actual_digest, length, blob_path
             FROM receipts WHERE object_id=?1
             ORDER BY stripe, shard, generation DESC, id",
        )?;
        let rows = stmt.query_map(rusqlite::params![object_id], map_receipt)?;
        rows.collect()
    }

    pub fn read_blob(&self, rel: &str) -> std::io::Result<Vec<u8>> {
        fs::read(self.root.join(rel))
    }

    // ----- source isolation -----

    pub fn isolate_source(&self, object_id: &str, source: &str) -> rusqlite::Result<()> {
        let conn = self.db.lock().unwrap();
        conn.execute(
            "INSERT INTO isolated_sources(object_id, source) VALUES (?1,?2)
             ON CONFLICT(object_id, source) DO NOTHING",
            rusqlite::params![object_id, source],
        )?;
        // Committed stripes are untrusted after isolation and must be
        // recomputed before anyone may read them again.
        conn.execute(
            "DELETE FROM committed_stripes WHERE object_id=?1",
            rusqlite::params![object_id],
        )?;
        Ok(())
    }

    pub fn restore_source(&self, object_id: &str, source: &str) -> rusqlite::Result<()> {
        let conn = self.db.lock().unwrap();
        conn.execute(
            "DELETE FROM isolated_sources WHERE object_id=?1 AND source=?2",
            rusqlite::params![object_id, source],
        )?;
        Ok(())
    }

    pub fn isolated_sources(&self, object_id: &str) -> rusqlite::Result<Vec<String>> {
        let conn = self.db.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT source FROM isolated_sources WHERE object_id=?1 ORDER BY source",
        )?;
        let rows = stmt.query_map(rusqlite::params![object_id], |r| r.get::<_, String>(0))?;
        rows.collect()
    }

    pub fn all_sources(&self, object_id: &str) -> rusqlite::Result<Vec<String>> {
        let conn = self.db.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT DISTINCT source FROM receipts WHERE object_id=?1 ORDER BY source",
        )?;
        let rows = stmt.query_map(rusqlite::params![object_id], |r| r.get::<_, String>(0))?;
        rows.collect()
    }

    // ----- stripe commit / resume -----

    /// Persist a committed stripe. Bytes are written first, then re-read and
    /// hashed; only matching blocks are recorded as committed.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_stripe(
        &self,
        object_id: &str,
        stripe: usize,
        codec_version: i64,
        generation: i64,
        status: &str,
        resolved: bool,
        solution_count: usize,
        participant_ids: &[i64],
        witness_ids: &[i64],
        exclusions_json: &str,
        stripe_digest: &str,
        data_digest: &str,
        shards: &[Vec<u8>],
        run_id: &str,
    ) -> std::io::Result<()> {
        if self.faults.lock().unwrap().fail_commit_write {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "injected commit write failure",
            ));
        }
        let rel = format!(
            "committed/{}/stripe{:06}.bin",
            object_id, stripe
        );
        let mut flat = Vec::new();
        for s in shards {
            flat.extend_from_slice(s);
        }
        let abs = self.root.join(&rel);
        atomic_write(&abs, &flat)?;

        // Verify the durable copy before declaring the stripe committed.
        let reread = fs::read(&abs)?;
        if sha256_hex(&reread) != stripe_digest {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "committed block digest verification failed",
            ));
        }

        {
            let conn = self.db.lock().unwrap();
            conn.execute(
                "INSERT INTO committed_stripes(object_id, stripe, codec_version, generation,
                     status, resolved, solution_count, participant_ids, witness_ids,
                     exclusions_json, stripe_digest, data_digest, blob_path, run_id)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)
                 ON CONFLICT(object_id, stripe) DO UPDATE SET
                    codec_version=excluded.codec_version,
                    generation=excluded.generation,
                    status=excluded.status,
                    resolved=excluded.resolved,
                    solution_count=excluded.solution_count,
                    participant_ids=excluded.participant_ids,
                    witness_ids=excluded.witness_ids,
                    exclusions_json=excluded.exclusions_json,
                    stripe_digest=excluded.stripe_digest,
                    data_digest=excluded.data_digest,
                    blob_path=excluded.blob_path,
                    run_id=excluded.run_id",
                rusqlite::params![
                    object_id,
                    stripe as i64,
                    codec_version,
                    generation,
                    status,
                    resolved as i64,
                    solution_count as i64,
                    serde_json::to_string(participant_ids).unwrap(),
                    serde_json::to_string(witness_ids).unwrap(),
                    exclusions_json,
                    stripe_digest,
                    data_digest,
                    rel,
                    run_id,
                ],
            )
            .map_err(io_err)?;
        }
        Ok(())
    }

    pub fn committed_stripes(&self, object_id: &str) -> rusqlite::Result<Vec<CommittedRow>> {
        let conn = self.db.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT object_id, stripe, codec_version, generation, status,
                    resolved, solution_count, participant_ids, witness_ids,
                    exclusions_json, stripe_digest, data_digest, blob_path, run_id
             FROM committed_stripes WHERE object_id=?1 ORDER BY stripe",
        )?;
        let rows = stmt.query_map(rusqlite::params![object_id], |r| {
            Ok(CommittedRow {
                object_id: r.get(0)?,
                stripe: r.get(1)?,
                codec_version: r.get(2)?,
                generation: r.get(3)?,
                status: r.get(4)?,
                resolved: r.get::<_, i64>(5)? != 0,
                solution_count: r.get(6)?,
                participant_ids: r.get(7)?,
                witness_ids: r.get(8)?,
                exclusions_json: r.get(9)?,
                stripe_digest: r.get(10)?,
                data_digest: r.get(11)?,
                blob_path: r.get(12)?,
                run_id: r.get(13)?,
            })
        })?;
        rows.collect()
    }

    /// Verify a previously committed stripe against its stored bytes. A stripe
    /// is reusable only when the on-disk digest is intact; corrupt or missing
    /// committed data is purged so it cannot serve final reads.
    pub fn verify_committed(&self, object_id: &str, shard_len: usize, k: usize, m: usize) -> Vec<i64> {
        let rows = self.committed_stripes(object_id).unwrap_or_default();
        let mut good = Vec::new();
        for row in rows {
            let bytes = fs::read(self.root.join(&row.blob_path));
            let ok = match bytes {
                Ok(b) => {
                    b.len() == (k + m) * shard_len && sha256_hex(&b) == row.stripe_digest
                }
                Err(_) => false,
            };
            if ok {
                good.push(row.stripe);
            } else {
                let conn = self.db.lock().unwrap();
                let _ = conn.execute(
                    "DELETE FROM committed_stripes WHERE object_id=?1 AND stripe=?2",
                    rusqlite::params![object_id, row.stripe],
                );
            }
        }
        good
    }

    // ----- runs -----

    pub fn start_run(&self, run_id: &str, object_id: &str, report_json: &str) -> rusqlite::Result<()> {
        let conn = self.db.lock().unwrap();
        conn.execute(
            "INSERT INTO recovery_runs(run_id, object_id, status, report_json, started_at)
             VALUES (?1,?2,'running',?3,?4)
             ON CONFLICT(run_id) DO UPDATE SET
                status='running', report_json=excluded.report_json, started_at=excluded.started_at",
            rusqlite::params![run_id, object_id, report_json, now_ts()],
        )?;
        Ok(())
    }

    pub fn finish_run(&self, run_id: &str, status: &str, report_json: &str) -> rusqlite::Result<()> {
        let conn = self.db.lock().unwrap();
        conn.execute(
            "UPDATE recovery_runs SET status=?2, report_json=?3, finished_at=?4 WHERE run_id=?1",
            rusqlite::params![run_id, status, report_json, now_ts()],
        )?;
        Ok(())
    }

    pub fn run_report(&self, run_id: &str) -> rusqlite::Result<Option<String>> {
        let conn = self.db.lock().unwrap();
        conn.query_row(
            "SELECT report_json FROM recovery_runs WHERE run_id=?1",
            rusqlite::params![run_id],
            |r| r.get::<_, String>(0),
        )
        .optional()
    }

    pub fn last_run(&self, object_id: &str) -> rusqlite::Result<Option<(String, String)>> {
        let conn = self.db.lock().unwrap();
        conn.query_row(
            "SELECT run_id, report_json FROM recovery_runs
             WHERE object_id=?1 ORDER BY started_at DESC, rowid DESC LIMIT 1",
            rusqlite::params![object_id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .optional()
    }

    // ----- exports -----

    pub fn record_export(
        &self,
        object_id: &str,
        dir: &str,
        manifest_path: &str,
        object_digest: &str,
        bytes_len: usize,
        status: &str,
    ) -> rusqlite::Result<()> {
        let conn = self.db.lock().unwrap();
        conn.execute(
            "INSERT INTO exports(object_id, dir, manifest_path, object_digest, bytes_len, status, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            rusqlite::params![
                object_id,
                dir,
                manifest_path,
                object_digest,
                bytes_len as i64,
                status,
                now_ts()
            ],
        )?;
        Ok(())
    }

    pub fn latest_export(&self, object_id: &str) -> rusqlite::Result<Option<String>> {
        let conn = self.db.lock().unwrap();
        conn.query_row(
            "SELECT manifest_path FROM exports WHERE object_id=?1 AND status='complete'
             ORDER BY rowid DESC LIMIT 1",
            rusqlite::params![object_id],
            |r| r.get::<_, String>(0),
        )
        .optional()
    }

    /// Create a fresh, uniquely numbered export directory.
    pub fn new_export_dir(&self, object_id: &str) -> std::io::Result<PathBuf> {
        let base = self.root.join("exports");
        for attempt in 0..10_000 {
            let dir = base.join(format!("{}-{:04}", sanitize(object_id), attempt));
            if !dir.exists() {
                fs::create_dir_all(dir.join("stripes"))?;
                return Ok(dir);
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate export directory",
        ))
    }
}

// ----- free helpers -----

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS objects (
    object_id      TEXT PRIMARY KEY,
    codec_version  INTEGER NOT NULL,
    k              INTEGER NOT NULL,
    m              INTEGER NOT NULL,
    stripe_count   INTEGER NOT NULL,
    shard_len      INTEGER NOT NULL,
    object_digest  TEXT,
    generation     INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS receipts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id      TEXT NOT NULL,
    stripe         INTEGER NOT NULL,
    shard          INTEGER NOT NULL,
    generation     INTEGER NOT NULL,
    source         TEXT NOT NULL,
    claimed_digest TEXT NOT NULL,
    actual_digest  TEXT NOT NULL,
    length         INTEGER NOT NULL,
    blob_path      TEXT NOT NULL,
    created_at     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_receipts_object ON receipts(object_id, stripe, shard);
CREATE TABLE IF NOT EXISTS isolated_sources (
    object_id TEXT NOT NULL,
    source    TEXT NOT NULL,
    PRIMARY KEY (object_id, source)
);
CREATE TABLE IF NOT EXISTS committed_stripes (
    object_id       TEXT NOT NULL,
    stripe          INTEGER NOT NULL,
    codec_version   INTEGER NOT NULL,
    generation      INTEGER NOT NULL,
    status          TEXT NOT NULL,
    resolved        INTEGER NOT NULL DEFAULT 0,
    solution_count  INTEGER NOT NULL,
    participant_ids TEXT NOT NULL,
    witness_ids     TEXT NOT NULL,
    exclusions_json TEXT NOT NULL,
    stripe_digest   TEXT NOT NULL,
    data_digest     TEXT NOT NULL,
    blob_path       TEXT NOT NULL,
    run_id          TEXT NOT NULL,
    committed_at    TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (object_id, stripe)
);
CREATE TABLE IF NOT EXISTS recovery_runs (
    run_id       TEXT PRIMARY KEY,
    object_id    TEXT NOT NULL,
    status       TEXT NOT NULL,
    report_json  TEXT NOT NULL,
    started_at   TEXT NOT NULL,
    finished_at  TEXT
);
CREATE TABLE IF NOT EXISTS exports (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id     TEXT NOT NULL,
    dir           TEXT NOT NULL,
    manifest_path TEXT NOT NULL,
    object_digest TEXT NOT NULL,
    bytes_len     INTEGER NOT NULL,
    status        TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
"#;

fn map_receipt(r: &rusqlite::Row<'_>) -> rusqlite::Result<ReceiptRow> {
    Ok(ReceiptRow {
        id: r.get(0)?,
        object_id: r.get(1)?,
        stripe: r.get(2)?,
        shard: r.get(3)?,
        generation: r.get(4)?,
        source: r.get(5)?,
        claimed_digest: r.get(6)?,
        actual_digest: r.get(7)?,
        length: r.get(8)?,
        blob_path: r.get(9)?,
    })
}

/// Write `path` via a temp file + rename so readers never observe a partial
/// block. The temp file lives beside the target under `work/` staging when
/// needed; here it is simply `<path>.tmp.<pid>`.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extra_tmp()?;
    let res = (|| -> std::io::Result<()> {
        fs::write(&tmp, bytes)?;
        fs::rename(&tmp, path)
    })();
    if res.is_err() && tmp.exists() {
        let _ = fs::remove_file(&tmp);
    }
    res
}

trait WithExtraTmp {
    fn with_extra_tmp(&self) -> std::io::Result<PathBuf>;
}

impl WithExtraTmp for Path {
    fn with_extra_tmp(&self) -> std::io::Result<PathBuf> {
        let mut name = self
            .file_name()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no file name"))?
            .to_os_string();
        name.push(format!(".tmp.{}", std::process::id()));
        Ok(self.with_file_name(name))
    }
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

fn now_ts() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}

fn io_err(e: rusqlite::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
}

trait OptionalExt<T> {
    fn optional(self) -> rusqlite::Result<Option<T>>;
}

impl<T> OptionalExt<T> for rusqlite::Result<T> {
    fn optional(self) -> rusqlite::Result<Option<T>> {
        match self {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// Monotonic-ish timestamp used by run records.
pub fn store_atomic_ts() -> String {
    now_ts()
}
