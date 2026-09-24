//! SQLite-backed durable state plus an on-disk raw fragment byte store.

use rusqlite::{params, Connection};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::model::{FragmentRecord, Manifest};

pub struct Store {
    pub root: PathBuf,
    pub conn: Mutex<Connection>,
    /// Injected fault probability (0..=100) for temporary writes; used by tests.
    pub fail_temp_writes: std::cell::Cell<u8>,
}

#[derive(Clone, Debug)]
pub struct StripeCommitRow {
    pub object_id: String,
    pub stripe: usize,
    pub solution_json: String,
    pub output_digest: String,
    pub run_id: String,
    pub committed_at: i64,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS objects (
    object_id TEXT PRIMARY KEY,
    manifest_json TEXT NOT NULL,
    imported_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sources (
    source TEXT PRIMARY KEY,
    isolated INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS fragments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id TEXT NOT NULL,
    stripe INTEGER NOT NULL,
    position INTEGER NOT NULL,
    generation INTEGER NOT NULL,
    source TEXT NOT NULL,
    received_digest TEXT,
    actual_digest TEXT NOT NULL,
    size INTEGER NOT NULL,
    raw_path TEXT NOT NULL,
    digest_matches INTEGER NOT NULL,
    UNIQUE(object_id, stripe, position, generation, source, actual_digest)
);
CREATE TABLE IF NOT EXISTS stripe_commits (
    object_id TEXT NOT NULL,
    stripe INTEGER NOT NULL,
    run_id TEXT NOT NULL,
    solution_json TEXT NOT NULL,
    output_digest TEXT NOT NULL,
    committed_at INTEGER NOT NULL,
    PRIMARY KEY (object_id, stripe)
);
CREATE TABLE IF NOT EXISTS stripe_temp (
    object_id TEXT NOT NULL,
    stripe INTEGER NOT NULL,
    run_id TEXT NOT NULL,
    temp_path TEXT NOT NULL,
    output_digest TEXT,
    finalized INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (object_id, stripe)
);
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    object_id TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    status TEXT NOT NULL,
    canonical_json TEXT
);
CREATE TABLE IF NOT EXISTS exports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id TEXT NOT NULL,
    dir TEXT NOT NULL,
    manifest_path TEXT NOT NULL,
    output_digest TEXT NOT NULL,
    exported_at INTEGER NOT NULL
);
"#;

impl Store {
    pub fn open(root: impl AsRef<Path>) -> anyhow_lite::Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("raw")).map_err(|e| anyhow_lite::err(e.to_string()))?;
        fs::create_dir_all(root.join("tmp")).map_err(|e| anyhow_lite::err(e.to_string()))?;
        fs::create_dir_all(root.join("staging")).map_err(|e| anyhow_lite::err(e.to_string()))?;
        fs::create_dir_all(root.join("exports")).map_err(|e| anyhow_lite::err(e.to_string()))?;
        let db_path = root.join("pod.db");
        let conn = Connection::open(db_path).map_err(|e| anyhow_lite::err(e.to_string()))?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
            .map_err(|e| anyhow_lite::err(e.to_string()))?;
        conn.execute_batch(SCHEMA)
            .map_err(|e| anyhow_lite::err(e.to_string()))?;
        Ok(Self {
            root,
            conn: Mutex::new(conn),
            fail_temp_writes: std::cell::Cell::new(0),
        })
    }

    pub fn raw_dir(&self) -> PathBuf {
        self.root.join("raw")
    }

    pub fn tmp_dir(&self) -> PathBuf {
        self.root.join("tmp")
    }

    pub fn staging_dir(&self) -> PathBuf {
        self.root.join("staging")
    }

    pub fn exports_dir(&self) -> PathBuf {
        self.root.join("exports")
    }

    pub fn upsert_manifest(&self, m: &Manifest) -> anyhow_lite::Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = now_millis();
        conn.execute(
            "INSERT INTO objects(object_id, manifest_json, imported_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(object_id) DO UPDATE SET manifest_json=excluded.manifest_json",
            params![m.object_id, serde_json::to_string(m).unwrap(), now],
        )
        .map_err(|e| anyhow_lite::err(e.to_string()))?;
        Ok(())
    }

    pub fn list_objects(&self) -> anyhow_lite::Result<Vec<(String, Manifest)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT manifest_json FROM objects ORDER BY object_id")
            .map_err(|e| anyhow_lite::err(e.to_string()))?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(|e| anyhow_lite::err(e.to_string()))?;
        let mut out = Vec::new();
        for row in rows {
            let json = row.map_err(|e| anyhow_lite::err(e.to_string()))?;
            let m: Manifest = serde_json::from_str(&json).map_err(|e| anyhow_lite::err(e.to_string()))?;
            out.push((m.object_id.clone(), m));
        }
        Ok(out)
    }

    pub fn manifest(&self, object_id: &str) -> anyhow_lite::Result<Option<Manifest>> {
        let conn = self.conn.lock().unwrap();
        let json: Option<String> = conn
            .query_row(
                "SELECT manifest_json FROM objects WHERE object_id=?1",
                params![object_id],
                |r| r.get(0),
            )
            .ok();
        match json {
            Some(j) => Ok(Some(
                serde_json::from_str(&j).map_err(|e| anyhow_lite::err(e.to_string()))?
            )),
            None => Ok(None),
        }
    }
}

pub fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

impl Store {
    /// Persist raw fragment bytes without modifying the imported source files.
    pub fn save_fragment_bytes(&self, object_id: &str, id_hint: usize, bytes: &[u8]) -> anyhow_lite::Result<PathBuf> {
        let name = format!("{obj}-{id:06}.bin", obj = sanitize(object_id), id = id_hint);
        let dir = self.raw_dir();
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let target = dir.join(name);
        atomic_write(&target, bytes)
    }

    pub fn insert_fragment(&self, f: &FragmentRecord) -> anyhow_lite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO fragments
             (object_id, stripe, position, generation, source, received_digest,
              actual_digest, size, raw_path, digest_matches)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                f.object_id,
                f.stripe as i64,
                f.position as i64,
                f.generation as i64,
                f.source,
                f.received_digest,
                f.actual_digest,
                f.size as i64,
                f.raw_path,
                f.digest_matches as i64,
            ],
        )
        .map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT OR IGNORE INTO sources(source) VALUES (?1)",
            params![f.source],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn list_fragments(&self, object_id: &str) -> anyhow_lite::Result<Vec<FragmentRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT stripe,position,generation,source,received_digest,actual_digest,size,raw_path,digest_matches
                 FROM fragments WHERE object_id=?1 ORDER BY stripe,position,generation,source",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![object_id], |r| {
                Ok(FragmentRecord {
                    object_id: object_id.to_string(),
                    stripe: r.get::<_, i64>(0)? as usize,
                    position: r.get::<_, i64>(1)? as usize,
                    generation: r.get::<_, i64>(2)? as u64,
                    source: r.get(3)?,
                    received_digest: r.get(4)?,
                    actual_digest: r.get(5)?,
                    size: r.get::<_, i64>(6)? as usize,
                    raw_path: r.get(7)?,
                    digest_matches: r.get::<_, i64>(8)? != 0,
                })
            })
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    pub fn list_sources(&self) -> anyhow_lite::Result<Vec<(String, bool)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT source, isolated FROM sources ORDER BY source")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? != 0)))
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    pub fn set_source_isolated(&self, source: &str, isolated: bool) -> anyhow_lite::Result<()> {
        let conn = self.conn.lock().unwrap();
        let n = conn
            .execute(
                "UPDATE sources SET isolated=?2 WHERE source=?1",
                params![source, isolated as i64],
            )
            .map_err(|e| e.to_string())?;
        if n == 0 {
            return Err(format!("unknown source: {source}"));
        }
        Ok(())
    }

    pub fn isolated_sources(&self) -> anyhow_lite::Result<std::collections::BTreeSet<String>> {
        Ok(self
            .list_sources()?
            .into_iter()
            .filter_map(|(s, iso)| iso.then_some(s))
            .collect())
    }
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

/// fsync-less but rename-based atomic write, enough for the local pod.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> anyhow_lite::Result<PathBuf> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension(format!(
        "{}.part-{}",
        path.extension().and_then(|e| e.to_str()).unwrap_or("bin"),
        std::process::id()
    ));
    fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
    fs::rename(&tmp, path).map_err(|e| e.to_string())?;
    Ok(path.to_path_buf())
}

impl Store {
    pub fn committed_stripes(&self, object_id: &str) -> anyhow_lite::Result<Vec<StripeCommitRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT stripe, run_id, solution_json, output_digest, committed_at
                 FROM stripe_commits WHERE object_id=?1 ORDER BY stripe",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![object_id], |r| {
                Ok(StripeCommitRow {
                    object_id: object_id.to_string(),
                    stripe: r.get::<_, i64>(0)? as usize,
                    run_id: r.get(1)?,
                    solution_json: r.get(2)?,
                    output_digest: r.get(3)?,
                    committed_at: r.get(4)?,
                })
            })
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    /// A committed stripe is reused only when its stored output bytes still
    /// match the digest recorded at commit time.
    pub fn committed_output(
        &self,
        object_id: &str,
        stripe: usize,
    ) -> anyhow_lite::Result<Option<(StripeCommitRow, Vec<u8>)>> {
        let row = {
            let conn = self.conn.lock().unwrap();
            conn.query_row(
                "SELECT stripe, run_id, solution_json, output_digest, committed_at
                 FROM stripe_commits WHERE object_id=?1 AND stripe=?2",
                params![object_id, stripe as i64],
                |r| {
                    Ok(StripeCommitRow {
                        object_id: object_id.to_string(),
                        stripe: r.get::<_, i64>(0)? as usize,
                        run_id: r.get(1)?,
                        solution_json: r.get(2)?,
                        output_digest: r.get(3)?,
                        committed_at: r.get(4)?,
                    })
                },
            )
            .ok()
        };
        match row {
            Some(r) => {
                let path = self.staging_dir().join(format!(
                    "{obj}-stripe{stripe:04}.bin",
                    obj = sanitize(object_id),
                    stripe = r.stripe
                ));
                let bytes = match fs::read(&path) {
                    Ok(b) => b,
                    Err(_) => return Ok(None),
                };
                let actual = crate::digest::sha256_hex(&bytes);
                if actual != r.output_digest {
                    return Ok(None);
                }
                Ok(Some((r, bytes)))
            }
            None => Ok(None),
        }
    }

    /// Stage provisional bytes for one stripe. The finalized flag stays 0
    /// until the whole stripe transaction completes.
    pub fn stage_temp(
        &self,
        object_id: &str,
        stripe: usize,
        run_id: &str,
        bytes: &[u8],
    ) -> anyhow_lite::Result<()> {
        // Test-only injected fault: simulate a partial disk write.
        if self.fail_temp_writes.get() > 0 {
            let roll: u8 = rand_lite();
            if roll % 100 < self.fail_temp_writes.get() as u8 {
                return Err("simulated disk write failure".to_string());
            }
        }
        let tmp_path = self
            .tmp_dir()
            .join(format!("{obj}-{stripe:04}-{run}.part", obj = sanitize(object_id), stripe = stripe, run = sanitize(run_id)));
        atomic_write(&tmp_path, bytes)?;
        let digest = crate::digest::sha256_hex(bytes);
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO stripe_temp(object_id, stripe, run_id, temp_path, output_digest, finalized)
             VALUES (?1,?2,?3,?4,?5,0)
             ON CONFLICT(object_id, stripe) DO UPDATE SET
               run_id=excluded.run_id, temp_path=excluded.temp_path,
               output_digest=excluded.output_digest, finalized=0",
            params![object_id, stripe as i64, run_id, tmp_path.to_string_lossy(), digest],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Move staged bytes into the committed staging area and record the
    /// solution, in one SQLite transaction.
    pub fn commit_stripe(
        &self,
        object_id: &str,
        stripe: usize,
        run_id: &str,
        solution_json: &str,
    ) -> anyhow_lite::Result<String> {
        let temp = {
            let conn = self.conn.lock().unwrap();
            let row: Option<(String, String)> = conn
                .query_row(
                    "SELECT temp_path, output_digest FROM stripe_temp
                     WHERE object_id=?1 AND stripe=?2 AND run_id=?3 AND finalized=0",
                    params![object_id, stripe as i64, run_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .ok();
            row.ok_or_else(|| "no staged output for stripe".to_string())?
        };
        let (temp_path, digest) = temp;
        let bytes = fs::read(&temp_path).map_err(|e| e.to_string())?;
        if crate::digest::sha256_hex(&bytes) != digest {
            return Err("staged digest mismatch before commit".to_string());
        }
        let final_path = self.staging_dir().join(format!(
            "{obj}-stripe{stripe:04}.bin",
            obj = sanitize(object_id),
            stripe = stripe
        ));
        atomic_write(&final_path, &bytes)?;

        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO stripe_commits(object_id, stripe, run_id, solution_json, output_digest, committed_at)
             VALUES (?1,?2,?3,?4,?5,?6)
             ON CONFLICT(object_id, stripe) DO UPDATE SET
               run_id=excluded.run_id, solution_json=excluded.solution_json,
               output_digest=excluded.output_digest, committed_at=excluded.committed_at",
            params![object_id, stripe as i64, run_id, solution_json, digest, now_millis()],
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "UPDATE stripe_temp SET finalized=1 WHERE object_id=?1 AND stripe=?2",
            params![object_id, stripe as i64],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        let _ = fs::remove_file(&temp_path);
        Ok(digest)
    }

    /// Throw away provisional bytes for one stripe (used on failure).
    pub fn discard_temp(&self, object_id: &str, stripe: usize) {
        let temp = {
            let conn = self.conn.lock().unwrap();
            conn.query_row(
                "SELECT temp_path FROM stripe_temp WHERE object_id=?1 AND stripe=?2",
                params![object_id, stripe as i64],
                |r| r.get::<_, String>(0),
            )
            .ok()
        };
        if let Some(p) = temp {
            let _ = fs::remove_file(p);
        }
        let conn = self.conn.lock().unwrap();
        let _ = conn.execute(
            "DELETE FROM stripe_temp WHERE object_id=?1 AND stripe=?2",
            params![object_id, stripe as i64],
        );
    }

    pub fn invalidate_commits(&self, object_id: &str, stripes: &[usize]) -> anyhow_lite::Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        for &s in stripes {
            tx.execute(
                "DELETE FROM stripe_commits WHERE object_id=?1 AND stripe=?2",
                params![object_id, s as i64],
            )
            .map_err(|e| e.to_string())?;
            tx.execute(
                "DELETE FROM stripe_temp WHERE object_id=?1 AND stripe=?2",
                params![object_id, s as i64],
            )
            .map_err(|e| e.to_string())?;
            let path = self.staging_dir().join(format!(
                "{obj}-stripe{stripe:04}.bin",
                obj = sanitize(object_id),
                stripe = s
            ));
            let _ = fs::remove_file(path);
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn save_run(
        &self,
        run_id: &str,
        object_id: &str,
        status: &str,
        canonical_json: Option<&str>,
    ) -> anyhow_lite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO runs(run_id, object_id, started_at, status, canonical_json)
             VALUES (?1,?2,?3,?4,?5)
             ON CONFLICT(run_id) DO UPDATE SET status=excluded.status, canonical_json=excluded.canonical_json",
            params![run_id, object_id, now_millis(), status, canonical_json],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn latest_run(&self, object_id: &str) -> anyhow_lite::Result<Option<(String, String, Option<String>)>> {
        let conn = self.conn.lock().unwrap();
        let row = conn
            .query_row(
                "SELECT run_id, status, canonical_json FROM runs
                 WHERE object_id=?1 ORDER BY started_at DESC, rowid DESC LIMIT 1",
                params![object_id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get(2)?)),
            )
            .ok();
        Ok(row)
    }

    pub fn record_export(
        &self,
        object_id: &str,
        dir: &str,
        manifest_path: &str,
        output_digest: &str,
    ) -> anyhow_lite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO exports(object_id, dir, manifest_path, output_digest, exported_at)
             VALUES (?1,?2,?3,?4,?5)",
            params![object_id, dir, manifest_path, output_digest, now_millis()],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn list_exports(&self, object_id: &str) -> anyhow_lite::Result<Vec<(String, String, String, i64)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT dir, manifest_path, output_digest, exported_at FROM exports WHERE object_id=?1 ORDER BY id DESC")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![object_id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)?))
            })
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }
}

fn rand_lite() -> u8 {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    ((nanos >> 8) ^ nanos) as u8
}
