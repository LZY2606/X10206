//! SQLite-backed metadata store, immutable blob storage, atomic commits and
//! deterministic I/O fault injection.

use std::collections::HashMap;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{anyhow, Context, Result};
use rusqlite::Connection;

use crate::model::sha256_hex;

#[derive(Debug, Clone)]
pub struct Paths {
    pub root: PathBuf,
    pub db: PathBuf,
    pub recv: PathBuf,
    pub staging: PathBuf,
    pub committed: PathBuf,
    pub exports: PathBuf,
}

impl Paths {
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            db: root.join("pod.db"),
            recv: root.join("blobs").join("recv"),
            staging: root.join("blobs").join("staging"),
            committed: root.join("blobs").join("committed"),
            exports: root.join("exports"),
        }
    }
}

/// Named, deterministic fault points used by the durability tests.
pub const FAULT_COMMIT_WRITE: &str = "commit_write";
pub const FAULT_EXPORT_WRITE: &str = "export_write";

#[derive(Debug, Default)]
struct Fault {
    enabled: bool,
    /// The (fail_after+1)-th observed write fails.
    fail_after: u64,
    observed: u64,
}

pub struct Store {
    pub paths: Paths,
    conn: Mutex<Connection>,
    faults: Mutex<HashMap<String, Fault>>,
}

impl Store {
    pub fn open(root: &Path) -> Result<Self> {
        fs::create_dir_all(root).context("create data root")?;
        let paths = Paths::new(root);
        for d in [&paths.recv, &paths.staging, &paths.committed, &paths.exports] {
            fs::create_dir_all(d).with_context(|| format!("create {}", d.display()))?;
        }
        let conn = Connection::open(&paths.db).context("open sqlite database")?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "busy_timeout", 5000)?;
        migrate(&conn)?;
        let store = Self {
            paths,
            conn: Mutex::new(conn),
            faults: Mutex::new(HashMap::new()),
        };
        store.sweep_staging()?;
        Ok(store)
    }

    pub fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().expect("sqlite conn mutex poisoned")
    }

    // ---- fault injection -------------------------------------------------

    pub fn arm_fault(&self, name: &str, fail_after: u64) {
        self.faults.lock().unwrap().insert(
            name.to_string(),
            Fault {
                enabled: true,
                fail_after,
                observed: 0,
            },
        );
    }

    pub fn disarm_fault(&self, name: &str) {
        if let Some(f) = self.faults.lock().unwrap().get_mut(name) {
            f.enabled = false;
            f.observed = 0;
        }
    }

    fn trip(&self, name: &str) -> Result<()> {
        let mut faults = self.faults.lock().unwrap();
        if let Some(f) = faults.get_mut(name) {
            if f.enabled {
                f.observed += 1;
                if f.observed > f.fail_after {
                    f.enabled = false;
                    return Err(anyhow!(
                        "injected I/O failure at fault point `{name}` (write #{})",
                        f.observed
                    ));
                }
            }
        }
        Ok(())
    }

    // ---- low level I/O ---------------------------------------------------

    /// Copy imported bytes into the immutable receive area. The original file
    /// is never moved, modified or deleted.
    pub fn store_received(&self, frag_uid: i64, src: &Path, digest: &str) -> Result<PathBuf> {
        let dest = self.paths.recv.join(format!("{frag_uid:08}.{digest}.bin"));
        if !dest.exists() {
            fs::copy(src, &dest)
                .with_context(|| format!("copy received fragment to {}", dest.display()))?;
            sync_dir(&self.paths.recv)?;
        }
        Ok(dest)
    }

    pub fn read_recv(&self, rel_or_abs: &Path) -> Result<Vec<u8>> {
        let p = if rel_or_abs.is_absolute() {
            rel_or_abs.to_path_buf()
        } else {
            self.paths.root.join(rel_or_abs)
        };
        fs::read(&p).with_context(|| format!("read blob {}", p.display()))
    }

    /// Atomically write `data` plus a sidecar `.sha256`. A sibling `.tmp`
    /// file is fsynced and renamed, so readers can never observe a partial
    /// file. Optional named fault point interrupts the write before rename.
    pub fn write_with_digest(
        &self,
        dest: &Path,
        data: &[u8],
        fault: Option<&str>,
    ) -> Result<String> {
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
        if let Some(name) = fault {
            self.trip(name)?;
        }
        let digest = sha256_hex(data);
        let tmp = dest.with_extension("bin.tmp");
        {
            let mut f =
                fs::File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
            f.write_all(data)
                .with_context(|| format!("write {}", tmp.display()))?;
            f.sync_all().context("fsync data")?;
        }
        fs::rename(&tmp, dest).with_context(|| format!("rename into {}", dest.display()))?;

        let side = dest.with_extension("sha256");
        let side_tmp = side.with_extension("sha256.tmp");
        let line = format!("{digest}  {}\n", dest.file_name().unwrap().to_string_lossy());
        fs::write(&side_tmp, line)
            .with_context(|| format!("write {}", side_tmp.display()))?;
        fs::rename(&side_tmp, &side)
            .with_context(|| format!("rename into {}", side.display()))?;
        if let Some(dir) = dest.parent() {
            sync_dir(dir)?;
        }
        Ok(digest)
    }

    pub fn committed_shard(&self, object_id: &str, stripe: usize, shard: usize) -> PathBuf {
        self.paths
            .committed
            .join(safe_id(object_id))
            .join(format!("s{stripe:04}"))
            .join(format!("shard{shard:03}.bin"))
    }

    /// True only when every shard file in a committed stripe directory exists
    /// together with a digest sidecar that matches the bytes on disk.
    pub fn committed_stripe_complete(
        &self,
        object_id: &str,
        stripe: usize,
        n: usize,
    ) -> bool {
        let dir = self
            .paths
            .committed
            .join(safe_id(object_id))
            .join(format!("s{stripe:04}"));
        if !dir.is_dir() {
            return false;
        }
        for shard in 0..n {
            let bin = dir.join(format!("shard{shard:03}.bin"));
            let side = dir.join(format!("shard{shard:03}.sha256"));
            let (Ok(bytes), Ok(text)) = (fs::read(&bin), fs::read_to_string(&side)) else {
                return false;
            };
            let claimed = text.split_whitespace().next().unwrap_or("");
            if claimed != sha256_hex(&bytes) {
                return false;
            }
        }
        true
    }

    /// Remove every staging directory. Staging files are temporary and must
    /// never be read by final/commit paths.
    pub fn sweep_staging(&self) -> Result<()> {
        if self.paths.staging.exists() {
            for entry in fs::read_dir(&self.paths.staging)? {
                let p = entry?.path();
                if p.is_dir() {
                    fs::remove_dir_all(&p).ok();
                } else {
                    fs::remove_file(&p).ok();
                }
            }
        }
        fs::create_dir_all(&self.paths.staging)?;
        Ok(())
    }

    pub fn staging_dir(&self, token: &str) -> PathBuf {
        self.paths.staging.join(safe_id(token))
    }
}

fn sync_dir(dir: &Path) -> Result<()> {
    if let Ok(f) = fs::File::open(dir) {
        f.sync_all().ok();
    }
    Ok(())
}

/// Restrict filesystem id components so object ids cannot escape the data
/// directory.
pub fn safe_id(id: &str) -> String {
    let mut out = String::with_capacity(id.len());
    for c in id.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() || out == "." || out == ".." {
        out = format!("_{out}");
    }
    out
}

fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS schema_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS objects (
            object_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            data_len INTEGER NOT NULL,
            object_digest_sha256 TEXT,
            codec_version INTEGER NOT NULL,
            k INTEGER NOT NULL,
            n INTEGER NOT NULL,
            chunk_size INTEGER NOT NULL,
            stripe_count INTEGER NOT NULL,
            imported_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sources (
            object_id TEXT NOT NULL REFERENCES objects(object_id) ON DELETE CASCADE,
            source_id TEXT NOT NULL,
            name TEXT NOT NULL,
            note TEXT NOT NULL DEFAULT '',
            quarantined INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (object_id, source_id)
        );
        CREATE TABLE IF NOT EXISTS shard_decls (
            object_id TEXT NOT NULL REFERENCES objects(object_id) ON DELETE CASCADE,
            stripe_index INTEGER NOT NULL,
            shard_index INTEGER NOT NULL,
            generation INTEGER,
            length INTEGER,
            digest_sha256 TEXT,
            PRIMARY KEY (object_id, stripe_index, shard_index)
        );
        CREATE TABLE IF NOT EXISTS fragments (
            uid INTEGER PRIMARY KEY AUTOINCREMENT,
            object_id TEXT NOT NULL REFERENCES objects(object_id) ON DELETE CASCADE,
            fragment_id TEXT NOT NULL,
            source_id TEXT NOT NULL,
            stripe_index INTEGER NOT NULL,
            shard_index INTEGER NOT NULL,
            generation INTEGER NOT NULL,
            length INTEGER NOT NULL,
            blob_path TEXT NOT NULL,
            import_digest_sha256 TEXT NOT NULL,
            computed_digest_sha256 TEXT NOT NULL,
            declared_shard_digest_sha256 TEXT,
            declared_generation INTEGER,
            received_at TEXT NOT NULL DEFAULT '',
            flags TEXT NOT NULL DEFAULT '',
            UNIQUE(object_id, fragment_id)
        );
        CREATE INDEX IF NOT EXISTS idx_fragments_loc
            ON fragments(object_id, stripe_index, shard_index);
        CREATE TABLE IF NOT EXISTS stripes (
            object_id TEXT NOT NULL REFERENCES objects(object_id) ON DELETE CASCADE,
            stripe_index INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            committed_generation INTEGER,
            chosen_set_id INTEGER,
            committed_at INTEGER,
            reused INTEGER NOT NULL DEFAULT 0,
            verified INTEGER NOT NULL DEFAULT 0,
            sets_count INTEGER NOT NULL DEFAULT 0,
            rejected_count INTEGER NOT NULL DEFAULT 0,
            budget_hit INTEGER NOT NULL DEFAULT 0,
            difference_summary TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (object_id, stripe_index)
        );
        CREATE TABLE IF NOT EXISTS recovery_sets (
            set_id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER,
            object_id TEXT NOT NULL,
            stripe_index INTEGER NOT NULL,
            ordinal INTEGER NOT NULL,
            chosen_uids TEXT NOT NULL,
            chosen_generations TEXT NOT NULL,
            excluded_evidence TEXT NOT NULL,
            output_digests TEXT NOT NULL,
            consistent INTEGER NOT NULL,
            matches_declared INTEGER NOT NULL,
            object_confirmed INTEGER NOT NULL DEFAULT 0,
            UNIQUE(object_id, stripe_index, ordinal)
        );
        CREATE TABLE IF NOT EXISTS runs (
            run_id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at INTEGER NOT NULL,
            finished_at INTEGER,
            search_budget INTEGER NOT NULL,
            stripe_budget_hit TEXT NOT NULL DEFAULT '',
            object_budget_hit INTEGER NOT NULL DEFAULT 0,
            note TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS exports (
            export_id INTEGER PRIMARY KEY AUTOINCREMENT,
            object_id TEXT NOT NULL,
            directory TEXT NOT NULL,
            manifest_path TEXT NOT NULL,
            manifest_sha256 TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        "#,
    )
    .context("run schema migration")?;
    Ok(())
}
