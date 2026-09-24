//! Byte storage for received shards, staging blocks and committed stripes.
//!
//! Invariants:
//! * `received/` blobs are write-once and never mutated or deleted.
//!   Duplicate candidates for one shard index are stored side by side
//!   (content-hash suffix) so "two candidates for one number" survives.
//! * `staging/` holds temporary blocks only; nothing final ever reads them.
//!   On startup the whole tree is swept.
//! * A committed stripe is promoted by a single directory `rename` on the
//!   same filesystem, then `CURRENT` is switched with temp-file + rename.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub trait BlobStore: Send + Sync {
    fn root(&self) -> &Path;

    fn received_path(&self, object_id: &str, source: &str, stripe: u32, name: &str) -> PathBuf {
        self.root()
            .join("received")
            .join(safe(object_id))
            .join(safe(source))
            .join(format!("s{stripe}"))
            .join(name)
    }

    fn stage_dir(&self, run_id: i64, object_id: &str, stripe: u32) -> PathBuf {
        self.root()
            .join("staging")
            .join(format!("run{run_id}"))
            .join(safe(object_id))
            .join(format!("s{stripe}.tmp"))
    }

    fn commit_parent(&self, object_id: &str, stripe: u32) -> PathBuf {
        self.root().join("committed").join(safe(object_id)).join(format!("s{stripe}"))
    }

    fn write_received(
        &self,
        object_id: &str,
        source: &str,
        stripe: u32,
        name: &str,
        bytes: &[u8],
    ) -> io::Result<PathBuf> {
        let p = self.received_path(object_id, source, stripe, name);
        self.atomic_write(&p, bytes)
    }

    fn write_staging(&self, run_id: i64, object_id: &str, stripe: u32, name: &str, bytes: &[u8])
        -> io::Result<PathBuf>;

    /// Atomically promote the whole staged stripe directory to
    /// committed/.../p{pointer} and switch CURRENT.
    fn promote_staged(
        &self,
        run_id: i64,
        object_id: &str,
        stripe: u32,
        pointer: i64,
    ) -> io::Result<PathBuf>;

    fn atomic_write(&self, path: &Path, bytes: &[u8]) -> io::Result<PathBuf>;

    fn read_path(&self, path: &Path) -> io::Result<Vec<u8>> {
        fs::read(path)
    }

    /// Remove every staging directory (called on startup and at run start).
    fn sweep_staging(&self) -> io::Result<()> {
        let p = self.root().join("staging");
        if p.exists() {
            fs::remove_dir_all(&p)?;
        }
        Ok(())
    }

    fn current_commit_dir(&self, object_id: &str, stripe: u32) -> Option<PathBuf> {
        let cur = self.commit_parent(object_id, stripe).join("CURRENT");
        let target = fs::read_to_string(&cur).ok()?;
        Some(cur.parent().unwrap().join(target.trim()))
    }
}

pub struct FsStore {
    root: PathBuf,
    /// Test hook: any write whose final path contains one of these strings fails.
    fail_markers: Mutex<Vec<String>>,
}

impl FsStore {
    pub fn new(root: PathBuf) -> io::Result<FsStore> {
        for d in ["received", "staging", "committed", "exports"] {
            fs::create_dir_all(root.join(d))?;
        }
        Ok(FsStore { root, fail_markers: Mutex::new(Vec::new()) })
    }

    /// Make subsequent writes whose path contains `marker` return EIO.
    pub fn inject_write_failure(&self, marker: impl Into<String>) {
        self.fail_markers.lock().unwrap().push(marker.into());
    }

    pub fn clear_write_failures(&self) {
        self.fail_markers.lock().unwrap().clear();
    }

    fn check_failure(&self, path: &Path) -> io::Result<()> {
        let s = path.display().to_string();
        if self.fail_markers.lock().unwrap().iter().any(|m| s.contains(m)) {
            Err(io::Error::new(io::ErrorKind::Other, "injected disk write failure"))
        } else {
            Ok(())
        }
    }
}

impl BlobStore for FsStore {
    fn root(&self) -> &Path {
        &self.root
    }

    fn atomic_write(&self, path: &Path, bytes: &[u8]) -> io::Result<PathBuf> {
        self.check_failure(path)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        // Sibling temp file keeps the swap atomic and leaves the target
        // untouched if the write fails.
        let tmp = path.with_extra_temp_name();
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, path)?;
        Ok(path.to_path_buf())
    }

    fn write_staging(
        &self,
        run_id: i64,
        object_id: &str,
        stripe: u32,
        name: &str,
        bytes: &[u8],
    ) -> io::Result<PathBuf> {
        let p = self.stage_dir(run_id, object_id, stripe).join(name);
        self.atomic_write(&p, bytes)
    }

    fn promote_staged(
        &self,
        run_id: i64,
        object_id: &str,
        stripe: u32,
        pointer: i64,
    ) -> io::Result<PathBuf> {
        let src = self.stage_dir(run_id, object_id, stripe);
        let parent = self.commit_parent(object_id, stripe);
        fs::create_dir_all(&parent)?;
        let target = parent.join(format!("p{pointer}"));
        if target.exists() {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "commit pointer exists"));
        }
        self.check_failure(&target)?;
        fs::rename(&src, &target)?;
        // Atomic manifest/pointer switch for the stripe.
        self.atomic_write(&parent.join("CURRENT.tmp"), format!("p{pointer}\n").as_bytes())?;
        fs::rename(parent.join("CURRENT.tmp"), parent.join("CURRENT"))?;
        Ok(target)
    }
}

trait WithExtraTemp {
    fn with_extra_temp_name(&self) -> PathBuf;
}

impl WithExtraTemp for Path {
    fn with_extra_temp_name(&self) -> PathBuf {
        let mut n = self.file_name().unwrap().to_os_string();
        n.push(".parttmp");
        self.with_file_name(n)
    }
}

/// Keep path components filesystem-safe (object/source ids are external).
fn safe(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}
