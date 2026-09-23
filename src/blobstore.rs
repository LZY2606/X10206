//! Content-addressed, write-once blob storage with atomic temp-file writes.
//!
//! Writes go to `blobs.tmp/` and are `rename(2)`d into `blobs/` only after the
//! full content is fsynced, so a crash never leaves a final reader looking at
//! a partial blob. A process-wide fail point (see [`set_fail_point`]) lets
//! tests simulate disk write failures and interruptions.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use anyhow::{bail, Context};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailPoint {
    /// Fail every Nth final rename (counted per temp id cycle), deterministically.
    RenameEvery { modulus: u64, remainder: u64 },
    /// Panic-style abort between data write and rename (simulates power loss).
    AbortBeforeRename { modulus: u64, remainder: u64 },
    Off,
}

static FAIL_POINT: OnceLock<Mutex<FailPoint>> = OnceLock::new();
static CALL_COUNTER: OnceLock<Mutex<u64>> = OnceLock::new();

fn fp() -> &'static Mutex<FailPoint> {
    FAIL_POINT.get_or_init(|| Mutex::new(FailPoint::Off))
}

pub fn set_fail_point(f: FailPoint) {
    *fp().lock().unwrap() = f;
    *CALL_COUNTER.get_or_init(|| Mutex::new(0)).lock().unwrap() = 0;
}

pub fn reset_fail_point() {
    *fp().lock().unwrap() = FailPoint::Off;
    *CALL_COUNTER.get_or_init(|| Mutex::new(0)).lock().unwrap() = 0;
}

#[derive(Clone)]
pub struct BlobStore {
    root: PathBuf,
    final_dir: PathBuf,
    tmp_dir: PathBuf,
}

impl BlobStore {
    pub fn new(data_dir: &Path) -> anyhow::Result<Self> {
        let root = data_dir.to_path_buf();
        let final_dir = root.join("blobs");
        let tmp_dir = root.join("blobs.tmp");
        std::fs::create_dir_all(&final_dir).context("creating blobs dir")?;
        std::fs::create_dir_all(&tmp_dir).context("creating blobs.tmp dir")?;
        Ok(Self { root, final_dir, tmp_dir })
    }

    pub fn path_for(&self, digest_hex: &str) -> PathBuf {
        let (prefix, rest) = digest_hex.split_at(2);
        self.final_dir.join(prefix).join(rest)
    }

    pub fn contains(&self, digest_hex: &str) -> bool {
        self.path_for(digest_hex).is_file()
    }

    /// Write `bytes` under `expected_digest`. Returns `Ok(existed)` where
    /// `existed == true` means the content was already present.
    pub fn put(&self, expected_digest: &str, bytes: &[u8]) -> anyhow::Result<bool> {
        let dest = self.path_for(expected_digest);
        if dest.is_file() {
            return Ok(true);
        }
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).context("creating blob shard dir")?;
        }
        let call_id = {
            let mut c = CALL_COUNTER.get_or_init(|| Mutex::new(0)).lock().unwrap();
            *c += 1;
            *c
        };
        let tmp = self
            .tmp_dir
            .join(format!("tmp-{}-{}-{}", std::process::id(), call_id, expected_digest));
        {
            use std::io::Write as _;
            let mut f = std::fs::File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
            f.write_all(bytes).with_context(|| format!("writing {}", tmp.display()))?;
            f.sync_all().with_context(|| format!("fsyncing {}", tmp.display()))?;
        }
        let point = *fp().lock().unwrap();
        match point {
            FailPoint::RenameEvery { modulus, remainder } if call_id % modulus == remainder => {
                let _ = std::fs::remove_file(&tmp);
                bail!("simulated disk write failure before rename (call {call_id})");
            }
            FailPoint::AbortBeforeRename { modulus, remainder } if call_id % modulus == remainder => {
                std::process::abort();
            }
            _ => {}
        }
        std::fs::rename(&tmp, &dest).with_context(|| format!("renaming blob into {}", dest.display()))?;
        if let Ok(dir) = std::fs::File::open(&self.root) {
            let _ = dir.sync_all();
        }
        Ok(false)
    }

    pub fn get(&self, digest_hex: &str) -> anyhow::Result<Vec<u8>> {
        let p = self.path_for(digest_hex);
        std::fs::read(&p).with_context(|| format!("reading blob {}", p.display()))
    }

    /// Remove stranded temp files (recovery on startup). Final blobs are never
    /// touched.
    pub fn sweep_temp(&self) -> anyhow::Result<usize> {
        let mut removed = 0;
        for entry in std::fs::read_dir(&self.tmp_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                std::fs::remove_file(entry.path())?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}
