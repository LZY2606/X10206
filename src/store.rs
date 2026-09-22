//! Content-addressed blob store with a staging area for uncommitted blocks.
//!
//! Final readers are only ever handed blob paths referenced by committed
//! recovery blocks in SQLite. Staged blocks live under `staging/` and are
//! swept on startup; blobs that were promoted but never referenced by a
//! committed stripe remain unreferenced orphans and are never read.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::digest::sha256_hex;

#[derive(Default)]
pub struct FailInjection {
    pub blob_write_failures: AtomicUsize,
    pub blob_promote_failures: AtomicUsize,
    /// After this many successful promotes, the next promote fails.
    pub promote_fail_after_success: AtomicUsize,
    promote_success_count: std::sync::atomic::AtomicUsize,
}

impl FailInjection {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn arm_blob_write_failures(self: &Arc<Self>, n: usize) {
        self.blob_write_failures.store(n, Ordering::SeqCst);
    }

    pub fn arm_blob_promote_failures(self: &Arc<Self>, n: usize) {
        self.blob_promote_failures.store(n, Ordering::SeqCst);
        self.promote_fail_after_success.store(0, Ordering::SeqCst);
        self.promote_success_count.store(0, Ordering::SeqCst);
    }

    /// Let `after` promotes succeed, then fail the next one.
    pub fn arm_promote_fail_after(self: &Arc<Self>, after: usize) {
        self.promote_fail_after_success.store(after, Ordering::SeqCst);
        self.promote_success_count.store(0, Ordering::SeqCst);
        self.blob_promote_failures.store(1, Ordering::SeqCst);
    }
}

pub struct StagedBlob {
    pub hash: String,
    pub staged_path: PathBuf,
}

pub struct BlobStore {
    root: PathBuf,
    blobs: PathBuf,
    staging: PathBuf,
    pub failures: Arc<FailInjection>,
}

impl BlobStore {
    pub fn open(root: &Path, failures: Arc<FailInjection>) -> std::io::Result<Self> {
        let blobs = root.join("blobs");
        let staging = root.join("staging");
        fs::create_dir_all(&blobs)?;
        fs::create_dir_all(&staging)?;
        // Sweep uncommitted staged blocks from an interrupted run.
        for entry in fs::read_dir(&staging)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let _ = fs::remove_file(entry.path());
            }
        }
        Ok(Self { root: root.to_path_buf(), blobs, staging, failures })
    }

    fn blob_path(&self, hash: &str) -> PathBuf {
        self.blobs.join(&hash[0..2]).join(&hash[2..4]).join(hash)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn contains(&self, hash: &str) -> bool {
        self.blob_path(hash).exists()
    }

    pub fn read(&self, hash: &str) -> std::io::Result<Vec<u8>> {
        fs::read(self.blob_path(hash))
    }

    pub fn path_for(&self, hash: &str) -> PathBuf {
        self.blob_path(hash)
    }

    /// Write bytes into the staging area. Not readable through `read` until
    /// `promote` is called as part of stripe commit.
    pub fn stage(&self, bytes: &[u8]) -> std::io::Result<StagedBlob> {
        if self.failures.blob_write_failures.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
            if v == 0 { None } else { Some(v - 1) }
        }).is_ok() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "injected blob write failure",
            ));
        }
        let hash = sha256_hex(bytes);
        let staged_path = self.staging.join(format!("{}.tmp-{}", hash, std::process::id()));
        let mut f = fs::File::create(&staged_path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(StagedBlob { hash, staged_path })
    }

    /// Promote a staged blob into the content-addressed store (idempotent).
    pub fn promote(&self, staged: &StagedBlob) -> std::io::Result<String> {
        let armed = self.failures.blob_promote_failures.load(Ordering::SeqCst) > 0;
        if armed {
            let after = self.failures.promote_fail_after_success.load(Ordering::SeqCst);
            let seen = self.failures.promote_success_count.load(Ordering::SeqCst);
            if seen >= after
                && self
                    .failures
                    .blob_promote_failures
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                        if v == 0 { None } else { Some(v - 1) }
                    })
                    .is_ok()
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "injected blob promote failure",
                ));
            }
        }
        let dest = self.blob_path(&staged.hash);
        fs::create_dir_all(dest.parent().unwrap())?;
        if !dest.exists() {
            fs::rename(&staged.staged_path, &dest).or_else(|_| {
                // Fallback for cross-device edge cases.
                fs::copy(&staged.staged_path, &dest).map(|_| ())
            })?;
        } else if let Err(e) = fs::remove_file(&staged.staged_path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(e);
            }
        }
        if armed {
            self.failures.promote_success_count.fetch_add(1, Ordering::SeqCst);
        }
        Ok(staged.hash.clone())
    }

    /// Remove leftover staging files after a failed attempt.
    pub fn discard(&self, staged: &StagedBlob) {
        let _ = fs::remove_file(&staged.staged_path);
    }
}
