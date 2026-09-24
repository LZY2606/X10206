//! On-disk layout and atomic file operations.
//!
//! ```text
//! <data_dir>/
//!   bay.db
//!   originals/<object>/<stripe>/<idx>__<source>.bin   # imported bytes (never rewritten)
//!   stripe_results/<object>/<stripe>__<gen>.tmp       # in-flight result blocks
//!   stripe_results/<object>/<stripe>__<gen>.bin       # committed stripe results
//!   exports/<run_id>/...                              # each export gets a fresh dir
//! ```
//!
//! Only committed `*.bin` files are ever read as final results; temp blocks
//! are cleared on startup so a crashed process can never feed partial writes
//! into a final read.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use crate::model::BayError;

#[derive(Clone)]
pub struct Storage {
    root: PathBuf,
    fail_next_writes: Arc<AtomicBool>,
    fail_every_nth: Arc<AtomicU64>,
    write_counter: Arc<AtomicU64>,
}

impl Storage {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let s = Storage {
            root: root.into(),
            fail_next_writes: Arc::new(AtomicBool::new(false)),
            fail_every_nth: Arc::new(AtomicU64::new(0)),
            write_counter: Arc::new(AtomicU64::new(0)),
        };
        for dir in [s.originals_dir(), s.results_dir(), s.exports_dir(), s.tmp_dir()] {
            fs::create_dir_all(&dir).expect("create data directories");
        }
        s
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn db_path(&self) -> PathBuf {
        self.root.join("bay.db")
    }

    fn originals_dir(&self) -> PathBuf {
        self.root.join("originals")
    }
    fn results_dir(&self) -> PathBuf {
        self.root.join("stripe_results")
    }
    fn exports_dir(&self) -> PathBuf {
        self.root.join("exports")
    }
    fn tmp_dir(&self) -> PathBuf {
        self.root.join("tmp")
    }

    pub fn object_originals_dir(&self, object_id: &str) -> PathBuf {
        self.originals_dir().join(safe(object_id))
    }

    pub fn original_path(&self, object_id: &str, stripe_idx: usize, shard_idx: usize, source_id: &str) -> PathBuf {
        self.object_originals_dir(object_id)
            .join(format!("s{stripe_idx:04}_i{shard_idx:03}__{}.bin", safe(source_id)))
    }

    pub fn result_tmp(&self, object_id: &str, stripe_idx: usize, generation: u64) -> PathBuf {
        self.tmp_dir()
            .join(format!("{}__s{stripe_idx:04}_g{generation}.tmp", safe(object_id)))
    }

    pub fn result_path(&self, object_id: &str, stripe_idx: usize, generation: u64) -> PathBuf {
        self.results_dir().join(format!(
            "{}/s{stripe_idx:04}_g{generation}.bin",
            safe(object_id)
        ))
    }

    pub fn export_run_dir(&self, run_id: &str) -> PathBuf {
        self.exports_dir().join(safe(run_id))
    }

    pub fn latest_pointer(&self) -> PathBuf {
        self.exports_dir().join("LATEST")
    }

    /// Write imported bytes. Originals are write-once: an existing path is
    /// returned untouched (duplicate content goes to a distinct source name).
    pub fn write_original_once(&self, path: &Path, bytes: &[u8]) -> Result<(), BayError> {
        if path.exists() {
            return Ok(());
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|| BayError::Io {
                path: parent.display().to_string(),
                source: e,
            })?;
        }
        self.atomic_write(path, bytes)
    }

    pub fn read(&self, path: &Path) -> Result<Vec<u8>, BayError> {
        fs::read(path).map_err(|e| BayError::Io {
            path: path.display().to_string(),
            source: e,
        })
    }

    /// Write bytes atomically: unique temp file in the destination directory,
    /// fsync, then rename. Honors the test fault knobs.
    pub fn atomic_write(&self, dest: &Path, bytes: &[u8]) -> Result<(), BayError> {
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|| BayError::Io {
                path: parent.display().to_string(),
                source: e,
            })?;
        }
        let n = self.write_counter.fetch_add(1, Ordering::SeqCst) + 1;
        let every = self.fail_every_nth.load(Ordering::SeqCst);
        let fail = self.fail_next_writes.swap(false, Ordering::SeqCst) || (every != 0 && n % every == 0);
        let unique = format!(
            ".{}.{}.{}.part",
            dest.file_name().and_then(|s| s.to_str()).unwrap_or("out"),
            std::process::id(),
            n
        );
        let tmp = dest.parent().unwrap_or_else(|| Path::new(".")).join(unique);
        let result = (|| -> std::io::Result<()> {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
            if fail {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "injected disk write failure",
                ));
            }
            fs::rename(&tmp, dest)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result.map_err(|e| BayError::Io {
            path: dest.display().to_string(),
            source: e,
        })
    }

    /// Remove every stale temp block left by an interrupted run. Committed
    /// `.bin` results are preserved.
    pub fn clean_stale_temps(&self) -> Result<Vec<PathBuf>, BayError> {
        let mut removed = Vec::new();
        for dir in [self.tmp_dir(), self.results_dir()] {
            if !dir.exists() {
                continue;
            }
            for entry in walk_files(&dir) {
                let name = entry.file_name().to_string_lossy();
                if entry.extension().and_then(|s| s.to_str()) == Some("tmp") || name.starts_with('.') {
                    fs::remove_file(&entry).ok();
                    removed.push(entry);
                }
            }
        }
        Ok(removed)
    }

    // -- test fault knobs --------------------------------------------------

    pub fn inject_fail_next_write(&self) {
        self.fail_next_writes.store(true, Ordering::SeqCst);
    }

    /// 0 disables; otherwise every n-th `atomic_write` fails (temp file is
    /// cleaned up, dest never appears).
    pub fn inject_fail_every_nth(&self, n: u64) {
        self.fail_every_nth.store(n, Ordering::SeqCst);
    }

    pub fn clear_faults(&self) {
        self.fail_next_writes.store(false, Ordering::SeqCst);
        self.fail_every_nth.store(0, Ordering::SeqCst);
    }
}

fn walk_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk_files(&path));
        } else {
            out.push(path);
        }
    }
    out
}

/// Make an external identifier safe to embed in a path segment.
pub fn safe(id: &str) -> String {
    id.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_recovers_from_failure() {
        let dir = std::env::temp_dir().join(format!("bay-storage-test-{}", std::process::id()));
        let s = Storage::new(&dir);
        let dest = s.tmp_dir().join("x.bin");
        s.inject_fail_next_write();
        assert!(s.atomic_write(&dest, b"data").is_err());
        assert!(!dest.exists());
        s.atomic_write(&dest, b"data").unwrap();
        assert_eq!(s.read(&dest).unwrap(), b"data");
        let _ = fs::remove_dir_all(&dir);
    }
}
