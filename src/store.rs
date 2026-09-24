//! SQLite-backed metadata plus raw-blob storage on disk.
//!
//! Crash safety model:
//! * Received fragments and recovered blocks live in separate directories;
//!   recovered blocks are never written into the original fragment directory.
//! * A recovered stripe is committed in one SQLite transaction after its
//!   blocks were durably staged; a final rename publishes them, then the
//!   commit is marked `verified`. On startup, committed stripes whose blocks
//!   are missing or fail their digests are rolled back, unverified publishes
//!   are discarded, and orphaned temporary blocks are deleted. Final readers
//!   only ever read `verified = 1` committed blocks.

use crate::model::{Manifest};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    None,
    FailBlobWrites,
    CrashBeforeCommit,
    CrashAfterCommitBeforeRename,
}

#[derive(Debug, Clone)]
pub struct FragmentRow {
    pub id: i64,
    pub object_id: String,
    pub stripe_index: usize,
    pub shard_index: usize,
    pub generation: u64,
    pub source: String,
    pub length: usize,
    pub digest: Option<String>,
    pub blob_path: String,
    pub received_at: i64,
}

#[derive(Debug, Clone)]
pub struct CommitRow {
    pub run_id: i64,
    pub generation: u64,
    pub committed_at: i64,
    pub verified: bool,
    pub analysis_json: Option<String>,
}

#[derive(Clone)]
pub struct Store {
    inner: Arc<Mutex<Inner>>,
    pub data_dir: PathBuf,
}

struct Inner {
    conn: Connection,
    fault: Fault,
}

pub fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn safe_name(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    out.chars().take(48).collect()
}

impl Store {
    pub fn open(data_dir: impl Into<PathBuf>) -> std::io::Result<Self> {
        let data_dir = data_dir.into();
        for sub in ["fragments", "recovered", "tmp", "exports", "manifests"] {
            std::fs::create_dir_all(data_dir.join(sub))?;
        }
        let db_path = data_dir.join("pod.db");
        let mut conn = Connection::open(&db_path)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        conn.execute_batch(SCHEMA)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
            .ok();
        let mut inner = Inner {
            conn,
            fault: Fault::None,
        };
        inner.cleanup_temp(&data_dir)?;
        inner.verify_committed(&data_dir)?;
        Ok(Store {
            inner: Arc::new(Mutex::new(inner)),
            data_dir,
        })
    }

    pub fn set_fault(&self, fault: Fault) {
        self.inner.lock().unwrap().fault = fault;
    }

    pub fn fault(&self) -> Fault {
        self.inner.lock().unwrap().fault
    }

    pub fn with_conn<T>(&self, f: impl FnOnce(&mut Connection) -> T) -> T {
        let mut g = self.inner.lock().unwrap();
        f(&mut g.conn)
    }
}

// ---------------------------------------------------------------------------
// Startup recovery: delete temporary blocks, validate/rollback commits.
// ---------------------------------------------------------------------------

impl Inner {
    fn cleanup_temp(&mut self, data_dir: &Path) -> std::io::Result<()> {
        let tmp = data_dir.join("tmp");
        if tmp.exists() {
            for entry in std::fs::read_dir(&tmp)? {
                let p = entry?.path();
                if p.is_file() {
                    let _ = std::fs::remove_file(&p);
                }
            }
        }
        Ok(())
    }

    fn verify_committed(&mut self, data_dir: &Path) -> std::io::Result<()> {
        // Unverified commits were interrupted between the DB transaction and
        // publishing; their rows cannot be trusted as final data. Roll them
        // back so recovery restarts for those stripes.
        let stale: Vec<(i64, i64, String, usize)> = self
            .conn
            .prepare(
                "SELECT id, run_id, object_id, stripe_index FROM stripe_commits
                 WHERE verified = 0",
            )
            .unwrap()
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)? as usize,
                ))
            })
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        for (id, run_id, object_id, stripe) in stale {
            let _ = self.delete_recovered(&object_id, stripe, run_id, data_dir);
            self.conn
                .execute("DELETE FROM stripe_commits WHERE id = ?1", params![id])
                .ok();
        }

        // Re-hash every block of each verified commit; any missing or changed
        // block invalidates the whole stripe commit.
        let commits: Vec<(String, usize, i64)> = self
            .conn
            .prepare(
                "SELECT object_id, stripe_index, run_id FROM stripe_commits
                 WHERE verified = 1",
            )
            .unwrap()
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)? as usize,
                    r.get::<_, i64>(2)?,
                ))
            })
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        for (object_id, stripe, run_id) in commits {
            let valid = self
                .conn
                .prepare(
                    "SELECT blob_path, digest, length FROM recovered_shards
                     WHERE object_id = ?1 AND stripe_index = ?2 AND run_id = ?3",
                )
                .unwrap()
                .query_map(params![object_id, stripe as i64, run_id], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)? as usize,
                    ))
                })
                .unwrap()
                .all(|row| {
                    let (rel, digest, len) = row.unwrap();
                    let p = data_dir.join(&rel);
                    match std::fs::read(&p) {
                        Ok(bytes) => {
                            bytes.len() == len && crate::digest::of_bytes(&bytes) == digest
                        }
                        Err(_) => false,
                    }
                });
            if !valid {
                self.conn
                    .execute(
                        "DELETE FROM stripe_commits
                         WHERE object_id = ?1 AND stripe_index = ?2",
                        params![object_id, stripe as i64],
                    )
                    .ok();
                let _ = self.delete_recovered(&object_id, stripe, run_id, data_dir);
            }
        }
        Ok(())
    }

    fn delete_recovered(
        &mut self,
        object_id: &str,
        stripe: usize,
        run_id: i64,
        data_dir: &Path,
    ) -> std::io::Result<()> {
        let dir = data_dir
            .join("recovered")
            .join(safe_name(object_id))
            .join(format!("run{run_id}"))
            .join(format!("stripe{stripe}"));
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
        }
        self.conn
            .execute(
                "DELETE FROM recovered_shards
                 WHERE object_id = ?1 AND stripe_index = ?2 AND run_id = ?3",
                params![object_id, stripe as i64, run_id],
            )
            .ok();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Public operations.
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct IngestedFragment {
    pub id: i64,
    pub duplicated: bool,
}

impl Store {
    /// Import a manifest. The JSON is stored verbatim and parsed for the
    /// metadata columns. Re-importing the same object replaces it only when
    /// the new generation is equal or newer; an older generation is rejected.
    pub fn import_manifest(&self, manifest: &Manifest, raw_json: &str) -> Result<(), String> {
        manifest.validate()?;
        let mut g = self.inner.lock().unwrap();
        if let Some((gen, json)) = g
            .conn
            .query_row(
                "SELECT generation, manifest_json FROM objects WHERE object_id = ?1",
                params![manifest.object_id],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|e| e.to_string())?
        {
            if manifest.generation < gen as u64 {
                return Err(format!(
                    "stale manifest generation {} < {}",
                    manifest.generation, gen
                ));
            }
            if json == raw_json {
                return Ok(());
            }
            g.conn
                .execute("DELETE FROM stripe_commits WHERE object_id = ?1", params![manifest.object_id])
                .map_err(|e| e.to_string())?;
        }
        g.conn
            .execute(
                "INSERT INTO objects(object_id, codec_version, k, m, shard_len,
                    data_len, generation, object_digest, stripe_count,
                    manifest_json, imported_at, manifest_error)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,NULL)
                 ON CONFLICT(object_id) DO UPDATE SET
                    codec_version=excluded.codec_version, k=excluded.k,
                    m=excluded.m, shard_len=excluded.shard_len,
                    data_len=excluded.data_len, generation=excluded.generation,
                    object_digest=excluded.object_digest,
                    stripe_count=excluded.stripe_count,
                    manifest_json=excluded.manifest_json,
                    imported_at=excluded.imported_at,
                    manifest_error=NULL",
                params![
                    manifest.object_id,
                    crate::model::CODEC_V1,
                    manifest.codec.k as i64,
                    manifest.codec.m as i64,
                    manifest.codec.shard_len as i64,
                    manifest.data_len.map(|v| v as i64),
                    manifest.generation as i64,
                    manifest.object_digest,
                    manifest.stripes.len() as i64,
                    raw_json,
                    now_ms(),
                ],
            )
            .map_err(|e| e.to_string())?;
        let mp = self
            .data_dir
            .join("manifests")
            .join(format!("{}.json", safe_name(&manifest.object_id)));
        std::fs::write(mp, raw_json).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn object_ids(&self) -> Vec<String> {
        self.with_conn(|c| {
            c.prepare("SELECT object_id FROM objects ORDER BY object_id")
                .unwrap()
                .query_map([], |r| r.get::<_, String>(0))
                .unwrap()
                .filter_map(Result::ok)
                .collect()
        })
    }

    pub fn get_manifest(&self, object_id: &str) -> Option<Manifest> {
        let json: String = self
            .with_conn(|c| {
                c.query_row(
                    "SELECT manifest_json FROM objects WHERE object_id = ?1",
                    params![object_id],
                    |r| r.get(0),
                )
                .optional()
                    .unwrap()
            })
            ?;
        serde_json::from_str(&json).ok()
    }

    /// Persist a received fragment. Original bytes are written to
    /// `fragments/` and never modified; identical imports from the same
    /// source/generation are deduplicated.
    pub fn ingest_fragment(
        &self,
        object_id: &str,
        stripe: usize,
        shard: usize,
        generation: u64,
        source: &str,
        bytes: &[u8],
        received_at: i64,
        digest_claim: Option<&str>,
    ) -> Result<IngestedFragment, String> {
        let exists: bool = self.with_conn(|c| {
            c.query_row(
                "SELECT 1 FROM fragments
                 WHERE object_id=?1 AND stripe_index=?2 AND shard_index=?3
                   AND generation=?4 AND source=?5",
                params![object_id, stripe as i64, shard as i64, generation as i64, source],
                |_| Ok(()),
            )
            .optional()
            .unwrap()
            .is_some()
        });
        if exists {
            return Ok(IngestedFragment {
                id: -1,
                duplicated: true,
            });
        }
        let digest = crate::digest::of_bytes(bytes);
        let rel = format!(
            "fragments/{}/s{:04}_i{:02}_g{}_{}.bin",
            safe_name(object_id),
            stripe,
            shard,
            generation,
            safe_name(source)
        );
        let final_path = self.data_dir.join(&rel);
        std::fs::create_dir_all(final_path.parent().unwrap()).map_err(|e| e.to_string())?;
        let tmp_path = self.data_dir.join("tmp").join(format!(
            "frag_{}_{}_{}_{}_{}",
            safe_name(object_id),
            stripe,
            shard,
            generation,
            safe_name(source)
        ));
        std::fs::write(&tmp_path, bytes).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp_path, &final_path).map_err(|e| e.to_string())?;
        let mut g = self.inner.lock().unwrap();
        g.conn
            .execute(
                "INSERT INTO fragments(object_id, stripe_index, shard_index,
                    generation, source, length, digest, blob_path, received_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    object_id,
                    stripe as i64,
                    shard as i64,
                    generation as i64,
                    source,
                    bytes.len() as i64,
                    digest_claim.unwrap_or(&digest),
                    rel,
                    received_at,
                ],
            )
            .map_err(|e| e.to_string())?;
        let id = g.conn.last_insert_rowid();
        Ok(IngestedFragment {
            id,
            duplicated: false,
        })
    }

    pub fn fragments_for(&self, object_id: &str, stripe: usize) -> Vec<FragmentRow> {
        self.with_conn(|c| {
            c.prepare(
                "SELECT id, object_id, stripe_index, shard_index, generation,
                        source, length, digest, blob_path, received_at
                 FROM fragments
                 WHERE object_id=?1 AND stripe_index=?2
                 ORDER BY shard_index, generation, source, id",
            )
            .unwrap()
            .query_map(params![object_id, stripe as i64], row_to_fragment)
            .unwrap()
            .filter_map(Result::ok)
            .collect()
        })
    }

    pub fn all_fragments(&self, object_id: &str) -> Vec<FragmentRow> {
        self.with_conn(|c| {
            c.prepare(
                "SELECT id, object_id, stripe_index, shard_index, generation,
                        source, length, digest, blob_path, received_at
                 FROM fragments
                 WHERE object_id=?1
                 ORDER BY stripe_index, shard_index, generation, source, id",
            )
            .unwrap()
            .query_map(params![object_id], row_to_fragment)
            .unwrap()
            .filter_map(Result::ok)
            .collect()
        })
    }

    pub fn read_fragment(&self, row: &FragmentRow) -> std::io::Result<Vec<u8>> {
        std::fs::read(self.data_dir.join(&row.blob_path))
    }

    pub fn isolated_sources(&self) -> Vec<String> {
        self.with_conn(|c| {
            c.prepare("SELECT source FROM isolated_sources ORDER BY source")
                .unwrap()
                .query_map([], |r| r.get::<_, String>(0))
                .unwrap()
                .filter_map(Result::ok)
                .collect()
        })
    }

    pub fn set_isolated(&self, source: &str, isolated: bool, reason: &str) {
        self.with_conn(|c| {
            if isolated {
                c.execute(
                    "INSERT OR REPLACE INTO isolated_sources(source, isolated_at, reason)
                     VALUES (?1, ?2, ?3)",
                    params![source, now_ms(), reason],
                )
                .ok();
            } else {
                c.execute("DELETE FROM isolated_sources WHERE source=?1", params![source])
                    .ok();
            }
        });
    }

    pub fn committed(&self, object_id: &str, stripe: usize) -> Option<CommitRow> {
        self.with_conn(|c| {
            c.query_row(
                "SELECT run_id, generation, committed_at, verified, analysis_json
                 FROM stripe_commits WHERE object_id=?1 AND stripe_index=?2",
                params![object_id, stripe as i64],
                |r| {
                    Ok(CommitRow {
                        run_id: r.get(0)?,
                        generation: r.get::<_, i64>(1)? as u64,
                        committed_at: r.get(2)?,
                        verified: r.get::<_, i64>(3)? != 0,
                        analysis_json: r.get(4)?,
                    })
                },
            )
            .optional()
            .unwrap()
        })
    }

    pub fn committed_shards(
        &self,
        object_id: &str,
        stripe: usize,
    ) -> Vec<(usize, Vec<u8>, String)> {
        let rows: Vec<(i64, String)> = self.with_conn(|c| {
            c.prepare(
                "SELECT shard_index, blob_path FROM recovered_shards
                 WHERE object_id=?1 AND stripe_index=?2 AND run_id = (
                    SELECT run_id FROM stripe_commits
                    WHERE object_id=?1 AND stripe_index=?2)
                 ORDER BY shard_index",
            )
            .unwrap()
            .query_map(params![object_id, stripe as i64], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
            })
            .unwrap()
            .filter_map(Result::ok)
            .collect()
        });
        rows.into_iter()
            .filter_map(|(idx, rel)| {
                std::fs::read(self.data_dir.join(&rel))
                    .ok()
                    .map(|b| {
                        let d = crate::digest::of_bytes(&b);
                        (idx as usize, b, d)
                    })
            })
            .collect()
    }
}

fn row_to_fragment(r: &rusqlite::Row<'_>) -> rusqlite::Result<FragmentRow> {
    Ok(FragmentRow {
        id: r.get(0)?,
        object_id: r.get(1)?,
        stripe_index: r.get::<_, i64>(2)? as usize,
        shard_index: r.get::<_, i64>(3)? as usize,
        generation: r.get::<_, i64>(4)? as u64,
        source: r.get(5)?,
        length: r.get::<_, i64>(6)? as usize,
        digest: r.get(7)?,
        blob_path: r.get(8)?,
        received_at: r.get(9)?,
    })
}

impl Store {
    pub fn start_run(&self, note: &str) -> i64 {
        self.with_conn(|c| {
            c.execute(
                "INSERT INTO runs(started_at, status, note) VALUES (?1,'running',?2)",
                params![now_ms(), note],
            )
            .unwrap();
            c.last_insert_rowid()
        })
    }

    pub fn finish_run(&self, run_id: i64, status: &str) {
        self.with_conn(|c| {
            c.execute(
                "UPDATE runs SET finished_at=?1, status=?2 WHERE id=?3",
                params![now_ms(), status, run_id],
            )
            .ok();
        });
    }

    /// Remove a previously committed stripe (used by forced recompute after
    /// isolation changes).
    pub fn delete_commit(&self, object_id: &str, stripe: usize) -> std::io::Result<()> {
        let run_id = self.with_conn(|c| {
            c.query_row(
                "SELECT run_id FROM stripe_commits WHERE object_id=?1 AND stripe_index=?2",
                params![object_id, stripe as i64],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .unwrap()
        });
        if let Some(run_id) = run_id {
            let mut g = self.inner.lock().unwrap();
            let _ = g.delete_recovered(object_id, stripe, run_id, &self.data_dir);
            g.conn
                .execute(
                    "DELETE FROM stripe_commits WHERE object_id=?1 AND stripe_index=?2",
                    params![object_id, stripe as i64],
                )
                .ok();
        }
        Ok(())
    }

    /// Atomically commit a recovered stripe.
    ///
    /// 1. Stage every recovered block under `tmp/`.
    /// 2. Insert all rows (with `verified = 0`) in one transaction.
    /// 3. Rename staged blocks into `recovered/`.
    /// 4. Flip the commit to `verified = 1`.
    ///
    /// A crash anywhere before step 4 leaves no final-readable state; startup
    /// verification rolls the stripe back and deletes orphan blocks.
    pub fn commit_stripe(
        &self,
        object_id: &str,
        stripe: usize,
        generation: u64,
        run_id: i64,
        recovered: &[(usize, Vec<u8>)],
        analysis_json: &str,
    ) -> Result<(), String> {
        let fault = self.fault();
        if matches!(fault, Fault::FailBlobWrites) {
            return Err("injected disk failure: blob write denied".into());
        }
        let final_dir = self
            .data_dir
            .join("recovered")
            .join(safe_name(object_id))
            .join(format!("run{run_id}"))
            .join(format!("stripe{stripe}"));
        std::fs::create_dir_all(&final_dir).map_err(|e| e.to_string())?;

        struct Staged {
            shard: usize,
            bytes: Vec<u8>,
            digest: String,
            tmp: PathBuf,
            final_path: PathBuf,
            rel: String,
        }
        let mut staged = Vec::new();
        for (shard, bytes) in recovered {
            if matches!(fault, Fault::FailBlobWrites) {
                return Err("injected disk failure mid-batch".into());
            }
            let digest = crate::digest::of_bytes(bytes);
            let tmp = self.data_dir.join("tmp").join(format!(
                "rec_{}_{}_{}_{}.bin",
                safe_name(object_id),
                stripe,
                shard,
                run_id
            ));
            let rel = format!(
                "recovered/{}/run{}/stripe{}/shard{:02}.bin",
                safe_name(object_id),
                run_id,
                stripe,
                shard
            );
            let final_path = self.data_dir.join(&rel);
            std::fs::write(&tmp, bytes).map_err(|e| {
                let _ = std::fs::remove_file(&tmp);
                e.to_string()
            })?;
            staged.push(Staged {
                shard: *shard,
                bytes: bytes.clone(),
                digest,
                tmp,
                final_path,
                rel,
            });
        }

        if matches!(fault, Fault::CrashBeforeCommit) {
            return Err("injected crash before stripe commit".into());
        }

        {
            let mut g = self.inner.lock().unwrap();
            let tx = g.conn.transaction().map_err(|e| e.to_string())?;
            tx.execute(
                "INSERT INTO stripe_commits(object_id, stripe_index, run_id,
                    generation, committed_at, verified, analysis_json)
                 VALUES (?1,?2,?3,?4,?5,0,?6)",
                params![
                    object_id,
                    stripe as i64,
                    run_id,
                    generation as i64,
                    now_ms(),
                    analysis_json
                ],
            )
            .map_err(|e| e.to_string())?;
            for s in &staged {
                tx.execute(
                    "INSERT INTO recovered_shards(object_id, stripe_index,
                        shard_index, run_id, blob_path, digest, length)
                     VALUES (?1,?2,?3,?4,?5,?6,?7)",
                    params![
                        object_id,
                        stripe as i64,
                        s.shard as i64,
                        run_id,
                        s.rel,
                        s.digest,
                        s.bytes.len() as i64
                    ],
                )
                .map_err(|e| e.to_string())?;
            }
            tx.commit().map_err(|e| e.to_string())?;
        }

        if matches!(fault, Fault::CrashAfterCommitBeforeRename) {
            return Err("injected crash after commit before rename".into());
        }

        for s in &staged {
            std::fs::rename(&s.tmp, &s.final_path).map_err(|e| e.to_string())?;
        }

        self.with_conn(|c| {
            c.execute(
                "UPDATE stripe_commits SET verified=1, committed_at=?1
                 WHERE object_id=?2 AND stripe_index=?3 AND run_id=?4",
                params![now_ms(), object_id, stripe as i64, run_id],
            )
            .map_err(|e| e.to_string())?;
            Ok::<_, String>(())
        })?;
        Ok(())
    }
}
