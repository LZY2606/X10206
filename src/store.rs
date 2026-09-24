//! SQLite-backed persistence plus content-addressed byte storage.
//!
//! Directory layout (all under `data-dir`):
//!   db.sqlite3
//!   blobs/<sha256[0..2]>/<sha256>              raw received bytes (immutable)
//!   shards/<object>/stripe-<s>/shard-<i>.block committed stripe outputs
//!   shards/<object>/tmp.<pid>-<ts>/...         staging blocks (never final)
//!   exports/<object>-<ts>/.manifest.tmp        atomic manifest switch
//!
//! Original received fragments are never modified.

use crate::model::*;
use anyhow::{anyhow, bail, Context, Result};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct ImportedFragment {
    pub fragment_id: i64,
    pub object_id: String,
    pub shard_index: u32,
    pub generation: u32,
    pub received_digest: Option<String>,
    pub recomputed_digest: String,
    pub source: String,
    pub length: u64,
    pub status: FragmentStatus,
}

#[derive(Debug, Clone)]
pub struct DbFragment {
    pub id: i64,
    pub shard_index: u32,
    pub generation: u32,
    pub source: String,
    pub received_digest: Option<String>,
    pub recomputed_digest: String,
    pub length: u64,
    pub status: FragmentStatus,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StripeCommitRow {
    pub stripe_index: u32,
    pub generation: u32,
    pub solution_key: String,
    pub state: String,
    pub object_verified: bool,
    pub output_digests: Vec<String>,
}

/// Fault injection: fail the Nth staging block write with an IO error.
#[derive(Clone, Default)]
pub struct Faults {
    pub fail_commit_write_after: Option<u64>,
}

pub struct Store {
    pub root: PathBuf,
    pub conn: Mutex<Connection>,
    pub faults: Mutex<Faults>,
    pub commit_write_counter: Mutex<u64>,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

impl Store {
    pub fn open(root: impl AsRef<Path>) -> Result<Arc<Store>> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(root.join("blobs"))?;
        std::fs::create_dir_all(root.join("shards"))?;
        std::fs::create_dir_all(root.join("exports"))?;
        let conn = Connection::open(root.join("db.sqlite3"))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let store = Arc::new(Store {
            root,
            conn: Mutex::new(conn),
            faults: Mutex::new(Faults::default()),
            commit_write_counter: Mutex::new(0),
        });
        store.migrate()?;
        store.cleanup_temp_dirs()?;
        store.reconcile_commits()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<()> {
        let c = self.conn.lock().unwrap();
        c.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS objects (
                object_id      TEXT PRIMARY KEY,
                manifest_json  TEXT NOT NULL,
                data_len       INTEGER NOT NULL,
                object_digest  TEXT NOT NULL,
                k              INTEGER NOT NULL,
                n              INTEGER NOT NULL,
                stripe_size    INTEGER NOT NULL,
                stripe_count   INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS fragments (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                object_id         TEXT NOT NULL REFERENCES objects(object_id),
                shard_index       INTEGER NOT NULL,
                generation        INTEGER NOT NULL DEFAULT 0,
                source            TEXT NOT NULL DEFAULT 'unknown',
                received_digest   TEXT,
                recomputed_digest TEXT NOT NULL,
                length            INTEGER NOT NULL,
                blob_path         TEXT NOT NULL,
                status            TEXT NOT NULL DEFAULT 'eligible',
                imported_at       TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(object_id, shard_index, generation, source, recomputed_digest)
            );
            CREATE INDEX IF NOT EXISTS idx_fragments_obj ON fragments(object_id);
            CREATE TABLE IF NOT EXISTS isolated_sources (
                source      TEXT PRIMARY KEY,
                reason      TEXT NOT NULL DEFAULT '',
                isolated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS stripe_commits (
                object_id     TEXT NOT NULL REFERENCES objects(object_id),
                stripe_index  INTEGER NOT NULL,
                generation    INTEGER NOT NULL,
                solution_key  TEXT NOT NULL,
                state         TEXT NOT NULL DEFAULT 'committed',
                solutions_json TEXT NOT NULL DEFAULT '[]',
                output_digests TEXT NOT NULL,
                object_verified INTEGER NOT NULL DEFAULT 0,
                committed_at  TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (object_id, stripe_index)
            );
            CREATE TABLE IF NOT EXISTS exports (
                object_id TEXT PRIMARY KEY REFERENCES objects(object_id),
                dir       TEXT NOT NULL,
                digest    TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            "#,
        )?;
        Ok(())
    }

    pub fn blob_path(&self, digest: &str) -> PathBuf {
        self.root.join("blobs").join(&digest[0..2]).join(digest)
    }

    /// Store raw bytes once (content-addressed). Never overwrites user data.
    pub fn put_blob(&self, bytes: &[u8]) -> Result<(String, PathBuf)> {
        let digest = sha256_hex(bytes);
        let path = self.blob_path(&digest);
        if !path.exists() {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
            std::fs::write(&tmp, bytes)?;
            std::fs::rename(&tmp, &path)?;
        }
        Ok((digest, path))
    }

    pub fn read_blob(&self, digest: &str) -> Result<Vec<u8>> {
        std::fs::read(self.blob_path(digest)).context("reading content-addressed blob")
    }
}

// ---------------------------------------------------------------------------
// Manifest & fragment import
// ---------------------------------------------------------------------------

impl Store {
    pub fn upsert_manifest(&self, m: &ManifestV1) -> Result<()> {
        if m.manifest_format != "srm-manifest/v1" {
            bail!("unsupported manifest format: {}", m.manifest_format);
        }
        if m.codec.version != 1 {
            bail!("unsupported codec version: {}", m.codec.version);
        }
        let k = m.codec.k();
        let n = m.codec.n();
        if k == 0 || n < k || n > MAX_TOTAL_SHARDS || m.codec.stripe_size == 0 {
            bail!("invalid codec params: k={k}, n={n}");
        }
        let stripe_count = CodecParams::stripe_count(m.data_len, m.codec.stripe_size);
        self.conn.lock().unwrap().execute(
            "INSERT INTO objects(object_id, manifest_json, data_len, object_digest, k, n, stripe_size, stripe_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(object_id) DO UPDATE SET
               manifest_json=excluded.manifest_json, data_len=excluded.data_len,
               object_digest=excluded.object_digest, k=excluded.k, n=excluded.n,
               stripe_size=excluded.stripe_size, stripe_count=excluded.stripe_count",
            params![
                m.object_id,
                serde_json::to_string(m)?,
                m.data_len as i64,
                m.object_digest,
                k as i64,
                n as i64,
                m.codec.stripe_size as i64,
                stripe_count as i64,
            ],
        )?;
        self.reclassify(&m.object_id)?;
        Ok(())
    }

    pub fn get_manifest(&self, object_id: &str) -> Result<Option<ManifestV1>> {
        let c = self.conn.lock().unwrap();
        let mut stmt = c.prepare("SELECT manifest_json FROM objects WHERE object_id = ?1")?;
        let mut rows = stmt.query(params![object_id])?;
        match rows.next()? {
            None => Ok(None),
            Some(row) => Ok(Some(serde_json::from_str(row.get_ref(0)?.as_str()?)?)),
        }
    }

    pub fn list_objects(&self) -> Result<Vec<(String, i64, i64, i64)>> {
        let c = self.conn.lock().unwrap();
        let mut stmt = c.prepare(
            "SELECT object_id, data_len, k, stripe_count FROM objects ORDER BY object_id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn isolated_sources(&self) -> Result<Vec<String>> {
        let c = self.conn.lock().unwrap();
        let mut stmt = c.prepare("SELECT source FROM isolated_sources ORDER BY source")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn set_source_isolated(&self, source: &str, isolated: bool, reason: &str) -> Result<()> {
        let mut c = self.conn.lock().unwrap();
        let tx = c.transaction()?;
        if isolated {
            tx.execute(
                "INSERT INTO isolated_sources(source, reason) VALUES (?1, ?2)
                 ON CONFLICT(source) DO UPDATE SET reason=excluded.reason",
                params![source, reason],
            )?;
        } else {
            tx.execute("DELETE FROM isolated_sources WHERE source = ?1", params![source])?;
        }
        // Mark every committed stripe using this source as stale (best-effort
        // membership via stored solutions JSON).
        let mut sel = tx.prepare(
            "SELECT object_id, stripe_index, solutions_json FROM stripe_commits WHERE state='committed'",
        )?;
        let affected: Vec<(String, i64)> = sel
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?))
            })?
            .filter_map(|r| r.ok())
            .filter(|(_, _, json)| json.contains(&format!("\"source\":\"{source}\"")))
            .map(|(o, s, _)| (o, s))
            .collect();
        drop(sel);
        for (object_id, stripe_index) in affected {
            tx.execute(
                "UPDATE stripe_commits SET state='stale' WHERE object_id=?1 AND stripe_index=?2",
                params![object_id, stripe_index],
            )?;
        }
        tx.commit()?;
        drop(c);
        for object_id in self
            .list_objects()?
            .into_iter()
            .map(|(id, _, _, _)| id)
            .collect::<Vec<_>>()
        {
            self.reclassify(&object_id)?;
        }
        Ok(())
    }

    fn reclassify(&self, object_id: &str) -> Result<()> {
        let Some(manifest) = self.get_manifest(object_id)? else {
            return Ok(());
        };
        let isolated = self.isolated_sources()?;
        let k = manifest.codec.k();
        let n = manifest.codec.n();
        let block_len = manifest.codec.stripe_size as usize;
        let c = self.conn.lock().unwrap();
        let mut stmt = c.prepare(
            "SELECT id, shard_index, length, source, received_digest, recomputed_digest
             FROM fragments WHERE object_id = ?1",
        )?;
        let rows = stmt.query_map(params![object_id], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i32>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, String>(5)?,
            ))
        })?;
        let records = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        drop(stmt);
        for (id, shard_index, length, source, received_digest, recomputed) in records {
            let idx = shard_index as u32;
            let status = if idx as usize >= n {
                FragmentStatus::IndexOutOfRange
            } else if isolated.iter().any(|s| s == &source) {
                FragmentStatus::SourceIsolated
            } else if length != block_len as i64 {
                FragmentStatus::LengthMismatch
            } else if let Some(d) = &received_digest {
                if !digest_eq(d, &recomputed) {
                    FragmentStatus::ReceivedDigestMismatch
                } else if let Some(expected) = manifest.shard_digests.get(&idx) {
                    if !digest_eq(expected, &recomputed) {
                        FragmentStatus::ManifestDigestMismatch
                    } else {
                        FragmentStatus::Eligible
                    }
                } else {
                    FragmentStatus::Eligible
                }
            } else if let Some(expected) = manifest.shard_digests.get(&idx) {
                if !digest_eq(expected, &recomputed) {
                    FragmentStatus::ManifestDigestMismatch
                } else {
                    FragmentStatus::Eligible
                }
            } else {
                FragmentStatus::Eligible
            };
            c.execute(
                "UPDATE fragments SET status=?1 WHERE id=?2",
                params![status.as_str(), id],
            )?;
        }
        let _ = k;
        Ok(())
    }

    pub fn fragments_for_object(&self, object_id: &str) -> Result<Vec<DbFragment>> {
        let c = self.conn.lock().unwrap();
        let mut stmt = c.prepare(
            "SELECT id, shard_index, generation, source, received_digest, recomputed_digest, length, status
             FROM fragments WHERE object_id = ?1 ORDER BY shard_index, id",
        )?;
        let rows = stmt.query_map(params![object_id], |r| {
            Ok(DbFragment {
                id: r.get(0)?,
                shard_index: r.get::<_, i64>(1)? as u32,
                generation: r.get::<_, i64>(2)? as u32,
                source: r.get(3)?,
                received_digest: r.get(4)?,
                recomputed_digest: r.get(5)?,
                length: r.get::<_, i64>(6)? as u64,
                status: FragmentStatus::parse(r.get_ref(7)?.as_str()?),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn import_fragment(
        &self,
        object_id: &str,
        meta: &FragmentMeta,
        bytes: &[u8],
    ) -> Result<ImportedFragment> {
        if self.get_manifest(object_id)?.is_none() {
            bail!("no manifest known for object {object_id}; import the manifest first");
        }
        let (digest, blob_path) = self.put_blob(bytes)?;
        let source = meta.source.clone().unwrap_or_else(|| "unknown".to_string());
        let c = self.conn.lock().unwrap();
        c.execute(
            "INSERT INTO fragments(object_id, shard_index, generation, source, received_digest, recomputed_digest, length, blob_path, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'eligible')
             ON CONFLICT(object_id, shard_index, generation, source, recomputed_digest) DO NOTHING",
            params![
                object_id,
                meta.shard_index as i64,
                meta.generation as i64,
                source,
                meta.received_digest,
                digest,
                bytes.len() as i64,
                blob_path.to_string_lossy().as_ref(),
            ],
        )?;
        drop(c);
        self.reclassify(object_id)?;
        let frags = self.fragments_for_object(object_id)?;
        frags
            .into_iter()
            .find(|f| {
                f.shard_index == meta.shard_index
                    && f.generation == meta.generation
                    && f.source == source
                    && digest_eq(&f.recomputed_digest, &digest)
            })
            .map(|f| ImportedFragment {
                fragment_id: f.id,
                object_id: object_id.to_string(),
                shard_index: f.shard_index,
                generation: f.generation,
                received_digest: f.received_digest,
                recomputed_digest: f.recomputed_digest,
                source: f.source,
                length: f.length,
                status: f.status,
            })
            .ok_or_else(|| anyhow!("imported fragment vanished for {object_id}"))
    }

    pub fn blob_path_of_fragment(&self, fragment_id: i64) -> Result<PathBuf> {
        let c = self.conn.lock().unwrap();
        let p: String = c.query_row(
            "SELECT blob_path FROM fragments WHERE id = ?1",
            params![fragment_id],
            |r| r.get(0),
        )?;
        Ok(PathBuf::from(p))
    }
}

fn digest_eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

// ---------------------------------------------------------------------------
// Per-stripe commit, crash recovery reconciliation, object verification
// ---------------------------------------------------------------------------

impl Store {
    pub fn solution_dir(&self, object_id: &str, stripe_index: u32, solution_key: &str) -> PathBuf {
        self.root
            .join("shards")
            .join(object_id)
            .join(format!("stripe-{stripe_index}"))
            .join(format!("sol-{solution_key}"))
    }

    /// Materialize all n stripe blocks for a chosen solution in a fresh staging
    /// directory, verify every digest, then publish the directory + DB row
    /// atomically. On any failure the staging directory is removed and no
    /// final state is visible.
    pub fn commit_stripe(
        &self,
        object_id: &str,
        stripe_index: u32,
        generation: u32,
        solution_key: &str,
        candidates_json: &str,
        outputs: &[Vec<u8>],
    ) -> Result<()> {
        let manifest = self
            .get_manifest(object_id)?
            .ok_or_else(|| anyhow!("unknown object {object_id}"))?;
        let n = manifest.codec.n();
        if outputs.len() != n {
            bail!("expected {n} output blocks, got {}", outputs.len());
        }
        let expected_digests: Vec<String> = outputs.iter().map(|b| sha256_hex(b)).collect();

        let final_dir = self.solution_dir(object_id, stripe_index, solution_key);
        let staging = self.root.join("shards").join(object_id).join(format!(
            "tmp.{}.{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&staging)?;
        let write_result = (|| -> Result<()> {
            for (i, block) in outputs.iter().enumerate() {
                let mut counter = self.commit_write_counter.lock().unwrap();
                *counter += 1;
                let fail_after = self.faults.lock().unwrap().fail_commit_write_after;
                if let Some(limit) = fail_after {
                    if *counter > limit {
                        bail!("simulated disk write failure (injected after {limit} blocks)");
                    }
                }
                drop(counter);
                let name = format!("shard-{i}.block");
                let tmp_file = staging.join(format!("{name}.tmp"));
                std::fs::write(&tmp_file, block)?;
                std::fs::rename(&tmp_file, staging.join(&name))?;
                let on_disk = std::fs::read(staging.join(&name))?;
                if sha256_hex(&on_disk) != expected_digests[i] {
                    bail!("digest mismatch while staging block {i}");
                }
            }
            Ok(())
        })();
        if write_result.is_err() {
            let _ = std::fs::remove_dir_all(&staging);
            write_result?;
        }

        // Publish: rename the complete staging tree into its solution dir.
        if final_dir.exists() {
            // Identical solution already materialized (e.g. crash window).
            if let Ok(existing) = std::fs::read_dir(&final_dir) {
                let ok = existing.flatten().count() == n
                    && expected_digests.iter().enumerate().all(|(i, d)| {
                        std::fs::read(final_dir.join(format!("shard-{i}.block")))
                            .map(|b| sha256_hex(&b) == *d)
                            .unwrap_or(false)
                    });
                if !ok {
                    bail!("solution directory {final_dir:?} exists with different content");
                }
            }
            let _ = std::fs::remove_dir_all(&staging);
        } else {
            std::fs::create_dir_all(final_dir.parent().unwrap())?;
            std::fs::rename(&staging, &final_dir)?;
        }

        let digest_json = serde_json::to_string(&expected_digests)?;
        let mut c = self.conn.lock().unwrap();
        let tx = c.transaction()?;
        tx.execute(
            "INSERT INTO stripe_commits(object_id, stripe_index, generation, solution_key, state, solutions_json, output_digests, object_verified, committed_at)
             VALUES (?1, ?2, ?3, ?4, 'committed', ?5, ?6, 0, datetime('now'))
             ON CONFLICT(object_id, stripe_index) DO UPDATE SET
               generation=excluded.generation, solution_key=excluded.solution_key,
               state='committed', solutions_json=excluded.solutions_json,
               output_digests=excluded.output_digests, object_verified=0,
               committed_at=datetime('now')",
            params![object_id, stripe_index as i64, generation as i64, solution_key, candidates_json, digest_json],
        )?;
        tx.commit()?;
        drop(c);
        let verified = self.verify_object(object_id)?;
        self.verify_object(object_id)?;
        let _ = verified;
        Ok(())
    }

    pub fn clear_commit(&self, object_id: &str, stripe_index: u32) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "DELETE FROM stripe_commits WHERE object_id=?1 AND stripe_index=?2",
            params![object_id, stripe_index as i64],
        )?;
        Ok(())
    }

    pub fn list_commits(&self, object_id: &str) -> Result<Vec<StripeCommitRow>> {
        let c = self.conn.lock().unwrap();
        let mut stmt = c.prepare(
            "SELECT stripe_index, generation, solution_key, state, object_verified, output_digests
             FROM stripe_commits WHERE object_id=?1 ORDER BY stripe_index",
        )?;
        let rows = stmt.query_map(params![object_id], |r| {
            let digests: String = r.get(5)?;
            Ok(StripeCommitRow {
                stripe_index: r.get::<_, i64>(0)? as u32,
                generation: r.get::<_, i64>(1)? as u32,
                solution_key: r.get(2)?,
                state: r.get(3)?,
                object_verified: r.get::<_, i64>(4)? != 0,
                output_digests: serde_json::from_str(&digests).unwrap_or_default(),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    fn committed_block(&self, object_id: &str, stripe: u32, shard: usize) -> Result<Option<(Vec<u8>, String)>> {
        let row = {
            let c = self.conn.lock().unwrap();
            let v: Option<(String, String)> = c
                .query_row(
                    "SELECT solution_key, output_digests FROM stripe_commits
                     WHERE object_id=?1 AND stripe_index=?2 AND state='committed'",
                    params![object_id, stripe as i64],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .ok();
            v
        };
        let Some((solution_key, digest_json)) = row else {
            return Ok(None);
        };
        let digests: Vec<String> = serde_json::from_str(&digest_json).unwrap_or_default();
        let path = self
            .solution_dir(object_id, stripe, &solution_key)
            .join(format!("shard-{shard}.block"));
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => return Ok(None),
        };
        let actual = sha256_hex(&bytes);
        if digests.get(shard).map(|d| digest_eq(d, &actual)).unwrap_or(false) {
            Ok(Some((bytes, actual)))
        } else {
            Ok(None)
        }
    }

    /// Verify the assembled object from *committed, digest-complete* stripes.
    /// Only a full, correctly padded reconstruction counts as verified.
    pub fn verify_object(&self, object_id: &str) -> Result<bool> {
        let Some(manifest) = self.get_manifest(object_id)? else {
            return Ok(false);
        };
        let k = manifest.codec.k();
        let stripe_count = CodecParams::stripe_count(manifest.data_len, manifest.codec.stripe_size);
        let commits = self.list_commits(object_id)?;
        let all_committed = commits.len() == stripe_count
            && commits.iter().all(|c| c.state == CommitState::Committed.as_str());
        let mut assembled = Vec::with_capacity(manifest.data_len as usize);
        if all_committed {
            for s in 0..stripe_count as u32 {
                for j in 0..k {
                    match self.committed_block(object_id, s, j)? {
                        Some((bytes, _)) => assembled.extend_from_slice(&bytes),
                        None => {
                            self.set_object_verified(object_id, false)?;
                            return Ok(false);
                        }
                    }
                }
            }
            assembled.truncate(manifest.data_len as usize);
        }
        let ok = all_committed && sha256_hex(&assembled) == manifest.object_digest.to_lowercase();
        self.set_object_verified(object_id, ok)?;
        Ok(ok)
    }

    fn set_object_verified(&self, object_id: &str, ok: bool) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "UPDATE stripe_commits SET object_verified=?1 WHERE object_id=?2",
            params![ok as i64, object_id],
        )?;
        Ok(())
    }

    pub fn read_reconstructed_object(&self, object_id: &str) -> Result<Option<Vec<u8>>> {
        if !self.verify_object(object_id)? {
            return Ok(None);
        }
        let manifest = self.get_manifest(object_id)?.unwrap();
        let k = manifest.codec.k();
        let stripe_count = CodecParams::stripe_count(manifest.data_len, manifest.codec.stripe_size);
        let mut out = Vec::with_capacity(manifest.data_len as usize);
        for s in 0..stripe_count as u32 {
            for j in 0..k {
                let (bytes, _) = self.committed_block(object_id, s, j)?.expect("verified above");
                out.extend_from_slice(&bytes);
            }
        }
        out.truncate(manifest.data_len as usize);
        Ok(Some(out))
    }

    /// Startup reconciliation: reuse only digest-complete committed stripes;
    /// drop any row whose blocks are missing or whose digests disagree.
    fn reconcile_commits(&self) -> Result<()> {
        let objects: Vec<String> = {
            let c = self.conn.lock().unwrap();
            let mut stmt = c.prepare("SELECT object_id FROM objects")?;
            stmt.query_map([], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        for object_id in objects {
            let commits = self.list_commits(&object_id)?;
            for commit in commits {
                let mut complete = true;
                for (shard, expected) in commit.output_digests.iter().enumerate() {
                    let path = self
                        .solution_dir(&object_id, commit.stripe_index, &commit.solution_key)
                        .join(format!("shard-{shard}.block"));
                    match std::fs::read(&path) {
                        Ok(bytes) => {
                            if sha256_hex(&bytes) != expected.to_lowercase() {
                                complete = false;
                            }
                        }
                        Err(_) => complete = false,
                    }
                }
                if !complete {
                    self.conn.lock().unwrap().execute(
                        "DELETE FROM stripe_commits WHERE object_id=?1 AND stripe_index=?2",
                        params![object_id, commit.stripe_index as i64],
                    )?;
                }
            }
            self.verify_object(&object_id)?;
        }
        Ok(())
    }

    fn cleanup_temp_dirs(&self) -> Result<()> {
        let shard_root = self.root.join("shards");
        if !shard_root.exists() {
            return Ok(());
        }
        for obj in std::fs::read_dir(&shard_root)?.flatten() {
            if !obj.path().is_dir() {
                continue;
            }
            for entry in std::fs::read_dir(obj.path())?.flatten() {
                if entry.file_name().to_string_lossy().starts_with("tmp.") {
                    let _ = std::fs::remove_dir_all(entry.path());
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Export with a new directory and atomic manifest switch
// ---------------------------------------------------------------------------

impl Store {
    pub fn export_object(&self, object_id: &str) -> Result<PathBuf> {
        if !self.verify_object(object_id)? {
            bail!("object {object_id} is not fully verified; refusing to export");
        }
        let manifest = self.get_manifest(object_id)?.unwrap();
        let bytes = self
            .read_reconstructed_object(object_id)?
            .ok_or_else(|| anyhow!("reconstructed object unavailable"))?;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let dir = self.root.join("exports").join(format!("{object_id}-{ts}"));
        std::fs::create_dir_all(&dir)?;

        let tmp_obj = dir.join("object.bin.tmp");
        std::fs::write(&tmp_obj, &bytes)?;
        std::fs::rename(&tmp_obj, dir.join("object.bin"))?;

        let stripe_count = CodecParams::stripe_count(manifest.data_len, manifest.codec.stripe_size);
        let commits = self.list_commits(object_id)?;
        let mut stripes = Vec::new();
        for commit in &commits {
            stripes.push(serde_json::json!({
                "stripe_index": commit.stripe_index,
                "generation": commit.generation,
                "solution_key": commit.solution_key,
                "output_digests": commit.output_digests,
            }));
        }
        let export_manifest = serde_json::json!({
            "export_format": "srm-export/v1",
            "object_id": object_id,
            "object_digest": manifest.object_digest,
            "recomputed_digest": sha256_hex(&bytes),
            "data_len": bytes.len(),
            "codec": manifest.codec,
            "stripe_count": stripe_count,
            "stripes": stripes,
            "exported_at": ts,
        });
        // Atomic manifest switch: .manifest.tmp -> manifest.json.
        let tmp_manifest = dir.join(".manifest.tmp");
        std::fs::write(&tmp_manifest, serde_json::to_vec_pretty(&export_manifest)?)?;
        std::fs::rename(&tmp_manifest, dir.join("manifest.json"))?;

        let digest = sha256_hex(&bytes);
        self.conn.lock().unwrap().execute(
            "INSERT INTO exports(object_id, dir, digest) VALUES (?1, ?2, ?3)
             ON CONFLICT(object_id) DO UPDATE SET dir=excluded.dir, digest=excluded.digest, created_at=datetime('now')",
            params![object_id, dir.to_string_lossy().as_ref(), digest],
        )?;
        Ok(dir)
    }
}

// ---------------------------------------------------------------------------
// Offline inbox import
// ---------------------------------------------------------------------------

/// Expected layout:
///   inbox/<object_id>/manifest.json
///   inbox/<object_id>/shard<INDEX>-<source>-gen<GEN>.bin
///   inbox/<object_id>/shard<INDEX>-<source>-gen<GEN>.meta.json   (optional)
pub fn import_inbox(store: &Store, inbox_root: &Path) -> Result<ImportReport> {
    let mut report = ImportReport::default();
    if !inbox_root.exists() {
        return Ok(report);
    }
    for obj_dir in std::fs::read_dir(inbox_root)?.flatten() {
        if !obj_dir.path().is_dir() {
            continue;
        }
        let manifest_path = obj_dir.path().join("manifest.json");
        if !manifest_path.exists() {
            report.errors.push(format!(
                "{}: missing manifest.json",
                obj_dir.path().display()
            ));
            continue;
        }
        let manifest: ManifestV1 =
            serde_json::from_slice(&std::fs::read(&manifest_path)?).with_context(|| {
                format!("parsing {}", manifest_path.display())
            })?;
        let dir_object = obj_dir.file_name().to_string_lossy().to_string();
        if dir_object != manifest.object_id {
            report
                .errors
                .push(format!("{}: object_id mismatch", obj_dir.path().display()));
            continue;
        }
        store.upsert_manifest(&manifest)?;
        report.manifests.push(manifest.object_id.clone());

        for entry in std::fs::read_dir(obj_dir.path())?.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "manifest.json" || !name.ends_with(".bin") {
                continue;
            }
            let stem = &name[..name.len() - 4];
            let Some(parsed) = parse_fragment_name(stem) else {
                report.errors.push(format!("{}: unparseable fragment name", name));
                continue;
            };
            let bytes = std::fs::read(entry.path())?;
            let mut meta = FragmentMeta {
                object_id: manifest.object_id.clone(),
                shard_index: parsed.0,
                source: Some(parsed.1),
                generation: parsed.2,
                ..Default::default()
            };
            let sidecar = entry.path().with_file_name(format!("{stem}.meta.json"));
            if sidecar.exists() {
                let side: FragmentMeta = serde_json::from_slice(&std::fs::read(sidecar)?)?;
                if side.object_id != meta.object_id
                    || side.shard_index != meta.shard_index
                    || side.generation != meta.generation
                {
                    report
                        .errors
                        .push(format!("{name}: sidecar identity mismatch, skipped"));
                    continue;
                }
                meta.received_digest = side.received_digest;
            }
            match store.import_fragment(&manifest.object_id, &meta, &bytes) {
                Ok(f) => {
                    report.fragments += 1;
                    if f.status != FragmentStatus::Eligible {
                        report
                            .excluded
                            .push((manifest.object_id.clone(), f.fragment_id, f.status));
                    }
                }
                Err(e) => report.errors.push(format!("{name}: {e}")),
            }
        }
    }
    Ok(report)
}

/// `shard<INDEX>-<source>-gen<GEN>` (source must not contain '-').
fn parse_fragment_name(stem: &str) -> Option<(u32, String, u32)> {
    let rest = stem.strip_prefix("shard")?;
    let gen_idx = rest.rfind("-gen")?;
    let gen: u32 = rest[gen_idx + 4..].parse().ok()?;
    let middle = &rest[..gen_idx];
    let dash = middle.find('-')?;
    let index: u32 = middle[..dash].parse().ok()?;
    let source = middle[dash + 1..].to_string();
    if source.is_empty() {
        return None;
    }
    Some((index, source, gen))
}

#[derive(Debug, Default)]
pub struct ImportReport {
    pub manifests: Vec<String>,
    pub fragments: usize,
    pub excluded: Vec<(String, i64, FragmentStatus)>,
    pub errors: Vec<String>,
}

// Re-export for callers that build JSON summaries.
pub fn btreemap_summary(rows: &[DbFragment]) -> BTreeMap<u32, usize> {
    let mut m = BTreeMap::new();
    for f in rows {
        *m.entry(f.shard_index).or_insert(0) += 1;
    }
    m
}
