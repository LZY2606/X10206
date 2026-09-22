use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::models::*;

#[derive(Clone)]
pub struct Store {
    pub dir: PathBuf,
    conn: std::sync::Arc<Mutex<Connection>>,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"stripe-recovery-bay/v1/");
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub fn normalize_digest(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn init_sql() -> &'static str {
    r#"
    PRAGMA journal_mode=WAL;
    CREATE TABLE IF NOT EXISTS objects (
      object_id TEXT PRIMARY KEY,
      label TEXT NOT NULL,
      version TEXT NOT NULL,
      k INTEGER NOT NULL,
      m INTEGER NOT NULL,
      stripe_count INTEGER NOT NULL,
      shard_len INTEGER NOT NULL,
      data_len INTEGER,
      object_digest TEXT NOT NULL,
      actual_object_digest TEXT,
      manifest_path TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sources (
      source_id TEXT PRIMARY KEY,
      label TEXT NOT NULL,
      isolated INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS shards (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      object_id TEXT NOT NULL REFERENCES objects(object_id),
      source_id TEXT NOT NULL REFERENCES sources(source_id),
      stripe_index INTEGER NOT NULL,
      shard_index INTEGER NOT NULL,
      generation INTEGER NOT NULL,
      kind TEXT NOT NULL,
      byte_path TEXT NOT NULL,
      actual_len INTEGER NOT NULL,
      actual_digest TEXT NOT NULL,
      claimed_digest TEXT,
      digest_ok INTEGER NOT NULL,
      length_ok INTEGER NOT NULL,
      in_range INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_shards_lookup ON shards(object_id, stripe_index, shard_index, generation);
    CREATE TABLE IF NOT EXISTS solutions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      object_id TEXT NOT NULL REFERENCES objects(object_id),
      stripe_index INTEGER NOT NULL,
      generation INTEGER NOT NULL,
      digest TEXT NOT NULL,
      witness_ids TEXT NOT NULL,
      witness_indices TEXT NOT NULL,
      generated_indices TEXT NOT NULL,
      excluded_ids TEXT NOT NULL,
      excluded_reasons TEXT NOT NULL,
      cross_check_failures TEXT NOT NULL,
      alternative_ids TEXT NOT NULL DEFAULT '[]',
      consistent_ids TEXT NOT NULL DEFAULT '[]',
      search_complete INTEGER NOT NULL DEFAULT 1,
      trusted INTEGER NOT NULL,
      UNIQUE(object_id, stripe_index, digest, witness_ids)
    );
    CREATE TABLE IF NOT EXISTS stripe_commits (
      object_id TEXT NOT NULL,
      stripe_index INTEGER NOT NULL,
      generation INTEGER NOT NULL,
      solution_id INTEGER NOT NULL REFERENCES solutions(id),
      data_digest TEXT NOT NULL,
      output_path TEXT NOT NULL,
      manifest_path TEXT NOT NULL,
      search_budget INTEGER NOT NULL,
      created_at INTEGER NOT NULL,
      PRIMARY KEY(object_id, stripe_index)
    );
    CREATE TABLE IF NOT EXISTS recovery_runs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      object_id TEXT NOT NULL,
      started_at INTEGER NOT NULL,
      finished_at INTEGER,
      search_budget INTEGER NOT NULL,
      attempted INTEGER NOT NULL DEFAULT 0,
      committed INTEGER NOT NULL DEFAULT 0,
      failed TEXT NOT NULL DEFAULT '[]'
    );
    "#
}

impl Store {
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(dir.join("raw")).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(dir.join("stripes.tmp")).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(dir.join("stripes")).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(dir.join("exports")).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(dir.join("manifests")).map_err(|e| e.to_string())?;
        let db_path = dir.join("bay.sqlite3");
        let conn = Connection::open(db_path).map_err(|e| e.to_string())?;
        conn.execute_batch(init_sql()).map_err(|e| e.to_string())?;
        Ok(Self { dir, conn: std::sync::Arc::new(Mutex::new(conn)) })
    }

    pub fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().expect("database mutex poisoned")
    }

    pub fn raw_path(&self, digest: &str) -> PathBuf {
        self.dir.join("raw").join(format!("{digest}.bin"))
    }

    pub fn save_content_addressed(&self, bytes: &[u8]) -> Result<String> {
        let digest = sha256_hex(bytes);
        let path = self.raw_path(&digest);
        if !path.exists() {
            let tmp = self.dir.join("raw").join(format!(".{digest}.tmp"));
            atomic_write(&tmp, &path, bytes)?;
        }
        Ok(digest)
    }

    pub fn read_raw(&self, digest: &str) -> Result<Vec<u8>> {
        std::fs::read(self.raw_path(digest)).map_err(|e| e.to_string())
    }

    pub fn save_manifest(&self, object_id: &str, bytes: &[u8]) -> Result<String> {
        let digest = sha256_hex(bytes);
        let safe = object_id.replace(['/', '\\'], "_");
        let final_path = self.dir.join("manifests").join(format!("{safe}-{digest}.json"));
        if !final_path.exists() {
            let tmp = self.dir.join("manifests").join(format!(".{safe}-{digest}.tmp"));
            atomic_write(&tmp, &final_path, bytes)?;
        }
        Ok(final_path.to_string_lossy().into_owned())
    }

    pub fn ensure_object(&self, request: &ImportRequest, manifest_path: String) -> Result<()> {
        let mut conn = self.lock();
        let exists: i64 = conn
            .query_row("SELECT COUNT(*) FROM objects WHERE object_id=?1", params![request.object_id], |row| row.get(0))
            .map_err(|e| e.to_string())?;
        if exists == 0 {
            conn.execute(
                "INSERT INTO objects(object_id,label,version,k,m,stripe_count,shard_len,data_len,object_digest,manifest_path,created_at)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                params![
                    request.object_id,
                    request.object_label.clone().unwrap_or_else(|| request.object_id.clone()),
                    request.version,
                    request.k,
                    request.m,
                    request.stripe_count,
                    request.shard_len,
                    request.data_len,
                    request.object_digest.clone().unwrap_or_default(),
                    manifest_path,
                    now_millis()
                ],
            ).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub fn ensure_source(&self, source_id: &str, label: &str) -> Result<()> {
        self.lock()
            .execute(
                "INSERT INTO sources(source_id,label) VALUES(?1,?2)
                 ON CONFLICT(source_id) DO UPDATE SET label=CASE WHEN label='' THEN excluded.label ELSE label END",
                params![source_id, label],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    pub fn insert_shard(
        &self,
        object_id: &str,
        source_id: &str,
        stripe_index: i64,
        shard_index: i64,
        generation: i64,
        kind: &str,
        actual_digest: &str,
        claimed_digest: Option<String>,
        actual_len: i64,
        digest_ok: bool,
        length_ok: bool,
        in_range: bool,
    ) -> Result<i64> {
        let byte_path = self.raw_path(actual_digest).to_string_lossy().into_owned();
        self.lock()
            .execute(
                "INSERT INTO shards(object_id,source_id,stripe_index,shard_index,generation,kind,byte_path,actual_len,actual_digest,claimed_digest,digest_ok,length_ok,in_range)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
                params![object_id, source_id, stripe_index, shard_index, generation, kind, byte_path, actual_len, actual_digest, claimed_digest, digest_ok, length_ok, in_range],
            )
            .map_err(|e| e.to_string())?;
        let id = self.lock().last_insert_rowid();
        Ok(id)
    }
}

pub fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as i64
}

pub fn atomic_write(tmp: &Path, final_path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = final_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(tmp, bytes).map_err(|e| e.to_string())?;
    std::fs::rename(tmp, final_path).map_err(|e| e.to_string())
}
