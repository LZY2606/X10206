//! SQLite storage. One connection guarded by a mutex (the dataset is small and
//! offline); every stripe commit is a single transaction.

use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::Connection;

pub struct Db {
    pub conn: Mutex<Connection>,
}

const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS objects (
  object_id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS generations (
  object_id TEXT NOT NULL,
  generation INTEGER NOT NULL,
  codec TEXT NOT NULL,
  data_shards INTEGER NOT NULL,
  parity_shards INTEGER NOT NULL,
  shard_size INTEGER NOT NULL,
  stripe_count INTEGER NOT NULL,
  object_size INTEGER NOT NULL,
  object_digest TEXT NOT NULL,
  manifest_source TEXT NOT NULL,
  PRIMARY KEY (object_id, generation)
);

CREATE TABLE IF NOT EXISTS fragments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  object_id TEXT NOT NULL,
  generation INTEGER NOT NULL,
  stripe_index INTEGER NOT NULL,
  shard_index INTEGER NOT NULL,
  blob_hash TEXT NOT NULL,
  byte_length INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(object_id, generation, stripe_index, shard_index, blob_hash)
);

CREATE TABLE IF NOT EXISTS fragment_receipts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  fragment_id INTEGER NOT NULL,
  source TEXT NOT NULL,
  rel_path TEXT NOT NULL,
  received_at INTEGER NOT NULL,
  UNIQUE(fragment_id, source, rel_path)
);

CREATE TABLE IF NOT EXISTS block_digests (
  object_id TEXT NOT NULL,
  generation INTEGER NOT NULL,
  stripe_index INTEGER NOT NULL,
  shard_index INTEGER NOT NULL,
  digest TEXT NOT NULL,
  PRIMARY KEY (object_id, generation, stripe_index, shard_index)
);

CREATE TABLE IF NOT EXISTS isolated_sources (
  object_id TEXT NOT NULL,
  source TEXT NOT NULL,
  isolated_at INTEGER NOT NULL,
  PRIMARY KEY (object_id, source)
);

CREATE TABLE IF NOT EXISTS recoveries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  object_id TEXT NOT NULL,
  started_at INTEGER NOT NULL,
  finished_at INTEGER,
  forced INTEGER NOT NULL DEFAULT 0,
  trigger TEXT NOT NULL,
  isolated_signature TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS stripes (
  object_id TEXT NOT NULL,
  stripe_index INTEGER NOT NULL,
  active_recovery_id INTEGER,
  active_outcome_id INTEGER,
  generation INTEGER,
  isolated_signature TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL,
  ambiguous INTEGER NOT NULL DEFAULT 0,
  note TEXT NOT NULL DEFAULT '',
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (object_id, stripe_index)
);

CREATE TABLE IF NOT EXISTS outcomes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  recovery_id INTEGER NOT NULL,
  object_id TEXT NOT NULL,
  stripe_index INTEGER NOT NULL,
  generation INTEGER NOT NULL,
  rank INTEGER NOT NULL,
  feasible INTEGER NOT NULL,
  outcome_key TEXT NOT NULL,
  stripe_digest TEXT NOT NULL,
  all_digests_match INTEGER NOT NULL,
  differences_json TEXT NOT NULL,
  error TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS outcome_blocks (
  outcome_id INTEGER NOT NULL,
  shard_index INTEGER NOT NULL,
  fragment_id INTEGER,
  blob_hash TEXT NOT NULL,
  recomputed_digest TEXT NOT NULL,
  expected_digest TEXT NOT NULL,
  matches_expected INTEGER NOT NULL,
  rebuilt INTEGER NOT NULL,
  PRIMARY KEY (outcome_id, shard_index)
);

CREATE TABLE IF NOT EXISTS outcome_evidence (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  outcome_id INTEGER NOT NULL,
  shard_index INTEGER NOT NULL,
  fragment_id INTEGER,
  receipt_source TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS object_checks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  recovery_id INTEGER NOT NULL,
  object_id TEXT NOT NULL,
  generation INTEGER NOT NULL,
  stripe_count INTEGER NOT NULL,
  matching_stripes INTEGER NOT NULL,
  status TEXT NOT NULL,
  object_digest_expected TEXT NOT NULL,
  object_digest_actual TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS export_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  object_id TEXT NOT NULL,
  target_dir TEXT NOT NULL,
  status TEXT NOT NULL,
  generation INTEGER,
  stripe_count INTEGER NOT NULL,
  manifest_path TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_block_digest
  ON block_digests(object_id, generation, stripe_index, shard_index);
CREATE INDEX IF NOT EXISTS idx_frag_coord
  ON fragments(object_id, generation, stripe_index, shard_index);
CREATE INDEX IF NOT EXISTS idx_receipts_frag ON fragment_receipts(fragment_id);
CREATE INDEX IF NOT EXISTS idx_outcomes_recovery ON outcomes(recovery_id);
CREATE INDEX IF NOT EXISTS idx_outcomes_stripe ON outcomes(object_id, stripe_index);
CREATE INDEX IF NOT EXISTS idx_evidence_outcome ON outcome_evidence(outcome_id);
CREATE INDEX IF NOT EXISTS idx_checks_recovery ON object_checks(recovery_id);
"#;

impl Db {
    pub fn open(path: &Path) -> rusqlite::Result<Arc<Self>> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "foreign_keys", "on")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Arc::new(Db { conn: Mutex::new(conn) }))
    }
}

pub fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
