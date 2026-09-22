use crate::model::{FragmentView, ManifestFile, ObjectView, ReconstructionView, RunView, StripeView};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Default, Debug, Clone)]
pub struct FailureConfig {
    pub fail_next_raw: usize,
    pub fail_next_temp: usize,
    pub fail_next_commit: usize,
}

#[derive(Clone)]
pub struct Store {
    pub data_dir: PathBuf,
    pub conn: Arc<Mutex<Connection>>,
    pub failures: Arc<Mutex<FailureConfig>>,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub fn ensure_dir(path: &Path) -> std::io::Result<()> {
    fs::create_dir_all(path)
}

impl Store {
    pub fn init(data_dir: &Path) -> std::io::Result<()> {
        for dir in ["inbox", "raw", "stripes", "scratch", "exports", "recovered"] {
            ensure_dir(&data_dir.join(dir))?;
        }
        Ok(())
    }

    pub fn open(data_dir: &Path) -> rusqlite::Result<Self> {
        Self::init(data_dir).expect("data directories");
        let db_path = data_dir.join("pod.sqlite");
        let conn = Connection::open(db_path)?;
        conn.pragma_update(None, "foreign_keys", true)?;
        conn.pragma_update(None, "busy_timeout", 5000)?;
        conn.execute_batch(SCHEMA)?;
        cleanup_stale_scratch(&conn, data_dir)?;
        Ok(Self {
            data_dir: data_dir.to_path_buf(),
            conn: Arc::new(Mutex::new(conn)),
            failures: Arc::new(Mutex::new(FailureConfig::default())),
        })
    }

    pub fn set_failures(&self, config: FailureConfig) {
        *self.failures.lock().unwrap() = config;
    }

    pub fn raw_path(&self, object_id: &str, generation: i64, received_from: &str, file_name: &str) -> PathBuf {
        self.data_dir
            .join("raw")
            .join(safe(object_id))
            .join(generation.to_string())
            .join(safe(received_from))
            .join(safe(file_name))
    }

    pub fn stripe_path(&self, object_id: &str, generation: i64, stripe: usize) -> PathBuf {
        self.data_dir.join("stripes").join(safe(object_id)).join(generation.to_string()).join(format!("{stripe:08}.bin"))
    }

    pub fn stripe_digest_path(&self, object_id: &str, generation: i64, stripe: usize) -> PathBuf {
        self.data_dir.join("stripes").join(safe(object_id)).join(generation.to_string()).join(format!("{stripe:08}.sha256"))
    }

    pub fn copy_raw_atomic(&self, source: &Path, target: &Path) -> std::io::Result<()> {
        if target.exists() {
            return Ok(());
        }
        if let Some(parent) = target.parent() {
            ensure_dir(parent)?;
        }
        let mut guard = self.failures.lock().unwrap();
        if guard.fail_next_raw > 0 {
            guard.fail_next_raw -= 1;
            if guard.fail_next_raw == 0 {
                return Err(std::io::Error::other("injected raw write failure"));
            }
        }
        drop(guard);
        let temp = target.with_extension(format!("part.{}", std::process::id()));
        fs::copy(source, &temp)?;
        fs::rename(&temp, target)
    }

    pub fn write_temp_block(&self, object_id: &str, run_id: i64, stripe: usize, shard: usize, bytes: &[u8]) -> std::io::Result<PathBuf> {
        let mut guard = self.failures.lock().unwrap();
        if guard.fail_next_temp > 0 {
            guard.fail_next_temp -= 1;
            if guard.fail_next_temp == 0 {
                return Err(std::io::Error::other("injected temp write failure"));
            }
        }
        drop(guard);
        let dir = self.data_dir.join("scratch").join(run_id.to_string()).join(safe(object_id));
        ensure_dir(&dir)?;
        let path = dir.join(format!("stripe-{stripe:08}-shard-{shard:04}.part"));
        let temp = path.with_extension("tmp");
        let mut file = fs::File::create(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temp, &path)?;
        Ok(path)
    }

    pub fn commit_stripe_file(&self, object_id: &str, generation: i64, stripe: usize, bytes: &[u8], digest: &str) -> std::io::Result<()> {
        let target = self.stripe_path(object_id, generation, stripe);
        let digest_target = self.stripe_digest_path(object_id, generation, stripe);
        if let Some(parent) = target.parent() {
            ensure_dir(parent)?;
        }
        let mut guard = self.failures.lock().unwrap();
        if guard.fail_next_commit > 0 {
            guard.fail_next_commit -= 1;
            if guard.fail_next_commit == 0 {
                return Err(std::io::Error::other("injected commit failure"));
            }
        }
        drop(guard);
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let tmp_data = target.with_extension(format!("commit-{unique}.tmp"));
        let tmp_digest = digest_target.with_extension(format!("commit-{unique}.tmp"));
        fs::write(&tmp_data, bytes)?;
        fs::write(&tmp_digest, format!("{digest}  {stripe:08}.bin\n"))?;
        fs::rename(&tmp_data, &target)?;
        fs::rename(&tmp_digest, &digest_target)
    }

    pub fn verify_committed_stripe(&self, object_id: &str, generation: i64, stripe: usize, expected: &str) -> bool {
        match (fs::read(self.stripe_path(object_id, generation, stripe)), fs::read_to_string(self.stripe_digest_path(object_id, generation, stripe))) {
            (Ok(bytes), Ok(record)) => {
                let actual = sha256_hex(&bytes);
                let recorded = record.split_whitespace().next().unwrap_or_default();
                actual == expected && recorded == expected
            }
            _ => false,
        }
    }

    pub fn upsert_object(&self, manifest: &ManifestFile, source: &str, manifest_path: &str) -> rusqlite::Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let existing: Option<i64> = tx
            .query_row("SELECT id FROM objects WHERE object_id=?1 AND generation=?2 AND object_sha256=?3", params![manifest.object_id, manifest.generation, manifest.object_sha256], |row| row.get(0))
            .optional()?;
        let object_pk = if let Some(id) = existing {
            tx.execute("UPDATE objects SET source=?1, manifest_path=?2, object_sha256=?3, object_size=?4, data_shards=?5, parity_shards=?6, stripe_size=?7 WHERE id=?8", params![source, manifest_path, manifest.object_sha256, manifest.object_size, manifest.data_shards, manifest.parity_shards, manifest.stripe_size, id])?;
            id
        } else {
            tx.execute("INSERT INTO objects(object_id, generation, source, manifest_path, object_sha256, object_size, data_shards, parity_shards, stripe_size) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)", params![manifest.object_id, manifest.generation, source, manifest_path, manifest.object_sha256, manifest.object_size, manifest.data_shards, manifest.parity_shards, manifest.stripe_size])?;
            tx.last_insert_rowid()
        };
        tx.execute("DELETE FROM stripes WHERE object_pk=?1", params![object_pk])?;
        tx.execute("DELETE FROM fragments WHERE object_pk=?1", params![object_pk])?;
        for stripe in &manifest.stripes {
            let specs = serde_json::to_string(&stripe.shards).unwrap();
            tx.execute("INSERT INTO stripes(object_pk, stripe_index, data_len, expected_digest, shard_specs, status) VALUES(?1,?2,?3,?4,?5,'pending')", params![object_pk, stripe.index, stripe.data_len, stripe.sha256, specs])?;
        }
        tx.commit()
    }

    pub fn upsert_fragment(&self, object_pk: i64, stripe_index: usize, shard_index: Option<usize>, shard_generation: Option<i64>, received_from: &str, relative_path: &str, raw_path: &str, byte_length: i64, actual_sha256: &str, claimed_sha256: Option<&str>, expected_sha256: Option<&str>, health: &str, evidence: &str) -> rusqlite::Result<()> {
        let mut conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO fragments(object_pk, stripe_index, shard_index, shard_generation, received_from, relative_path, raw_path, byte_length, actual_sha256, claimed_sha256, expected_sha256, health, evidence)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
             ON CONFLICT(object_pk, stripe_index, shard_index, received_from, actual_sha256) DO NOTHING",
            params![object_pk, stripe_index, shard_index, shard_generation, received_from, relative_path, raw_path, byte_length, actual_sha256, claimed_sha256, expected_sha256, health, evidence],
        )?;
        Ok(())
    }

    pub fn object_pk(&self, object_id: &str, generation: i64, object_sha256: &str) -> rusqlite::Result<Option<i64>> {
        self.conn.lock().unwrap().query_row(
            "SELECT id FROM objects WHERE object_id=?1 AND generation=?2 AND object_sha256=?3",
            params![object_id, generation, object_sha256],
            |row| row.get(0),
        ).optional()
    }
}

fn cleanup_stale_scratch(conn: &Connection, data_dir: &Path) -> rusqlite::Result<()> {
    let scratch = data_dir.join("scratch");
    if scratch.exists() {
        let _ = fs::remove_dir_all(&scratch);
    }
    fs::create_dir_all(scratch).ok();
    conn.execute("DELETE FROM reconstructions WHERE committed=0", [])?;
    Ok(())
}

fn safe(value: &str) -> String {
    value.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect()
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS objects(
  id INTEGER PRIMARY KEY,
  object_id TEXT NOT NULL,
  generation INTEGER NOT NULL,
  source TEXT NOT NULL,
  manifest_path TEXT NOT NULL,
  object_sha256 TEXT NOT NULL,
  object_size INTEGER NOT NULL,
  data_shards INTEGER NOT NULL,
  parity_shards INTEGER NOT NULL,
  stripe_size INTEGER NOT NULL,
  UNIQUE(object_id, generation)
);
CREATE TABLE IF NOT EXISTS stripes(
  id INTEGER PRIMARY KEY,
  object_pk INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
  stripe_index INTEGER NOT NULL,
  data_len INTEGER NOT NULL,
  expected_digest TEXT NOT NULL,
  shard_specs TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL,
  committed_at INTEGER,
  UNIQUE(object_pk, stripe_index)
);
CREATE TABLE IF NOT EXISTS fragments(
  id INTEGER PRIMARY KEY,
  object_pk INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
  stripe_index INTEGER NOT NULL,
  shard_index INTEGER,
  shard_generation INTEGER,
  received_from TEXT NOT NULL,
  relative_path TEXT NOT NULL,
  raw_path TEXT NOT NULL,
  byte_length INTEGER NOT NULL,
  actual_sha256 TEXT NOT NULL,
  claimed_sha256 TEXT,
  expected_sha256 TEXT,
  health TEXT NOT NULL,
  evidence TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_received_fragment ON fragments(object_pk, stripe_index, COALESCE(shard_index, -1), received_from, actual_sha256);
CREATE TABLE IF NOT EXISTS runs(
  id INTEGER PRIMARY KEY,
  object_pk INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
  isolated_sources TEXT NOT NULL,
  budget INTEGER NOT NULL,
  status TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS reconstructions(
  id INTEGER PRIMARY KEY,
  run_pk INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  stripe_pk INTEGER NOT NULL REFERENCES stripes(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  valid INTEGER NOT NULL,
  committed INTEGER NOT NULL DEFAULT 0,
  combination_key TEXT NOT NULL,
  participating TEXT NOT NULL,
  excluded_evidence TEXT NOT NULL,
  recomputed_digests TEXT NOT NULL,
  discrepancy TEXT NOT NULL,
  UNIQUE(run_pk, stripe_pk, ordinal)
);
CREATE TABLE IF NOT EXISTS exports(
  id INTEGER PRIMARY KEY,
  object_pk INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
  directory TEXT NOT NULL,
  manifest_path TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
"#;

#[derive(Clone, Debug)]
pub struct ObjectRecord {
    pub pk: i64,
    pub object_id: String,
    pub generation: i64,
    pub source: String,
    pub object_sha256: String,
    pub object_size: usize,
    pub data_shards: usize,
    pub parity_shards: usize,
    pub stripe_size: usize,
}

#[derive(Clone, Debug)]
pub struct StripeRecord {
    pub pk: i64,
    pub index: usize,
    pub data_len: usize,
    pub expected_digest: String,
    pub shard_specs: Vec<crate::model::ManifestShard>,
    pub status: String,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct FragmentRecord {
    pub id: i64,
    pub stripe_index: usize,
    pub shard_index: Option<usize>,
    pub shard_generation: Option<i64>,
    pub received_from: String,
    pub raw_path: String,
    pub byte_length: i64,
    pub actual_sha256: String,
    pub claimed_sha256: Option<String>,
    pub expected_sha256: Option<String>,
    pub health: String,
    pub evidence: String,
}

impl Store {
    pub fn list_objects_records(&self) -> rusqlite::Result<Vec<ObjectRecord>> {
        self.conn.lock().unwrap().prepare(
            "SELECT id, object_id, generation, source, object_sha256, object_size, data_shards, parity_shards, stripe_size FROM objects ORDER BY object_id, generation, object_sha256"
        )?.query_map([], map_object)?.collect()
    }

    pub fn find_object(&self, object_id: &str, generation: Option<i64>) -> rusqlite::Result<Vec<ObjectRecord>> {
        let mut sql = String::from("SELECT id, object_id, generation, source, object_sha256, object_size, data_shards, parity_shards, stripe_size FROM objects WHERE object_id=?1");
        if generation.is_some() {
            sql.push_str(" AND generation=?2");
        }
        sql.push_str(" ORDER BY generation, object_sha256");
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(&sql)?;
        let rows = if let Some(generation) = generation {
            stmt.query_map(params![object_id, generation], map_object)?.collect::<rusqlite::Result<Vec<_>>>()?
        } else {
            stmt.query_map(params![object_id], map_object)?.collect::<rusqlite::Result<Vec<_>>>()?
        };
        Ok(rows)
    }

    pub fn list_stripes(&self, object_pk: i64) -> rusqlite::Result<Vec<StripeRecord>> {
        self.conn.lock().unwrap().prepare(
            "SELECT id, stripe_index, data_len, expected_digest, shard_specs, status FROM stripes WHERE object_pk=?1 ORDER BY stripe_index"
        )?.query_map(params![object_pk], |row| {
            let specs_json: String = row.get(4)?;
            Ok(StripeRecord {
                pk: row.get(0)?,
                index: row.get(1)?,
                data_len: row.get(2)?,
                expected_digest: row.get(3)?,
                shard_specs: serde_json::from_str(&specs_json).unwrap_or_default(),
                status: row.get(5)?,
            })
        })?.collect()
    }

    pub fn list_fragments(&self, object_pk: i64) -> rusqlite::Result<Vec<FragmentRecord>> {
        self.conn.lock().unwrap().prepare(
            "SELECT id, stripe_index, shard_index, shard_generation, received_from, raw_path, byte_length, actual_sha256, claimed_sha256, expected_sha256, health, evidence FROM fragments WHERE object_pk=?1 ORDER BY stripe_index, COALESCE(shard_index,-1), received_from, actual_sha256"
        )?.query_map(params![object_pk], |row| Ok(FragmentRecord {
            id: row.get(0)?,
            stripe_index: row.get(1)?,
            shard_index: row.get(2)?,
            shard_generation: row.get(3)?,
            received_from: row.get(4)?,
            raw_path: row.get(5)?,
            byte_length: row.get(6)?,
            actual_sha256: row.get(7)?,
            claimed_sha256: row.get(8)?,
            expected_sha256: row.get(9)?,
            health: row.get(10)?,
            evidence: row.get(11)?,
        }))?.collect()
    }

    pub fn create_run(&self, object_pk: i64, isolated_sources: &[String], budget: i64) -> rusqlite::Result<i64> {
        let now = timestamp();
        let sources = serde_json::to_string(isolated_sources).unwrap();
        let mut conn = self.conn.lock().unwrap();
        conn.execute("INSERT INTO runs(object_pk, isolated_sources, budget, status, created_at) VALUES(?1,?2,?3,'running',?4)", params![object_pk, sources, budget, now])?;
        Ok(conn.last_insert_rowid())
    }

    pub fn finish_run(&self, run_id: i64, status: &str) -> rusqlite::Result<()> {
        self.conn.lock().unwrap().execute("UPDATE runs SET status=?1 WHERE id=?2", params![status, run_id])?;
        Ok(())
    }

    pub fn insert_reconstruction(&self, run_id: i64, stripe_pk: i64, ordinal: i64, valid: bool, committed: bool, combination_key: &str, participating: &serde_json::Value, excluded: &serde_json::Value, digests: &serde_json::Value, discrepancy: &str) -> rusqlite::Result<()> {
        self.conn.lock().unwrap().execute(
            "INSERT OR REPLACE INTO reconstructions(run_pk, stripe_pk, ordinal, valid, committed, combination_key, participating, excluded_evidence, recomputed_digests, discrepancy) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![run_id, stripe_pk, ordinal, valid as i64, committed as i64, combination_key, participating.to_string(), excluded.to_string(), digests.to_string(), discrepancy],
        )?;
        Ok(())
    }

    pub fn mark_stripe(&self, stripe_pk: i64, status: &str) -> rusqlite::Result<()> {
        let committed_at = if status == "committed" { Some(timestamp()) } else { None };
        self.conn.lock().unwrap().execute("UPDATE stripes SET status=?1, committed_at=COALESCE(?2, committed_at) WHERE id=?3", params![status, committed_at, stripe_pk])?;
        Ok(())
    }

    pub fn committed_bytes(&self, object: &ObjectRecord, stripe: usize) -> std::io::Result<Vec<u8>> {
        fs::read(self.stripe_path(&object.object_id, object.generation, stripe))
    }
}

fn map_object(row: &rusqlite::Row<'_>) -> rusqlite::Result<ObjectRecord> {
    Ok(ObjectRecord {
        pk: row.get(0)?,
        object_id: row.get(1)?,
        generation: row.get(2)?,
        source: row.get(3)?,
        object_sha256: row.get(4)?,
        object_size: row.get(5)?,
        data_shards: row.get(6)?,
        parity_shards: row.get(7)?,
        stripe_size: row.get(8)?,
    })
}

pub fn timestamp() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

impl Store {
    pub fn object_views(&self) -> rusqlite::Result<Vec<ObjectView>> {
        let mut conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT o.id, o.object_id, o.generation, o.source, o.object_sha256, o.object_size, o.data_shards, o.parity_shards, o.stripe_size,
               COUNT(DISTINCT s.id),
               COUNT(DISTINCT CASE WHEN s.status='committed' THEN s.id END),
               COUNT(DISTINCT CASE WHEN f.health IN ('healthy','generation_mixed_eligible') THEN f.id END),
               COUNT(DISTINCT CASE WHEN f.health IN ('corrupt','excluded') THEN f.id END),
               CASE WHEN COUNT(DISTINCT s.id)=COUNT(DISTINCT CASE WHEN s.status='committed' THEN s.id END) THEN 'committed'
                    WHEN COUNT(DISTINCT CASE WHEN s.status='committed' THEN s.id END)>0 THEN 'partial'
                    ELSE 'pending' END
             FROM objects o LEFT JOIN stripes s ON s.object_pk=o.id LEFT JOIN fragments f ON f.object_pk=o.id
             GROUP BY o.id ORDER BY o.object_id, o.generation, o.object_sha256"
        )?;
        let result: rusqlite::Result<Vec<ObjectView>> = stmt.query_map([], |row| Ok(ObjectView {
            id: row.get(0)?, object_id: row.get(1)?, generation: row.get(2)?, source: row.get(3)?,
            object_sha256: row.get(4)?, object_size: row.get(5)?, data_shards: row.get(6)?,
            parity_shards: row.get(7)?, stripe_size: row.get(8)?, stripe_count: row.get::<_,i64>(9)? as usize,
            committed_stripes: row.get(10)?, healthy_fragments: row.get(11)?, excluded_fragments: row.get(12)?,
            status: row.get(13)?,
        }))?.collect();
        result
    }

    pub fn stripe_views(&self, object_pk: i64) -> rusqlite::Result<Vec<StripeView>> {
        let mut conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT s.id, o.object_id, s.stripe_index, s.data_len, s.expected_digest, s.status, s.committed_at,
               (SELECT object_id FROM objects WHERE id=s.object_pk),
               COUNT(CASE WHEN r.valid=1 THEN 1 END),
               COUNT(DISTINCT CASE WHEN r.valid=1 THEN substr(json_extract(r.recomputed_digests,'$.stripe_sha256'),1,64) END)
             FROM stripes s JOIN objects o ON o.id=s.object_pk LEFT JOIN reconstructions r ON r.stripe_pk=s.id
             WHERE s.object_pk=?1 GROUP BY s.id ORDER BY s.stripe_index"
        )?;
        let result: rusqlite::Result<Vec<StripeView>> = stmt.query_map(params![object_pk], |row| {
            let object_id: String = row.get(1)?;
            Ok(StripeView {
                id: row.get(0)?, object_id, index: row.get(2)?, data_len: row.get(3)?, expected_digest: row.get(4)?,
                status: row.get(5)?, committed_at: row.get(6)?, valid_answers: row.get(8)?, distinct_outputs: row.get(9)?
            })
        })?.collect();
        result
    }

    pub fn fragment_views(&self, object_pk: i64) -> rusqlite::Result<Vec<FragmentView>> {
        let mut conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT f.id, o.object_id, f.stripe_index, f.shard_index, f.shard_generation, f.received_from, f.relative_path, f.raw_path, f.byte_length, f.actual_sha256, f.claimed_sha256, f.expected_sha256, f.health, f.evidence
             FROM fragments f JOIN objects o ON o.id=f.object_pk WHERE f.object_pk=?1
             ORDER BY f.stripe_index, COALESCE(f.shard_index,-1), f.received_from, f.actual_sha256"
        )?;
        let result: rusqlite::Result<Vec<FragmentView>> = stmt.query_map(params![object_pk], |row| Ok(FragmentView {
            id: row.get(0)?, object_id: row.get(1)?, stripe_index: row.get(2)?, shard_index: row.get(3)?,
            shard_generation: row.get(4)?, received_from: row.get(5)?, relative_path: row.get(6)?, raw_path: row.get(7)?,
            byte_length: row.get(8)?, actual_sha256: row.get(9)?, claimed_sha256: row.get(10)?,
            expected_sha256: row.get(11)?, health: row.get(12)?, evidence: row.get(13)?
        }))?.collect();
        result
    }

    pub fn run_views(&self, object_pk: i64) -> rusqlite::Result<Vec<RunView>> {
        let mut conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT id, (SELECT object_id FROM objects WHERE id=object_pk), isolated_sources, budget, status, created_at FROM runs WHERE object_pk=?1 ORDER BY id DESC")?;
        let result: rusqlite::Result<Vec<RunView>> = stmt.query_map(params![object_pk], |row| {
            let sources_json: String = row.get(2)?;
            Ok(RunView { id: row.get(0)?, object_id: row.get(1)?, isolated_sources: serde_json::from_str(&sources_json).unwrap_or_default(), budget: row.get(3)?, status: row.get(4)?, created_at: row.get(5)? })
        })?.collect();
        result
    }

    pub fn reconstruction_views(&self, object_pk: i64) -> rusqlite::Result<Vec<ReconstructionView>> {
        let mut conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT r.id, r.run_pk, o.object_id, s.stripe_index, r.ordinal, r.valid, r.combination_key, r.participating, r.excluded_evidence, r.recomputed_digests, r.discrepancy
             FROM reconstructions r JOIN stripes s ON s.id=r.stripe_pk JOIN objects o ON o.id=s.object_pk
             WHERE o.id=?1 ORDER BY r.run_pk DESC, s.stripe_index, r.ordinal"
        )?;
        let result: rusqlite::Result<Vec<ReconstructionView>> = stmt.query_map(params![object_pk], |row| {
            let parse = |index: usize| {
                let value: String = row.get(index)?;
                serde_json::from_str(&value).map_err(|e| rusqlite::Error::FromSqlConversionFailure(index, rusqlite::types::Type::Text, Box::new(e)))
            };
            Ok(ReconstructionView {
                id: row.get(0)?, run_id: row.get(1)?, object_id: row.get(2)?, stripe_index: row.get(3)?, ordinal: row.get(4)?,
                valid: row.get(5)?, combination_key: row.get(6)?, participating: parse(7)?, excluded_evidence: parse(8)?,
                recomputed_digests: parse(9)?, discrepancy: row.get(10)?
            })
        })?.collect();
        result
    }

    pub fn sources(&self, object_pk: i64) -> rusqlite::Result<Vec<String>> {
        let mut conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT DISTINCT received_from FROM fragments WHERE object_pk=?1 ORDER BY received_from")?;
        let result: rusqlite::Result<Vec<String>> = stmt.query_map(params![object_pk], |row| row.get(0))?.collect();
        result
    }
}
