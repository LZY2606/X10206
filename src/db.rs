//! SQLite 持久层：来源、对象、碎片、stripe、解、证据、恢复批次。
//! 原始碎片字节以 BLOB 入库，导入后来源目录不再被修改或依赖。

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: i64 = 1;

pub fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub struct Storage {
    pub conn: Connection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceRow {
    pub id: i64,
    pub name: String,
    pub path: String,
    pub imported_at: i64,
    pub isolated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectRow {
    pub id: i64,
    pub object_id: String,
    pub coding_version: String,
    pub object_digest: Option<String>,
    pub declared_len: Option<i64>,
    pub stripe_count: i64,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentRow {
    pub id: i64,
    pub object_id: i64,
    pub source_id: i64,
    pub stripe_idx: i64,
    pub shard_idx: i64,
    pub generation: i64,
    pub declared_length: i64,
    pub actual_length: i64,
    pub digest_declared: String,
    pub digest_actual: String,
    pub health: String,
    pub content: Vec<u8>,
    pub received_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeRow {
    pub id: i64,
    pub object_id: i64,
    pub stripe_idx: i64,
    pub stripe_len: i64,
    pub max_generation: i64,
    pub status: String,
    pub tier: Option<String>,
    pub committed_run: Option<i64>,
    pub output_digest: Option<String>,
    pub output_len: Option<i64>,
    pub search_combos: i64,
    pub budget_exceeded: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolutionRow {
    pub id: i64,
    pub stripe_id: i64,
    pub tier: String,
    pub generation: i64,
    pub output_digest: String,
    pub distinct_key: String,
    pub chosen_subset: String,
    pub output: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRow {
    pub id: i64,
    pub stripe_id: Option<i64>,
    pub object_id: Option<i64>,
    pub fragment_id: Option<i64>,
    pub run_id: Option<i64>,
    pub kind: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRow {
    pub id: i64,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    pub status: String,
    pub stripes_total: i64,
    pub stripes_done: i64,
    pub fault_inject: Option<String>,
}

impl Storage {
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let mut s = Storage { conn };
        s.init()?;
        Ok(s)
    }

    fn init(&mut self) -> rusqlite::Result<()> {
        self.conn.execute_batch(
            r#"
CREATE TABLE IF NOT EXISTS schema_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sources (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  path TEXT NOT NULL,
  imported_at INTEGER NOT NULL,
  isolated INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS objects (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  object_id TEXT NOT NULL UNIQUE,
  coding_version TEXT NOT NULL,
  object_digest TEXT,
  declared_len INTEGER,
  stripe_count INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'incomplete',
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS fragments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  object_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
  source_id INTEGER NOT NULL REFERENCES sources(id),
  stripe_idx INTEGER NOT NULL,
  shard_idx INTEGER NOT NULL,
  generation INTEGER NOT NULL,
  declared_length INTEGER NOT NULL,
  actual_length INTEGER NOT NULL,
  digest_declared TEXT NOT NULL,
  digest_actual TEXT NOT NULL,
  health TEXT NOT NULL,
  content BLOB NOT NULL,
  received_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fragments_lookup
  ON fragments(object_id, stripe_idx, shard_idx, generation);
CREATE TABLE IF NOT EXISTS stripes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  object_id INTEGER NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
  stripe_idx INTEGER NOT NULL,
  stripe_len INTEGER NOT NULL,
  max_generation INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending',
  tier TEXT,
  committed_run INTEGER,
  output_digest TEXT,
  output_len INTEGER,
  search_combos INTEGER NOT NULL DEFAULT 0,
  budget_exceeded INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL,
  UNIQUE(object_id, stripe_idx)
);
CREATE TABLE IF NOT EXISTS solutions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  stripe_id INTEGER NOT NULL REFERENCES stripes(id) ON DELETE CASCADE,
  tier TEXT NOT NULL,
  generation INTEGER NOT NULL,
  output_digest TEXT NOT NULL,
  distinct_key TEXT NOT NULL,
  chosen_subset TEXT NOT NULL,
  output BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(stripe_id, distinct_key)
);
CREATE INDEX IF NOT EXISTS idx_solutions_stripe ON solutions(stripe_id);
CREATE TABLE IF NOT EXISTS evidence (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  stripe_id INTEGER REFERENCES stripes(id) ON DELETE CASCADE,
  object_id INTEGER REFERENCES objects(id) ON DELETE CASCADE,
  fragment_id INTEGER REFERENCES fragments(id) ON DELETE SET NULL,
  run_id INTEGER,
  kind TEXT NOT NULL,
  detail TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_stripe ON evidence(stripe_id);
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at INTEGER NOT NULL,
  finished_at INTEGER,
  status TEXT NOT NULL,
  stripes_total INTEGER NOT NULL DEFAULT 0,
  stripes_done INTEGER NOT NULL DEFAULT 0,
  fault_inject TEXT
);
            "#,
        )?;
        self.conn
            .execute(
                "INSERT OR IGNORE INTO schema_meta(key, value) VALUES ('version', ?1)",
                params![SCHEMA_VERSION.to_string()],
            )?;
        Ok(())
    }

    // ---------- sources ----------

    pub fn upsert_source(&mut self, name: &str, path: &str) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO sources(name, path, imported_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(name) DO UPDATE SET path=excluded.path",
            params![name, path, now_ms()],
        )?;
        self.conn
            .query_row("SELECT id FROM sources WHERE name=?1", params![name], |r| r.get(0))
    }

    pub fn set_source_isolated(&mut self, id: i64, isolated: bool) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE sources SET isolated=?1 WHERE id=?2",
            params![isolated, id],
        )?;
        Ok(())
    }

    pub fn list_sources(&mut self) -> rusqlite::Result<Vec<SourceRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, path, imported_at, isolated FROM sources ORDER BY name",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(SourceRow {
                id: r.get(0)?,
                name: r.get(1)?,
                path: r.get(2)?,
                imported_at: r.get(3)?,
                isolated: r.get::<_, i64>(4)? != 0,
            })
        })?;
        rows.collect()
    }

    // ---------- objects ----------

    pub fn upsert_object(
        &mut self,
        object_id: &str,
        coding_version: &str,
        object_digest: Option<&str>,
        declared_len: Option<i64>,
        stripe_count: i64,
    ) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO objects(object_id, coding_version, object_digest, declared_len,
                                 stripe_count, status, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'incomplete', ?6)
             ON CONFLICT(object_id) DO UPDATE SET
               coding_version=excluded.coding_version,
               object_digest=COALESCE(excluded.object_digest, objects.object_digest),
               declared_len=COALESCE(excluded.declared_len, objects.declared_len),
               stripe_count=MAX(objects.stripe_count, excluded.stripe_count),
               updated_at=excluded.updated_at",
            params![object_id, coding_version, object_digest, declared_len, stripe_count, now_ms()],
        )?;
        self.conn
            .query_row("SELECT id FROM objects WHERE object_id=?1", params![object_id], |r| r.get(0))
    }

    pub fn list_objects(&mut self) -> rusqlite::Result<Vec<ObjectRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, object_id, coding_version, object_digest, declared_len, stripe_count, status
             FROM objects ORDER BY object_id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(ObjectRow {
                id: r.get(0)?,
                object_id: r.get(1)?,
                coding_version: r.get(2)?,
                object_digest: r.get(3)?,
                declared_len: r.get(4)?,
                stripe_count: r.get(5)?,
                status: r.get(6)?,
            })
        })?;
        rows.collect()
    }

    pub fn get_object(&mut self, id: i64) -> rusqlite::Result<Option<ObjectRow>> {
        self.conn
            .query_row(
                "SELECT id, object_id, coding_version, object_digest, declared_len, stripe_count, status
                 FROM objects WHERE id=?1",
                params![id],
                |r| {
                    Ok(ObjectRow {
                        id: r.get(0)?,
                        object_id: r.get(1)?,
                        coding_version: r.get(2)?,
                        object_digest: r.get(3)?,
                        declared_len: r.get(4)?,
                        stripe_count: r.get(5)?,
                        status: r.get(6)?,
                    })
                },
            )
            .optional()
    }

    pub fn set_object_status(&mut self, id: i64, status: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE objects SET status=?1, updated_at=?2 WHERE id=?3",
            params![status, now_ms(), id],
        )?;
        Ok(())
    }

    // ---------- stripes ----------

    pub fn ensure_stripe(
        &mut self,
        object_id: i64,
        stripe_idx: i64,
        stripe_len: i64,
    ) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO stripes(object_id, stripe_idx, stripe_len, status, updated_at)
             VALUES (?1, ?2, ?3, 'pending', ?4)
             ON CONFLICT(object_id, stripe_idx) DO UPDATE SET
               stripe_len=CASE WHEN stripes.stripe_len < ?3 THEN ?3 ELSE stripes.stripe_len END",
            params![object_id, stripe_idx, stripe_len, now_ms()],
        )?;
        self.conn.query_row(
            "SELECT id FROM stripes WHERE object_id=?1 AND stripe_idx=?2",
            params![object_id, stripe_idx],
            |r| r.get(0),
        )
    }

    pub fn list_stripes(&mut self, object_id: i64) -> rusqlite::Result<Vec<StripeRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, object_id, stripe_idx, stripe_len, max_generation, status, tier,
                    committed_run, output_digest, output_len, search_combos, budget_exceeded
             FROM stripes WHERE object_id=?1 ORDER BY stripe_idx",
        )?;
        let rows = stmt.query_map(params![object_id], stripe_from_row)?;
        rows.collect()
    }
}

fn stripe_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<StripeRow> {
    Ok(StripeRow {
        id: r.get(0)?,
        object_id: r.get(1)?,
        stripe_idx: r.get(2)?,
        stripe_len: r.get(3)?,
        max_generation: r.get(4)?,
        status: r.get(5)?,
        tier: r.get(6)?,
        committed_run: r.get(7)?,
        output_digest: r.get(8)?,
        output_len: r.get(9)?,
        search_combos: r.get(10)?,
        budget_exceeded: r.get::<_, i64>(11)? != 0,
    })
}

impl Storage {
    // ---------- fragments ----------

    pub fn insert_fragment(
        &mut self,
        object_id: i64,
        source_id: i64,
        stripe_idx: i64,
        shard_idx: i64,
        generation: i64,
        declared_length: i64,
        actual_length: i64,
        digest_declared: &str,
        digest_actual: &str,
        health: &str,
        content: &[u8],
    ) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO fragments(object_id, source_id, stripe_idx, shard_idx, generation,
               declared_length, actual_length, digest_declared, digest_actual, health, content, received_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![
                object_id,
                source_id,
                stripe_idx,
                shard_idx,
                generation,
                declared_length,
                actual_length,
                digest_declared,
                digest_actual,
                health,
                content,
                now_ms()
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn list_fragments(&mut self, object_id: i64) -> rusqlite::Result<Vec<FragmentRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT f.id, f.object_id, f.source_id, f.stripe_idx, f.shard_idx, f.generation,
                    f.declared_length, f.actual_length, f.digest_declared, f.digest_actual,
                    f.health, f.content, f.received_at
             FROM fragments f
             JOIN sources s ON s.id = f.source_id
             WHERE f.object_id=?1 AND s.isolated=0
             ORDER BY f.stripe_idx, f.shard_idx, f.generation, f.id",
        )?;
        let rows = stmt.query_map(params![object_id], |r| {
            Ok(FragmentRow {
                id: r.get(0)?,
                object_id: r.get(1)?,
                source_id: r.get(2)?,
                stripe_idx: r.get(3)?,
                shard_idx: r.get(4)?,
                generation: r.get(5)?,
                declared_length: r.get(6)?,
                actual_length: r.get(7)?,
                digest_declared: r.get(8)?,
                digest_actual: r.get(9)?,
                health: r.get(10)?,
                content: r.get(11)?,
                received_at: r.get(12)?,
            })
        })?;
        rows.collect()
    }

    /// 含已隔离来源（用于页面展示与恢复后再核对）。
    pub fn list_all_fragments(&mut self, object_id: i64) -> rusqlite::Result<Vec<FragmentRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT f.id, f.object_id, f.source_id, f.stripe_idx, f.shard_idx, f.generation,
                    f.declared_length, f.actual_length, f.digest_declared, f.digest_actual,
                    f.health, f.content, f.received_at
             FROM fragments f
             WHERE f.object_id=?1
             ORDER BY f.stripe_idx, f.shard_idx, f.generation, f.id",
        )?;
        let rows = stmt.query_map(params![object_id], |r| {
            Ok(FragmentRow {
                id: r.get(0)?,
                object_id: r.get(1)?,
                source_id: r.get(2)?,
                stripe_idx: r.get(3)?,
                shard_idx: r.get(4)?,
                generation: r.get(5)?,
                declared_length: r.get(6)?,
                actual_length: r.get(7)?,
                digest_declared: r.get(8)?,
                digest_actual: r.get(9)?,
                health: r.get(10)?,
                content: r.get(11)?,
                received_at: r.get(12)?,
            })
        })?;
        rows.collect()
    }

    pub fn fragment_source(&mut self, fragment_id: i64) -> rusqlite::Result<Option<(i64, bool)>> {
        self.conn
            .query_row(
                "SELECT s.id, s.isolated FROM fragments f JOIN sources s ON s.id=f.source_id
                 WHERE f.id=?1",
                params![fragment_id],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)? != 0)),
            )
            .optional()
    }

    // ---------- evidence ----------

    pub fn add_evidence(
        &mut self,
        stripe_id: Option<i64>,
        object_id: Option<i64>,
        fragment_id: Option<i64>,
        run_id: Option<i64>,
        kind: &str,
        detail: &str,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO evidence(stripe_id, object_id, fragment_id, run_id, kind, detail, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![stripe_id, object_id, fragment_id, run_id, kind, detail, now_ms()],
        )?;
        Ok(())
    }

    pub fn evidence_for_stripe(&mut self, stripe_id: i64) -> rusqlite::Result<Vec<EvidenceRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, stripe_id, object_id, fragment_id, run_id, kind, detail
             FROM evidence WHERE stripe_id=?1 ORDER BY id",
        )?;
        let rows = stmt.query_map(params![stripe_id], |r| {
            Ok(EvidenceRow {
                id: r.get(0)?,
                stripe_id: r.get(1)?,
                object_id: r.get(2)?,
                fragment_id: r.get(3)?,
                run_id: r.get(4)?,
                kind: r.get(5)?,
                detail: r.get(6)?,
            })
        })?;
        rows.collect()
    }
}

impl Storage {
    // ---------- stripe mutation ----------

    #[allow(clippy::too_many_arguments)]
    pub fn update_stripe_state(
        &mut self,
        stripe_id: i64,
        status: &str,
        tier: Option<&str>,
        max_generation: i64,
        committed_run: Option<i64>,
        output_digest: Option<&str>,
        output_len: Option<i64>,
        search_combos: i64,
        budget_exceeded: bool,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE stripes SET status=?1, tier=?2, max_generation=?3, committed_run=?4,
                 output_digest=?5, output_len=?6, search_combos=?7, budget_exceeded=?8, updated_at=?9
             WHERE id=?10",
            params![
                status,
                tier,
                max_generation,
                committed_run,
                output_digest,
                output_len,
                search_combos,
                budget_exceeded,
                now_ms(),
                stripe_id
            ],
        )?;
        Ok(())
    }

    pub fn get_stripe(&mut self, id: i64) -> rusqlite::Result<Option<StripeRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, object_id, stripe_idx, stripe_len, max_generation, status, tier,
                    committed_run, output_digest, output_len, search_combos, budget_exceeded
             FROM stripes WHERE id=?1",
        )?;
        stmt.query_row(params![id], stripe_from_row).optional()
    }

    pub fn reset_stripe(&mut self, stripe_id: i64) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE stripes SET status='pending', tier=NULL, committed_run=NULL,
                 output_digest=NULL, output_len=NULL, search_combos=0, budget_exceeded=0, updated_at=?1
             WHERE id=?2",
            params![now_ms(), stripe_id],
        )?;
        self.conn.execute("DELETE FROM solutions WHERE stripe_id=?1", params![stripe_id])?;
        Ok(())
    }

    pub fn reset_stripes_for_source(&mut self, source_id: i64) -> rusqlite::Result<Vec<i64>> {
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT s.id FROM stripes s
             JOIN fragments f ON f.object_id=s.object_id AND f.stripe_idx=s.stripe_idx
             WHERE f.source_id=?1 ORDER BY s.id",
        )?;
        let ids = stmt
            .query_map(params![source_id], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(stmt);
        for id in &ids {
            self.reset_stripe(*id)?;
        }
        Ok(ids)
    }

    pub fn list_pending_stripe_ids(&mut self) -> rusqlite::Result<Vec<(i64, i64, i64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, object_id, stripe_idx FROM stripes WHERE status='pending'
             ORDER BY object_id, stripe_idx",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        rows.collect()
    }

    pub fn list_stripe_ids(&mut self) -> rusqlite::Result<Vec<(i64, i64, i64)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, object_id, stripe_idx FROM stripes ORDER BY object_id, stripe_idx")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        rows.collect()
    }

    pub fn committed_solution_output(&mut self, stripe_id: i64) -> rusqlite::Result<Option<Vec<u8>>> {
        self.conn
            .query_row(
                "SELECT so.output FROM stripes s JOIN solutions so ON so.stripe_id=s.id
                 WHERE s.id=?1 AND so.tier=s.tier AND so.output_digest=s.output_digest
                 LIMIT 1",
                params![stripe_id],
                |r| r.get(0),
            )
            .optional()
    }

    // ---------- solutions ----------

    pub fn insert_solution(
        &mut self,
        stripe_id: i64,
        tier: &str,
        generation: i64,
        output_digest: &str,
        distinct_key: &str,
        chosen_subset: &str,
        output: &[u8],
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO solutions(stripe_id, tier, generation, output_digest, distinct_key,
                 chosen_subset, output, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
             ON CONFLICT(stripe_id, distinct_key) DO NOTHING",
            params![
                stripe_id,
                tier,
                generation,
                output_digest,
                distinct_key,
                chosen_subset,
                output,
                now_ms()
            ],
        )?;
        Ok(())
    }

    pub fn list_solutions(&mut self, stripe_id: i64) -> rusqlite::Result<Vec<SolutionRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, stripe_id, tier, generation, output_digest, distinct_key, chosen_subset, output
             FROM solutions WHERE stripe_id=?1
             ORDER BY tier DESC, generation DESC, output_digest, id",
        )?;
        let rows = stmt.query_map(params![stripe_id], |r| {
            Ok(SolutionRow {
                id: r.get(0)?,
                stripe_id: r.get(1)?,
                tier: r.get(2)?,
                generation: r.get(3)?,
                output_digest: r.get(4)?,
                distinct_key: r.get(5)?,
                chosen_subset: r.get(6)?,
                output: r.get(7)?,
            })
        })?;
        rows.collect()
    }

    pub fn delete_solutions(&mut self, stripe_id: i64) -> rusqlite::Result<()> {
        self.conn.execute("DELETE FROM solutions WHERE stripe_id=?1", params![stripe_id])?;
        Ok(())
    }

    /// 删除恢复批次产生的证据；导入时的 digest/length/duplicate/conflict 证据保留。
    pub fn clear_run_evidence(&mut self, stripe_id: i64) -> rusqlite::Result<()> {
        self.conn.execute(
            "DELETE FROM evidence WHERE stripe_id=?1
             AND (run_id IS NOT NULL
                  OR kind IN ('stale_generation','coding_inconsistent',
                              'search_budget_exceeded','disk_write',
                              'incomplete_commit','object_digest_resolved'))",
            params![stripe_id],
        )?;
        Ok(())
    }

    // ---------- runs ----------

    pub fn start_run(&mut self, total: i64, fault_inject: Option<&str>) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO runs(started_at, status, stripes_total, stripes_done, fault_inject)
             VALUES (?1, 'running', ?2, 0, ?3)",
            params![now_ms(), total, fault_inject],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn finish_run(&mut self, run_id: i64, done: i64, status: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE runs SET finished_at=?1, stripes_done=?2, status=?3 WHERE id=?4",
            params![now_ms(), done, status, run_id],
        )?;
        Ok(())
    }

    pub fn last_run(&mut self) -> rusqlite::Result<Option<RunRow>> {
        self.conn
            .query_row(
                "SELECT id, started_at, finished_at, status, stripes_total, stripes_done, fault_inject
                 FROM runs ORDER BY id DESC LIMIT 1",
                [],
                |r| {
                    Ok(RunRow {
                        id: r.get(0)?,
                        started_at: r.get(1)?,
                        finished_at: r.get(2)?,
                        status: r.get(3)?,
                        stripes_total: r.get(4)?,
                        stripes_done: r.get(5)?,
                        fault_inject: r.get(6)?,
                    })
                },
            )
            .optional()
    }

    pub fn object_count(&mut self) -> rusqlite::Result<i64> {
        self.conn.query_row("SELECT COUNT(*) FROM objects", [], |r| r.get(0))
    }
}
