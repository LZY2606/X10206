//! SQLite-backed storage. Every stripe commit is one transaction:
//! pending rows are promoted atomically, so a crash never leaves a stripe
//! half committed. Temporary rows are deleted on startup.

use rusqlite::{params, Connection, OptionalExtension};
use std::path::PathBuf;
use std::sync::Mutex;

use crate::model::EvidenceKind;

#[derive(Debug, Clone)]
pub struct Paths {
    pub root: PathBuf,
    pub db: PathBuf,
    pub incoming: PathBuf,
    pub fragments: PathBuf,
    pub exports: PathBuf,
}

impl Paths {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            db: root.join("pod.sqlite"),
            incoming: root.join("incoming"),
            fragments: root.join("fragments"),
            exports: root.join("exports"),
            root,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ObjectRow {
    pub id: String,
    pub scheme: String,
    pub version: u32,
    pub stripe_count: usize,
    pub shard_len: usize,
    pub data_shards: usize,
    pub parity_shards: usize,
    pub generation: u64,
    pub data_len: usize,
    pub object_digest_hex: String,
    pub run_status: String,
    pub run_detail: String,
    pub search_budget: i64,
    pub export_dir: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FragmentRow {
    pub id: i64,
    pub object_id: String,
    pub source: String,
    pub stripe: usize,
    pub shard_index: usize,
    pub generation: u64,
    pub content_digest: String,
    pub declared_digest: Option<String>,
    pub length: usize,
    pub file_path: String,
    pub digest_verified: i64,
}

#[derive(Debug, Clone)]
pub struct EvidenceRow {
    pub id: i64,
    pub object_id: String,
    pub stripe: Option<usize>,
    pub shard_index: Option<usize>,
    pub fragment_id: Option<i64>,
    pub source: Option<String>,
    pub kind: String,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct StripeRow {
    pub object_id: String,
    pub stripe: usize,
    pub status: String,
    pub generation: Option<u64>,
    pub object_digest: Option<String>,
    pub chosen_solution_id: Option<i64>,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct SolutionRow {
    pub id: i64,
    pub object_id: String,
    pub stripe: usize,
    pub gen: i64,
    pub rank_order: i64,
    pub combo_json: String,
    pub excluded_json: String,
    pub reconstructed_digest: String,
    pub shards_json: String,
}

pub struct Store {
    conn: Mutex<Connection>,
    pub paths: Paths,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS objects (
    object_id         TEXT PRIMARY KEY,
    scheme            TEXT NOT NULL,
    version           INTEGER NOT NULL,
    stripe_count      INTEGER NOT NULL,
    shard_len         INTEGER NOT NULL,
    data_shards       INTEGER NOT NULL,
    parity_shards     INTEGER NOT NULL,
    generation        INTEGER NOT NULL,
    data_len          INTEGER NOT NULL,
    object_digest_hex TEXT NOT NULL,
    run_status        TEXT NOT NULL DEFAULT 'new',
    run_detail        TEXT NOT NULL DEFAULT '',
    search_budget     INTEGER NOT NULL DEFAULT 256,
    export_dir        TEXT
);
CREATE TABLE IF NOT EXISTS sources (
    name       TEXT PRIMARY KEY,
    isolated   INTEGER NOT NULL DEFAULT 0,
    note       TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS fragments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id       TEXT NOT NULL REFERENCES objects(object_id),
    source          TEXT NOT NULL,
    stripe          INTEGER NOT NULL,
    shard_index     INTEGER NOT NULL,
    generation      INTEGER NOT NULL,
    content_digest  TEXT NOT NULL,
    declared_digest TEXT,
    length          INTEGER NOT NULL,
    file_path       TEXT NOT NULL,
    digest_verified INTEGER NOT NULL,
    UNIQUE(object_id, source, stripe, shard_index, content_digest)
);
CREATE TABLE IF NOT EXISTS evidence (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id   TEXT NOT NULL,
    stripe      INTEGER,
    shard_index INTEGER,
    fragment_id INTEGER,
    source      TEXT,
    kind        TEXT NOT NULL,
    detail      TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS stripe_commits (
    object_id            TEXT NOT NULL,
    stripe               INTEGER NOT NULL,
    status               TEXT NOT NULL,
    generation           INTEGER,
    object_digest        TEXT,
    chosen_solution_id   INTEGER,
    detail               TEXT NOT NULL DEFAULT '',
    committed_at         TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (object_id, stripe)
);
CREATE TABLE IF NOT EXISTS stripe_solutions (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id            TEXT NOT NULL,
    stripe               INTEGER NOT NULL,
    gen                  INTEGER NOT NULL,
    rank_order           INTEGER NOT NULL,
    combo_json           TEXT NOT NULL,
    excluded_json        TEXT NOT NULL,
    reconstructed_digest TEXT NOT NULL,
    shards_json          TEXT NOT NULL,
    UNIQUE(object_id, stripe, reconstructed_digest)
);
CREATE TABLE IF NOT EXISTS committed_shards (
    object_id      TEXT NOT NULL,
    stripe         INTEGER NOT NULL,
    shard_index    INTEGER NOT NULL,
    generation     INTEGER NOT NULL,
    content_digest TEXT NOT NULL,
    shard_hex      TEXT NOT NULL,
    PRIMARY KEY (object_id, stripe, shard_index)
);
CREATE TABLE IF NOT EXISTS pending_shards (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id       TEXT NOT NULL,
    stripe          INTEGER NOT NULL,
    shard_index     INTEGER NOT NULL,
    generation      INTEGER NOT NULL,
    content_digest  TEXT NOT NULL,
    shard_hex       TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
"#;

impl Store {
    pub fn open(paths: Paths) -> anyhow::Result<Self> {
        std::fs::create_dir_all(&paths.incoming)?;
        std::fs::create_dir_all(&paths.fragments)?;
        std::fs::create_dir_all(&paths.exports)?;
        let conn = Connection::open(&paths.db)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "busy_timeout", 10_000)?;
        conn.execute_batch(SCHEMA)?;
        let store = Store { conn: Mutex::new(conn), paths };
        store.delete_pending();
        Ok(store)
    }

    pub fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().expect("store mutex poisoned")
    }

    fn delete_pending(&self) {
        let mut conn = self.lock();
        let tx = conn.transaction().expect("pending cleanup tx");
        tx.execute("DELETE FROM pending_shards", []).ok();
        tx.commit().ok();
    }
}

impl Store {
    pub fn upsert_source(&self, name: &str) -> anyhow::Result<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO sources(name) VALUES (?1) ON CONFLICT(name) DO NOTHING",
            params![name],
        )?;
        Ok(())
    }

    pub fn set_isolated(&self, name: &str, isolated: bool, note: &str) -> anyhow::Result<()> {
        let conn = self.lock();
        conn.execute(
            "UPDATE sources SET isolated = ?1, note = ?2 WHERE name = ?3",
            params![isolated as i64, note, name],
        )?;
        Ok(())
    }

    pub fn is_isolated(&self, name: &str) -> bool {
        let conn = self.lock();
        conn.query_row("SELECT isolated FROM sources WHERE name = ?1", params![name], |r| {
            r.get::<_, i64>(0)
        })
        .map(|v| v != 0)
        .unwrap_or(false)
    }

    pub fn list_sources(&self) -> anyhow::Result<Vec<(String, bool, String)>> {
        let conn = self.lock();
        let mut stmt = conn.prepare("SELECT name, isolated, note FROM sources ORDER BY name")?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? != 0, r.get::<_, String>(2)?))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn upsert_object(&self, o: &ObjectRow) -> anyhow::Result<bool> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let existed = tx
            .query_row("SELECT 1 FROM objects WHERE object_id = ?1", params![o.id], |_| Ok(()))
            .optional()?
            .is_some();
        tx.execute(
            "INSERT INTO objects(object_id, scheme, version, stripe_count, shard_len,
                data_shards, parity_shards, generation, data_len, object_digest_hex,
                run_status, run_detail, search_budget)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,
                COALESCE((SELECT run_status FROM objects WHERE object_id = ?1),'new'),
                COALESCE((SELECT run_detail FROM objects WHERE object_id = ?1),''),
                COALESCE((SELECT search_budget FROM objects WHERE object_id = ?1),256))
             ON CONFLICT(object_id) DO UPDATE SET
                scheme=excluded.scheme, version=excluded.version,
                stripe_count=excluded.stripe_count, shard_len=excluded.shard_len,
                data_shards=excluded.data_shards, parity_shards=excluded.parity_shards,
                generation=excluded.generation, data_len=excluded.data_len,
                object_digest_hex=excluded.object_digest_hex",
            params![
                o.id, o.scheme, o.version, o.stripe_count, o.shard_len,
                o.data_shards, o.parity_shards, o.generation, o.data_len,
                o.object_digest_hex,
            ],
        )?;
        tx.commit()?;
        Ok(existed)
    }

    pub fn get_object(&self, id: &str) -> anyhow::Result<Option<ObjectRow>> {
        let conn = self.lock();
        self.read_object(&conn, id)
    }

    fn read_object(&self, conn: &Connection, id: &str) -> anyhow::Result<Option<ObjectRow>> {
        let row = conn
            .query_row(
                "SELECT object_id, scheme, version, stripe_count, shard_len, data_shards,
                        parity_shards, generation, data_len, object_digest_hex,
                        run_status, run_detail, search_budget, export_dir
                 FROM objects WHERE object_id = ?1",
                params![id],
                |r| {
                    Ok(ObjectRow {
                        id: r.get(0)?,
                        scheme: r.get(1)?,
                        version: r.get(2)?,
                        stripe_count: r.get(3)?,
                        shard_len: r.get(4)?,
                        data_shards: r.get(5)?,
                        parity_shards: r.get(6)?,
                        generation: r.get(7)?,
                        data_len: r.get(8)?,
                        object_digest_hex: r.get(9)?,
                        run_status: r.get(10)?,
                        run_detail: r.get(11)?,
                        search_budget: r.get(12)?,
                        export_dir: r.get(13)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    pub fn list_objects(&self) -> anyhow::Result<Vec<ObjectRow>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT object_id, scheme, version, stripe_count, shard_len, data_shards,
                    parity_shards, generation, data_len, object_digest_hex,
                    run_status, run_detail, search_budget, export_dir
             FROM objects ORDER BY object_id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(ObjectRow {
                id: r.get(0)?,
                scheme: r.get(1)?,
                version: r.get(2)?,
                stripe_count: r.get(3)?,
                shard_len: r.get(4)?,
                data_shards: r.get(5)?,
                parity_shards: r.get(6)?,
                generation: r.get(7)?,
                data_len: r.get(8)?,
                object_digest_hex: r.get(9)?,
                run_status: r.get(10)?,
                run_detail: r.get(11)?,
                search_budget: r.get(12)?,
                export_dir: r.get(13)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn insert_fragment(&self, f: &FragmentRow) -> anyhow::Result<i64> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let existing_id: Option<i64> = tx
            .query_row(
                "SELECT id FROM fragments
                 WHERE object_id=?1 AND source=?2 AND stripe=?3 AND shard_index=?4
                   AND content_digest=?5",
                params![f.object_id, f.source, f.stripe, f.shard_index, f.content_digest],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(id) = existing_id {
            tx.commit()?;
            return Ok(id);
        }
        tx.execute(
            "INSERT INTO fragments(object_id, source, stripe, shard_index, generation,
                content_digest, declared_digest, length, file_path, digest_verified)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                f.object_id, f.source, f.stripe, f.shard_index, f.generation,
                f.content_digest, f.declared_digest, f.length, f.file_path,
                f.digest_verified,
            ],
        )?;
        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(id)
    }

    pub fn find_fragment_by_content(
        &self,
        object_id: &str,
        stripe: usize,
        shard_index: usize,
        content_digest: &str,
    ) -> anyhow::Result<Option<FragmentRow>> {
        let conn = self.lock();
        let row = conn
            .query_row(
                "SELECT id, object_id, source, stripe, shard_index, generation,
                        content_digest, declared_digest, length, file_path, digest_verified
                 FROM fragments
                 WHERE object_id=?1 AND stripe=?2 AND shard_index=?3 AND content_digest=?4
                 ORDER BY source, generation",
                params![object_id, stripe, shard_index, content_digest],
                fragment_from_row,
            )
            .optional()?;
        Ok(row)
    }

    pub fn fragments_for_stripe(&self, object_id: &str, stripe: usize) -> anyhow::Result<Vec<FragmentRow>> {
        let conn = self.lock();
        self.fragments_for_stripe_conn(&conn, object_id, stripe)
    }

    fn fragments_for_stripe_conn(
        &self,
        conn: &Connection,
        object_id: &str,
        stripe: usize,
    ) -> anyhow::Result<Vec<FragmentRow>> {
        let mut stmt = conn.prepare(
            "SELECT id, object_id, source, stripe, shard_index, generation,
                    content_digest, declared_digest, length, file_path, digest_verified
             FROM fragments WHERE object_id=?1 AND stripe=?2
             ORDER BY shard_index, generation DESC, source, id",
        )?;
        let rows = stmt.query_map(params![object_id, stripe], fragment_from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn all_fragments(&self, object_id: &str) -> anyhow::Result<Vec<FragmentRow>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT id, object_id, source, stripe, shard_index, generation,
                    content_digest, declared_digest, length, file_path, digest_verified
             FROM fragments WHERE object_id=?1
             ORDER BY stripe, shard_index, generation DESC, source, id",
        )?;
        let rows = stmt.query_map(params![object_id], fragment_from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn add_evidence(
        &self,
        object_id: &str,
        stripe: Option<usize>,
        shard_index: Option<usize>,
        fragment_id: Option<i64>,
        source: Option<&str>,
        kind: EvidenceKind,
        detail: &str,
    ) -> anyhow::Result<()> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO evidence(object_id, stripe, shard_index, fragment_id, source, kind, detail)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![object_id, stripe, shard_index, fragment_id, source, kind.as_str(), detail],
        )?;
        Ok(())
    }

    pub fn evidence_for_object(&self, object_id: &str) -> anyhow::Result<Vec<EvidenceRow>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT id, object_id, stripe, shard_index, fragment_id, source, kind, detail
             FROM evidence WHERE object_id=?1
             ORDER BY stripe, shard_index, kind, id",
        )?;
        let rows = stmt.query_map(params![object_id], |r| {
            Ok(EvidenceRow {
                id: r.get(0)?,
                object_id: r.get(1)?,
                stripe: r.get(2)?,
                shard_index: r.get(3)?,
                fragment_id: r.get(4)?,
                source: r.get(5)?,
                kind: r.get(6)?,
                detail: r.get(7)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

fn fragment_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<FragmentRow> {
    Ok(FragmentRow {
        id: r.get(0)?,
        object_id: r.get(1)?,
        source: r.get(2)?,
        stripe: r.get(3)?,
        shard_index: r.get(4)?,
        generation: r.get(5)?,
        content_digest: r.get(6)?,
        declared_digest: r.get(7)?,
        length: r.get(8)?,
        file_path: r.get(9)?,
        digest_verified: r.get(10)?,
    })
}

/// A staged stripe ready for the atomic commit transaction.
pub struct StagedStripe {
    pub generation: i64,
    pub detail: String,
    pub chosen_rank: Option<i64>,
    pub solutions: Vec<StagedSolution>,
    pub shards: Vec<StagedShard>,
}

pub struct StagedSolution {
    pub gen: i64,
    pub rank_order: i64,
    pub combo_json: String,
    pub excluded_json: String,
    pub reconstructed_digest: String,
    pub shards_json: String,
}

pub struct StagedShard {
    pub shard_index: usize,
    pub generation: i64,
    pub content_digest: String,
    pub shard_hex: String,
}

impl Store {
    pub fn get_stripe(&self, object_id: &str, stripe: usize) -> anyhow::Result<Option<StripeRow>> {
        let conn = self.lock();
        self.read_stripe(&conn, object_id, stripe)
    }

    fn read_stripe(
        &self,
        conn: &Connection,
        object_id: &str,
        stripe: usize,
    ) -> anyhow::Result<Option<StripeRow>> {
        let row = conn
            .query_row(
                "SELECT object_id, stripe, status, generation, object_digest,
                        chosen_solution_id, detail
                 FROM stripe_commits WHERE object_id=?1 AND stripe=?2",
                params![object_id, stripe],
                |r| {
                    Ok(StripeRow {
                        object_id: r.get(0)?,
                        stripe: r.get(1)?,
                        status: r.get(2)?,
                        generation: r.get(3)?,
                        object_digest: r.get(4)?,
                        chosen_solution_id: r.get(5)?,
                        detail: r.get(6)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    pub fn list_stripes(&self, object_id: &str) -> anyhow::Result<Vec<StripeRow>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT object_id, stripe, status, generation, object_digest,
                    chosen_solution_id, detail
             FROM stripe_commits WHERE object_id=?1 ORDER BY stripe",
        )?;
        let rows = stmt.query_map(params![object_id], |r| {
            Ok(StripeRow {
                object_id: r.get(0)?,
                stripe: r.get(1)?,
                status: r.get(2)?,
                generation: r.get(3)?,
                object_digest: r.get(4)?,
                chosen_solution_id: r.get(5)?,
                detail: r.get(6)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn list_solutions(&self, object_id: &str, stripe: usize) -> anyhow::Result<Vec<SolutionRow>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT id, object_id, stripe, gen, rank_order, combo_json, excluded_json,
                    reconstructed_digest, shards_json
             FROM stripe_solutions WHERE object_id=?1 AND stripe=?2 ORDER BY rank_order, id",
        )?;
        let rows = stmt.query_map(params![object_id, stripe], |r| {
            Ok(SolutionRow {
                id: r.get(0)?,
                object_id: r.get(1)?,
                stripe: r.get(2)?,
                gen: r.get(3)?,
                rank_order: r.get(4)?,
                combo_json: r.get(5)?,
                excluded_json: r.get(6)?,
                reconstructed_digest: r.get(7)?,
                shards_json: r.get(8)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn committed_shard_hex(
        &self,
        object_id: &str,
        stripe: usize,
        shard_index: usize,
    ) -> anyhow::Result<Option<(String, i64)>> {
        let conn = self.lock();
        let row = conn
            .query_row(
                "SELECT content_digest, generation FROM committed_shards
                 WHERE object_id=?1 AND stripe=?2 AND shard_index=?3",
                params![object_id, stripe, shard_index],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
            )
            .optional()?;
        Ok(row)
    }

    /// Verify every committed stripe still has all n shard rows. Returns the
    /// list of incomplete stripe indices (they must not be reused).
    pub fn verify_committed_completeness(&self, object_id: &str, n: usize) -> anyhow::Result<Vec<usize>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT sc.stripe, COUNT(cs.shard_index)
             FROM stripe_commits sc
             LEFT JOIN committed_shards cs
               ON cs.object_id = sc.object_id AND cs.stripe = sc.stripe
             WHERE sc.object_id=?1 AND sc.status='committed'
             GROUP BY sc.stripe",
        )?;
        let mut bad = Vec::new();
        let rows = stmt.query_map(params![object_id], |r| {
            Ok((r.get::<_, usize>(0)?, r.get::<_, i64>(1)?))
        })?;
        for row in rows {
            let (stripe, count) = row?;
            if count as usize != n {
                bad.push(stripe);
            }
        }
        Ok(bad)
    }

    /// Drop all recovery state for an object (used on hard reset / recompute all).
    pub fn reset_object_state(&self, object_id: &str) -> anyhow::Result<()> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM committed_shards WHERE object_id=?1", params![object_id])?;
        tx.execute("DELETE FROM stripe_solutions WHERE object_id=?1", params![object_id])?;
        tx.execute("DELETE FROM stripe_commits WHERE object_id=?1", params![object_id])?;
        tx.execute("DELETE FROM pending_shards WHERE object_id=?1", params![object_id])?;
        tx.execute(
            "UPDATE objects SET run_status='new', run_detail='', export_dir=NULL WHERE object_id=?1",
            params![object_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Drop recovery state of stripes touched by a source, plus object-level state.
    pub fn invalidate_stripes_for_source(&self, object_id: &str, source: &str) -> anyhow::Result<Vec<usize>> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let mut sel = tx.prepare(
            "SELECT DISTINCT stripe FROM fragments WHERE object_id=?1 AND source=?2 ORDER BY stripe",
        )?;
        let stripes: Vec<usize> = sel
            .query_map(params![object_id, source], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(sel);
        for &stripe in &stripes {
            tx.execute("DELETE FROM committed_shards WHERE object_id=?1 AND stripe=?2", params![object_id, stripe])?;
            tx.execute("DELETE FROM stripe_solutions WHERE object_id=?1 AND stripe=?2", params![object_id, stripe])?;
            tx.execute("DELETE FROM stripe_commits WHERE object_id=?1 AND stripe=?2", params![object_id, stripe])?;
        }
        tx.execute("DELETE FROM pending_shards WHERE object_id=?1", params![object_id])?;
        tx.execute(
            "UPDATE objects SET run_status='stale', run_detail='', export_dir=NULL WHERE object_id=?1",
            params![object_id],
        )?;
        tx.commit()?;
        Ok(stripes)
    }

    /// Stage reconstructed shards into the never-final-read pending table.
    pub fn stage_pending(&self, object_id: &str, stripe: usize, shards: &[StagedShard]) -> anyhow::Result<()> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM pending_shards WHERE object_id=?1 AND stripe=?2", params![object_id, stripe])?;
        for s in shards {
            tx.execute(
                "INSERT INTO pending_shards(object_id, stripe, shard_index, generation,
                    content_digest, shard_hex)
                 VALUES (?1,?2,?3,?4,?5,?6)",
                params![object_id, stripe, s.shard_index, s.generation, s.content_digest, s.shard_hex],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Atomically promote staged work for one stripe. `crash_before_commit`
    /// rolls the transaction back to simulate a process killed mid-commit.
    pub fn commit_staged_stripe(
        &self,
        object_id: &str,
        stripe: usize,
        status: &str,
        staged: StagedStripe,
        crash_before_commit: bool,
    ) -> anyhow::Result<()> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM committed_shards WHERE object_id=?1 AND stripe=?2", params![object_id, stripe])?;
        tx.execute("DELETE FROM stripe_solutions WHERE object_id=?1 AND stripe=?2", params![object_id, stripe])?;
        tx.execute("DELETE FROM stripe_commits WHERE object_id=?1 AND stripe=?2", params![object_id, stripe])?;
        let mut chosen_id: Option<i64> = None;
        for sol in &staged.solutions {
            tx.execute(
                "INSERT INTO stripe_solutions(object_id, stripe, gen, rank_order, combo_json,
                    excluded_json, reconstructed_digest, shards_json)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    object_id, stripe, sol.gen, sol.rank_order, sol.combo_json,
                    sol.excluded_json, sol.reconstructed_digest, sol.shards_json,
                ],
            )?;
            let id = tx.last_insert_rowid();
            if staged.chosen_rank == Some(sol.rank_order) {
                chosen_id = Some(id);
            }
        }
        for s in &staged.shards {
            tx.execute(
                "INSERT INTO committed_shards(object_id, stripe, shard_index, generation,
                    content_digest, shard_hex)
                 VALUES (?1,?2,?3,?4,?5,?6)",
                params![object_id, stripe, s.shard_index, s.generation, s.content_digest, s.shard_hex],
            )?;
        }
        tx.execute(
            "INSERT INTO stripe_commits(object_id, stripe, status, generation, object_digest,
                chosen_solution_id, detail)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![object_id, stripe, status, staged.generation,
                object_digest_none(&staged), chosen_id, staged.detail],
        )?;
        tx.execute("DELETE FROM pending_shards WHERE object_id=?1 AND stripe=?2", params![object_id, stripe])?;
        if crash_before_commit {
            tx.rollback()?;
            anyhow::bail!("simulated crash before stripe {} commit (rolled back)", stripe);
        }
        tx.commit()?;
        Ok(())
    }

    pub fn set_run_status(&self, object_id: &str, status: &str, detail: &str) -> anyhow::Result<()> {
        let conn = self.lock();
        conn.execute(
            "UPDATE objects SET run_status=?1, run_detail=?2 WHERE object_id=?3",
            params![status, detail, object_id],
        )?;
        Ok(())
    }

    pub fn set_export_dir(&self, object_id: &str, dir: Option<&str>) -> anyhow::Result<()> {
        let conn = self.lock();
        conn.execute("UPDATE objects SET export_dir=?1 WHERE object_id=?2", params![dir, object_id])?;
        Ok(())
    }
}

fn object_digest_none(_staged: &StagedStripe) -> Option<String> {
    None
}
