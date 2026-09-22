use crate::models::Manifest;
use rusqlite::Connection;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub struct Db {
    pub conn: Mutex<Connection>,
    pub data_dir: PathBuf,
}

fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version < 1 {
        conn.execute_batch(
            r#"
            CREATE TABLE objects (
                object_id   TEXT NOT NULL,
                version     INTEGER NOT NULL,
                manifest    TEXT NOT NULL,
                created_at  TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (object_id, version)
            );
            CREATE TABLE fragments (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                object_id       TEXT NOT NULL,
                version         INTEGER NOT NULL,
                generation      INTEGER NOT NULL,
                stripe_index    INTEGER NOT NULL,
                shard_index     INTEGER NOT NULL,
                source          TEXT NOT NULL,
                length          INTEGER NOT NULL,
                actual_digest   TEXT NOT NULL,
                expected_digest TEXT,
                digest_ok       INTEGER NOT NULL,
                state           TEXT NOT NULL,
                excluded_reason TEXT
            );
            CREATE INDEX idx_frag_obj ON fragments(object_id, version, stripe_index);
            CREATE TABLE isolated_sources (
                source      TEXT PRIMARY KEY,
                isolated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE runs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                object_id   TEXT NOT NULL,
                version     INTEGER NOT NULL,
                budget      INTEGER NOT NULL,
                status      TEXT NOT NULL,
                report_json TEXT,
                failpoint   TEXT,
                created_at  TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE stripe_states (
                object_id    TEXT NOT NULL,
                version      INTEGER NOT NULL,
                stripe_index INTEGER NOT NULL,
                status       TEXT NOT NULL,
                generation   INTEGER,
                data_digest  TEXT,
                blob_path    TEXT,
                evidence_json TEXT NOT NULL DEFAULT '[]',
                detail       TEXT,
                updated_run  INTEGER,
                updated_at   TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (object_id, version, stripe_index)
            );
            CREATE TABLE solutions (
                id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id             INTEGER NOT NULL,
                stripe_index       INTEGER NOT NULL,
                generation         INTEGER NOT NULL,
                key_tuple          TEXT NOT NULL,
                verification       TEXT NOT NULL,
                data_digest        TEXT NOT NULL,
                blob_path          TEXT,
                selected_rows_json TEXT NOT NULL,
                evidence_json      TEXT NOT NULL,
                excluded_json      TEXT NOT NULL,
                committed          INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE exports (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                object_id     TEXT NOT NULL,
                version       INTEGER NOT NULL,
                dir           TEXT NOT NULL,
                manifest_path TEXT NOT NULL,
                status        TEXT NOT NULL,
                result_json   TEXT,
                created_at    TEXT NOT NULL DEFAULT (datetime('now'))
            );
            "#,
        )?;
        conn.execute("PRAGMA user_version = 1", [])?;
    }
    Ok(())
}

impl Db {
    pub fn open(data_dir: &Path) -> rusqlite::Result<Self> {
        fs::create_dir_all(data_dir.join("fragments")).ok();
        fs::create_dir_all(data_dir.join("committed")).ok();
        fs::create_dir_all(data_dir.join("tmp")).ok();
        fs::create_dir_all(data_dir.join("exports")).ok();
        let db_path = data_dir.join("db").join("capsule.sqlite");
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(db_path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        migrate(&conn)?;
        Ok(Db {
            conn: Mutex::new(conn),
            data_dir: data_dir.to_path_buf(),
        })
    }

    pub fn fragment_path(&self, id: i64) -> PathBuf {
        self.data_dir.join("fragments").join(format!("{id}.bin"))
    }

    pub fn tmp_dir(&self) -> PathBuf {
        self.data_dir.join("tmp")
    }

    pub fn upsert_manifest(&self, manifest: &Manifest) -> rusqlite::Result<()> {
        let json = serde_json::to_string(manifest).expect("manifest serializes");
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO objects(object_id, version, manifest) VALUES (?1, ?2, ?3)
             ON CONFLICT(object_id, version) DO UPDATE SET manifest = excluded.manifest,
                 created_at = datetime('now')",
            rusqlite::params![manifest.object_id, manifest.version, json],
        )?;
        Ok(())
    }

    pub fn load_manifest(&self, object_id: &str, version: u32) -> rusqlite::Result<Option<Manifest>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT manifest FROM objects WHERE object_id = ?1 AND version = ?2")?;
        let mut rows = stmt.query(rusqlite::params![object_id, version])?;
        if let Some(row) = rows.next()? {
            let json: String = row.get(0)?;
            Ok(Some(serde_json::from_str(&json).expect("stored manifest")))
        } else {
            Ok(None)
        }
    }

    pub fn list_manifests(&self) -> rusqlite::Result<Vec<Manifest>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT manifest FROM objects ORDER BY object_id, version")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for json in rows {
            out.push(serde_json::from_str(&json?).expect("stored manifest"));
        }
        Ok(out)
    }

    pub fn insert_fragment(
        &self,
        object_id: &str,
        version: u32,
        generation: u64,
        stripe: usize,
        shard: usize,
        source: &str,
        bytes: &[u8],
        expected: Option<&str>,
        digest_ok: bool,
        state: &str,
        excluded_reason: Option<&str>,
    ) -> rusqlite::Result<i64> {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(bytes);
        let digest = hex::encode(h.finalize());
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO fragments(object_id, version, generation, stripe_index, shard_index,
                source, length, actual_digest, expected_digest, digest_ok, state, excluded_reason)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            rusqlite::params![
                object_id,
                version,
                generation as i64,
                stripe as i64,
                shard as i64,
                source,
                bytes.len() as i64,
                digest,
                expected,
                digest_ok as i64,
                state,
                excluded_reason
            ],
        )?;
        let id = conn.last_insert_rowid();
        drop(conn);
        let tmp = self.data_dir.join("tmp").join(format!("frag-{id}.tmp"));
        fs::write(&tmp, bytes).expect("write fragment tmp");
        fs::rename(&tmp, self.fragment_path(id)).expect("commit fragment bytes");
        Ok(id)
    }

    pub fn list_fragments(&self, object_id: &str, version: u32) -> rusqlite::Result<Vec<crate::models::FragmentRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, object_id, version, generation, stripe_index, shard_index, source, length,
                    actual_digest, expected_digest, digest_ok, state, excluded_reason
             FROM fragments WHERE object_id = ?1 AND version = ?2
             ORDER BY stripe_index, shard_index, generation DESC, id",
        )?;
        let rows = stmt.query_map(rusqlite::params![object_id, version], |r| {
            Ok(crate::models::FragmentRecord {
                id: r.get(0)?,
                object_id: r.get(1)?,
                version: r.get::<_, i64>(2)? as u32,
                generation: r.get::<_, i64>(3)? as u64,
                stripe_index: r.get::<_, i64>(4)? as usize,
                shard_index: r.get::<_, i64>(5)? as usize,
                source: r.get(6)?,
                length: r.get::<_, i64>(7)? as usize,
                actual_digest: r.get(8)?,
                expected_digest: r.get(9)?,
                digest_ok: r.get::<_, i64>(10)? != 0,
                state: r.get(11)?,
                excluded_reason: r.get(12)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn fragment_bytes(&self, id: i64) -> std::io::Result<Vec<u8>> {
        fs::read(self.fragment_path(id))
    }

    pub fn isolated_sources(&self) -> rusqlite::Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT source FROM isolated_sources ORDER BY source")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn set_source_isolated(&self, source: &str, isolated: bool) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        if isolated {
            conn.execute(
                "INSERT OR IGNORE INTO isolated_sources(source) VALUES (?1)",
                rusqlite::params![source],
            )?;
        } else {
            conn.execute("DELETE FROM isolated_sources WHERE source = ?1", rusqlite::params![source])?;
        }
        Ok(())
    }
}
