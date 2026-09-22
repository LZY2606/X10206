use std::path::{Path, PathBuf};

use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};

use crate::model::{FragmentView, Manifest, RunReport};

#[derive(Debug, Clone)]
pub struct Storage {
    root: PathBuf,
    db: PathBuf,
}

#[derive(Debug, Clone)]
pub struct RawFragment {
    pub manifest: Manifest,
    pub stripe: usize,
    pub kind: crate::model::StoredShardKind,
    pub index: usize,
    pub generation: u64,
    pub declared_length: Option<usize>,
    pub received_digest: Option<String>,
    pub expected_digest: Option<String>,
    pub source: String,
    pub bytes: Vec<u8>,
}

impl Storage {
    pub fn open(root: impl AsRef<Path>) -> std::io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(root.join("fragments"))?;
        std::fs::create_dir_all(root.join("recovered").join("tmp"))?;
        std::fs::create_dir_all(root.join("exports"))?;
        let db = root.join("bay.sqlite3");
        let storage = Self { root, db };
        storage.init()?;
        Ok(storage)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn db_path(&self) -> &Path {
        &self.db
    }

    fn connect(&self) -> rusqlite::Result<Connection> {
        let mut conn = Connection::open(&self.db)?;
        conn.pragma_update(None, "foreign_keys", true)?;
        Ok(conn)
    }

    fn init(&self) -> std::io::Result<()> {
        let conn = self.connect()?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS objects (
              object_id TEXT PRIMARY KEY,
              manifest_json TEXT NOT NULL,
              imported_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS fragments (
              id INTEGER PRIMARY KEY,
              object_id TEXT NOT NULL REFERENCES objects(object_id),
              source TEXT NOT NULL,
              stripe INTEGER NOT NULL,
              kind TEXT NOT NULL,
              shard_index INTEGER NOT NULL,
              generation INTEGER NOT NULL,
              actual_length INTEGER NOT NULL,
              declared_length INTEGER,
              received_digest TEXT,
              expected_digest TEXT,
              actual_digest TEXT NOT NULL,
              raw_path TEXT NOT NULL,
              UNIQUE(object_id, source, stripe, kind, shard_index)
            );
            CREATE TABLE IF NOT EXISTS runs (
              id INTEGER PRIMARY KEY,
              object_id TEXT NOT NULL REFERENCES objects(object_id),
              state TEXT NOT NULL,
              isolated_sources_json TEXT NOT NULL,
              report_json TEXT NOT NULL,
              started_at TEXT NOT NULL DEFAULT (datetime('now')),
              completed_at TEXT
            );
            CREATE TABLE IF NOT EXISTS committed_stripes (
              object_id TEXT NOT NULL REFERENCES objects(object_id),
              stripe INTEGER NOT NULL,
              generation INTEGER NOT NULL,
              solution_id TEXT NOT NULL,
              object_digest TEXT,
              committed_at TEXT NOT NULL DEFAULT (datetime('now')),
              PRIMARY KEY(object_id, stripe)
            );
            CREATE TABLE IF NOT EXISTS committed_shards (
              id INTEGER PRIMARY KEY,
              object_id TEXT NOT NULL,
              stripe INTEGER NOT NULL,
              kind TEXT NOT NULL,
              shard_index INTEGER NOT NULL,
              generation INTEGER NOT NULL,
              solution_id TEXT NOT NULL,
              rebuilt INTEGER NOT NULL,
              digest TEXT NOT NULL,
              path TEXT NOT NULL,
              UNIQUE(object_id, stripe, kind, shard_index)
            );
            CREATE TABLE IF NOT EXISTS committed_participants (
              object_id TEXT NOT NULL,
              stripe INTEGER NOT NULL,
              solution_id TEXT NOT NULL,
              fragment_id INTEGER NOT NULL,
              source TEXT NOT NULL,
              PRIMARY KEY(object_id, stripe, fragment_id)
            );
            CREATE TABLE IF NOT EXISTS solution_shards (
              run_id INTEGER NOT NULL REFERENCES runs(id),
              stripe INTEGER NOT NULL,
              solution_id TEXT NOT NULL,
              kind TEXT NOT NULL,
              shard_index INTEGER NOT NULL,
              rebuilt INTEGER NOT NULL,
              digest TEXT NOT NULL,
              path TEXT NOT NULL,
              PRIMARY KEY(run_id, stripe, solution_id, kind, shard_index)
            );
            "#,
        )?;
        Ok(())
    }

    pub fn reset_interrupted_runs(&self) -> std::io::Result<()> {
        let mut conn = self.connect()?;
        conn.execute("UPDATE runs SET state='interrupted' WHERE state='running'", [])?;
        Ok(())
    }

    pub fn object_count(&self) -> std::io::Result<usize> {
        let conn = self.connect()?;
        Ok(conn.query_row("SELECT COUNT(*) FROM objects", [], |row| row.get(0))?)
    }

    pub fn import_fragment(&self, fragment: &RawFragment) -> std::io::Result<i64> {
        let mut conn = self.connect()?;
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT OR IGNORE INTO objects(object_id, manifest_json) VALUES (?1, ?2)",
            params![
                fragment.manifest.object_id,
                serde_json::to_string(&fragment.manifest).unwrap()
            ],
        )?;
        let object_dir = self.root.join("fragments").join(&fragment.manifest.object_id);
        std::fs::create_dir_all(&object_dir)?;
        let safe_source = sanitize_component(&fragment.source);
        let filename = format!(
            "s{:04}_{}_i{:04}_g{:020}_{}.bin",
            fragment.stripe,
            kind_name(fragment.kind),
            fragment.index,
            fragment.generation,
            safe_source
        );
        let path = object_dir.join(filename);
        std::fs::write(&path, &fragment.bytes)?;
        let actual_digest = digest_hex(&fragment.bytes);
        tx.execute(
            r#"INSERT OR REPLACE INTO fragments
               (object_id, source, stripe, kind, shard_index, generation, actual_length,
                declared_length, received_digest, expected_digest, actual_digest, raw_path)
               VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)"#,
            params![
                fragment.manifest.object_id,
                fragment.source,
                fragment.stripe as i64,
                kind_name(fragment.kind),
                fragment.index as i64,
                fragment.generation as i64,
                fragment.bytes.len() as i64,
                fragment.declared_length.map(|value| value as i64),
                fragment.received_digest,
                fragment.expected_digest,
                actual_digest,
                path.to_string_lossy()
            ],
        )?;
        tx.commit()?;
        Ok(conn.last_insert_rowid())
    }

    pub fn manifests(&self) -> std::io::Result<Vec<Manifest>> {
        let conn = self.connect()?;
        let mut statement = conn.prepare("SELECT manifest_json FROM objects ORDER BY object_id")?;
        let rows = statement.query_map([], |row| {
            let json: String = row.get(0)?;
            Ok(serde_json::from_str::<Manifest>(&json).unwrap())
        })?;
        let mut manifests = Vec::new();
        for manifest in rows {
            manifests.push(manifest?);
        }
        Ok(manifests)
    }

    pub fn fragments(&self, object_id: &str) -> std::io::Result<Vec<FragmentView>> {
        let conn = self.connect()?;
        let mut statement = conn.prepare(
            r#"SELECT id, object_id, source, stripe, kind, shard_index, generation,
                      received_digest, expected_digest, actual_digest, declared_length,
                      actual_length, raw_path
               FROM fragments WHERE object_id=?1
               ORDER BY stripe, kind, shard_index, generation, actual_digest, source, id"#,
        )?;
        let rows = statement.query_map(params![object_id], |row| {
            let kind_text: String = row.get(4)?;
            Ok(FragmentView {
                id: row.get(0)?,
                object_id: row.get(1)?,
                source: row.get(2)?,
                stripe: row.get::<_, i64>(3)? as usize,
                kind: parse_kind(&kind_text),
                index: row.get::<_, i64>(5)? as usize,
                generation: row.get::<_, i64>(6)? as u64,
                received_digest: row.get(7)?,
                expected_digest: row.get(8)?,
                actual_digest: row.get(9)?,
                declared_length: row.get::<_, Option<i64>>(10)?.map(|value| value as usize),
                actual_length: row.get::<_, i64>(11)? as usize,
                raw_path: row.get(12)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
    }

    pub fn start_run(&self, object_id: &str, isolated_sources: &[String], report: &RunReport) -> std::io::Result<i64> {
        let mut conn = self.connect()?;
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE runs SET state='interrupted' WHERE object_id=?1 AND state='running'",
            params![object_id],
        )?;
        tx.execute(
            "INSERT INTO runs(object_id, state, isolated_sources_json, report_json) VALUES (?1, 'running', ?2, ?3)",
            params![
                object_id,
                serde_json::to_string(isolated_sources).unwrap(),
                serde_json::to_string(report).unwrap()
            ],
        )?;
        let run_id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(run_id)
    }

    pub fn update_run(&self, run_id: i64, report: &RunReport) -> std::io::Result<()> {
        let conn = self.connect()?;
        conn.execute(
            "UPDATE runs SET state=?1, report_json=?2, completed_at=CASE WHEN ?1='running' THEN NULL ELSE datetime('now') END WHERE id=?3",
            params![report.state, serde_json::to_string(report).unwrap(), run_id],
        )?;
        Ok(())
    }

    pub fn committed_generation(&self, object_id: &str, stripe: usize) -> std::io::Result<Option<u64>> {
        let conn = self.connect()?;
        let value = conn.query_row(
            "SELECT generation FROM committed_stripes WHERE object_id=?1 AND stripe=?2",
            params![object_id, stripe as i64],
            |row| row.get::<_, i64>(0),
        );
        match value {
            Ok(generation) => Ok(Some(generation as u64)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    pub fn committed_solution_id(&self, object_id: &str, stripe: usize) -> std::io::Result<Option<String>> {
        let conn = self.connect()?;
        let value = conn.query_row(
            "SELECT solution_id FROM committed_stripes WHERE object_id=?1 AND stripe=?2",
            params![object_id, stripe as i64],
            |row| row.get(0),
        );
        match value {
            Ok(solution_id) => Ok(Some(solution_id)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    pub fn committed_shards(&self, object_id: &str, stripe: usize) -> std::io::Result<Vec<CommittedShard>> {
        let conn = self.connect()?;
        let mut statement = conn.prepare(
            r#"SELECT kind, shard_index, generation, solution_id, rebuilt, digest, path
               FROM committed_shards WHERE object_id=?1 AND stripe=?2
               ORDER BY kind, shard_index"#,
        )?;
        let rows = statement.query_map(params![object_id, stripe as i64], |row| {
            let kind_text: String = row.get(0)?;
            Ok(CommittedShard {
                kind: parse_kind(&kind_text),
                index: row.get::<_, i64>(1)? as usize,
                generation: row.get::<_, i64>(2)? as u64,
                solution_id: row.get(3)?,
                rebuilt: row.get::<_, i64>(4)? != 0,
                digest: row.get(5)?,
                path: row.get(6)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
    }

    pub fn committed_sources(&self, object_id: &str, stripe: usize) -> std::io::Result<Vec<String>> {
        let conn = self.connect()?;
        let mut statement = conn.prepare(
            "SELECT DISTINCT source FROM committed_participants WHERE object_id=?1 AND stripe=?2 ORDER BY source",
        )?;
        let rows = statement.query_map(params![object_id, stripe as i64], |row| row.get(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
    }

    pub fn delete_commit(&self, object_id: &str, stripe: usize) -> std::io::Result<()> {
        let conn = self.connect()?;
        conn.execute(
            "DELETE FROM committed_shards WHERE object_id=?1 AND stripe=?2",
            params![object_id, stripe as i64],
        )?;
        conn.execute(
            "DELETE FROM committed_stripes WHERE object_id=?1 AND stripe=?2",
            params![object_id, stripe as i64],
        )?;
        Ok(())
    }

    pub fn commit_solution(&self, run_id: i64, stripe: usize, solution: &PreparedCommit) -> std::io::Result<()> {
        let object_dir = self.root.join("recovered")
            .join(&solution.object_id)
            .join(format!("stripe-{:04}", stripe));
        std::fs::create_dir_all(object_dir)?;
        let tmp_dir = self.root.join("recovered").join("tmp");
        std::fs::create_dir_all(&tmp_dir)?;

        let mut prepared_files = Vec::new();
        for shard in &solution.shards {
            let final_path = object_dir.join(format!(
                "{}-i{:04}-g{:020}-{}.bin",
                kind_name(shard.kind),
                shard.index,
                shard.generation,
                &shard.digest[..16]
            ));
            if !final_path.exists() {
                let temp_path = tmp_dir.join(format!(
                    "run{}-s{:04}-{}-i{:04}-{}.tmp",
                    run_id,
                    stripe,
                    kind_name(shard.kind),
                    shard.index,
                    &shard.digest[..16]
                ));
                atomic_write(&temp_path, &shard.bytes)?;
                std::fs::rename(&temp_path, &final_path)?;
            }
            if digest_hex_path(&final_path)? != shard.digest {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "final shard digest mismatch",
                ));
            }
            prepared_files.push((shard, final_path));
        }

        let mut conn = self.connect()?;
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM committed_shards WHERE object_id=?1 AND stripe=?2",
            params![solution.object_id, stripe as i64],
        )?;
        tx.execute(
            "DELETE FROM committed_participants WHERE object_id=?1 AND stripe=?2",
            params![solution.object_id, stripe as i64],
        )?;
        tx.execute(
            "DELETE FROM committed_stripes WHERE object_id=?1 AND stripe=?2",
            params![solution.object_id, stripe as i64],
        )?;
        for (shard, path) in &prepared_files {
            tx.execute(
                r#"INSERT INTO committed_shards
                   (object_id, stripe, kind, shard_index, generation, solution_id, rebuilt, digest, path)
                   VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)"#,
                params![
                    solution.object_id,
                    stripe as i64,
                    kind_name(shard.kind),
                    shard.index as i64,
                    shard.generation as i64,
                    solution.solution_id,
                    shard.rebuilt as i64,
                    shard.digest,
                    path.to_string_lossy()
                ],
            )?;
        }
        tx.execute(
            "INSERT INTO committed_stripes(object_id, stripe, generation, solution_id, object_digest) VALUES (?1,?2,?3,?4,?5)",
            params![
                solution.object_id,
                stripe as i64,
                solution.generation as i64,
                solution.solution_id,
                solution.object_digest
            ],
        )?;
        for fragment in &solution.participant_fragment_ids {
            tx.execute(
                "INSERT INTO committed_participants(object_id, stripe, solution_id, fragment_id, source) VALUES (?1,?2,?3,?4,?5)",
                params![solution.object_id, stripe as i64, solution.solution_id, fragment.0, fragment.1],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
}

pub fn kind_name(kind: crate::model::StoredShardKind) -> &'static str {
    match kind {
        crate::model::StoredShardKind::Data => "data",
        crate::model::StoredShardKind::Parity => "parity",
    }
}

pub fn parse_kind(value: &str) -> crate::model::StoredShardKind {
    match value {
        "parity" => crate::model::StoredShardKind::Parity,
        _ => crate::model::StoredShardKind::Data,
    }
}

pub fn sanitize_component(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

pub fn digest_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[derive(Debug, Clone)]
pub struct CommittedShard {
    pub kind: crate::model::StoredShardKind,
    pub index: usize,
    pub generation: u64,
    pub solution_id: String,
    pub rebuilt: bool,
    pub digest: String,
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct PreparedShard {
    pub kind: crate::model::StoredShardKind,
    pub index: usize,
    pub generation: u64,
    pub rebuilt: bool,
    pub digest: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PreparedCommit {
    pub object_id: String,
    pub generation: u64,
    pub solution_id: String,
    pub object_digest: Option<String>,
    pub shards: Vec<PreparedShard>,
    pub participant_fragment_ids: Vec<(i64, String)>,
}

fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::File::create(path)?;
    std::io::Write::write_all(&mut file, bytes)?;
    file.sync_all()?;
    Ok(())
}

pub fn digest_hex_path(path: &Path) -> std::io::Result<String> {
    let bytes = std::fs::read(path)?;
    Ok(digest_hex(&bytes))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    digest_hex(bytes)
}

pub fn latest_report(storage: &Storage, object_id: &str) -> std::io::Result<Option<RunReport>> {
    let conn = storage.connect()?;
    let mut statement = conn.prepare(
        "SELECT report_json FROM runs WHERE object_id=?1 ORDER BY id DESC LIMIT 1",
    )?;
    let mut rows = statement.query_map(params![object_id], |row| {
        let json: String = row.get(0)?;
        Ok(serde_json::from_str::<RunReport>(&json).unwrap())
    })?;
    Ok(rows.next().transpose()?)
}
