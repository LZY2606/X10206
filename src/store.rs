//! SQLite 元数据 + 文件块存储；所有写操作经过可注入故障的 Fs 钩子。

use crate::model::*;
use rusqlite::Connection;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultPoint {
    WriteRawFragment,
    WriteTempBlock,
    CommitRename,
    WriteExport,
    ExportRename,
}

impl FaultPoint {
    pub fn name(self) -> &'static str {
        match self {
            FaultPoint::WriteRawFragment => "write_raw_fragment",
            FaultPoint::WriteTempBlock => "write_temp_block",
            FaultPoint::CommitRename => "commit_rename",
            FaultPoint::WriteExport => "write_export",
            FaultPoint::ExportRename => "export_rename",
        }
    }
}

/// 故障注入：在指定点制造磁盘写失败。
pub trait FsFault: Send + Sync {
    fn should_fail(&self, point: FaultPoint, path: &Path) -> bool;
}

pub struct NoFault;
impl FsFault for NoFault {
    fn should_fail(&self, _: FaultPoint, _: &Path) -> bool {
        false
    }
}

#[derive(Clone)]
pub struct Store {
    base: PathBuf,
    conn: Arc<Mutex<Connection>>,
    fault: Arc<dyn FsFault>,
}

pub struct PersistedFragment {
    pub fragment_id: String,
    pub object_id: String,
    pub stripe: i64,
    pub shard: i64,
    pub generation: i64,
    pub source: String,
    pub rel_path: String,
    pub claimed_digest: Option<String>,
    pub recomputed_digest: String,
    pub received_at: String,
}

impl Store {
    pub fn open(base: impl Into<PathBuf>) -> Result<Store, String> {
        Self::open_with_fault(base, Arc::new(NoFault))
    }

    pub fn open_with_fault(
        base: impl Into<PathBuf>,
        fault: Arc<dyn FsFault>,
    ) -> Result<Store, String> {
        let base = base.into();
        std::fs::create_dir_all(base.join("raw")).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(base.join("tmp")).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(base.join("blocks")).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(base.join("exports")).map_err(|e| e.to_string())?;
        let db_path = base.join("cabin.db");
        let conn = Connection::open(db_path).map_err(|e| e.to_string())?;
        conn.execute_batch(SCHEMA).map_err(|e| e.to_string())?;
        Ok(Store {
            base,
            conn: Arc::new(Mutex::new(conn)),
            fault,
        })
    }

    pub fn base(&self) -> &Path {
        &self.base
    }
    pub fn raw_dir(&self) -> PathBuf {
        self.base.join("raw")
    }
    pub fn tmp_dir(&self) -> PathBuf {
        self.base.join("tmp")
    }
    pub fn blocks_dir(&self) -> PathBuf {
        self.base.join("blocks")
    }
    pub fn exports_dir(&self) -> PathBuf {
        self.base.join("exports")
    }
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS manifests (
    object_id TEXT PRIMARY KEY,
    codec_version INTEGER NOT NULL,
    field TEXT NOT NULL,
    k INTEGER NOT NULL,
    m INTEGER NOT NULL,
    stripe_length INTEGER NOT NULL,
    stripe_count INTEGER NOT NULL,
    object_length INTEGER,
    object_digest TEXT,
    json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS fragments (
    fragment_id TEXT PRIMARY KEY,
    object_id TEXT NOT NULL,
    stripe INTEGER NOT NULL,
    shard INTEGER NOT NULL,
    generation INTEGER NOT NULL,
    source TEXT NOT NULL,
    rel_path TEXT NOT NULL,
    length INTEGER NOT NULL,
    claimed_digest TEXT,
    recomputed_digest TEXT NOT NULL,
    received_at TEXT NOT NULL,
    UNIQUE(object_id, stripe, shard, source, recomputed_digest)
);
CREATE INDEX IF NOT EXISTS idx_frag_lookup ON fragments(object_id, stripe);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS recovery_runs (
    run_id TEXT PRIMARY KEY,
    object_id TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS stripe_commits (
    object_id TEXT NOT NULL,
    stripe INTEGER NOT NULL,
    run_id TEXT NOT NULL,
    primary_solution_id TEXT NOT NULL,
    committed_at TEXT NOT NULL,
    analysis_json TEXT NOT NULL,
    PRIMARY KEY (object_id, stripe)
);
CREATE TABLE IF NOT EXISTS solution_blocks (
    object_id TEXT NOT NULL,
    stripe INTEGER NOT NULL,
    solution_id TEXT NOT NULL,
    shard INTEGER NOT NULL,
    block_digest TEXT NOT NULL,
    rel_path TEXT NOT NULL,
    PRIMARY KEY (object_id, stripe, solution_id, shard)
);
CREATE TABLE IF NOT EXISTS object_outcomes (
    object_id TEXT NOT NULL,
    outcome_id TEXT NOT NULL,
    rank INTEGER NOT NULL,
    outcome_json TEXT NOT NULL,
    PRIMARY KEY (object_id, outcome_id)
);
CREATE TABLE IF NOT EXISTS exports (
    export_id TEXT PRIMARY KEY,
    object_id TEXT NOT NULL,
    outcome_id TEXT NOT NULL,
    rel_dir TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"#;

impl Store {
    pub fn get_manifest_json(&self, object_id: &str) -> Result<Option<String>, String> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT json FROM manifests WHERE object_id = ?1",
            [object_id],
            |r| r.get::<_, String>(0),
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other.to_string()),
        })
    }

    pub fn list_objects(&self) -> Result<Vec<String>, String> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT object_id FROM manifests ORDER BY object_id")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    pub fn upsert_manifest(&self, manifest: &Manifest) -> Result<(), String> {
        let json = serde_json::to_string(manifest).map_err(|e| e.to_string())?;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO manifests(object_id, codec_version, field, k, m, stripe_length,
                stripe_count, object_length, object_digest, json)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
             ON CONFLICT(object_id) DO UPDATE SET
                codec_version=excluded.codec_version, field=excluded.field, k=excluded.k,
                m=excluded.m, stripe_length=excluded.stripe_length,
                stripe_count=excluded.stripe_count, object_length=excluded.object_length,
                object_digest=excluded.object_digest, json=excluded.json",
            rusqlite::params![
                manifest.object_id,
                manifest.codec_version,
                manifest.field,
                manifest.k as i64,
                manifest.m as i64,
                manifest.stripe_length as i64,
                manifest.stripe_count as i64,
                manifest.object_length.map(|v| v as i64),
                manifest.object_digest,
                json,
            ],
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
    }

    pub fn setting(&self, key: &str) -> Option<String> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT value FROM settings WHERE key = ?1",
            [key],
            |r| r.get::<_, String>(0),
        )
        .ok()
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO settings(key,value) VALUES (?1,?2)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            [key, value],
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
    }

    /// 保存原始碎片字节（永不改动），幂等。
    pub fn save_fragment(&self, f: &FragmentInput) -> Result<(), String> {
        let recomputed = sha256_hex(&f.bytes);
        let rel = format!(
            "raw/{}/s{:04}_sh{:02}_g{}_{}.bin",
            f.object_id, f.stripe, f.shard, f.generation, &recomputed[..16]
        );
        let path = self.base.join(&rel);
        if !path.exists() {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            if self.fault.should_fail(FaultPoint::WriteRawFragment, &path) {
                return Err("注入故障：原始碎片写入失败".into());
            }
            atomic_write(&path, &f.bytes)?;
        }
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO fragments(fragment_id, object_id, stripe, shard, generation,
                source, rel_path, length, claimed_digest, recomputed_digest, received_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            rusqlite::params![
                f.fragment_id,
                f.object_id,
                f.stripe as i64,
                f.shard as i64,
                f.generation as i64,
                f.source,
                rel,
                f.bytes.len() as i64,
                f.claimed_digest,
                recomputed,
                f.received_at,
            ],
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
    }

    pub fn list_fragments(&self, object_id: &str) -> Result<Vec<PersistedFragment>, String> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT fragment_id, object_id, stripe, shard, generation, source, rel_path,
                        claimed_digest, recomputed_digest, received_at
                 FROM fragments WHERE object_id = ?1 ORDER BY stripe, shard, generation, fragment_id",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([object_id], |r| {
                Ok(PersistedFragment {
                    fragment_id: r.get(0)?,
                    object_id: r.get(1)?,
                    stripe: r.get(2)?,
                    shard: r.get(3)?,
                    generation: r.get(4)?,
                    source: r.get(5)?,
                    rel_path: r.get(6)?,
                    claimed_digest: r.get(7)?,
                    recomputed_digest: r.get(8)?,
                    received_at: r.get(9)?,
                })
            })
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    pub fn read_raw(&self, rel_path: &str) -> Result<Vec<u8>, String> {
        let path = self.base.join(rel_path);
        std::fs::read(path).map_err(|e| e.to_string())
    }

    pub fn isolated_sources(&self, object_id: &str) -> BTreeSet<String> {
        self.setting(&format!("isolate:{}", object_id))
            .map(|v| v.split(',').filter(|s| !s.is_empty()).map(String::from).collect())
            .unwrap_or_default()
    }

    pub fn set_isolated_sources(&self, object_id: &str, sources: &BTreeSet<String>) -> Result<(), String> {
        let joined = sources.iter().cloned().collect::<Vec<_>>().join(",");
        self.set_setting(&format!("isolate:{}", object_id), &joined)
    }

    /// 写临时块（原子写在 tmp 下；最终读取绝不从 tmp 取）。
    pub fn write_tmp_block(&self, name: &str, bytes: &[u8]) -> Result<PathBuf, String> {
        let dir = self.tmp_dir();
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let tmp = dir.join(name);
        if self.fault.should_fail(FaultPoint::WriteTempBlock, &tmp) {
            return Err("注入故障：临时块写入失败".into());
        }
        atomic_write(&tmp, bytes)?;
        Ok(tmp)
    }

    /// 将临时块提升为内容寻址的最终块。
    pub fn commit_block(&self, tmp: &Path, digest: &str) -> Result<PathBuf, String> {
        let final_path = self.blocks_dir().join(format!("{}.bin", digest));
        if !final_path.exists() {
            if let Some(parent) = final_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            if self.fault.should_fail(FaultPoint::CommitRename, &final_path) {
                return Err("注入故障：块提交重命名失败".into());
            }
            std::fs::rename(tmp, &final_path).map_err(|e| e.to_string())?;
        } else {
            let _ = std::fs::remove_file(tmp);
        }
        Ok(final_path)
    }

    pub fn clean_tmp(&self) -> Result<(), String> {
        let dir = self.tmp_dir();
        if dir.exists() {
            for entry in std::fs::read_dir(&dir).map_err(|e| e.to_string())? {
                let entry = entry.map_err(|e| e.to_string())?;
                let _ = std::fs::remove_file(entry.path());
            }
        }
        Ok(())
    }

    pub fn block_exists(&self, digest: &str) -> bool {
        self.blocks_dir().join(format!("{}.bin", digest)).exists()
    }

    pub fn read_block(&self, digest: &str) -> Result<Vec<u8>, String> {
        std::fs::read(self.blocks_dir().join(format!("{}.bin", digest))).map_err(|e| e.to_string())
    }

    pub fn upsert_solution_block(
        &self,
        object_id: &str,
        stripe: usize,
        solution_id: &str,
        shard: usize,
        digest: &str,
    ) -> Result<(), String> {
        let rel = format!("blocks/{}.bin", digest);
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO solution_blocks(object_id, stripe, solution_id, shard, block_digest, rel_path)
             VALUES (?1,?2,?3,?4,?5,?6)",
            rusqlite::params![
                object_id,
                stripe as i64,
                solution_id,
                shard as i64,
                digest,
                rel
            ],
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
    }

    pub fn solution_block_digest(
        &self,
        object_id: &str,
        stripe: usize,
        solution_id: &str,
        shard: usize,
    ) -> Option<String> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT block_digest FROM solution_blocks
             WHERE object_id=?1 AND stripe=?2 AND solution_id=?3 AND shard=?4",
            rusqlite::params![object_id, stripe as i64, solution_id, shard as i64],
            |r| r.get::<_, String>(0),
        )
        .ok()
    }

    pub fn put_stripe_commit(
        &self,
        object_id: &str,
        stripe: usize,
        run_id: &str,
        primary_solution_id: &str,
        analysis_json: &str,
        committed_at: &str,
    ) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO stripe_commits(object_id, stripe, run_id, primary_solution_id, committed_at, analysis_json)
             VALUES (?1,?2,?3,?4,?5,?6)
             ON CONFLICT(object_id, stripe) DO UPDATE SET
                run_id=excluded.run_id, primary_solution_id=excluded.primary_solution_id,
                committed_at=excluded.committed_at, analysis_json=excluded.analysis_json",
            rusqlite::params![
                object_id,
                stripe as i64,
                run_id,
                primary_solution_id,
                committed_at,
                analysis_json
            ],
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
    }

    pub fn get_stripe_commit(&self, object_id: &str, stripe: usize) -> Option<(String, String)> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT primary_solution_id, analysis_json FROM stripe_commits
             WHERE object_id=?1 AND stripe=?2",
            rusqlite::params![object_id, stripe as i64],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .ok()
    }

    pub fn start_run(&self, run_id: &str, object_id: &str, at: &str) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO recovery_runs(run_id, object_id, started_at, status)
             VALUES (?1,?2,?3,'running')",
            rusqlite::params![run_id, object_id, at],
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
    }

    pub fn finish_run(&self, run_id: &str, status: &str, detail: &str, at: &str) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE recovery_runs SET finished_at=?1, status=?2, detail=?3 WHERE run_id=?4",
            rusqlite::params![at, status, detail, run_id],
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
    }

    pub fn replace_outcomes(&self, object_id: &str, outcomes: &[(String, String)]) -> Result<(), String> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        tx.execute("DELETE FROM object_outcomes WHERE object_id=?1", [object_id])
            .map_err(|e| e.to_string())?;
        for (rank, (id, json)) in outcomes.iter().enumerate() {
            tx.execute(
                "INSERT INTO object_outcomes(object_id, outcome_id, rank, outcome_json)
                 VALUES (?1,?2,?3,?4)",
                rusqlite::params![object_id, id, rank as i64, json],
            )
            .map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())
    }

    pub fn list_outcomes(&self, object_id: &str) -> Result<Vec<String>, String> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT outcome_json FROM object_outcomes WHERE object_id=?1 ORDER BY rank",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([object_id], |r| r.get::<_, String>(0))
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    pub fn record_export(
        &self,
        export_id: &str,
        object_id: &str,
        outcome_id: &str,
        rel_dir: &str,
        status: &str,
        at: &str,
    ) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO exports(export_id, object_id, outcome_id, rel_dir, status, created_at)
             VALUES (?1,?2,?3,?4,?5,?6)",
            rusqlite::params![export_id, object_id, outcome_id, rel_dir, status, at],
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
    }

    pub fn list_exports(&self, object_id: &str) -> Result<Vec<String>, String> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT json_object('export_id', export_id, 'outcome_id', outcome_id,
                    'rel_dir', rel_dir, 'status', status, 'created_at', created_at)
                 FROM exports WHERE object_id=?1 ORDER BY created_at DESC",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([object_id], |r| r.get::<_, String>(0))
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    pub fn fault(&self) -> &dyn FsFault {
        self.fault.as_ref()
    }

    pub fn write_export_file(&self, path: &Path, bytes: &[u8]) -> Result<(), String> {
        if self.fault.should_fail(FaultPoint::WriteExport, path) {
            return Err("注入故障：导出文件写入失败".into());
        }
        atomic_write(path, bytes)
    }

    pub fn export_rename(&self, from: &Path, to: &Path) -> Result<(), String> {
        if self.fault.should_fail(FaultPoint::ExportRename, to) {
            return Err("注入故障：导出清单切换失败".into());
        }
        std::fs::rename(from, to).map_err(|e| e.to_string())
    }
}

/// 原子写：同目录临时文件 + rename。
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension(format!(
        "{}.tmp{}",
        path.extension().and_then(|s| s.to_str()).unwrap_or("bin"),
        std::process::id()
    ));
    std::fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        e.to_string()
    })
}
