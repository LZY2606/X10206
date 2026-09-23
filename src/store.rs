//! SQLite 元数据存储 + 可注入故障的块 I/O。
//!
//! 目录布局（数据位于项目目录下的 `data/`）：
//! - `data/fragments/<oid>/s<stripe>_k<shard>_<digest8>.bin` 原始碎片（只读保存）
//! - `data/commits/<oid>/stripe<stripe>__gen<gen>/` 已提交 stripe（shardN.bin + sidecar.json）
//! - `data/staging/<run_id>/` 进程内临时块，提交成功后删除，崩溃后启动时清理
//! - `data/exports/<timestamp>/` 每次导出一个新目录
//! - `data/state.sqlite` 元数据库

use crate::model::{BayError, BayResult, IncomingFragment, Manifest};
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// 块存储 I/O 抽象：测试用 [`FailingIo`] 模拟磁盘写失败。
pub trait BlockIo: Send + Sync {
    fn read(&self, path: &Path) -> std::io::Result<Vec<u8>>;
    fn write_atomic(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()>;
    fn create_dir_all(&self, path: &Path) -> std::io::Result<()>;
    fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()>;
    fn remove_file(&self, path: &Path) -> std::io::Result<()>;
    fn remove_dir_all(&self, path: &Path) -> std::io::Result<()>;
}

/// 真实磁盘 I/O：write_atomic 走同目录临时文件 + rename。
pub struct DiskIo;

impl BlockIo for DiskIo {
    fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        std::fs::read(path)
    }

    fn write_atomic(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut tmp = path.to_path_buf();
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "tmp".into());
        tmp.set_file_name(format!(".{file_name}.tmp-{}", std::process::id()));
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, path)
    }

    fn create_dir_all(&self, path: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(path)
    }

    fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        if let Some(parent) = to.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::rename(from, to)
    }

    fn remove_file(&self, path: &Path) -> std::io::Result<()> {
        match std::fs::remove_file(path) {
            Ok(v) => Ok(v),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn remove_dir_all(&self, path: &Path) -> std::io::Result<()> {
        match std::fs::remove_dir_all(path) {
            Ok(v) => Ok(v),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// 故障注入：每次 write/rename/create_dir 都失败，用于磁盘写失败与中断测试。
pub struct FailingIo {
    pub message: String,
}

impl BlockIo for FailingIo {
    fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        std::fs::read(path)
    }
    fn write_atomic(&self, _path: &Path, _bytes: &[u8]) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            self.message.clone(),
        ))
    }
    fn create_dir_all(&self, _path: &Path) -> std::io::Result<()> {
        Ok(())
    }
    fn rename(&self, _from: &Path, _to: &Path) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            self.message.clone(),
        ))
    }
    fn remove_file(&self, path: &Path) -> std::io::Result<()> {
        DiskIo.remove_file(path)
    }
    fn remove_dir_all(&self, path: &Path) -> std::io::Result<()> {
        DiskIo.remove_dir_all(path)
    }
}

/// 单个 stripe 提交记录。
#[derive(Debug, Clone, serde::Serialize)]
pub struct CommitRecord {
    pub object_id: String,
    pub stripe_index: usize,
    pub generation: u64,
    pub trust: String,
    pub solution_id: String,
    pub solution_count: usize,
    pub digest_key: String,
    pub committed_at: String,
}

pub struct Store {
    pub data_dir: PathBuf,
    conn: Mutex<Connection>,
    io: Arc<dyn BlockIo>,
}

const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS objects (
    object_id TEXT PRIMARY KEY,
    manifest_json TEXT NOT NULL,
    imported_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS fragments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id TEXT NOT NULL,
    stripe_index INTEGER NOT NULL,
    shard INTEGER NOT NULL,
    source TEXT NOT NULL,
    rel_path TEXT NOT NULL,
    length INTEGER NOT NULL,
    actual_digest TEXT NOT NULL,
    source_generation INTEGER,
    source_digest TEXT,
    received_at TEXT NOT NULL,
    isolated INTEGER NOT NULL DEFAULT 0,
    UNIQUE(object_id, stripe_index, shard, source)
);
CREATE TABLE IF NOT EXISTS commits (
    object_id TEXT NOT NULL,
    stripe_index INTEGER NOT NULL,
    generation INTEGER NOT NULL,
    trust TEXT NOT NULL,
    solution_id TEXT NOT NULL,
    solution_count INTEGER NOT NULL,
    digest_key TEXT NOT NULL,
    committed_at TEXT NOT NULL,
    PRIMARY KEY (object_id, stripe_index, generation)
);
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    object_id TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS exports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id TEXT NOT NULL,
    dir TEXT NOT NULL,
    manifest_path TEXT,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id TEXT,
    run_id TEXT,
    ts TEXT NOT NULL,
    level TEXT NOT NULL,
    message TEXT NOT NULL
);
"#;

impl Store {
    /// 在 `data_dir` 下打开/创建存储；崩溃遗留的 staging 目录会被清理。
    pub fn open(data_dir: impl Into<PathBuf>) -> BayResult<Arc<Self>> {
        Self::open_with_io(data_dir, Arc::new(DiskIo))
    }

    pub fn open_with_io(
        data_dir: impl Into<PathBuf>,
        io: Arc<dyn BlockIo>,
    ) -> BayResult<Arc<Self>> {
        let data_dir = data_dir.into();
        io.create_dir_all(&data_dir)?;
        io.create_dir_all(&data_dir.join("fragments"))?;
        io.create_dir_all(&data_dir.join("commits"))?;
        io.create_dir_all(&data_dir.join("staging"))?;
        io.create_dir_all(&data_dir.join("exports"))?;

        // 中断续跑：临时块不得被最终读取 —— 启动时清掉所有 staging 残留。
        let staging = data_dir.join("staging");
        if let Ok(entries) = std::fs::read_dir(&staging) {
            for entry in entries.flatten() {
                let _ = io.remove_dir_all(&entry.path());
            }
        }

        let db_path = data_dir.join("state.sqlite");
        let mut conn = Connection::open(db_path)?;
        conn.execute_batch(SCHEMA)?;
        conn.pragma_update(None, "foreign_keys", true)?;
        Ok(Arc::new(Self {
            data_dir,
            conn: Mutex::new(conn),
            io,
        }))
    }

    pub fn io(&self) -> &Arc<dyn BlockIo> {
        &self.io
    }

    pub fn now_iso() -> String {
        // 离线环境不依赖系统时区数据库，使用 UNIX 毫秒的确定性时间戳。
        let ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        format!("t={ms}")
    }

    pub fn log_event(&self, object_id: Option<&str>, run_id: Option<&str>, level: &str, message: &str) {
        let conn = self.conn.lock().unwrap();
        let _ = conn.execute(
            "INSERT INTO events(object_id, run_id, ts, level, message) VALUES (?1,?2,?3,?4,?5)",
            rusqlite::params![object_id, run_id, Self::now_iso(), level, message],
        );
    }

    // ---------- manifest ----------

    pub fn put_manifest(&self, manifest: &Manifest) -> BayResult<()> {
        let json = serde_json::to_string(manifest).map_err(|e| BayError::Store(e.to_string()))?;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO objects(object_id, manifest_json, imported_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(object_id) DO UPDATE SET manifest_json=excluded.manifest_json",
            rusqlite::params![manifest.object_id, json, Self::now_iso()],
        )?;
        Ok(())
    }

    pub fn get_manifest(&self, object_id: &str) -> BayResult<Option<Manifest>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT manifest_json FROM objects WHERE object_id=?1")?;
        let mut rows = stmt.query(rusqlite::params![object_id])?;
        match rows.next()? {
            None => Ok(None),
            Some(row) => {
                let json: String = row.get(0)?;
                let m = serde_json::from_str(&json).map_err(|e| BayError::Store(e.to_string()))?;
                Ok(Some(m))
            }
        }
    }

    pub fn require_manifest(&self, object_id: &str) -> BayResult<Manifest> {
        self.get_manifest(object_id)?
            .ok_or_else(|| BayError::NoManifest { object_id: object_id.into() })
    }

    pub fn list_objects(&self) -> BayResult<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT object_id FROM objects ORDER BY object_id")?;
        let ids = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ids)
    }

    // ---------- fragments ----------

    pub fn fragment_rel_path(oid: &str, f: &IncomingFragment, digest: &str) -> String {
        let safe: String = oid
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect();
        let src_safe: String = f
            .source
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect();
        format!(
            "fragments/{safe}/s{}_k{}_{}_{}.bin",
            f.stripe_index, f.shard, digest.get(..8).unwrap_or("short"), src_safe
        )
    }

    /// 保存一个原始碎片：字节原样落盘，记录接收来源；重复 (stripe,shard,source) 跳过。
    pub fn insert_fragment(&self, oid: &str, f: &IncomingFragment) -> BayResult<bool> {
        let digest = crate::model::sha256_hex(&f.bytes);
        let rel = Self::fragment_rel_path(oid, f, &digest);
        let abs = self.data_dir.join(&rel);
        self.io
            .write_atomic(&abs, &f.bytes)
            .map_err(|e| BayError::Store(format!("写入碎片失败: {e}")))?;
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "INSERT OR IGNORE INTO fragments
             (object_id, stripe_index, shard, source, rel_path, length, actual_digest,
              source_generation, source_digest, received_at, isolated)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,0)",
            rusqlite::params![
                oid,
                f.stripe_index as i64,
                f.shard as i64,
                f.source,
                rel,
                f.bytes.len() as i64,
                digest,
                f.source_generation.map(|g| g as i64),
                f.source_digest,
                Self::now_iso()
            ],
        )?;
        Ok(n > 0)
    }

    #[derive(Debug, Clone)]
    pub struct FragmentRow {
        pub id: i64,
        pub stripe_index: usize,
        pub shard: usize,
        pub source: String,
        pub rel_path: String,
        pub length: usize,
        pub actual_digest: String,
        pub source_generation: Option<u64>,
        pub source_digest: Option<String>,
        pub isolated: bool,
    }

    pub fn list_fragments(&self, oid: &str) -> BayResult<Vec<FragmentRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, stripe_index, shard, source, rel_path, length, actual_digest,
                    source_generation, source_digest, isolated
             FROM fragments WHERE object_id=?1
             ORDER BY stripe_index, shard, actual_digest, source",
        )?;
        let rows = stmt
            .query_map(rusqlite::params![oid], |r| {
                Ok(FragmentRow {
                    id: r.get(0)?,
                    stripe_index: r.get::<_, i64>(1)? as usize,
                    shard: r.get::<_, i64>(2)? as usize,
                    source: r.get(3)?,
                    rel_path: r.get(4)?,
                    length: r.get::<_, i64>(5)? as usize,
                    actual_digest: r.get(6)?,
                    source_generation: r.get::<_, Option<i64>>(7)?.map(|g| g as u64),
                    source_digest: r.get(8)?,
                    isolated: r.get::<_, i64>(9)? != 0,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn read_fragment(&self, rel_path: &str) -> BayResult<Vec<u8>> {
        self.io
            .read(&self.data_dir.join(rel_path))
            .map_err(|e| BayError::Store(format!("读取碎片 {rel_path} 失败: {e}")))
    }

    /// 隔离/解除隔离一个来源（人工排除坏来源）。
    pub fn set_source_isolated(&self, oid: &str, source: &str, isolated: bool) -> BayResult<usize> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "UPDATE fragments SET isolated=?1 WHERE object_id=?2 AND source=?3",
            rusqlite::params![isolated as i64, oid, source],
        )?;
        Ok(n)
    }

    pub fn list_sources(&self, oid: &str) -> BayResult<Vec<(String, bool)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT DISTINCT source,
                    EXISTS(SELECT 1 FROM fragments f2 WHERE f2.object_id=fragments.object_id
                           AND f2.source=fragments.source AND f2.isolated=1) AS any_iso
             FROM fragments WHERE object_id=?1 ORDER BY source",
        )?;
        let rows = stmt
            .query_map(rusqlite::params![oid], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? != 0))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }
