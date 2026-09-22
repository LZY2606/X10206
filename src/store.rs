//! 持久层：SQLite 连接、目录布局、原始字节保存、原子写与故障注入。

use rusqlite::Connection;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::model::sha256_hex;

/// 故障注入开关，供磁盘写失败测试使用。
#[derive(Debug, Default, Clone)]
pub struct FaultFlags {
    /// 提交阶段：临时块写出失败（模拟写一半崩溃之前的 I/O 错误）
    pub fail_commit_tmp_write: bool,
    /// 提交阶段：临时块已验证但最终发布失败
    pub fail_commit_final_write: bool,
    /// 导出阶段：原子清单切换失败
    pub fail_export_switch: bool,
}

pub struct Store {
    pub root: PathBuf,
    conn: Mutex<Connection>,
    pub fault: Mutex<FaultFlags>,
}

#[derive(Debug)]
pub enum StoreError {
    Io(String),
    Db(String),
    Fault(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Io(s) | StoreError::Db(s) | StoreError::Fault(s) => write!(f, "{s}"),
        }
    }
}
impl std::error::Error for StoreError {}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        StoreError::Io(e.to_string())
    }
}
impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Db(e.to_string())
    }
}

pub fn now_ts() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}

impl Store {
    pub fn open(root: impl AsRef<Path>) -> Result<Store, StoreError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("raw"))?;
        fs::create_dir_all(root.join("manifests"))?;
        fs::create_dir_all(root.join("staging"))?;
        fs::create_dir_all(root.join("committed"))?;
        fs::create_dir_all(root.join("exports"))?;
        let db_path = root.join("pod.db");
        let conn = Connection::open(db_path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "busy_timeout", 5000)?;
        let store = Store {
            root,
            conn: Mutex::new(conn),
            fault: Mutex::new(FaultFlags::default()),
        };
        store.migrate()?;
        store.cleanup_staging()?;
        Ok(store)
    }

    pub fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().expect("db mutex poisoned")
    }

    pub fn set_fault(&self, f: FaultFlags) {
        *self.fault.lock().unwrap() = f;
    }

    fn migrate(&self) -> Result<(), StoreError> {
        let c = self.lock();
        c.execute_batch(
            r#"
CREATE TABLE IF NOT EXISTS run (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    search_budget INTEGER NOT NULL,
    note TEXT
);
CREATE TABLE IF NOT EXISTS object (
    object_id TEXT PRIMARY KEY,
    latest_generation INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS object_manifest (
    import_id TEXT PRIMARY KEY,
    object_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    object_len INTEGER NOT NULL,
    object_digest TEXT NOT NULL,
    coding_version TEXT NOT NULL,
    data_shards INTEGER NOT NULL,
    parity_shards INTEGER NOT NULL,
    shard_size INTEGER NOT NULL,
    manifest_rel_path TEXT,
    imported_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS stripe (
    object_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    stripe_index INTEGER NOT NULL,
    data_len INTEGER NOT NULL,
    data_digest TEXT NOT NULL,
    PRIMARY KEY(object_id, generation, stripe_index)
);
CREATE TABLE IF NOT EXISTS fragment (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    import_id TEXT NOT NULL,
    object_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    stripe_index INTEGER NOT NULL,
    shard_index INTEGER NOT NULL,
    frag_generation INTEGER NOT NULL,
    source TEXT NOT NULL,
    expected_digest TEXT,
    actual_digest TEXT,
    length INTEGER,
    expected_length INTEGER NOT NULL,
    status TEXT NOT NULL,
    raw_rel_path TEXT,
    original_path TEXT,
    reasons TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_frag_lookup
    ON fragment(object_id, generation, stripe_index, status);
CREATE INDEX IF NOT EXISTS idx_frag_source ON fragment(source);
CREATE TABLE IF NOT EXISTS source_isolation (
    source TEXT PRIMARY KEY,
    isolated INTEGER NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS stripe_analysis (
    object_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    stripe_index INTEGER NOT NULL,
    feasible INTEGER NOT NULL,
    chosen INTEGER NOT NULL DEFAULT 0,
    committed INTEGER NOT NULL DEFAULT 0,
    strategy TEXT,
    combos_seen INTEGER NOT NULL DEFAULT 0,
    combos_tested INTEGER NOT NULL DEFAULT 0,
    truncated INTEGER NOT NULL DEFAULT 0,
    output_digest TEXT,
    failure_reason TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(object_id, generation, stripe_index)
);
CREATE TABLE IF NOT EXISTS attempt (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    stripe_index INTEGER NOT NULL,
    seq INTEGER NOT NULL,
    frag_generation INTEGER,
    fragment_ids TEXT NOT NULL,
    shard_indexes TEXT NOT NULL,
    invert_ok INTEGER NOT NULL,
    parity_ok INTEGER NOT NULL,
    data_digest_match INTEGER NOT NULL,
    output_digest TEXT,
    infeasible_reason TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS solution (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    stripe_index INTEGER NOT NULL,
    frag_generation INTEGER NOT NULL,
    output_digest TEXT NOT NULL,
    fragment_ids TEXT NOT NULL,
    shard_indexes TEXT NOT NULL,
    equivalent_combos INTEGER NOT NULL,
    chosen INTEGER NOT NULL DEFAULT 0,
    differences TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS stripe_commit (
    object_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    stripe_index INTEGER NOT NULL,
    solution_id INTEGER,
    output_digest TEXT,
    reused INTEGER NOT NULL DEFAULT 0,
    write_failed INTEGER NOT NULL DEFAULT 0,
    committed_at TEXT,
    PRIMARY KEY(object_id, generation, stripe_index)
);
CREATE TABLE IF NOT EXISTS export_record (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    export_dir TEXT NOT NULL,
    object_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    trusted INTEGER NOT NULL,
    manifest_rel_path TEXT,
    created_at TEXT NOT NULL
);
            "#,
        )?;
        Ok(())
    }

    /// 重启后清理所有临时块：临时块永远不会被最终读取。
    fn cleanup_staging(&self) -> Result<(), StoreError> {
        let dir = self.root.join("staging");
        if dir.exists() {
            for entry in fs::read_dir(&dir)? {
                let p = entry?.path();
                if p.is_dir() {
                    fs::remove_dir_all(&p).ok();
                } else {
                    fs::remove_file(&p).ok();
                }
            }
        }
        Ok(())
    }

    /// 保存碎片原始字节（content-addressed，天然去重），返回相对路径与摘要。
    pub fn save_raw(&self, data: &[u8]) -> Result<(String, String), StoreError> {
        let digest = sha256_hex(data);
        let rel = format!("raw/{}/{}", &digest[0..2], &digest[2..]);
        let full = self.root.join(&rel);
        if !full.exists() {
            if let Some(parent) = full.parent() {
                fs::create_dir_all(parent)?;
            }
            self.atomic_write(&full, data)?;
        }
        Ok((rel, digest))
    }

    pub fn read_raw(&self, rel: &str) -> Result<Vec<u8>, StoreError> {
        Ok(fs::read(self.root.join(rel))?)
    }

    pub fn save_manifest_bytes(&self, import_id: &str, data: &[u8]) -> Result<String, StoreError> {
        let rel = format!("manifests/{import_id}.json");
        let full = self.root.join(&rel);
        self.atomic_write(&full, data)?;
        Ok(rel)
    }

    /// 同目录临时文件 + rename 的原子写。
    pub fn atomic_write(&self, path: &Path, data: &[u8]) -> Result<(), StoreError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension(format!(
            "tmp.{}.{}",
            std::process::id(),
            now_ts()
        ));
        fs::write(&tmp, data)?;
        fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn staging_dir(&self, object_id: &str, generation: u64, stripe_index: usize) -> PathBuf {
        self.root
            .join("staging")
            .join(object_id)
            .join(format!("gen{generation}"))
            .join(format!("stripe_{stripe_index:04}"))
    }

    pub fn committed_dir(&self, object_id: &str, generation: u64, stripe_index: usize) -> PathBuf {
        self.root
            .join("committed")
            .join(object_id)
            .join(format!("gen{generation}"))
            .join(format!("stripe_{stripe_index:04}"))
    }

    pub fn committed_marker(&self, object_id: &str, generation: u64, stripe_index: usize) -> PathBuf {
        self.committed_dir(object_id, generation, stripe_index)
            .join("committed.json")
    }

    pub fn exports_root(&self) -> PathBuf {
        self.root.join("exports")
    }

    pub fn committed_exists(&self, object_id: &str, generation: u64, stripe_index: usize) -> bool {
        self.committed_marker(object_id, generation, stripe_index).exists()
    }
}
