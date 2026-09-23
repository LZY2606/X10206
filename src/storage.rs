//! SQLite 持久化 + 字节块落盘。
//!
//! 分层：
//! `fragments/` 导入的原始碎片（永不改动）
//! `committed/` 已按 stripe 提交的输出块
//! `tmp/`       临时块（崩溃/重启时清理，绝不参与最终读取）
//! `exports/`   新目录导出 + 原子清单切换

use crate::model::{FragmentMeta, ImportManifest};
use rusqlite::{params, Connection};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
pub struct Paths {
    pub root: PathBuf,
    pub db: PathBuf,
    pub fragments_dir: PathBuf,
    pub committed_dir: PathBuf,
    pub tmp_dir: PathBuf,
    pub exports_dir: PathBuf,
}

impl Paths {
    pub fn new(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref().to_path_buf();
        Paths {
            db: root.join("capsule.db"),
            fragments_dir: root.join("fragments"),
            committed_dir: root.join("committed"),
            tmp_dir: root.join("tmp"),
            exports_dir: root.join("exports"),
            root,
        }
    }

    pub fn ensure(&self) -> std::io::Result<()> {
        for d in [
            &self.root,
            &self.fragments_dir,
            &self.committed_dir,
            &self.tmp_dir,
            &self.exports_dir,
        ] {
            fs::create_dir_all(d)?;
        }
        Ok(())
    }

    pub fn fragment_bin(&self, fragment_id: &str) -> PathBuf {
        self.fragments_dir.join(format!("{fragment_id}.bin"))
    }

    pub fn committed_file(&self, object_id: &str, generation: u64, stripe: usize, index: usize) -> PathBuf {
        self.committed_dir
            .join(object_id)
            .join(format!("gen{generation}"))
            .join(format!("stripe{stripe}"))
            .join(format!("shard{index}.bin"))
    }

    pub fn committed_stripe_dir(&self, object_id: &str, generation: u64, stripe: usize) -> PathBuf {
        self.committed_dir
            .join(object_id)
            .join(format!("gen{generation}"))
            .join(format!("stripe{stripe}"))
    }

    pub fn tmp_file(&self, tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        self.tmp_dir
            .join(format!("{tag}-{}-{nanos}.tmp", std::process::id()))
    }
}

pub fn open_db(paths: &Paths) -> rusqlite::Result<Connection> {
    let conn = Connection::open(&paths.db)?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    migrate(&conn)?;
    Ok(conn)
}

pub fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS imports (
            manifest_id TEXT PRIMARY KEY,
            object_id TEXT NOT NULL,
            received_at TEXT NOT NULL,
            manifest_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS fragments (
            fragment_id TEXT PRIMARY KEY,
            manifest_id TEXT NOT NULL REFERENCES imports(manifest_id),
            object_id TEXT NOT NULL,
            generation INTEGER NOT NULL,
            stripe INTEGER NOT NULL,
            shard_index INTEGER NOT NULL,
            source TEXT NOT NULL,
            received_at TEXT NOT NULL,
            length INTEGER NOT NULL,
            claimed_digest_hex TEXT,
            actual_digest_hex TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_frag_lookup
            ON fragments(object_id, generation, stripe, shard_index);
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS stripe_commits (
            object_id TEXT NOT NULL,
            generation INTEGER NOT NULL,
            stripe INTEGER NOT NULL,
            solution_no INTEGER NOT NULL,
            stripe_digest_hex TEXT NOT NULL,
            shard_count INTEGER NOT NULL,
            participating_fragments TEXT NOT NULL,
            excluded_evidence TEXT NOT NULL,
            report_json TEXT NOT NULL,
            committed_at TEXT NOT NULL,
            PRIMARY KEY (object_id, generation, stripe, solution_no)
        );
        CREATE TABLE IF NOT EXISTS committed_files (
            object_id TEXT NOT NULL,
            generation INTEGER NOT NULL,
            stripe INTEGER NOT NULL,
            shard_index INTEGER NOT NULL,
            path TEXT NOT NULL,
            digest_hex TEXT NOT NULL,
            length INTEGER NOT NULL,
            PRIMARY KEY (object_id, generation, stripe, shard_index)
        );
        "#,
    )
}

pub type IoFault = Arc<Mutex<IoFaultState>>;

#[derive(Debug, Default, Clone)]
pub struct IoFaultState {
    /// 剩余可成功执行的“变更操作”次数；耗尽后写/原子改名全部失败。
    pub remaining: Option<u64>,
    pub failures: u64,
}

impl IoFaultState {
    pub fn reset(&mut self, remaining: Option<u64>) {
        self.remaining = remaining;
        self.failures = 0;
    }
}

/// 字节块 IO 抽象：测试可注入磁盘写失败。
pub struct BlobStore {
    pub paths: Paths,
    pub fault: IoFault,
}

impl BlobStore {
    pub fn new(paths: Paths) -> Self {
        BlobStore {
            paths,
            fault: Arc::new(Mutex::new(IoFaultState::default())),
        }
    }

    fn tick_mutating(&self) -> std::io::Result<()> {
        let mut f = self.fault.lock().unwrap();
        match f.remaining {
            Some(0) => {
                f.failures += 1;
                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "注入的磁盘写失败 (ENOSPC)",
                ))
            }
            Some(n) => {
                f.remaining = Some(n - 1);
                Ok(())
            }
            None => Ok(()),
        }
    }

    /// 先写临时文件、校验再原子改名；临时文件绝不被最终读取。
    pub fn atomic_write(&self, dest: &Path, data: &[u8]) -> std::io::Result<()> {
        self.tick_mutating()?;
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        let tag = dest
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "blob".to_string());
        let tmp = self.paths.tmp_file(&tag);
        fs::write(&tmp, data)?;
        // 临时块自检：落盘字节必须与内存一致
        if fs::read(&tmp)? != data {
            let _ = fs::remove_file(&tmp);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "临时块自检失败",
            ));
        }
        self.tick_mutating()?;
        fs::rename(&tmp, dest)?;
        Ok(())
    }

    pub fn read(&self, p: &Path) -> std::io::Result<Vec<u8>> {
        fs::read(p)
    }

    pub fn remove_tmp_dir(&self) -> std::io::Result<()> {
        if self.paths.tmp_dir.exists() {
            fs::remove_dir_all(&self.paths.tmp_dir)?;
        }
        fs::create_dir_all(&self.paths.tmp_dir)
    }
}

/// 幂等导入：保存原始字节与接收来源，返回已登记 fragment_id。
pub fn import_manifest(
    conn: &mut Connection,
    paths: &Paths,
    manifest: &ImportManifest,
    fragments: &[(FragmentMeta, Vec<u8>)],
    save_original: impl Fn(&Path, &[u8]) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let tx = conn.transaction().map_err(io_err)?;
    let exists: bool = tx
        .query_row(
            "SELECT 1 FROM imports WHERE manifest_id = ?1",
            params![manifest.manifest_id],
            |_| Ok(()),
        )
        .optional()
        .map_err(io_err)?
        .is_some();
    if !exists {
        tx.execute(
            "INSERT INTO imports(manifest_id, object_id, received_at, manifest_json)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                manifest.manifest_id,
                manifest.object_id,
                manifest.received_at,
                serde_json::to_string(manifest).unwrap()
            ],
        )
        .map_err(io_err)?;
    }
    for (meta, bytes) in fragments {
        let dest = paths.fragment_bin(&meta.fragment_id);
        if !dest.exists() {
            save_original(&dest, bytes)?;
        }
        let actual = crate::model::shard_digest(bytes);
        let already: bool = tx
            .query_row(
                "SELECT 1 FROM fragments WHERE fragment_id = ?1",
                params![meta.fragment_id],
                |_| Ok(()),
            )
            .optional()
            .map_err(io_err)?
            .is_some();
        if already {
            continue;
        }
        tx.execute(
            "INSERT INTO fragments(fragment_id, manifest_id, object_id, generation, stripe,
                 shard_index, source, received_at, length, claimed_digest_hex, actual_digest_hex)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                meta.fragment_id,
                manifest.manifest_id,
                meta.object_id,
                meta.generation as i64,
                meta.stripe as i64,
                meta.shard_index as i64,
                meta.source,
                meta.received_at,
                bytes.len() as i64,
                meta.claimed_digest_hex,
                actual
            ],
        )
        .map_err(io_err)?;
    }
    tx.commit().map_err(io_err)?;
    Ok(())
}

fn io_err(e: rusqlite::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e)
}

trait OptionalExt<T> {
    fn optional(self) -> rusqlite::Result<Option<T>>;
}

impl<T> OptionalExt<T> for rusqlite::Result<T> {
    fn optional(self) -> rusqlite::Result<Option<T>> {
        match self {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }
}
