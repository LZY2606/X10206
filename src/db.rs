//! SQLite 持久化、vault 原始字节保存、按 stripe 提交目录与崩溃恢复。

use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Mutex;

pub const SCHEMA_VERSION: u32 = 1;

pub struct Faults {
    /// 下一次提交的任何落盘写返回错误（磁盘写失败）。
    pub fail_commit_io: AtomicBool,
    /// 提交时写完临时块后“进程被杀”：不留 commit 行。
    pub crash_after_staging: AtomicBool,
    /// 导出在最终 rename 前失败。
    pub fail_export_promote: AtomicBool,
}

impl Default for Faults {
    fn default() -> Self {
        Self {
            fail_commit_io: AtomicBool::new(false),
            crash_after_staging: AtomicBool::new(false),
            fail_export_promote: AtomicBool::new(false),
        }
    }
}

impl Faults {
    pub fn fail_commit_io(&self) -> bool {
        self.fail_commit_io.swap(false, Ordering::SeqCst)
    }
    pub fn crash_after_staging(&self) -> bool {
        self.crash_after_staging.swap(false, Ordering::SeqCst)
    }
    pub fn fail_export_promote(&self) -> bool {
        self.fail_export_promote.swap(false, Ordering::SeqCst)
    }
}

pub struct Store {
    pub root: PathBuf,
    pub conn: Mutex<Connection>,
    pub faults: Faults,
}

impl Store {
    pub fn vault_shard_path(&self, rel: &str) -> PathBuf {
        self.root.join("vault").join("shards").join(rel)
    }

    pub fn commits_dir(&self, object_id: &str) -> PathBuf {
        self.root.join("commits").join(safe_seg(object_id))
    }

    pub fn exports_dir(&self) -> PathBuf {
        self.root.join("exports")
    }

    pub fn open(root: impl AsRef<Path>) -> std::io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(root.join("vault").join("shards"))?;
        std::fs::create_dir_all(root.join("commits"))?;
        std::fs::create_dir_all(root.join("exports"))?;

        let db_path = root.join("chamber.db");
        let conn = Connection::open(&db_path)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .and_then(|_| conn.pragma_update(None, "foreign_keys", "ON"))
            .and_then(|_| conn.pragma_update(None, "busy_timeout", 5000))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        conn.execute_batch(SCHEMA)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        let store = Store {
            root,
            conn: Mutex::new(conn),
            faults: Faults::default(),
        };
        store.recover_from_crash()?;
        Ok(store)
    }

    /// 进程中断续跑：
    /// 1. 所有提交临时目录（`.tmp-*`）一律删除——临时块永不被最终读取；
    /// 2. 核对 commits 表中的已提交 stripe：摘要完整才可复用，否则标记 Broken。
    fn recover_from_crash(&self) -> std::io::Result<()> {
        let commits_root = self.root.join("commits");
        if commits_root.is_dir() {
            for entry in std::fs::read_dir(&commits_root)? {
                let entry = entry?;
                if !entry.file_type()?.is_dir() {
                    continue;
                }
                for sub in std::fs::read_dir(entry.path())? {
                    let sub = sub?;
                    if sub.file_type()?.is_dir()
                        && sub.file_name().to_string_lossy().starts_with(".tmp-")
                    {
                        std::fs::remove_dir_all(sub.path())?;
                    }
                }
            }
        }

        let broken: Vec<(String, usize)> = {
            let conn = self.conn.lock().unwrap();
            let mut stmt = conn
                .prepare("SELECT object_id, stripe_idx, dir FROM commits")
                .unwrap();
            let rows = stmt
                .query_map([], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as usize, r.get::<_, String>(2)?))
                })
                .unwrap();
            let mut broken = Vec::new();
            for row in rows {
                let (oid, stripe, dir) = row.unwrap();
                match crate::commit::verify_committed(Path::new(&dir)) {
                    Ok(true) => {}
                    _ => broken.push((oid, stripe)),
                }
            }
            broken
        };
        if !broken.is_empty() {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction().unwrap();
            for (oid, stripe) in &broken {
                tx.execute(
                    "UPDATE stripe_analysis SET state='broken' WHERE object_id=?1 AND stripe_idx=?2",
                    rusqlite::params![oid, *stripe as i64],
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }
        Ok(())
    }
}

pub fn safe_seg(s: &str) -> String {
    let t: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if t.is_empty() || t == "." || t == ".." {
        "_".to_string()
    } else {
        t
    }
}

const SCHEMA: &str = r#"
PRAGMA user_version = 1;

CREATE TABLE IF NOT EXISTS objects (
    object_id    TEXT PRIMARY KEY,
    params_json  TEXT NOT NULL,
    stripe_len   INTEGER NOT NULL,
    stripe_count INTEGER NOT NULL,
    object_digest TEXT,
    imported_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS stripe_expected (
    object_id  TEXT NOT NULL,
    stripe_idx INTEGER NOT NULL,
    digest     TEXT NOT NULL,
    PRIMARY KEY (object_id, stripe_idx)
);

CREATE TABLE IF NOT EXISTS shards (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id      TEXT NOT NULL,
    stripe_idx     INTEGER NOT NULL,
    shard_idx      INTEGER NOT NULL,
    generation     INTEGER NOT NULL,
    source         TEXT NOT NULL,
    claimed_len    INTEGER NOT NULL,
    actual_len     INTEGER NOT NULL,
    claimed_digest TEXT,
    actual_digest  TEXT NOT NULL,
    health         INTEGER NOT NULL,
    bytes_path     TEXT NOT NULL,
    received_at    INTEGER NOT NULL,
    UNIQUE(object_id, stripe_idx, shard_idx, generation, source, actual_digest)
);

CREATE TABLE IF NOT EXISTS stripe_analysis (
    object_id     TEXT NOT NULL,
    stripe_idx    INTEGER NOT NULL,
    state         TEXT NOT NULL,
    feasible_count INTEGER NOT NULL,
    search_budget INTEGER NOT NULL,
    search_visited INTEGER NOT NULL,
    search_truncated INTEGER NOT NULL,
    selected_solution_id INTEGER,
    analyzed_at   INTEGER NOT NULL,
    PRIMARY KEY (object_id, stripe_idx)
);

CREATE TABLE IF NOT EXISTS solutions (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id             TEXT NOT NULL,
    stripe_idx            INTEGER NOT NULL,
    rank                  INTEGER NOT NULL,
    data_digest           TEXT NOT NULL,
    stripe_digest         TEXT NOT NULL,
    matches_stripe_digest INTEGER NOT NULL,
    mix_level             INTEGER NOT NULL,
    min_generation        INTEGER NOT NULL,
    excluded_count        INTEGER NOT NULL,
    participating_json    TEXT NOT NULL,
    excluded_json         TEXT NOT NULL,
    shard_reports_json    TEXT NOT NULL,
    diff_json             TEXT NOT NULL,
    created_at            INTEGER NOT NULL,
    UNIQUE(object_id, stripe_idx, stripe_digest)
);

CREATE TABLE IF NOT EXISTS commits (
    object_id       TEXT NOT NULL,
    stripe_idx      INTEGER NOT NULL,
    solution_id     INTEGER NOT NULL,
    dir             TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    readback_ok     INTEGER NOT NULL,
    committed_at    INTEGER NOT NULL,
    PRIMARY KEY (object_id, stripe_idx)
);

CREATE TABLE IF NOT EXISTS isolated_sources (
    source      TEXT PRIMARY KEY,
    isolated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS exports (
    export_id       TEXT PRIMARY KEY,
    object_id       TEXT NOT NULL,
    dir             TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    created_at      INTEGER NOT NULL
);
"#;
