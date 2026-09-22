//! 条带复原舱（Stripe Recovery Capsule）
//!
//! 离线对象碎片审阅：导入 manifest + data/parity shard + 每块摘要，保存原始字节
//! 与接收来源；在版本化编码参数下枚举式重建，为每个输出列出参与 shard、
//! 被排除的损坏证据与重算摘要；按 stripe 原子提交，中断后续跑只复用校验通过
//! 的已提交 stripe；导出写入新目录并原子切换清单，原始碎片不改动。

pub mod api;
pub mod db;
pub mod engine;
pub mod export;
pub mod fixtures;
pub mod gf;
pub mod hashutil;
pub mod import;
pub mod recovery;
pub mod types;

use std::path::Path;
use std::sync::{Arc, Mutex};

use db::Storage;
use recovery::{audit_committed, FsSink};

pub struct System {
    pub storage: Arc<Mutex<Storage>>,
    pub data_root: std::path::PathBuf,
}

/// 打开/初始化数据目录：建库、清扫临时块、生成演示 fixture 并导入。
pub fn init_system(data_root: &Path) -> Result<System> {
    std::fs::create_dir_all(data_root.join("sources"))?;
    std::fs::create_dir_all(data_root.join("recovered"))?;
    let db_path = data_root.join("capsule.db");
    let mut storage = Storage::open(db_path.to_str().unwrap())?;

    if storage.object_count()? == 0 {
        fixtures::create_demo_fixtures(data_root);
        let sources_dir = data_root.join("sources");
        let mut dirs: Vec<_> = std::fs::read_dir(&sources_dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        dirs.sort();
        for dir in dirs {
            match import::import_bundle(&mut storage, &dir) {
                Ok(msg) => eprintln!("[导入] {msg}"),
                Err(e) => eprintln!("[导入] 跳过 {} : {e}", dir.display()),
            }
        }
    }

    recovery::clean_temp_dir(data_root)?;
    let sink = FsSink::new(data_root)?;
    audit_committed(&mut storage, &sink);

    Ok(System {
        storage: Arc::new(Mutex::new(storage)),
        data_root: data_root.to_path_buf(),
    })
}

/// 极轻量错误聚合，避免引入 anyhow 依赖。
pub mod anyhow_lite {
    use std::fmt;

    #[derive(Debug)]
    pub struct Error(pub String);

    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.0)
        }
    }
    impl std::error::Error for Error {}

    impl From<std::io::Error> for Error {
        fn from(e: std::io::Error) -> Self {
            Error(e.to_string())
        }
    }
    impl From<rusqlite::Error> for Error {
        fn from(e: rusqlite::Error) -> Self {
            Error(e.to_string())
        }
    }
}

pub type Result<T> = std::result::Result<T, anyhow_lite::Error>;

