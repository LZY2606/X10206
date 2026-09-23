//! 原始字节、临时块、已提交块与导出目录的文件存储。
//! 所有写操作先写暂存文件再原子 rename；临时块永不出现在最终读取路径上。

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Default, Clone)]
pub struct FaultRules {
    /// 若目标路径包含该子串，则模拟磁盘写失败（在 rename 前抛错）。
    pub fail_pattern: Option<String>,
}

impl FaultRules {
    fn blocks(&self, target: &Path) -> bool {
        match &self.fail_pattern {
            Some(p) if !p.is_empty() => target.to_string_lossy().contains(p),
            _ => false,
        }
    }
}

#[derive(Clone)]
pub struct FileStore {
    root: PathBuf,
    fault: Arc<Mutex<FaultRules>>,
}

impl FileStore {
    pub fn new(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        for d in ["raw", "tmp", "committed", "exports"] {
            fs::create_dir_all(root.join(d))?;
        }
        Ok(FileStore {
            root,
            fault: Arc::new(Mutex::new(FaultRules::default())),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// 测试用：安装磁盘写失败规则。
    pub fn set_fault(&self, rules: FaultRules) {
        *self.fault.lock().unwrap() = rules;
    }

    pub fn clear_fault(&self) {
        *self.fault.lock().unwrap() = FaultRules::default();
    }

    pub fn raw_path(&self, digest: &str) -> PathBuf {
        self.root.join("raw").join(digest)
    }

    pub fn tmp_dir(&self) -> PathBuf {
        self.root.join("tmp")
    }

    /// 启动时清理全部临时块（中断残留，永不复用）。
    pub fn clean_tmp(&self) -> io::Result<()> {
        let tmp = self.tmp_dir();
        if tmp.exists() {
            for entry in fs::read_dir(&tmp)? {
                let p = entry?.path();
                if p.is_dir() {
                    fs::remove_dir_all(&p)?;
                } else {
                    fs::remove_file(&p)?;
                }
            }
        }
        Ok(())
    }

    /// 保存原始字节（内容寻址），返回 sha256 摘要；已存在则校验后复用。
    pub fn save_raw(&self, bytes: &[u8]) -> io::Result<String> {
        let digest = crate::digest::sha256_hex(bytes);
        let path = self.raw_path(&digest);
        if path.exists() {
            let existing = fs::read(&path)?;
            if existing != bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("内容寻址冲突: {digest}"),
                ));
            }
            return Ok(digest);
        }
        fs::create_dir_all(path.parent().unwrap())?;
        self.atomic_write(&path, bytes)?;
        Ok(digest)
    }

    pub fn read_raw(&self, digest: &str) -> io::Result<Vec<u8>> {
        fs::read(self.raw_path(digest))
    }

    /// 任务临时块（每个 job 独立子目录，名字包含 stripe/shard 便于故障注入定位）。
    pub fn write_tmp(&self, job_id: i64, name: &str, bytes: &[u8]) -> io::Result<PathBuf> {
        let dir = self.tmp_dir().join(format!("job-{job_id}"));
        fs::create_dir_all(&dir)?;
        let path = dir.join(name);
        fs::write(&path, bytes)?;
        Ok(path)
    }

    /// 清理一个 stripe 的全部临时块。
    pub fn discard_tmp_stripe(&self, job_id: i64, stripe_index: u32) {
        let dir = self.tmp_dir().join(format!("job-{job_id}"));
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with(&format!("s{stripe_index}-")))
                    .unwrap_or(false)
                {
                    let _ = fs::remove_file(&p);
                }
            }
        }
    }

    pub fn committed_path(&self, object_id: &str, stripe_index: u32, shard_index: u32) -> PathBuf {
        self.root
            .join("committed")
            .join(safe_id(object_id))
            .join(format!("s{stripe_index}-sh{shard_index}.block"))
    }

    /// 原子提交重建块：暂存 → fsync → rename 到 committed 区。
    pub fn write_committed(
        &self,
        object_id: &str,
        stripe_index: u32,
        shard_index: u32,
        bytes: &[u8],
    ) -> io::Result<(String, PathBuf)> {
        let target = self.committed_path(object_id, stripe_index, shard_index);
        fs::create_dir_all(target.parent().unwrap())?;
        self.atomic_write(&target, bytes)?;
        Ok((crate::digest::sha256_hex(bytes), target))
    }

    pub fn read_committed(
        &self,
        object_id: &str,
        stripe_index: u32,
        shard_index: u32,
    ) -> io::Result<Vec<u8>> {
        fs::read(self.committed_path(object_id, stripe_index, shard_index))
    }

    pub fn remove_committed_stripe(&self, object_id: &str, stripe_index: u32) -> io::Result<()> {
        let dir = self.root.join("committed").join(safe_id(object_id));
        if !dir.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(&dir)? {
            let p = entry?.path();
            if p
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with(&format!("s{stripe_index}-")))
                .unwrap_or(false)
            {
                fs::remove_file(&p)?;
            }
        }
        Ok(())
    }

    /// 通用原子写：同目录暂存文件 + fsync + rename。
    fn atomic_write(&self, target: &Path, bytes: &[u8]) -> io::Result<()> {
        fs::create_dir_all(target.parent().unwrap())?;
        let staging = target.with_extension(format!(
            "part-{}-{}",
            std::process::id(),
            next_serial()
        ));
        let mut f = fs::File::create(&staging)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        let blocks = self.fault.lock().unwrap().blocks(target);
        if blocks {
            // 模拟“磁盘写失败”：暂存文件保留（模拟部分写），rename 永不发生。
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("注入的磁盘写失败: {}", target.display()),
            ));
        }
        fs::rename(&staging, target)?;
        Ok(())
    }
}

/// 将对象 ID 规范化为安全目录名。
pub fn safe_id(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

use std::sync::atomic::{AtomicU64, Ordering};
static SERIAL: AtomicU64 = AtomicU64::new(0);
fn next_serial() -> u64 {
    SERIAL.fetch_add(1, Ordering::Relaxed)
}
