//! 磁盘布局与原子写。所有原始碎片永不改动；恢复产物分 staging/committed，
//! 只有校验通过并原子 rename 后的 stripe 才允许被最终读取。

use crate::digest::sha256_hex;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// 磁盘写故障注入：环境变量 SR_FAILPOINT=staging_write|commit_rename|export_write。
pub fn failpoint(name: &str) -> Result<()> {
    if let Ok(v) = std::env::var("SR_FAILPOINT") {
        if v.split(',').any(|f| f == name) {
            bail!("injected disk failure: {name}");
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommitManifest {
    pub kind: String,
    pub object_id: String,
    pub stripe: u64,
    pub generation: u64,
    pub object_digest: String,
    pub combo_index: usize,
    pub output_digest: String,
    pub shard_digests: Vec<String>,
    pub block_digests: Vec<String>,
    pub isolated_snapshot: Vec<String>,
}

pub struct BlockStore {
    pub root: PathBuf,
}

impl BlockStore {
    pub fn new(root: &Path) -> Result<Self> {
        let store = BlockStore {
            root: root.to_path_buf(),
        };
        for d in [
            store.original_dir(),
            store.manifest_dir(),
            store.staging_dir(),
            store.committed_dir(),
            store.quarantine_dir(),
            store.export_dir(),
            store.tmp_dir(),
        ] {
            fs::create_dir_all(&d).with_context(|| format!("create dir {}", d.display()))?;
        }
        Ok(store)
    }

    pub fn original_dir(&self) -> PathBuf {
        self.root.join("original")
    }
    pub fn manifest_dir(&self) -> PathBuf {
        self.root.join("manifests")
    }
    pub fn staging_dir(&self) -> PathBuf {
        self.root.join("staging")
    }
    pub fn committed_dir(&self) -> PathBuf {
        self.root.join("committed")
    }
    pub fn quarantine_dir(&self) -> PathBuf {
        self.root.join("quarantine")
    }
    pub fn export_dir(&self) -> PathBuf {
        self.root.join("exports")
    }
    pub fn tmp_dir(&self) -> PathBuf {
        self.root.join("tmp")
    }

    /// 按内容寻址保存原始字节；同一摘要只落盘一次，原文件不被修改。
    pub fn save_original(&self, bytes: &[u8]) -> Result<(String, PathBuf)> {
        let digest = sha256_hex(bytes);
        let path = self.original_dir().join(format!("{digest}.bin"));
        if !path.exists() {
            self.atomic_write(&path, bytes)?;
        }
        Ok((digest, path))
    }

    pub fn save_manifest_bytes(&self, object_id: &str, bytes: &[u8]) -> Result<PathBuf> {
        let path = self
            .manifest_dir()
            .join(format!("{}.manifest.json", sanitize(object_id)));
        self.atomic_write(&path, bytes)?;
        Ok(path)
    }

    /// 启动时清理遗留 staging：中断后的临时块不得被最终读取。
    pub fn clean_stale_staging(&self) -> Result<()> {
        let staging = self.staging_dir();
        if staging.exists() {
            for entry in fs::read_dir(&staging)? {
                let p = entry?.path();
                if p.is_dir() {
                    fs::remove_dir_all(&p).ok();
                } else {
                    fs::remove_file(&p).ok();
                }
            }
        }
        let tmp = self.tmp_dir();
        if tmp.exists() {
            for entry in fs::read_dir(&tmp)? {
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

    fn staging_stripe_dir(&self, object_id: &str, stripe: u64) -> PathBuf {
        self.staging_dir()
            .join(format!("{}__s{}", sanitize(object_id), stripe))
    }

    fn committed_stripe_dir(&self, object_id: &str, stripe: u64) -> PathBuf {
        self.committed_dir()
            .join(format!("{}__s{}", sanitize(object_id), stripe))
    }

    /// 把重建块写入该 stripe 的临时目录，返回块路径与摘要。
    pub fn write_staging(
        &self,
        object_id: &str,
        stripe: u64,
        blocks: &[Vec<u8>],
        manifest: &CommitManifest,
    ) -> Result<(PathBuf, Vec<String>, String)> {
        failpoint("staging_write")?;
        let dir = self.staging_stripe_dir(object_id, stripe);
        if dir.exists() {
            fs::remove_dir_all(&dir)?;
        }
        fs::create_dir_all(&dir)?;
        let mut block_digests = Vec::new();
        for (i, block) in blocks.iter().enumerate() {
            let digest = sha256_hex(block);
            self.atomic_write(&dir.join(format!("block_{i:03}.bin")), block)?;
            block_digests.push(digest);
        }
        let output_digest = stripe_output_digest(blocks);
        let manifest_json = serde_json::to_vec_pretty(manifest)?;
        self.atomic_write(&dir.join("commit.json"), &manifest_json)?;
        Ok((dir, block_digests, output_digest))
    }

    /// 原子提交：staging 整体 rename 到 committed；旧提交移入 quarantine。
    pub fn commit_stripe(&self, object_id: &str, stripe: u64) -> Result<PathBuf> {
        failpoint("commit_rename")?;
        let staging = self.staging_stripe_dir(object_id, stripe);
        let target = self.committed_stripe_dir(object_id, stripe);
        if target.exists() {
            let qdir = self.quarantine_dir().join(format!(
                "{}__s{}__{}",
                sanitize(object_id),
                stripe,
                timestamp_token()
            ));
            fs::rename(&target, &qdir).with_context(|| {
                format!("quarantine old commit {}", target.display())
            })?;
        }
        fs::rename(&staging, &target)
            .with_context(|| format!("commit rename {}", staging.display()))?;
        Ok(target)
    }

    /// 读取并严格校验已提交 stripe；任何不完整/被篡改都返回 None（不得复用）。
    pub fn load_committed(&self, object_id: &str, stripe: u64) -> Result<Option<(CommitManifest, Vec<Vec<u8>>)>> {
        let dir = self.committed_stripe_dir(object_id, stripe);
        if !dir.exists() {
            return Ok(None);
        }
        let manifest_bytes = match fs::read(dir.join("commit.json")) {
            Ok(b) => b,
            Err(_) => return Ok(None),
        };
        let manifest: CommitManifest = match serde_json::from_slice(&manifest_bytes) {
            Ok(m) => m,
            Err(_) => return Ok(None),
        };
        let mut blocks = Vec::new();
        for (i, expected) in manifest.block_digests.iter().enumerate() {
            let path = dir.join(format!("block_{i:03}.bin"));
            let bytes = match fs::read(&path) {
                Ok(b) => b,
                Err(_) => return Ok(None),
            };
            if &sha256_hex(&bytes) != expected {
                return Ok(None);
            }
            blocks.push(bytes);
        }
        let shard_digests: Vec<String> = blocks.iter().map(|b| sha256_hex(b)).collect();
        if shard_digests != manifest.shard_digests
            || stripe_output_digest(&blocks) != manifest.output_digest
        {
            return Ok(None);
        }
        Ok(Some((manifest, blocks)))
    }

    /// 将已失效的提交整体移入隔离区，返回是否移动成功。
    pub fn quarantine_commit(&self, object_id: &str, stripe: u64) -> Result<bool> {
        let target = self.committed_stripe_dir(object_id, stripe);
        if !target.exists() {
            return Ok(false);
        }
        let qdir = self.quarantine_dir().join(format!(
            "{}__s{}__{}",
            sanitize(object_id),
            stripe,
            timestamp_token()
        ));
        fs::rename(&target, &qdir)?;
        Ok(true)
    }

    /// 组装对象（截断到 object_size），校验对象摘要，写入全新导出目录，
    /// 最后原子切换清单指针。
    #[allow(clippy::too_many_arguments)]
    pub fn export_object(
        &self,
        object_id: &str,
        object_digest: &str,
        object_size: u64,
        stripe_blocks: &[Vec<Vec<u8>>],
        stripe_count: usize,
        shard_size: usize,
        k: usize,
    ) -> Result<PathBuf> {
        failpoint("export_write")?;
        let mut padded = Vec::new();
        for blocks in stripe_blocks {
            if blocks.len() < k {
                bail!("export requires committed data blocks");
            }
            for b in &blocks[..k] {
                padded.extend_from_slice(b);
            }
        }
        if padded.len() < object_size as usize {
            bail!("padded object shorter than declared size");
        }
        padded.truncate(object_size as usize);
        if sha256_hex(&padded) != object_digest {
            bail!("recomputed object digest does not match manifest");
        }

        let token = timestamp_token();
        let out_dir = self
            .export_dir()
            .join(format!("{}-{token}", sanitize(object_id)));
        fs::create_dir_all(&out_dir)?;
        self.atomic_write(&out_dir.join("object.bin"), &padded)?;
        let mut stripe_manifests = Vec::new();
        for (stripe, blocks) in stripe_blocks.iter().enumerate().take(stripe_count) {
            let block_digests: Vec<String> = blocks.iter().map(|b| sha256_hex(b)).collect();
            stripe_manifests.push(serde_json::json!({
                "stripe": stripe,
                "block_digests": block_digests,
                "output_digest": stripe_output_digest(blocks),
            }));
        }
        let export_manifest = serde_json::json!({
            "kind": "stripe-recovery-export",
            "version": "1",
            "object_id": object_id,
            "object_digest": object_digest,
            "object_size": object_size,
            "codec": { "k": k, "shard_size": shard_size },
            "stripes": stripe_manifests,
        });
        self.atomic_write(
            &out_dir.join("export-manifest.json"),
            serde_json::to_vec_pretty(&export_manifest)?.as_slice(),
        )?;
        let pointer = self.export_dir().join(format!("{}.latest.json", sanitize(object_id)));
        self.atomic_write(&pointer, serde_json::to_vec_pretty(&export_manifest)?.as_slice())?;
        Ok(out_dir)
    }

    fn atomic_write(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = self.tmp_dir().join(format!(
            "{}.{}.tmp",
            sanitize(&path.file_name().unwrap().to_string_lossy()),
            timestamp_token()
        ));
        fs::write(&tmp, bytes).with_context(|| format!("write {}", tmp.display()))?;
        fs::rename(&tmp, path).with_context(|| format!("rename to {}", path.display()))?;
        Ok(())
    }
}

/// stripe 输出摘要：按编号顺序对全部 k+m 块重新计算的拼接摘要。
pub fn stripe_output_digest(blocks: &[Vec<u8>]) -> String {
    let mut joined = String::new();
    for b in blocks {
        joined.push_str(&sha256_hex(b));
        joined.push('\n');
    }
    sha256_hex(joined.as_bytes())
}

pub fn snapshot_from(sources: &[String], isolated: &HashSet<String>) -> Vec<String> {
    let mut snap: Vec<String> = sources
        .iter()
        .filter(|s| isolated.contains(*s))
        .cloned()
        .collect();
    snap.sort();
    snap.dedup();
    snap
}

pub fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn timestamp_token() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{nanos:x}")
}
