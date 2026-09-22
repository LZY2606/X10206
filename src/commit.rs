//! 按 stripe 的崩溃安全提交与导出（原子清单切换，原碎片不改动）。

use crate::db::Store;
use crate::model::EncodingParamsV1;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitManifestV1 {
    pub version: String,
    pub object_id: String,
    pub stripe_idx: usize,
    pub params: EncodingParamsV1,
    pub generation_mix_level: u64,
    pub solution_stripe_digest: String,
    pub participating_shard_ids: Vec<i64>,
    pub shards: Vec<CommittedShard>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommittedShard {
    pub shard_idx: usize,
    pub file: String,
    pub length: usize,
    pub sha256: String,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn stripe_digest(shards: &[Vec<u8>]) -> String {
    let mut h = Sha256::new();
    for s in shards {
        Digest::update(&mut h, (s.len() as u64).to_be_bytes());
        Digest::update(&mut h, s);
    }
    hex::encode(h.finalize())
}

fn fsync_dir(p: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let f = std::fs::File::open(p)?;
        let rc = unsafe { libc_fsync(f.as_raw_fd()) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    #[cfg(not(unix))]
    {
        let _ = p;
    }
    Ok(())
}

#[cfg(unix)]
extern "C" {
    fn fsync(fd: i32) -> i32;
}

#[cfg(unix)]
unsafe fn libc_fsync(fd: i32) -> i32 {
    fsync(fd)
}

fn write_durable(path: &Path, bytes: &[u8], fail_io: bool) -> std::io::Result<()> {
    if fail_io {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "injected disk write failure",
        ));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, bytes)?;
    if let Some(parent) = path.parent() {
        let _ = fsync_dir(parent);
    }
    Ok(())
}

/// 校验已提交目录：清单在、所有块在、逐块 sha256 与清单一致、stripe 摘要一致。
/// 返回 Ok(true) 完整可复用。
pub fn verify_committed(dir: &Path) -> std::io::Result<bool> {
    let manifest_bytes = match std::fs::read(dir.join("commit-manifest.json")) {
        Ok(b) => b,
        Err(_) => return Ok(false),
    };
    let manifest: CommitManifestV1 = match serde_json::from_slice(&manifest_bytes) {
        Ok(m) => m,
        Err(_) => return Ok(false),
    };
    let mut blocks = vec![None; manifest.params.n()];
    for s in &manifest.shards {
        let bytes = match std::fs::read(dir.join(&s.file)) {
            Ok(b) => b,
            Err(_) => return Ok(false),
        };
        if bytes.len() != s.length || sha256_hex(&bytes) != s.sha256 {
            return Ok(false);
        }
        if blocks[s.shard_idx].is_some() {
            return Ok(false);
        }
        blocks[s.shard_idx] = Some(bytes);
    }
    if blocks.iter().any(Option::is_none) {
        return Ok(false);
    }
    let shards: Vec<Vec<u8>> = blocks.into_iter().map(Option::unwrap).collect();
    if stripe_digest(&shards) != manifest.solution_stripe_digest {
        return Ok(false);
    }
    let sidecar = match std::fs::read(dir.join("commit-manifest.json.sha256")) {
        Ok(b) => b,
        Err(_) => return Ok(false),
    };
    if String::from_utf8_lossy(&sidecar).trim() != sha256_hex(&manifest_bytes) {
        return Ok(false);
    }
    Ok(String::from_utf8_lossy(&sidecar).trim() == sha256_hex(&manifest_bytes))
}

/// 读取已提交 stripe 的全部块（供导出）；摘要不完整则失败。
pub fn read_committed(dir: &Path) -> std::io::Result<(CommitManifestV1, Vec<Vec<u8>>)> {
    if !verify_committed(dir)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "已提交 stripe 摘要不完整，拒绝复用临时/残缺块",
        ));
    }
    let manifest_bytes = std::fs::read(dir.join("commit-manifest.json"))?;
    let manifest: CommitManifestV1 = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut blocks = vec![Vec::new(); manifest.params.n()];
    for s in &manifest.shards {
        blocks[s.shard_idx] = std::fs::read(dir.join(&s.file))?;
    }
    Ok((manifest, blocks))
}

pub struct CommitOutput {
    pub dir: PathBuf,
    pub manifest_digest: String,
}

/// 暂存 -> 读回校验 -> 原子切换。
/// `full_shards` 必须是重建后的全部 n 块（参与块为原始字节，缺块为重算字节）。
pub fn commit_stripe(
    store: &Store,
    object_id: &str,
    stripe_idx: usize,
    params: &EncodingParamsV1,
    generation_mix_level: u64,
    solution_stripe_digest: &str,
    participating_shard_ids: &[i64],
    full_shards: &[Vec<u8>],
) -> std::io::Result<CommitOutput> {
    let object_dir = store.commits_dir(object_id);
    std::fs::create_dir_all(&object_dir)?;
    let unique = format!(
        ".tmp-{}-{}-{}",
        stripe_idx,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let stage = object_dir.join(unique);
    let final_dir = object_dir.join(format!("stripe-{:06}", stripe_idx));

    let cleanup = |p: &Path| {
        let _ = std::fs::remove_dir_all(p);
    };

    let fail_io = store.faults.fail_commit_io();

    let mut committed_shards = Vec::new();
    for (idx, bytes) in full_shards.iter().enumerate() {
        let rel = format!("shard-{:03}.bin", idx);
        if let Err(e) = write_durable(&stage.join(&rel), bytes, fail_io) {
            cleanup(&stage);
            return Err(e);
        }
        committed_shards.push(CommittedShard {
            shard_idx: idx,
            file: rel,
            length: bytes.len(),
            sha256: sha256_hex(bytes),
        });
    }

    let manifest = CommitManifestV1 {
        version: "commit-manifest/v1".into(),
        object_id: object_id.into(),
        stripe_idx,
        params: params.clone(),
        generation_mix_level,
        solution_stripe_digest: solution_stripe_digest.into(),
        participating_shard_ids: participating_shard_ids.to_vec(),
        shards: committed_shards,
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(io_other)?;
    if let Err(e) = write_durable(&stage.join("commit-manifest.json"), &manifest_bytes, fail_io) {
        cleanup(&stage);
        return Err(e);
    }

    let manifest_digest = sha256_hex(&manifest_bytes);
    // 把 manifest 摘要落进清单的伴随文件（commit-manifest.json.sha256），原子同切。
    if let Err(e) = write_durable(
        &stage.join("commit-manifest.json.sha256"),
        manifest_digest.as_bytes(),
        fail_io,
    ) {
        cleanup(&stage);
        return Err(e);
    }

    // “写完临时块后进程中断”：保留 stage（重启时清），绝不写 commits 行。
    if store.faults.crash_after_staging() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "injected crash after staging (no commit row)",
        ));
    }

    // 读回校验：临时块必须通过逐块摘要 + stripe 摘要 + 清单摘要，才允许最终切换。
    match verify_committed(&stage) {
        Ok(true) => {}
        Ok(false) => {
            cleanup(&stage);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "暂存块读回校验失败，拒绝提交",
            ));
        }
        Err(e) => {
            cleanup(&stage);
            return Err(e);
        }
    }

    // 重新提交（切换到另一可行解）：旧目录先改名为备份，避免 rename 覆盖语义差异。
    let backup = if final_dir.exists() {
        let b = object_dir.join(format!(
            ".obsolete-stripe-{:06}-{}",
            stripe_idx,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::rename(&final_dir, &b)?;
        Some(b)
    } else {
        None
    };
    if let Err(e) = std::fs::rename(&stage, &final_dir) {
        if let Some(b) = backup {
            let _ = std::fs::rename(&b, &final_dir);
        }
        cleanup(&stage);
        return Err(e);
    }
    let _ = fsync_dir(&object_dir);
    if let Some(b) = backup {
        let _ = std::fs::remove_dir_all(b);
    }

    Ok(CommitOutput {
        dir: final_dir,
        manifest_digest,
    })
}

fn io_other<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
}
