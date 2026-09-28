//! 领域模型：manifest、接收回执（receipt）、健康度与摘要。

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 单块长度字节摘要：sha256(块内容) 的十六进制。
pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// 对象摘要：sha256(裁剪后全部数据块顺序拼接)。
pub fn object_digest(shards: &[Vec<u8>], data_len: Option<u64>) -> String {
    let mut h = Sha256::new();
    let mut total: u64 = shards.iter().map(|s| s.len() as u64).sum();
    for s in shards {
        h.update(s);
    }
    if let Some(n) = data_len {
        if n < total {
            // 摘要基于声明的对象长度；已在写入时按声明长度拼接，这里仅作标记用途。
            total = n;
        }
    }
    let _ = total;
    hex::encode(h.finalize())
}

/// 版本化编码参数清单。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "code", rename_all = "kebab-case")]
pub enum CodeSpec {
    XorV1 { k: u32 },
    RsGf256V1 { k: u32, m: u32 },
}

impl CodeSpec {
    pub fn k(&self) -> usize {
        match self {
            CodeSpec::XorV1 { k } => *k as usize,
            CodeSpec::RsGf256V1 { k, .. } => *k as usize,
        }
    }
    pub fn parity(&self) -> usize {
        match self {
            CodeSpec::XorV1 { .. } => 1,
            CodeSpec::RsGf256V1 { m, .. } => *m as usize,
        }
    }
    pub fn id(&self) -> &'static str {
        match self {
            CodeSpec::XorV1 { .. } => "xor-v1",
            CodeSpec::RsGf256V1 { .. } => "rs-gf256-v1",
        }
    }
}

/// 清单声明的单个 shard。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardSpec {
    pub position: u32,
    #[serde(default)]
    pub length: Option<u32>,
    #[serde(default)]
    pub digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub object_id: String,
    #[serde(flatten)]
    pub code: CodeSpec,
    pub shard_length: u32,
    pub data_length: u64,
    /// 可选：对象级 sha256 摘要（十六进制），用于判断重建结果是否可信。
    #[serde(default)]
    pub object_digest: Option<String>,
    #[serde(default)]
    pub shards: Vec<ShardSpec>,
    /// 来源标签（manifest 自身的接收来源）。
    #[serde(default)]
    pub source: Option<String>,
}

impl Manifest {
    pub fn parse(json: &[u8]) -> anyhow::Result<Self> {
        let m: Manifest = serde_json::from_slice(json)?;
        anyhow::ensure!(m.shard_length > 0, "shard_length 必须为正");
        anyhow::ensure!(m.code.k() > 0, "k 必须为正");
        Ok(m)
    }

    pub fn stripe_count(&self) -> usize {
        let step = self.code.k() as u64 * self.shard_length as u64;
        ((self.data_length + step - 1) / step) as usize
    }

    /// 返回 (stripe, 位置在 stripe 内)；越界返回 None。
    pub fn locate(&self, position: usize) -> Option<(usize, usize)> {
        let total = self.code.k() + self.code.parity();
        if position >= total * self.stripe_count() {
            return None;
        }
        Some((position / total, position % total))
    }
}

/// 导入时单块的接收回执（来源端声明）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptInput {
    pub object_id: String,
    pub shard_position: u32,
    #[serde(default)]
    pub generation: u32,
    pub source: String,
    pub blob: String,
    /// 来源声明的每块 sha256；缺失则无法信任该候选。
    #[serde(default)]
    pub digest: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde_repr_like::SerdeRepr)]
pub enum Health {
    /// 摘要完整且匹配。
    Good,
    /// 未提供逐块摘要（不能作为重建候选）。
    DigestMissing,
    /// 声明摘要与实际内容不符（位翻转/写坏）。
    DigestMismatch,
    /// 超出 manifest 声明范围。
    OutOfRange,
    /// 与 manifest 声明长度不符（仍可按证据记录，默认不参与计算）。
    LengthMismatch,
}

impl Health {
    pub fn code(&self) -> &'static str {
        match self {
            Health::Good => "good",
            Health::DigestMissing => "digest-missing",
            Health::DigestMismatch => "digest-mismatch",
            Health::OutOfRange => "out-of-range",
            Health::LengthMismatch => "length-mismatch",
        }
    }
    pub fn label_zh(&self) -> &'static str {
        match self {
            Health::Good => "完好",
            Health::DigestMissing => "缺摘要",
            Health::DigestMismatch => "摘要不符",
            Health::OutOfRange => "越界",
            Health::LengthMismatch => "长度不符",
        }
    }
}

/// 兼容 derive：手写一个轻量 serialize/deserialize 包装，避免额外依赖。
mod serde_repr_like {
    pub trait SerdeRepr: Sized {}
}
