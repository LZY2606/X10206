//! 版本化编码参数与清单（manifest）模型。

use serde::{Deserialize, Serialize};

/// 当前支持的编码版本。未知版本一律拒绝导入后的重建。
pub const SUPPORTED_CODEC_VERSIONS: &[u32] = &[1];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ShardKind {
    Data,
    Parity,
}

impl ShardKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ShardKind::Data => "data",
            ShardKind::Parity => "parity",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "data" | "d" => Some(ShardKind::Data),
            "parity" | "p" => Some(ShardKind::Parity),
            _ => None,
        }
    }
}

/// 对象清单。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectManifest {
    pub object_id: String,
    pub codec_version: u32,
    /// 每个 stripe 的数据块数（恢复下限）。
    pub k: usize,
    /// 校验块数。
    pub m: usize,
    /// 固定块长（字节）。
    pub block_len: usize,
    /// stripe 数量。
    pub stripe_count: usize,
    /// 对象逻辑长度（拼接截断用）。
    pub object_len: usize,
    /// 对象级 SHA-256（可空，表示导入方未提供）。
    #[serde(default)]
    pub object_digest: Option<String>,
    /// 每块预期摘要：stripe -> shard -> sha256(hex)。可缺项。
    #[serde(default)]
    pub block_digests: std::collections::BTreeMap<usize, std::collections::BTreeMap<usize, String>>,
}

impl ObjectManifest {
    pub fn n(&self) -> usize {
        self.k + self.m
    }

    pub fn shard_kind(&self, shard: usize) -> Option<ShardKind> {
        if shard < self.k {
            Some(ShardKind::Data)
        } else if shard < self.n() {
            Some(ShardKind::Parity)
        } else {
            None
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.object_id.trim().is_empty() {
            return Err("object_id 为空".into());
        }
        if !SUPPORTED_CODEC_VERSIONS.contains(&self.codec_version) {
            return Err(format!("不支持的 codec_version: {}", self.codec_version));
        }
        if self.k == 0 || self.m == 0 {
            return Err("k/m 必须为正".into());
        }
        if self.n() > 256 {
            return Err("k+m 不能超过 256（GF256 行空间）".into());
        }
        if self.block_len == 0 {
            return Err("block_len 必须为正".into());
        }
        if self.stripe_count == 0 {
            return Err("stripe_count 必须为正".into());
        }
        let max_len = self.stripe_count * self.k * self.block_len;
        if self.object_len == 0 || self.object_len > max_len {
            return Err(format!("object_len 必须在 1..={max_len}"));
        }
        for (&stripe, row) in &self.block_digests {
            if stripe >= self.stripe_count {
                return Err(format!("block_digests 出现越界 stripe {stripe}"));
            }
            for &shard in row.keys() {
                if shard >= self.n() {
                    return Err(format!("block_digests 出现越界 shard {shard}"));
                }
            }
        }
        Ok(())
    }
}

/// 接收到的原始碎片（原始字节 + 接收来源 + 导入解析信息）。
#[derive(Debug, Clone)]
pub struct ReceivedBlock {
    pub object_id: String,
    pub stripe: usize,
    pub shard: usize,
    pub generation: u64,
    pub source: String,
    pub bytes: Vec<u8>,
    /// 导入时随附的 .digest 内容（若有）。
    pub attached_digest: Option<String>,
    /// 导入文件路径（供审计展示）。
    pub origin_path: String,
}
