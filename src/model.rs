//! 领域模型：manifest、对象/stripe 布局与收到的原始碎片。

use crate::codec::CodingParams;
use serde::{Deserialize, Serialize};

/// manifest 中单个 shard 的期望信息（可选，摘要缺失时该 shard 无权威校验）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SlotSpec {
    /// 该 shard 的期望长度；None 表示 manifest 未声明。
    #[serde(default)]
    pub length: Option<usize>,
    /// 该 shard 的期望 sha256 摘要（十六进制）；None 表示 manifest 未声明。
    #[serde(default)]
    pub digest: Option<String>,
    /// 该 shard 的写入代际；None 表示 manifest 未声明。
    #[serde(default)]
    pub generation: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeSpec {
    /// stripe 内每个 shard（编号即数组下标 0..k+m-1）的期望信息。
    pub slots: Vec<SlotSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub object_id: String,
    pub object_generation: u64,
    /// 权威编码版本与参数。
    pub k: usize,
    pub m: usize,
    pub codec_version: u32,
    /// 每个 stripe 的 shard 长度（固定 stripe 大小）。
    pub stripe_length: usize,
    pub stripes: Vec<StripeSpec>,
    /// 完整对象逻辑字节（拼接各 stripe 的数据 shard、去除最后一块填充）的摘要。
    #[serde(default)]
    pub object_digest: Option<String>,
    /// 对象逻辑长度，用于确定最后一个 stripe 的有效尾部。
    #[serde(default)]
    pub object_length: Option<usize>,
    /// manifest 自身代际（部分写检测）。
    #[serde(default = "default_manifest_generation")]
    pub manifest_generation: u64,
}

fn default_manifest_generation() -> u64 {
    1
}

impl Manifest {
    pub fn params(&self) -> CodingParams {
        CodingParams::new(self.k, self.m, self.codec_version)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.object_id.trim().is_empty() {
            return Err("object_id 为空".into());
        }
        let p = CodingParams::new(self.k, self.m, self.codec_version);
        for (si, stripe) in self.stripes.iter().enumerate() {
            if stripe.slots.len() != p.n() {
                return Err(format!(
                    "stripe {si} 的 shard 数 {} 与 k+m={} 不符",
                    stripe.slots.len(),
                    p.n()
                ));
            }
            for (slot, spec) in stripe.slots.iter().enumerate() {
                if let Some(len) = spec.length {
                    if len != self.stripe_length {
                        return Err(format!(
                            "stripe {si} shard {slot} 长度 {len} 与 stripe_length {} 不符",
                            self.stripe_length
                        ));
                    }
                }
            }
        }
        if let Some(obj_len) = self.object_length {
            let max = self.stripes.len() * self.k * self.stripe_length;
            if obj_len > max {
                return Err(format!(
                    "object_length {obj_len} 超过容量 {max}（{} stripe × k{} × {}）",
                    self.stripes.len(),
                    self.k,
                    self.stripe_length
                ));
            }
        }
        Ok(())
    }
}

/// 一个“接收到的原始碎片”：字节与来源都原样保存，不覆盖、不去重丢弃。
#[derive(Debug, Clone)]
pub struct IncomingFragment {
    pub stripe_index: usize,
    pub shard: usize,
    pub source: String,
    pub bytes: Vec<u8>,
    /// 来源随附的自报代际；None 表示来源未声明。
    pub source_generation: Option<u64>,
    /// 来源随附的自报摘要；None 表示来源未提供。
    pub source_digest: Option<String>,
}

/// 计算 sha256 十六进制摘要。
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

#[derive(Debug, thiserror::Error)]
pub enum BayError {
    #[error("存储错误: {0}")]
    Store(String),
    #[error("导入错误: {0}")]
    Import(String),
    #[error("编码错误: {0}")]
    Coding(String),
    #[error("对象 {object_id} 尚未导入 manifest")]
    NoManifest { object_id: String },
    #[error("I/O 模拟故障: {0}")]
    IoFault(String),
}

impl From<rusqlite::Error> for BayError {
    fn from(e: rusqlite::Error) -> Self {
        BayError::Store(e.to_string())
    }
}

impl From<std::io::Error> for BayError {
    fn from(e: std::io::Error) -> Self {
        BayError::Store(e.to_string())
    }
}

pub type BayResult<T> = Result<T, BayError>;
