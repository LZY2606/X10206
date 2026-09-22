//! 领域模型：manifest 结构、摘要工具、公共枚举。

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 支持的版本化编码参数标识。当前仅有一种版本化方案（GF(256) 系统型 RS）。
pub const CODING_VERSION: &str = "rs-gf256-v1";

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    let mut s = String::with_capacity(64);
    for b in out {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestFile {
    /// manifest 格式版本
    pub manifest_version: u32,
    /// 对象全局标识
    pub object_id: String,
    /// 本次导入的 generation；缺省值 1
    #[serde(default = "default_generation")]
    pub generation: u64,
    /// 对象原始长度（字节）
    pub object_len: u64,
    /// 对象整体摘要（对未分块前的原始字节计算）
    pub object_digest: String,
    /// 版本化编码参数
    pub coding: CodingParams,
    /// 每个 stripe 的规格与期望摘要
    pub stripes: Vec<StripeSpec>,
}

fn default_generation() -> u64 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodingParams {
    /// 编码版本标识，例如 rs-gf256-v1
    pub version: String,
    pub data_shards: usize,
    pub parity_shards: usize,
    /// 单个 shard 的字节长度
    pub shard_size: usize,
}

impl CodingParams {
    pub fn n(&self) -> usize {
        self.data_shards + self.parity_shards
    }
    pub fn k(&self) -> usize {
        self.data_shards
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeSpec {
    pub stripe_index: usize,
    /// 该 stripe 的真实数据长度（去除尾部零填充）
    pub data_len: u64,
    /// 对 stripe 数据（零填充前 data_len 字节）计算的摘要
    pub data_digest: String,
    pub fragments: Vec<FragmentSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentSpec {
    pub shard_index: usize,
    /// 期望的 shard 字节摘要
    pub digest: String,
    /// 相对导入目录的碎片文件路径
    pub path: String,
    /// 可选的单碎片 generation 覆盖（模拟部分写 / generation 混杂）
    #[serde(default)]
    pub generation: Option<u64>,
    /// 可选来源标注；缺省取路径首段
    #[serde(default)]
    pub source: Option<String>,
}

/// 碎片健康状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentStatus {
    /// 与期望摘要一致
    Valid,
    /// 文件存在但摘要不符（位翻转等）
    DigestMismatch,
    /// 文件长度与编码 shard_size 不符
    LengthMismatch,
    /// 清单引用但文件缺失
    Missing,
    /// 来源被人工隔离
    Isolated,
}

impl FragmentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            FragmentStatus::Valid => "valid",
            FragmentStatus::DigestMismatch => "digest_mismatch",
            FragmentStatus::LengthMismatch => "length_mismatch",
            FragmentStatus::Missing => "missing",
            FragmentStatus::Isolated => "isolated",
        }
    }
}
