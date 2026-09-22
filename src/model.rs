//! 领域模型与 manifest/sidecar 序列化格式（encoding-params v1）。

use serde::{Deserialize, Serialize};

/// 版本化编码参数。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncodingParamsV1 {
    pub version: String,
    /// 数据 shard 数 k
    pub k: usize,
    /// 校验 shard 数 m
    pub m: usize,
    /// 有限域位数：4 或 8
    pub field_bits: u32,
}

impl EncodingParamsV1 {
    pub fn v1(k: usize, m: usize, field_bits: u32) -> Self {
        Self {
            version: "encoding-params/v1".to_string(),
            k,
            m,
            field_bits,
        }
    }

    pub fn n(&self) -> usize {
        self.k + self.m
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectManifestV1 {
    pub version: String,
    pub object_id: String,
    pub params: EncodingParamsV1,
    pub stripe_len: usize,
    pub stripe_count: usize,
    /// stripe 序号 -> 重建后的 stripe 摘要（sha256 of all shards concatenated）
    #[serde(default)]
    pub stripe_digests: std::collections::BTreeMap<usize, String>,
    /// 可选：对象整体摘要（各 stripe digest 按序拼接后 sha256）
    #[serde(default)]
    pub object_digest: Option<String>,
}

/// `*.sidecar.json`：单个 shard 的接收记录。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardSidecarV1 {
    pub version: String,
    pub object_id: String,
    pub stripe_idx: usize,
    pub shard_idx: usize,
    /// 逻辑生成号，越大越新（部分写会造成同 stripe 内 generation 混杂）
    #[serde(default)]
    pub generation: u64,
    /// 接收来源（节点/通道/介质），可被人工隔离
    #[serde(default)]
    pub source: String,
    /// 随碎片提供的每块摘要；缺省表示未提供（只能靠码词校验）
    #[serde(default)]
    pub sha256: Option<String>,
}

impl ShardSidecarV1 {
    pub fn new(
        object_id: impl Into<String>,
        stripe_idx: usize,
        shard_idx: usize,
        generation: u64,
        source: impl Into<String>,
        sha256: Option<String>,
    ) -> Self {
        Self {
            version: "shard-sidecar/v1".into(),
            object_id: object_id.into(),
            stripe_idx,
            shard_idx,
            generation,
            source: source.into(),
            sha256,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ShardHealth {
    /// 摘要完整、长度匹配
    Verified = 0,
    /// 未提供摘要但长度匹配（只能参与码词校验）
    Unverified = 1,
    /// 摘要不符（位翻转等损坏证据）
    DigestMismatch = 2,
    /// 与 manifest 声明长度不符
    LengthMismatch = 3,
}

impl ShardHealth {
    pub fn code(v: i64) -> Self {
        match v {
            0 => ShardHealth::Verified,
            1 => ShardHealth::Unverified,
            2 => ShardHealth::DigestMismatch,
            _ => ShardHealth::LengthMismatch,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ShardHealth::Verified => "摘要完整",
            ShardHealth::Unverified => "无摘要",
            ShardHealth::DigestMismatch => "摘要不符",
            ShardHealth::LengthMismatch => "长度不符",
        }
    }

    pub fn cls(self) -> &'static str {
        match self {
            ShardHealth::Verified => "ok",
            ShardHealth::Unverified => "warn",
            ShardHealth::DigestMismatch | ShardHealth::LengthMismatch => "bad",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StripeState {
    /// 无法重建
    Unrecoverable,
    /// 枚举到可行重建
    Solved,
    /// 已按 stripe 原子提交
    Committed,
    /// 已提交但落盘结果丢失/损坏
    Broken,
}

impl StripeState {
    pub fn label(self) -> &'static str {
        match self {
            StripeState::Unrecoverable => "不可恢复",
            StripeState::Solved => "可恢复",
            StripeState::Committed => "已提交",
            StripeState::Broken => "提交损坏",
        }
    }
}
