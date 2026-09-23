//! 导入侧版本化清单（`stripe-bay/import/v1`）。
//!
//! 导入物包含：一个 manifest JSON、若干 data/parity shard 原始字节文件，
//! 以及每块可选的摘要。shard 条目中的 `file` 相对清单目录解析。

use serde::{Deserialize, Serialize};

use crate::coding::CodingParams;

pub const IMPORT_MANIFEST_VERSION: &str = "stripe-bay/import/v1";
pub const SCHEMA_VERSION: i64 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DigestRef {
    #[serde(default = "default_alg")]
    pub alg: String,
    pub value: String,
}

fn default_alg() -> String {
    "sha256".into()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CodingSpec {
    /// "gf16"（测试 fixture）或 "gf256"（字节分片）。
    pub field: String,
    pub k: usize,
    pub m: usize,
    pub shard_size: usize,
}

impl CodingSpec {
    pub fn params(&self) -> Result<CodingParams, String> {
        let field_bits = match self.field.as_str() {
            "gf16" => 4,
            "gf256" => 8,
            other => return Err(format!("未知域 {other}")),
        };
        let p = CodingParams { field_bits, k: self.k, m: self.m, shard_size: self.shard_size };
        p.validate()?;
        Ok(p)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShardEntry {
    pub file: String,
    pub stripe: usize,
    pub slot: usize,
    #[serde(default = "default_generation")]
    pub generation: i64,
    /// 接收来源（节点名 / 介质 / 批次通道），人工隔离依据。
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub digest: Option<DigestRef>,
}

fn default_generation() -> i64 {
    1
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImportManifest {
    pub manifest_version: String,
    pub object_id: String,
    #[serde(default)]
    pub object_digest: Option<DigestRef>,
    pub coding: CodingSpec,
    pub stripes: usize,
    #[serde(default)]
    pub shards: Vec<ShardEntry>,
}

impl ImportManifest {
    pub fn parse(json_bytes: &[u8]) -> Result<Self, String> {
        let m: ImportManifest =
            serde_json::from_slice(json_bytes).map_err(|e| format!("清单解析失败: {e}"))?;
        if m.manifest_version != IMPORT_MANIFEST_VERSION {
            return Err(format!(
                "不支持的清单版本 {}（期望 {IMPORT_MANIFEST_VERSION}）",
                m.manifest_version
            ));
        }
        if m.object_id.trim().is_empty() {
            return Err("object_id 不能为空".into());
        }
        let p = m.coding.params()?;
        if m.stripes == 0 {
            return Err("stripes 必须为正".into());
        }
        for s in &m.shards {
            if s.stripe >= m.stripes {
                return Err(format!("shard {} 的 stripe 越界", s.file));
            }
            if s.slot >= p.n() {
                return Err(format!("shard {} 的 slot 越界", s.file));
            }
            if s.generation < 1 {
                return Err(format!("shard {} 的 generation 必须 >=1", s.file));
            }
        }
        Ok(m)
    }
}
