//! 导入 manifest（版本化 JSON）与领域类型。

use serde::{Deserialize, Serialize};

pub const MANIFEST_FORMAT_VERSION: u32 = 1;

/// 导入包 manifest.json。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestFile {
    pub format_version: u32,
    pub object_id: String,
    pub object_len: u64,
    /// 对象整体摘要（可选；存在时作为最终信任锚点）。
    pub object_digest: Option<String>,
    pub coding: crate::coding::CodingParams,
    pub stripes: Vec<ManifestStripe>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestStripe {
    pub stripe_index: u32,
    pub shards: Vec<ManifestShard>,
}

/// 单个 shard 的导入声明（同一 shard_index 可出现多次 = 多个内容候选）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestShard {
    pub shard_index: u32,
    pub generation: u64,
    /// 相对于导入目录的碎片文件路径（可能重复指向不同内容）。
    pub file: String,
    /// manifest 声明的长度；None 表示不检查。
    pub declared_len: Option<u64>,
    /// manifest 声明的块摘要（per-block 信任锚点，可选）。
    pub declared_digest: Option<String>,
    /// 接收来源（离线介质/渠道标识）。
    pub source: String,
    /// 保存到原始字节区后回填（导入器内部使用）。
    #[serde(default)]
    pub artifact_digest: Option<String>,
}

/// 候选集合枚举预算（组合数上限），超过即停止并标注预算截断。
pub const SEARCH_BUDGET: u64 = 4096;

/// 导出 manifest.json（恢复产物清单）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportManifest {
    pub format_version: u32,
    pub exported_at: String,
    pub object_id: String,
    pub object_len: u64,
    pub object_digest: String,
    pub object_digest_matches: bool,
    pub coding: crate::coding::CodingParams,
    pub stripes: Vec<ExportStripe>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportStripe {
    pub stripe_index: u32,
    pub status: String,
    pub shards: Vec<ExportShard>,
    pub chosen_reconstruction_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportShard {
    pub shard_index: u32,
    pub origin: String,
    pub fragment_id: Option<i64>,
    pub generation: u64,
    pub digest: String,
}
