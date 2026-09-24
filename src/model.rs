//! 导入 manifest 的版本化领域模型。

use serde::{Deserialize, Serialize};

pub const MANIFEST_KIND: &str = "stripe-recovery-manifest";
pub const MANIFEST_VERSION: &str = "1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodecParams {
    /// 编解码方案标识，例如 `rs-v1`。
    pub codec: String,
    pub k: usize,
    pub m: usize,
    pub shard_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StripeSpec {
    pub stripe: u64,
    /// 长度 k+m，元素为该 stripe 各 shard 的期望摘要（小写 hex）。
    pub digests: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenPlan {
    pub generation: u64,
    pub stripe_digests: Vec<StripeSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub manifest_kind: String,
    pub manifest_version: String,
    pub object_id: String,
    pub object_size: u64,
    pub object_digest: String,
    pub codec: CodecParams,
    pub current_generation: u64,
    pub generations: Vec<GenPlan>,
}

impl Manifest {
    pub fn plan(&self, generation: u64) -> Option<&GenPlan> {
        self.generations.iter().find(|g| g.generation == generation)
    }

    pub fn current_plan(&self) -> Option<&GenPlan> {
        self.plan(self.current_generation)
    }

    pub fn stripe_spec(&self, generation: u64, stripe: u64) -> Option<&StripeSpec> {
        self.plan(generation)?
            .stripe_digests
            .iter()
            .find(|s| s.stripe == stripe)
    }

    pub fn expected_digest(&self, generation: u64, stripe: u64, index: usize) -> Option<&str> {
        self.stripe_spec(generation, stripe)?
            .digests
            .get(index)
            .map(String::as_str)
    }

    pub fn stripe_count(&self) -> usize {
        self.current_plan().map(|p| p.stripe_digests.len()).unwrap_or(0)
    }
}
