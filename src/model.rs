use serde::{Deserialize, Serialize};

pub const MANIFEST_VERSION: &str = "stripe-recovery-bay/v1";

/// 导入清单。每个来源目录一份，描述一个对象的一个 generation 候选。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestV1 {
    pub format: String,
    pub object_id: String,
    pub object_name: String,
    pub generation: i64,
    pub k: i64,
    pub m: i64,
    /// 原始对象字节数（重建后用于裁掉零填充）。
    pub object_length: i64,
    /// 条带大小（字节），缺省为 shard_size 且仅 1 个 stripe。
    #[serde(default)]
    pub stripe_size: Option<i64>,
    /// 重建后完整对象的期望摘要。
    pub object_digest: String,
    #[serde(default)]
    pub shards: Vec<ManifestShardSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestShardSpec {
    pub index: i64,
    pub file: String,
    pub digest: String,
}

impl ManifestV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.format != MANIFEST_VERSION {
            return Err(format!("不支持的清单格式 {}", self.format));
        }
        if self.object_id.trim().is_empty() {
            return Err("object_id 为空".into());
        }
        let k = self.k;
        let m = self.m;
        if k < 1 || m < 1 || k + m > 256 {
            return Err(format!("非法编码参数 k={k} m={m}"));
        }
        if self.generation < 0 {
            return Err("generation 不能为负".into());
        }
        if self.object_length < 0 {
            return Err("object_length 不能为负".into());
        }
        if self.object_digest.trim().is_empty() {
            return Err("object_digest 为空".into());
        }
        let n = (k + m) as usize;
        if self.shards.len() > n {
            return Err(format!("清单列出 {} 块，超过 n={n}", self.shards.len()));
        }
        let mut seen = vec![false; n];
        for s in &self.shards {
            if s.index < 0 || s.index as usize >= n {
                return Err(format!("shard 编号 {} 越界", s.index));
            }
            if seen[s.index as usize] {
                return Err(format!("清单内 shard 编号 {} 重复", s.index));
            }
            seen[s.index as usize] = true;
        }
        Ok(())
    }

    pub fn stripe_count(&self) -> usize {
        let shard_size = self.shard_size() as usize;
        (self.object_length as usize + shard_size - 1) / shard_size
    }

    pub fn shard_size(&self) -> i64 {
        let stripe = self
            .stripe_size
            .unwrap_or(((self.object_length as f64) / (self.k as f64)).ceil() as i64);
        stripe.max(1)
    }

    pub fn expected_shard_length(&self) -> i64 {
        let stripes = self.stripe_count();
        let n = (self.k + self.m) as usize;
        let stripe = self.shard_size() as usize;
        // 每块 shard 跨越所有 stripe，长度 = stripe 数 × ceil(stripe_size/n)
        let per = (stripe + n - 1) / n;
        (stripes * per) as i64
    }
}

/// 从原始对象字节生成条带化 data 分片（循环跨 stripe 切分，零填充）。
pub fn split_data_shards(object: &[u8], k: usize, m: usize, stripe_size: usize) -> Vec<Vec<u8>> {
    let n = k + m;
    let stripe_size = stripe_size.max(1);
    let stripe_count = (object.len() + stripe_size - 1) / stripe_size.max(1);
    let per = (stripe_size + n - 1) / n;
    let shard_len = stripe_count * per;
    let mut shards = vec![vec![0u8; shard_len]; n];
    for (pos, &b) in object.iter().enumerate() {
        let stripe = pos / stripe_size;
        let within = pos % stripe_size;
        let idx = within % n;
        let cell = within / n;
        shards[idx][stripe * per + cell] = b;
    }
    shards
}

/// 重建后把 n 块 shard 合并回对象并裁到 object_length。
pub fn join_data_shards(
    shards: &[Vec<u8>],
    k: usize,
    m: usize,
    stripe_size: usize,
    object_length: usize,
) -> Vec<u8> {
    let n = k + m;
    let stripe_size = stripe_size.max(1);
    let per = (stripe_size + n - 1) / n;
    let stripe_count = shards.first().map(|s| s.len() / per).unwrap_or(0);
    let mut out = vec![0u8; object_length];
    for pos in 0..object_length {
        let stripe = pos / stripe_size;
        let within = pos % stripe_size;
        let idx = within % n;
        let cell = within / n;
        out[pos] = shards[idx][stripe * per + cell];
    }
    out
}
