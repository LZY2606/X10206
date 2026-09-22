//! Manifest 模型与通用工具（摘要、UTC 时间）。

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

pub fn normalize_digest(text: &str) -> Option<String> {
    let mut s = String::new();
    for ch in text.chars() {
        if ch.is_ascii_hexdigit() {
            s.push(ch.to_ascii_lowercase());
        }
        if s.len() == 64 {
            break;
        }
    }
    if s.len() == 64 { Some(s) } else { None }
}

/// ISO8601 UTC（不依赖 chrono）。
pub fn utc_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (y, m, d) = civil_from_days(days + 719468);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 32044;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as i64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (y + if m <= 2 { 1 } else { 0 }, m, d)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    pub object_id: String,
    #[serde(default)]
    pub name: Option<String>,
    pub k: usize,
    pub m: usize,
    pub w: u8,
    pub shard_size: usize,
    pub data_len: usize,
    pub generation: u64,
    #[serde(default)]
    pub object_digest: Option<String>,
    #[serde(default)]
    pub stripes: Vec<StripeSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeSpec {
    pub index: usize,
    #[serde(default)]
    pub generation: Option<u64>,
    #[serde(default)]
    pub data_len: Option<usize>,
    #[serde(default)]
    pub shard_size: Option<usize>,
    /// v2：该 stripe 完整数据（截断到 data_len）的 SHA-256。
    #[serde(default)]
    pub digest: Option<String>,
}

impl Manifest {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1 && self.version != 2 {
            return Err(format!("不支持的 manifest 版本 {}", self.version));
        }
        if self.object_id.trim().is_empty() {
            return Err("object_id 为空".into());
        }
        if self.k == 0 || self.m == 0 {
            return Err("k/m 必须 >= 1".into());
        }
        if !(1..=8).contains(&self.w) {
            return Err("w 必须在 1..=8".into());
        }
        if (self.k + self.m) as u32 > (1u32 << self.w) {
            return Err("k+m 超过有限域大小".into());
        }
        if self.shard_size == 0 {
            return Err("shard_size 必须为正".into());
        }
        let mut seen = vec![false; self.stripes.len().max(1)];
        for s in &self.stripes {
            if s.index >= self.stripes.len() {
                return Err(format!("stripe 编号越界: {}", s.index));
            }
            if seen[s.index] {
                return Err(format!("manifest 中 stripe 编号重复: {}", s.index));
            }
            seen[s.index] = true;
        }
        Ok(())
    }

    pub fn stripe_data_len(&self, idx: usize) -> usize {
        self.stripes
            .iter()
            .find(|s| s.index == idx)
            .and_then(|s| s.data_len)
            .unwrap_or(self.shard_size * self.k)
    }

    pub fn stripe_shard_size(&self, idx: usize) -> usize {
        self.stripes
            .iter()
            .find(|s| s.index == idx)
            .and_then(|s| s.shard_size)
            .unwrap_or(self.shard_size)
    }

    pub fn stripe_generation(&self, idx: usize) -> u64 {
        self.stripes
            .iter()
            .find(|s| s.index == idx)
            .and_then(|s| s.generation)
            .unwrap_or(self.generation)
    }

    pub fn stripe_digest(&self, idx: usize) -> Option<String> {
        self.stripes.iter().find(|s| s.index == idx).and_then(|s| s.digest.clone())
    }
}
