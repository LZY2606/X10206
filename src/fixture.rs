//! 小有限域测试/演示夹具：确定性对象字节 + RS 编码后的 stripe/shard。

use crate::digest::sha256_hex;
use crate::model::shard_len;
use crate::rs::RsCodec;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Map, Value};

pub struct Fixture {
    pub object_id: String,
    pub size: u64,
    pub stripe_size: u64,
    pub k: usize,
    pub m: usize,
    pub object_bytes: Vec<u8>,
    /// stripes[stripe][shard_index] = 编码后的原始字节
    pub stripes: Vec<Vec<Vec<u8>>>,
}

impl Fixture {
    pub fn new(
        object_id: &str,
        k: usize,
        m: usize,
        size: u64,
        stripe_size: u64,
    ) -> Result<Self, String> {
        if size == 0 || stripe_size == 0 {
            return Err("size/stripe_size 必须为正".into());
        }
        let object_bytes: Vec<u8> = (0..size)
            .map(|i| ((i as u32).wrapping_mul(31).wrapping_add(7) % 251) as u8)
            .collect();
        let codec = RsCodec::for_version(1, k, m)?;
        let count = crate::model::stripe_count(size, stripe_size);
        let mut stripes = Vec::new();
        for stripe in 0..count {
            let slen = shard_len(size, stripe_size, k, stripe);
            let start = (stripe as u64 * stripe_size) as usize;
            let end = ((stripe as u64 + 1) * stripe_size).min(size) as usize;
            let data_slice = &object_bytes[start..end];
            let mut data_shards = vec![vec![0u8; slen]; k];
            for (j, shard) in data_shards.iter_mut().enumerate() {
                let a = j * slen;
                let b = ((j + 1) * slen).min(data_slice.len());
                if a < b {
                    shard[..b - a].copy_from_slice(&data_slice[a..b]);
                }
            }
            stripes.push(codec.encode(&data_shards)?);
        }
        Ok(Self {
            object_id: object_id.to_string(),
            size,
            stripe_size,
            k,
            m,
            object_bytes,
            stripes,
        })
    }

    pub fn manifest_value(&self, include_digests: bool) -> Value {
        let stripes: Vec<Value> = self
            .stripes
            .iter()
            .enumerate()
            .map(|(stripe, shards)| {
                let mut map = Map::new();
                if include_digests {
                    for (idx, bytes) in shards.iter().enumerate() {
                        map.insert(idx.to_string(), Value::String(sha256_hex(bytes)));
                    }
                }
                json!({"index": stripe as u32, "shard_digests": map})
            })
            .collect();
        json!({
            "object_id": self.object_id,
            "size": self.size,
            "stripe_size": self.stripe_size,
            "encoding": {"version": 1, "data_shards": self.k, "parity_shards": self.m},
            "stripes": stripes,
        })
    }

    pub fn manifest_json(&self) -> String {
        self.manifest_value(true).to_string()
    }

    pub fn shard_value(
        &self,
        stripe: u32,
        shard_index: usize,
        generation: u64,
        source: &str,
    ) -> Value {
        self.shard_value_with_bytes(
            stripe,
            shard_index,
            self.stripes[stripe as usize][shard_index].clone(),
            None,
            generation,
            source,
        )
    }

    pub fn shard_value_with_bytes(
        &self,
        stripe: u32,
        shard_index: usize,
        bytes: Vec<u8>,
        claimed_digest: Option<String>,
        generation: u64,
        source: &str,
    ) -> Value {
        json!({
            "object_id": self.object_id,
            "stripe": stripe,
            "shard_index": shard_index as u32,
            "generation": generation,
            "source": source,
            "digest": claimed_digest.unwrap_or_else(|| sha256_hex(&bytes)),
            "data_b64": STANDARD.encode(bytes),
        })
    }

    pub fn shard_json(
        &self,
        stripe: u32,
        shard_index: usize,
        generation: u64,
        source: &str,
    ) -> String {
        self.shard_value(stripe, shard_index, generation, source)
            .to_string()
    }
}
