//! SHA-256 digests and versioned erasure-coding parameters.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Versioned coding parameters. Unknown versions must be rejected on import.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scheme", rename_all = "lowercase")]
pub enum CodingParams {
    /// GF(2^8) systematic Cauchy Reed-Solomon: k data + p parity.
    RsGf256V1 {
        version: u32,
        data_shards: u32,
        parity_shards: u32,
    },
}

impl CodingParams {
    pub fn current(k: u32, p: u32) -> Self {
        CodingParams::RsGf256V1 {
            version: 1,
            data_shards: k,
            parity_shards: p,
        }
    }

    pub fn k(&self) -> usize {
        match self {
            CodingParams::RsGf256V1 { data_shards, .. } => *data_shards as usize,
        }
    }

    pub fn p(&self) -> usize {
        match self {
            CodingParams::RsGf256V1 { parity_shards, .. } => *parity_shards as usize,
        }
    }

    pub fn version(&self) -> u32 {
        match self {
            CodingParams::RsGf256V1 { version, .. } => *version,
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        let (k, p) = (self.k(), self.p());
        if k == 0 || p == 0 {
            anyhow::bail!("data_shards and parity_shards must be positive");
        }
        if k + p > 256 {
            anyhow::bail!("data_shards + parity_shards must not exceed 256 on GF(2^8)");
        }
        if self.version() != 1 {
            anyhow::bail!("unsupported coding version {}", self.version());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_loss_patterns() {
        let (k, p) = (3, 2);
        let params = CodingParams::current(k as u32, p as u32);
        params.validate().unwrap();
        let data = vec![vec![1u8, 2, 3, 4, 5], vec![6, 7, 8, 9, 10], vec![11, 12, 13, 14, 15]];
        let parity = crate::gf::encode(&data, p);
        let mut all = data;
        all.extend(parity);

        // Every loss pattern up to p missing shards must decode identically.
        for mask in 0u32..1 << (k + p) {
            let missing_count = mask.count_ones() as usize;
            if missing_count > p || missing_count == 0 {
                continue;
            }
            let known: Vec<(usize, Vec<u8>)> = all
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) == 0)
                .map(|(i, b)| (i, b.clone()))
                .collect();
            if known.len() != k {
                continue;
            }
            let out = crate::gf::decode(&known, k, p, 5).unwrap();
            for i in 0..k + p {
                assert_eq!(out[i], all[i], "mask {mask:b} shard {i}");
            }
        }
    }
}
