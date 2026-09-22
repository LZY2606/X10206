//! Reed-Solomon style codec over GF(2^8).
//!
//! Encoding uses a Vandermonde matrix: shard `i` is the dot product of the
//! row `[1, x, x^2, ...]` (with `x = i` as a field element) and the `k` data
//! shards. Any `k` distinct rows form an invertible matrix, so any `k` of
//! the `k + m` shards suffice to reconstruct everything.

use anyhow::{ensure, Context};

use crate::gf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Codec {
    pub k: usize,
    pub m: usize,
}

impl Codec {
    pub fn new(k: usize, m: usize) -> anyhow::Result<Self> {
        ensure!(k >= 1, "k must be >= 1");
        ensure!(k + m <= 256, "k + m must fit GF(2^8): {k} + {m}");
        Ok(Self { k, m })
    }

    pub fn shard_count(&self) -> usize {
        self.k + self.m
    }

    /// Vandermonde row for shard index `idx`: [1, x, x^2, ..., x^(k-1)].
    fn encoding_row(&self, idx: usize) -> Vec<u8> {
        let x = idx as u8;
        let mut row = Vec::with_capacity(self.k);
        let mut power = 1u8;
        for _ in 0..self.k {
            row.push(power);
            power = gf::mul(power, x);
        }
        row
    }

    /// Encode `k` equally-sized data shards into `k + m` shards.
    pub fn encode(&self, data: &[Vec<u8>]) -> anyhow::Result<Vec<Vec<u8>>> {
        ensure!(data.len() == self.k, "expected {} data shards", self.k);
        let size = data[0].len();
        ensure!(
            data.iter().all(|s| s.len() == size),
            "data shards must have equal length"
        );
        let mut out = vec![vec![0u8; size]; self.shard_count()];
        for idx in 0..self.shard_count() {
            let row = self.encoding_row(idx);
            for (j, data_shard) in data.iter().enumerate() {
                let coef = row[j];
                if coef == 0 {
                    continue;
                }
                for (b, &byte) in out[idx].iter_mut().zip(data_shard.iter()) {
                    *b = gf::add(*b, gf::mul(coef, byte));
                }
            }
        }
        Ok(out)
    }

    /// Reconstruct all `k + m` shards from exactly `k` present shards given
    /// as `(shard_index, bytes)` pairs.
    pub fn reconstruct(&self, present: &[(usize, Vec<u8>)]) -> anyhow::Result<Vec<Vec<u8>>> {
        Ok(self.decode(present)?.1)
    }

    /// Like [`reconstruct`](Self::reconstruct) but also returns the recovered
    /// `k` original data shards.
    pub fn decode(
        &self,
        present: &[(usize, Vec<u8>)],
    ) -> anyhow::Result<(Vec<Vec<u8>>, Vec<Vec<u8>>)> {
        ensure!(
            present.len() == self.k,
            "reconstruction needs exactly {} shards, got {}",
            self.k,
            present.len()
        );
        let size = present[0].1.len();
        ensure!(
            present.iter().all(|(_, s)| s.len() == size),
            "present shards must have equal length"
        );
        let mut indices: Vec<usize> = present.iter().map(|(i, _)| *i).collect();
        indices.sort_unstable();
        indices.dedup();
        ensure!(indices.len() == self.k, "duplicate shard indices supplied");
        ensure!(
            indices.iter().all(|&i| i < self.shard_count()),
            "shard index out of range"
        );

        let sub_matrix: Vec<Vec<u8>> = present
            .iter()
            .map(|(i, _)| self.encoding_row(*i))
            .collect();
        let inverse = gf::matrix_invert(&sub_matrix).context("decode matrix is singular")?;

        // Recover the original data shards column by column, then re-encode.
        let mut data = vec![vec![0u8; size]; self.k];
        for (row_idx, inv_row) in inverse.iter().enumerate() {
            for (coef, (_, shard_bytes)) in inv_row.iter().zip(present.iter()) {
                if *coef == 0 {
                    continue;
                }
                for (b, &byte) in data[row_idx].iter_mut().zip(shard_bytes.iter()) {
                    *b = gf::add(*b, gf::mul(*coef, byte));
                }
            }
        }
        let all = self.encode(&data)?;
        Ok((data, all))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_data(k: usize, size: usize) -> Vec<Vec<u8>> {
        (0..k)
            .map(|j| {
                (0..size)
                    .map(|b| ((j * 31 + b * 7 + 3) % 256) as u8)
                    .collect()
            })
            .collect()
    }

    #[test]
    fn encode_reconstruct_roundtrip_all_present() {
        let codec = Codec::new(3, 2).unwrap();
        let data = sample_data(3, 16);
        let shards = codec.encode(&data).unwrap();
        let present: Vec<(usize, Vec<u8>)> =
            shards.iter().cloned().enumerate().take(3).collect();
        let rebuilt = codec.reconstruct(&present).unwrap();
        assert_eq!(rebuilt, shards);
    }

    #[test]
    fn reconstruct_single_missing() {
        let codec = Codec::new(4, 2).unwrap();
        let data = sample_data(4, 9);
        let shards = codec.encode(&data).unwrap();
        for missing in 0..codec.shard_count() {
            let present: Vec<(usize, Vec<u8>)> = shards
                .iter()
                .cloned()
                .enumerate()
                .filter(|(i, _)| *i != missing)
                .take(codec.k)
                .collect();
            let rebuilt = codec.reconstruct(&present).unwrap();
            assert_eq!(rebuilt, shards, "missing={missing}");
        }
    }

    #[test]
    fn reconstruct_multi_missing_at_erasure_limit() {
        let codec = Codec::new(3, 3).unwrap();
        let data = sample_data(3, 32);
        let shards = codec.encode(&data).unwrap();
        let present: Vec<(usize, Vec<u8>)> = [1usize, 3, 5]
            .iter()
            .map(|&i| (i, shards[i].clone()))
            .collect();
        let rebuilt = codec.reconstruct(&present).unwrap();
        assert_eq!(rebuilt, shards);
    }

    #[test]
    fn reconstruct_requires_exactly_k() {
        let codec = Codec::new(3, 1).unwrap();
        let data = sample_data(3, 4);
        let shards = codec.encode(&data).unwrap();
        let too_few: Vec<(usize, Vec<u8>)> =
            shards.iter().cloned().enumerate().take(2).collect();
        assert!(codec.reconstruct(&too_few).is_err());
    }
}
