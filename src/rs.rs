//! Reed-Solomon over GF(2^8) with a systematic Vandermonde matrix.
//! Shard indices 0..k-1 are data, k..k+m-1 are parity.

use crate::gf;

#[derive(Clone, Debug)]
pub struct ReedSolomon {
    pub k: usize,
    pub m: usize,
    /// (k+m) x k encoding matrix; row i produces shard i from the k data shards.
    matrix: Vec<Vec<u8>>,
}

impl ReedSolomon {
    pub fn new(k: usize, m: usize) -> Self {
        assert!(k >= 1 && m >= 1 && k + m <= 256);
        let matrix = (0..(k + m))
            .map(|r| (0..k).map(|c| gf::pow(r as u8, c as u32)).collect())
            .collect();
        ReedSolomon { k, m, matrix }
    }

    /// Encode: given k data shards, produce all k+m shards.
    pub fn encode(&self, data: &[Vec<u8>]) -> Vec<Vec<u8>> {
        assert_eq!(data.len(), self.k);
        gf::mat_mul_vec(&self.matrix, data)
    }

    /// Reconstruct the full set of k+m shards from exactly k present shards.
    /// `present` maps shard index -> bytes. Returns all k+m shards in index order.
    pub fn reconstruct(&self, present: &[(usize, Vec<u8>)]) -> Option<Vec<Vec<u8>>> {
        if present.len() != self.k {
            return None;
        }
        let mut present = present.to_vec();
        present.sort_by_key(|(i, _)| *i);
        let sub: Vec<Vec<u8>> = present.iter().map(|(i, _)| self.matrix[*i].clone()).collect();
        let inv = gf::mat_invert(&sub)?;
        let shards: Vec<Vec<u8>> = present.into_iter().map(|(_, b)| b).collect();
        let data = gf::mat_mul_vec(&inv, &shards);
        Some(self.encode(&data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(k: usize, len: usize) -> Vec<Vec<u8>> {
        (0..k)
            .map(|s| (0..len).map(|i| (s * 31 + i * 7 + 3) as u8).collect())
            .collect()
    }

    #[test]
    fn encode_is_systematic() {
        let rs = ReedSolomon::new(4, 2);
        let data = sample(4, 16);
        let all = rs.encode(&data);
        assert_eq!(&all[..4], &data[..]);
    }

    #[test]
    fn reconstruct_any_k() {
        let rs = ReedSolomon::new(4, 3);
        let data = sample(4, 32);
        let all = rs.encode(&data);
        // drop shards 1, 4, 5 (m=3 missing)
        let present: Vec<(usize, Vec<u8>)> = [0usize, 2, 3, 6]
            .into_iter()
            .map(|i| (i, all[i].clone()))
            .collect();
        let rebuilt = rs.reconstruct(&present).unwrap();
        assert_eq!(rebuilt, all);
    }
}
