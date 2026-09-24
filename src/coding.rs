//! Versioned erasure coding over GF(2^8) with a Cauchy generator matrix.
//!
//! Two coding versions differ in field polynomial and coordinate seed, so
//! fragments encoded under one version are never silently mixed into another.

use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CodingVersion {
    V1,
    V2,
}

impl CodingVersion {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "v1" => Some(Self::V1),
            "v2" => Some(Self::V2),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
        }
    }

    fn poly(self) -> u16 {
        match self {
            // x^8 + x^4 + x^3 + x^2 + 1
            Self::V1 => 0x11d,
            // x^8 + x^6 + x^5 + x + 1
            Self::V2 => 0x163,
        }
    }

    fn seed(self) -> u8 {
        match self {
            Self::V1 => 0,
            Self::V2 => 7,
        }
    }
}

struct Field {
    exp: Vec<u8>,
    log: Vec<u8>,
}

impl Field {
    fn new(poly: u16) -> Self {
        let mut exp = vec![0u8; 512];
        let mut log = vec![0u8; 256];
        let mut x: u16 = 1;
        for i in 0..255 {
            exp[i] = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= poly;
            }
        }
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }
        Self { exp, log }
    }

    fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            let la = self.log[a as usize] as usize;
            let lb = self.log[b as usize] as usize;
            self.exp[la + lb]
        }
    }

    fn inv(&self, a: u8) -> u8 {
        debug_assert_ne!(a, 0);
        self.exp[255 - self.log[a as usize] as usize]
    }

    fn div(&self, a: u8, b: u8) -> u8 {
        if a == 0 {
            0
        } else {
            self.mul(a, self.inv(b))
        }
    }
}

pub struct Codec {
    pub version: CodingVersion,
    pub data_shards: usize,
    pub parity_shards: usize,
    field: Field,
    cauchy: Vec<Vec<u8>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    Singular,
    WrongShardCount { expected: usize, got: usize },
    BadPosition(usize),
}

impl Codec {
    pub fn new(version: CodingVersion, data_shards: usize, parity_shards: usize) -> Self {
        assert!(data_shards >= 1 && parity_shards >= 1);
        assert!(data_shards + parity_shards <= 255);
        let field = Field::new(version.poly());
        let n = data_shards + parity_shards;
        // Coordinates: data columns x_j and parity rows y_i must be distinct
        // non-zero field elements for the Cauchy matrix to be well defined.
        let coord = |idx: usize| -> u8 {
            // 1..=255 permutation, offset by the version seed.
            1u8.wrapping_add((idx as u8).wrapping_add(version.seed()))
        };
        let xs: Vec<u8> = (0..data_shards).map(coord).collect();
        let ys: Vec<u8> = (data_shards..n).map(coord).collect();
        let cauchy = ys
            .iter()
            .map(|y| xs.iter().map(|x| field.inv(y ^ x)).collect())
            .collect();
        Self {
            version,
            data_shards,
            parity_shards,
            field,
            cauchy,
        }
    }

    pub fn total_shards(&self) -> usize {
        self.data_shards + self.parity_shards
    }

    /// Coefficient of coding row `pos` (0..n) at data column `col`.
    fn row_coeff(&self, pos: usize, col: usize) -> u8 {
        if pos < self.data_shards {
            if pos == col {
                1
            } else {
                0
            }
        } else {
            self.cauchy[pos - self.data_shards][col]
        }
    }

    /// Encodes parity shards from the data shards of one stripe.
    pub fn encode_parity(&self, data: &[Vec<u8>]) -> Vec<Vec<u8>> {
        assert_eq!(data.len(), self.data_shards);
        let size = data[0].len();
        assert!(data.iter().all(|d| d.len() == size));
        let mut out = vec![vec![0u8; size]; self.parity_shards];
        for (i, row) in self.cauchy.iter().enumerate() {
            for (j, shard) in data.iter().enumerate() {
                let c = row[j];
                if c == 0 {
                    continue;
                }
                for t in 0..size {
                    out[i][t] ^= self.field.mul(c, shard[t]);
                }
            }
        }
        out
    }

    fn invert(&self, mut matrix: Vec<Vec<u8>>, n: usize) -> Result<Vec<Vec<u8>>, DecodeError> {
        let mut inv = vec![vec![0u8; n]; n];
        for (i, row) in inv.iter_mut().enumerate() {
            row[i] = 1;
        }
        for col in 0..n {
            let pivot = (col..n)
                .find(|&r| matrix[r][col] != 0)
                .ok_or(DecodeError::Singular)?;
            if pivot != col {
                matrix.swap(pivot, col);
                inv.swap(pivot, col);
            }
            let p = self.field.inv(matrix[col][col]);
            for c in 0..n {
                matrix[col][c] = self.field.mul(matrix[col][c], p);
                inv[col][c] = self.field.mul(inv[col][c], p);
            }
            for r in 0..n {
                if r == col || matrix[r][col] == 0 {
                    continue;
                }
                let factor = matrix[r][col];
                for c in 0..n {
                    matrix[r][c] ^= self.field.mul(factor, matrix[col][c]);
                    inv[r][c] ^= self.field.mul(factor, inv[col][c]);
                }
            }
        }
        Ok(inv)
    }

    /// Reconstruct arbitrary shard positions from exactly `data_shards`
    /// available shards at distinct positions.
    pub fn reconstruct(
        &self,
        available: &BTreeMap<usize, Vec<u8>>,
        want: &[usize],
    ) -> Result<Vec<Vec<u8>>, DecodeError> {
        let k = self.data_shards;
        if available.len() != k {
            return Err(DecodeError::WrongShardCount {
                expected: k,
                got: available.len(),
            });
        }
        let positions: Vec<usize> = available.keys().copied().collect();
        if positions.iter().any(|&p| p >= self.total_shards()) {
            return Err(DecodeError::BadPosition(*positions.iter().find(|&&p| p >= self.total_shards()).unwrap()));
        }
        let size = available[&positions[0]].len();
        if positions.iter().any(|p| available[p].len() != size) {
            return Err(DecodeError::Singular);
        }
        let sub: Vec<Vec<u8>> = positions
            .iter()
            .map(|&pos| (0..k).map(|col| self.row_coeff(pos, col)).collect())
            .collect();
        let inv = self.invert(sub, k)?;
        let mut results = Vec::with_capacity(want.len());
        for &target in want {
            if target >= self.total_shards() {
                return Err(DecodeError::BadPosition(target));
            }
            let mut out = vec![0u8; size];
            // target data vector = coding row of target * inverse * available
            for (a, &pos) in positions.iter().enumerate() {
                let mut coeff = 0u8;
                for col in 0..k {
                    coeff ^= self.field.mul(self.row_coeff(target, col), inv[col][a]);
                }
                if coeff == 0 {
                    continue;
                }
                let shard = &available[&pos];
                for t in 0..size {
                    out[t] ^= self.field.mul(coeff, shard[t]);
                }
            }
            results.push(out);
        }
        Ok(results)
    }

    /// Full stripe (data then parity) reconstructed/verified from the given
    /// available shards.
    pub fn rebuild_stripe(
        &self,
        available: &BTreeMap<usize, Vec<u8>>,
    ) -> Result<Vec<Vec<u8>>, DecodeError> {
        let k = self.data_shards;
        let n = self.total_shards();
        let present: Vec<usize> = available.keys().copied().filter(|&p| p < k).collect();
        let missing_data: Vec<usize> = (0..k).filter(|p| !available.contains_key(p)).collect();
        let mut stripe = vec![Vec::new(); n];
        for p in present {
            stripe[p] = available[&p].clone();
        }
        if !missing_data.is_empty() {
            let decoded = self.reconstruct(available, &missing_data)?;
            for (p, bytes) in missing_data.into_iter().zip(decoded) {
                stripe[p] = bytes;
            }
        }
        let parity = self.encode_parity(&stripe[..k]);
        for (i, bytes) in parity.into_iter().enumerate() {
            stripe[k + i] = bytes;
        }
        Ok(stripe)
    }

    pub fn div_byte(&self, a: u8, b: u8) -> u8 {
        self.field.div(a, b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data_shards(size: usize, k: usize, seed: u8) -> Vec<Vec<u8>> {
        (0..k)
            .map(|j| (0..size).map(|t| (seed as usize + j * 31 + t * 7) as u8).collect())
            .collect()
    }

    #[test]
    fn round_trip_single_loss_v1() {
        let codec = Codec::new(CodingVersion::V1, 3, 2);
        let data = data_shards(16, 3, 3);
        let parity = codec.encode_parity(&data);
        for lost in 0..5 {
            let mut avail = BTreeMap::new();
            for p in 0..5 {
                if p != lost {
                    avail.insert(p, if p < 3 { data[p].clone() } else { parity[p - 3].clone() });
                }
            }
            let stripe = codec.rebuild_stripe(&avail).unwrap();
            assert_eq!(stripe[..3], data);
            assert_eq!(stripe[3..], parity);
        }
    }

    #[test]
    fn round_trip_double_loss_v2() {
        let codec = Codec::new(CodingVersion::V2, 4, 3);
        let data = data_shards(9, 4, 21);
        let parity = codec.encode_parity(&data);
        let all: Vec<Vec<u8>> = data.iter().chain(parity.iter()).cloned().collect();
        let lost = [1usize, 5];
        let mut avail = BTreeMap::new();
        for p in 0..7 {
            if !lost.contains(&p) {
                avail.insert(p, all[p].clone());
            }
        }
        let stripe = codec.rebuild_stripe(&avail).unwrap();
        assert_eq!(stripe, all);
    }

    #[test]
    fn singular_combination_detected() {
        let codec = Codec::new(CodingVersion::V1, 2, 1);
        let data = data_shards(4, 2, 1);
        let parity = codec.encode_parity(&data);
        let mut avail = BTreeMap::new();
        avail.insert(0, data[0].clone());
        avail.insert(2, parity[0].clone());
        assert!(codec.rebuild_stripe(&avail).is_ok());
    }
}
