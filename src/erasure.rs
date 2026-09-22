use crate::gf::{invert_matrix, mul};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodingParams {
    pub k: usize,
    pub n: usize,
}

impl EncodingParams {
    pub fn validate(&self) -> Result<(), String> {
        if self.k == 0 || self.n < self.k || self.n > 256 {
            return Err(format!("invalid erasure params {}/{}", self.k, self.n));
        }
        if self.n < 256 && self.n - self.k > 255 - self.k {
            return Err("cauchy row coordinates overlap data coordinates".into());
        }
        Ok(())
    }
}

pub fn cauchy_row(parity_index: usize, k: usize, byte_index: usize) -> u8 {
    let x = parity_index as u16 + k as u16;
    let y = byte_index as u16;
    let denominator = (x ^ y) as u8;
    crate::gf::inv(denominator)
        .expect("coordinates in a Cauchy matrix must have a nonzero denominator")
}

pub fn parity_byte(params: EncodingParams, parity_index: usize, data: &[Vec<u8>], offset: usize) -> u8 {
    (0..params.k).fold(0u8, |acc, data_index| {
        acc ^ mul(cauchy_row(parity_index, params.k, data_index), data[data_index][offset])
    })
}

pub fn encode(params: EncodingParams, data: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
    params.validate()?;
    if data.len() != params.k {
        return Err(format!("expected {} data shards", params.k));
    }
    let stripe_size = data.first().map(|shard| shard.len()).unwrap_or(0);
    if stripe_size == 0 || data.iter().any(|shard| shard.len() != stripe_size) {
        return Err("all data shards must be nonempty and equal length".into());
    }
    let mut shards = data.to_vec();
    for parity_index in 0..params.n - params.k {
        let parity: Vec<u8> = (0..stripe_size)
            .map(|offset| parity_byte(params, parity_index, data, offset))
            .collect();
        shards.push(parity);
    }
    Ok(shards)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvailableShard {
    pub index: usize,
    pub bytes: Vec<u8>,
}

pub fn reconstruct(
    params: EncodingParams,
    available: &[AvailableShard],
) -> Result<Vec<Vec<u8>>, String> {
    params.validate()?;
    if available.len() != params.k {
        return Err(format!("recovery threshold is exactly {}, got {}", params.k, available.len()));
    }
    let mut indices: Vec<usize> = available.iter().map(|shard| shard.index).collect();
    if indices.iter().any(|index| *index >= params.n) {
        return Err("shard index outside manifest range".into());
    }
    indices.sort_unstable();
    indices.dedup();
    if indices.len() != params.k {
        return Err("duplicate shard indices cannot participate in one equation set".into());
    }
    let stripe_size = available[0].bytes.len();
    if stripe_size == 0 || available.iter().any(|shard| shard.bytes.len() != stripe_size) {
        return Err("participating shards must have equal nonzero length".into());
    }

    let mut ordered = available.to_vec();
    ordered.sort_by_key(|shard| shard.index);
    let matrix: Vec<Vec<u8>> = ordered
        .iter()
        .map(|shard| {
            if shard.index < params.k {
                (0..params.k)
                    .map(|column| u8::from(column == shard.index))
                    .collect()
            } else {
                let parity = shard.index - params.k;
                (0..params.k)
                    .map(|column| cauchy_row(parity, params.k, column))
                    .collect()
            }
        })
        .collect();
    let inverse = invert_matrix(&matrix).ok_or("selected equation set is singular")?;
    let mut data = vec![vec![0u8; stripe_size]; params.k];
    for row in 0..params.k {
        for equation in 0..params.k {
            for offset in 0..stripe_size {
                data[row][offset] ^= mul(inverse[row][equation], ordered[equation].bytes[offset]);
            }
        }
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconstructs_single_and_multiple_missing_blocks() {
        let params = EncodingParams { k: 2, n: 4 };
        let data = vec![vec![1, 9, 2], vec![8, 3, 7]];
        let all = encode(params, &data).unwrap();
        let one_missing = vec![
            AvailableShard { index: 1, bytes: all[1].clone() },
            AvailableShard { index: 2, bytes: all[2].clone() },
        ];
        assert_eq!(reconstruct(params, &one_missing).unwrap(), data);
        let two_missing = vec![
            AvailableShard { index: 2, bytes: all[2].clone() },
            AvailableShard { index: 3, bytes: all[3].clone() },
        ];
        assert_eq!(reconstruct(params, &two_missing).unwrap(), data);
    }
}
