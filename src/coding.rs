use serde::{Deserialize, Serialize};
use crate::gf::{inverse, multiply};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CodingSpec {
    pub version: String,
    pub data_shards: usize,
    pub parity_shards: usize,
}

impl CodingSpec {
    pub fn total_shards(&self) -> usize {
        self.data_shards + self.parity_shards
    }

    pub fn coding_row(&self, shard_index: usize) -> Option<Vec<u8>> {
        if shard_index >= self.total_shards() {
            return None;
        }
        if shard_index < self.data_shards {
            let mut row = vec![0u8; self.data_shards];
            row[shard_index] = 1;
            Some(row)
        } else {
            let x = (shard_index - self.data_shards + 1) as u8;
            Some((0..self.data_shards()).map(|power| crate::gf::power(x, power)).collect())
        }
    }

    pub fn encode(&self, data: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
        if data.len() != self.data_shards || data.iter().any(|shard| shard.is_empty()) {
            return None;
        }
        let length = data[0].len();
        if data.iter().any(|shard| shard.len() != length) {
            return None;
        }
        let mut result = Vec::with_capacity(self.total_shards());
        for index in 0..self.total_shards() {
            let coefficients = self.coding_row(index)?;
            let mut shard = vec![0u8; length];
            for (position, output) in shard.iter_mut().enumerate() {
                let mut value = 0u8;
                for (data_index, coefficient) in coefficients.iter().enumerate() {
                    value ^= multiply(*coefficient, data[data_index][position]);
                }
                *output = value;
            }
            result.push(shard);
        }
        Some(result)
    }

    pub fn reconstruct(
        &self,
        known: &[(usize, Vec<u8>)],
    ) -> Result<Reconstruction, String> {
        if self.version != "rs-gf256-v1" {
            return Err(format!("unsupported coding version: {}", self.version));
        }
        if known.len() != self.data_shards {
            return Err(format!("need {} independent shards, received {}", self.data_shards, known.len()));
        }
        let length = known.first().map(|(_, bytes)| bytes.len()).unwrap_or(0);
        if length == 0 || known.iter().any(|(_, bytes)| bytes.len() != length) {
            return Err("known shards have inconsistent or empty lengths".to_string());
        }
        if known.iter().any(|(index, _)| *index >= self.total_shards()) {
            return Err("known shard index is outside coding matrix".to_string());
        }
        let mut indices = known.iter().map(|(index, _)| *index).collect::<Vec<_>>();
        indices.sort_unstable();
        indices.dedup();
        if indices.len() != self.data_shards {
            return Err("known shard indices must be distinct".to_string());
        }

        let mut matrix = Vec::with_capacity(self.data_shards);
        for (index, _) in known {
            matrix.push(self.coding_row(*index).ok_or("invalid coding row")?);
        }
        let inverse_matrix = invert(&matrix)?;
        let mut data = vec![vec![0u8; length]; self.data_shards];
        for data_index in 0..self.data_shards {
            for position in 0..length {
                let mut value = 0u8;
                for known_index in 0..self.data_shards {
                    value ^= multiply(
                        inverse_matrix[data_index][known_index],
                        known[known_index].1[position],
                    );
                }
                data[data_index][position] = value;
            }
        }
        let all_shards = self.encode(&data).ok_or("re-encoding failed")?;
        Ok(Reconstruction { data, all_shards })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reconstruction {
    pub data: Vec<Vec<u8>>,
    pub all_shards: Vec<Vec<u8>>,
}

fn invert(matrix: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
    let n = matrix.len();
    if matrix.iter().any(|row| row.len() != n) || n == 0 {
        return Err("matrix is not square".to_string());
    }
    let mut augmented = vec![vec![0u8; n * 2]; n];
    for row in 0..n {
        augmented[row][..n].copy_from_slice(&matrix[row]);
        augmented[row][n + row] = 1;
    }
    for column in 0..n {
        let pivot = (column..n)
            .find(|row| augmented[*row][column] != 0)
            .ok_or_else(|| "coding rows are linearly dependent".to_string())?;
        augmented.swap(column, pivot);
        let pivot_value = augmented[column][column];
        let pivot_inverse = inverse(pivot_value).ok_or("pivot has no inverse")?;
        for value in &mut augmented[column] {
            *value = multiply(*value, pivot_inverse);
        }
        for row in 0..n {
            if row == column {
                continue;
            }
            let factor = augmented[row][column];
            if factor == 0 {
                continue;
            }
            for col in 0..n * 2 {
                let scaled = multiply(factor, augmented[column][col]);
                augmented[row][col] ^= scaled;
            }
        }
    }
    Ok(augmented.into_iter().map(|row| row[n..].to_vec()).collect())
}
