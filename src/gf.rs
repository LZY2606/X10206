const POLY: u16 = 0x11d;

pub struct Gf256 {
    exp: [u8; 512],
    log: [u8; 256],
}

impl Gf256 {
    pub fn new() -> Self {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut value = 1u8;
        for i in 0..255 {
            exp[i] = value;
            log[value as usize] = i as u8;
            let next = (value as u16) << 1;
            value = if next & 0x100 != 0 {
                (next ^ POLY) as u8
            } else {
                next as u8
            };
        }
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }
        Self { exp, log }
    }

    pub fn mul(&self, left: u8, right: u8) -> u8 {
        if left == 0 || right == 0 {
            return 0;
        }
        let exponent = self.log[left as usize] as usize + self.log[right as usize] as usize;
        self.exp[exponent]
    }

    pub fn inv(&self, value: u8) -> u8 {
        assert!(value != 0, "zero has no inverse");
        self.exp[255 - self.log[value as usize] as usize]
    }

    pub fn cauchy(&self, row: usize, column: usize, data_count: usize) -> u8 {
        let row_label = (data_count + row) as u8;
        let column_label = column as u8;
        self.inv(row_label ^ column_label)
    }

    pub fn parity(&self, data_shards: &[Vec<u8>], parity_count: usize) -> Vec<Vec<u8>> {
        let data_count = data_shards.len();
        let shard_len = data_shards.first().map_or(0, |shard| shard.len());
        let mut parity = vec![vec![0u8; shard_len]; parity_count];
        for parity_index in 0..parity_count {
            for data_index in 0..data_count {
                let coefficient = self.cauchy(parity_index, data_index, data_count);
                for offset in 0..shard_len {
                    parity[parity_index][offset] ^=
                        self.mul(coefficient, data_shards[data_index][offset]);
                }
            }
        }
        parity
    }

    pub fn reconstruct(
        &self,
        data_count: usize,
        available: &[(usize, Vec<u8>)],
        missing: &[usize],
    ) -> Result<Vec<Vec<u8>>, String> {
        if available.len() != data_count {
            return Err(format!(
                "需要恰好 {data_count} 个参与 shard，实际为 {}",
                available.len()
            ));
        }
        let shard_len = available
            .first()
            .map(|(_, bytes)| bytes.len())
            .ok_or_else(|| "空参与集合".to_string())?;
        if available.iter().any(|(_, bytes)| bytes.len() != shard_len) {
            return Err("参与 shard 长度不一致".to_string());
        }
        let mut matrix = vec![vec![0u8; data_count * 2]; data_count];
        for (row, (shard_index, _)) in available.iter().enumerate() {
            if *shard_index < data_count {
                matrix[row][*shard_index] = 1;
            } else {
                let parity_index = shard_index - data_count;
                for column in 0..data_count {
                    matrix[row][column] = self.cauchy(parity_index, column, data_count);
                }
            }
            matrix[row][data_count + row] = 1;
        }
        let inverse = invert(self, &matrix)?;
        let mut rebuilt = Vec::new();
        for missing_index in missing {
            let mut output = vec![0u8; shard_len];
            for participant in 0..data_count {
                let coefficient = inverse[*missing_index][data_count + participant];
                let bytes = &available[participant].1;
                if coefficient != 0 {
                    for offset in 0..shard_len {
                        output[offset] ^= self.mul(coefficient, bytes[offset]);
                    }
                }
            }
            rebuilt.push(output);
        }
        Ok(rebuilt)
    }
}

impl Default for Gf256 {
    fn default() -> Self {
        Self::new()
    }
}

fn invert(gf: &Gf256, matrix: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
    let size = matrix.len();
    let mut augmented = matrix.to_vec();
    for pivot in 0..size {
        let swap = (pivot..size)
            .find(|row| augmented[*row][pivot] != 0)
            .ok_or_else(|| "编码矩阵不可逆".to_string())?;
        augmented.swap(pivot, swap);
        let pivot_value = augmented[pivot][pivot];
        if pivot_value != 1 {
            let multiplier = gf.inv(pivot_value);
            for value in augmented[pivot].iter_mut() {
                *value = gf.mul(*value, multiplier);
            }
        }
        for row in 0..size {
            if row == pivot || augmented[row][pivot] == 0 {
                continue;
            }
            let multiplier = augmented[row][pivot];
            for column in 0..augmented[row].len() {
                augmented[row][column] ^= gf.mul(multiplier, augmented[pivot][column]);
            }
        }
    }
    Ok(augmented)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconstructs_data_and_parity() {
        let gf = Gf256::new();
        let data = vec![vec![1, 9, 3], vec![4, 5, 6], vec![7, 8, 0]];
        let parity = gf.parity(&data, 2);
        let available = vec![
            (1, data[1].clone()),
            (3, parity[0].clone()),
            (4, parity[1].clone()),
        ];
        let rebuilt = gf.reconstruct(3, &available, &[0, 2]).unwrap();
        assert_eq!(rebuilt[0], data[0]);
        assert_eq!(rebuilt[1], data[2]);
    }
}
