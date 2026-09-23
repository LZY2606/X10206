pub struct Gf256 {
    exp: [u8; 512],
    log: [u8; 256],
}

impl Default for Gf256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Gf256 {
    pub fn new() -> Self {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for i in 0..255 {
            exp[i] = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= 0x11d;
            }
        }
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }
        Self { exp, log }
    }

    pub fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            let i = self.log[a as usize] as usize + self.log[b as usize] as usize;
            self.exp[i]
        }
    }

    pub fn inv(&self, a: u8) -> u8 {
        assert!(a != 0, "zero has no inverse");
        self.exp[255 - self.log[a as usize] as usize]
    }

    pub fn pow(&self, mut x: u8, mut p: u8) -> u8 {
        let mut result = 1u8;
        while p > 0 {
            if p & 1 == 1 {
                result = self.mul(result, x);
            }
            x = self.mul(x, x);
            p >>= 1;
        }
        result
    }

fn solve_in_place(&self, mut matrix: Vec<Vec<u8>>) -> Option<Vec<Vec<u8>>> {
        let n = matrix.len();
        let mut inverse = vec![vec![0u8; n]; n];
        for i in 0..n {
            inverse[i][i] = 1;
        }
        for col in 0..n {
            let pivot = (col..n).find(|&row| matrix[row][col] != 0)?;
            if pivot != col {
                matrix.swap(pivot, col);
                inverse.swap(pivot, col);
            }
            let scale = self.inv(matrix[col][col]);
            for j in 0..n {
                matrix[col][j] = self.mul(matrix[col][j], scale);
                inverse[col][j] = self.mul(inverse[col][j], scale);
            }
            for row in 0..n {
                if row != col && matrix[row][col] != 0 {
                    let factor = matrix[row][col];
                    for j in 0..n {
                        matrix[row][j] ^= self.mul(factor, matrix[col][j]);
                        inverse[row][j] ^= self.mul(factor, inverse[col][j]);
                    }
                }
            }
        }
        Some(inverse)
    }

    pub fn decode(
        &self,
        available: &[(usize, Vec<u8>)],
        total_count: usize,
    ) -> Option<Vec<Vec<u8>>> {
        let k = available.len();
        if k == 0 || total_count < k {
            return None;
        }
        let shard_len = available.first()?.1.len();
        if available.iter().any(|(_, bytes)| bytes.len() != shard_len) {
            return None;
        }
        let mut coding = vec![vec![0u8; k]; k];
        for (row, (shard_index, _)) in available.iter().enumerate() {
            let x = (*shard_index + 1) as u8;
            for col in 0..k {
                coding[row][col] = self.pow(x, col as u8);
            }
        }
        let inverse = self.solve_in_place(coding)?;
        let mut decoded = vec![vec![0u8; shard_len]; total_count];
        for output_index in 0..total_count {
            let x = (output_index + 1) as u8;
            for input_row in 0..k {
                let mut coefficient = 0u8;
                for data_col in 0..k {
                    coefficient ^= self.mul(self.pow(x, data_col as u8), inverse[data_col][input_row]);
                }
                for byte_index in 0..shard_len {
                    decoded[output_index][byte_index] ^=
                        self.mul(coefficient, available[input_row].1[byte_index]);
                }
            }
        }
        Some(decoded)
    }


pub fn pad_data(data: &[u8], k: usize) -> Vec<Vec<u8>> {
    assert!(k > 0);
    let shard_len = data.len().div_ceil(k);
    let mut padded = vec![0u8; shard_len * k];
    padded[..data.len()].copy_from_slice(data);
    if data.len() < padded.len() {
        padded[data.len()] = 0x80;
    }
    (0..k)
        .map(|index| padded[index * shard_len..(index + 1) * shard_len].to_vec())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_and_decodes_with_missing_shards() {
        let gf = Gf256::new();
        let data = pad_data(b"hello recovery bay", 3);
        let all = gf.encode(&data, 2);
        let available = vec![(1, all[1].clone()), (3, all[3].clone()), (4, all[4].clone())];
        let decoded = gf.decode(&available, 5).unwrap();
        assert_eq!(decoded, all);
    }
}
