use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Params {
    pub data_shards: usize,
    pub parity_shards: usize,
    pub generation: i64,
    pub stripe_size: usize,
}

impl Params {
    pub fn total(&self) -> usize {
        self.data_shards + self.parity_shards
    }
}

pub fn build_tables() -> ([u8; 256], [u8; 256]) {
    let mut exp = [0u8; 256];
    let mut log = [0u8; 256];
    let mut value: u16 = 1;
    for i in 0..255 {
        exp[i] = value as u8;
        log[value as usize] = i as u8;
        value <<= 1;
        if value & 0x100 != 0 {
            value ^= 0x11d;
        }
    }
    (exp, log)
}

pub fn gf_mul(a: u8, b: u8, exp: &[u8; 256], log: &[u8; 256]) -> u8 {
    if a == 0 || b == 0 {
        0
    } else {
        exp[((log[a as usize] as usize + log[b as usize] as usize) % 255) as usize]
    }
}

fn gf_inv(a: u8, exp: &[u8; 256], log: &[u8; 256]) -> u8 {
    assert_ne!(a, 0);
    exp[(255 - log[a as usize] as usize) % 255]
}

pub fn row_coefficient(row: usize, col: usize, k: usize) -> u8 {
    let (exp, _) = build_tables();
    if row < k {
        u8::from(row == col)
    } else {
        let parity_row = row - k + 1;
        exp[(parity_row * col) % 255]
    }
}

pub fn encode(data: &[Vec<u8>], parity_shards: usize, stripe_size: usize) -> Vec<Vec<u8>> {
    let (exp, log) = build_tables();
    let k = data.len();
    let mut parity = vec![vec![0u8; stripe_size]; parity_shards];
    for p in 0..parity_shards {
        for (col, shard) in data.iter().enumerate() {
            let coefficient = row_coefficient(k + p, col, k);
            for (output, value) in parity[p].iter_mut().zip(shard) {
                *output ^= gf_mul(coefficient, *value, &exp, &log);
            }
        }
    }
    parity
}

pub fn reconstruct(
    available: &BTreeMap<usize, Vec<u8>>,
    missing: &[usize],
    params: Params,
) -> Option<BTreeMap<usize, Vec<u8>>> {
    let k = params.data_shards;
    let n = params.total();
    if available.len() < k || available.keys().any(|index| *index >= n) {
        return None;
    }
    let chosen: Vec<usize> = available.keys().copied().take(k).collect();
    let (exp, log) = build_tables();
    let matrix: Vec<Vec<u8>> = chosen
        .iter()
        .map(|row| (0..k).map(|col| row_coefficient(*row, col, k)).collect())
        .collect();
    let inverse = invert_matrix(&matrix, &exp, &log)?;
    let mut data = vec![vec![0u8; params.stripe_size]; k];
    for col in 0..k {
        for (r, shard_index) in chosen.iter().enumerate() {
            let coefficient = inverse[col][r];
            let shard = &available[shard_index];
            for (output, value) in data[col].iter_mut().zip(shard) {
                *output ^= gf_mul(coefficient, *value, &exp, &log);
            }
        }
    }

    let mut result = BTreeMap::new();
    for missing_index in missing {
        if *missing_index >= n || available.contains_key(missing_index) {
            return None;
        }
        let bytes = if *missing_index < k {
            data[*missing_index].clone()
        } else {
            let mut out = vec![0u8; params.stripe_size];
            for (col, shard) in data.iter().enumerate() {
                let coefficient = row_coefficient(*missing_index, col, k);
                for (output, value) in out.iter_mut().zip(shard) {
                    *output ^= gf_mul(coefficient, *value, &exp, &log);
                }
            }
            out
        };
        result.insert(*missing_index, bytes);
    }
    Some(result)
}

fn invert_matrix(matrix: &[Vec<u8>], exp: &[u8; 256], log: &[u8; 256]) -> Option<Vec<Vec<u8>>> {
    let n = matrix.len();
    let mut augmented = vec![vec![0u8; n * 2]; n];
    for r in 0..n {
        augmented[r][..n].copy_from_slice(&matrix[r]);
        augmented[r][n + r] = 1;
    }
    for col in 0..n {
        let pivot = (col..n).find(|r| augmented[*r][col] != 0)?;
        augmented.swap(col, pivot);
        let inverse_pivot = gf_inv(augmented[col][col], exp, log);
        for value in &mut augmented[col] {
            *value = gf_mul(*value, inverse_pivot, exp, log);
        }
        for r in 0..n {
            if r == col {
                continue;
            }
            let factor = augmented[r][col];
            if factor == 0 {
                continue;
            }
            for c in 0..n * 2 {
                let remove = gf_mul(factor, augmented[col][c], exp, log);
                augmented[r][c] ^= remove;
            }
        }
    }
    Some(augmented.into_iter().map(|row| row[n..].to_vec()).collect())
}
