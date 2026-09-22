pub const CODE_VERSION: &str = "rs-gf256-cauchy-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeParams {
    pub data_shards: usize,
    pub parity_shards: usize,
}

impl CodeParams {
    pub fn total(self) -> usize {
        self.data_shards + self.parity_shards
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedStripe {
    pub data: Vec<Vec<u8>>,
    pub parity: Vec<Vec<u8>>,
}

fn mul(a: u8, b: u8) -> u8 {
    let mut x = a;
    let mut y = b;
    let mut result = 0u8;
    while y != 0 {
        if y & 1 != 0 {
            result ^= x;
        }
        let high = x & 0x80;
        x <<= 1;
        if high != 0 {
            x ^= 0x1d;
        }
        y >>= 1;
    }
    result
}

fn inv(value: u8) -> u8 {
    if value == 0 {
        panic!("zero has no inverse in GF(256)");
    }
    let mut result = 1u8;
    let mut base = value;
    let mut exponent = 255u16;
    while exponent > 0 {
        if exponent & 1 != 0 {
            result = mul(result, base);
        }
        base = mul(base, base);
        exponent >>= 1;
    }
    result
}

fn parity_matrix(params: CodeParams) -> Vec<Vec<u8>> {
    (0..params.parity_shards)
        .map(|parity_index| {
            let x = (params.data_shards + parity_index + 1) as u8;
            (0..params.data_shards)
                .map(|data_index| inv(x ^ (data_index as u8 + 1)))
                .collect()
        })
        .collect()
}

pub fn encode(data: &[Vec<u8>], params: CodeParams) -> EncodedStripe {
    assert_eq!(data.len(), params.data_shards);
    if data.iter().any(|shard| shard.len() != data[0].len()) {
        panic!("all shards must have equal length");
    }
    let length = data.first().map_or(0, |shard| shard.len());
    let matrix = parity_matrix(params);
    let parity = matrix
        .iter()
        .map(|row| {
            let mut output = vec![0u8; length];
            for (data_index, coefficient) in row.iter().enumerate() {
                for offset in 0..length {
                    output[offset] ^= mul(*coefficient, data[data_index][offset]);
                }
            }
            output
        })
        .collect();
    EncodedStripe { data: data.to_vec(), parity }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SlotKind {
    Data,
    Parity,
}

#[derive(Clone)]
pub struct AvailableShard {
    pub kind: SlotKind,
    pub index: usize,
    pub bytes: Vec<u8>,
}

fn matrix_solve(mut matrix: Vec<Vec<u8>>, mut values: Vec<Vec<u8>>, rank: usize) -> Option<Vec<Vec<u8>>> {
    let mut row = 0;
    for column in 0..rank {
        let pivot = (row..rank).find(|candidate| matrix[*candidate][column] != 0)?;
        matrix.swap(row, pivot);
        values.swap(row, pivot);
        let pivot_value = matrix[row][column];
        let pivot_inverse = inv(pivot_value);
        for item in &mut matrix[row] {
            *item = mul(*item, pivot_inverse);
        }
        for item in &mut values[row] {
            *item = mul(*item, pivot_inverse);
        }
        for candidate in 0..rank {
            if candidate == row {
                continue;
            }
            let factor = matrix[candidate][column];
            if factor == 0 {
                continue;
            }
            for c in 0..rank {
                matrix[candidate][c] ^= mul(factor, matrix[row][c]);
            }
            for offset in 0..values[candidate].len() {
                values[candidate][offset] ^= mul(factor, values[row][offset]);
            }
        }
        row += 1;
    }
    Some(values)
}

pub fn reconstruct(
    available: &[AvailableShard],
    params: CodeParams,
) -> Option<Vec<Vec<u8>>> {
    let length = available.first().map(|shard| shard.bytes.len())?;
    if available.len() != params.data_shards
        || available.iter().any(|shard| shard.bytes.len() != length)
    {
        return None;
    }

    let mut rows: Vec<Vec<u8>> = Vec::with_capacity(params.data_shards);
    let mut values = Vec::with_capacity(params.data_shards);
    let parity_matrix = parity_matrix(params);

    for shard in available {
        let mut row = vec![0u8; params.data_shards];
        match shard.kind {
            SlotKind::Data => row[shard.index] = 1,
            SlotKind::Parity => {
                if shard.index >= params.parity_shards {
                    return None;
                }
                row.copy_from_slice(&parity_matrix[shard.index]);
            }
        }
        rows.push(row);
        values.push(shard.bytes.clone());
    }

    matrix_solve(rows, values, params.data_shards)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shards(values: &[u8]) -> Vec<Vec<u8>> {
        values.iter().map(|value| vec![*value]).collect()
    }

    #[test]
    fn reconstructs_with_boundary_parity_count() {
        let params = CodeParams { data_shards: 3, parity_shards: 2 };
        let encoded = encode(&shards(&[7, 21, 42]), params);
        let mut mixed = vec![encoded.data[0].clone(), encoded.parity[0].clone(), encoded.parity[1].clone()];
        let available: Vec<_> = [
            AvailableShard { kind: SlotKind::Data, index: 0, bytes: mixed.remove(0) },
            AvailableShard { kind: SlotKind::Parity, index: 0, bytes: mixed.remove(0) },
            AvailableShard { kind: SlotKind::Parity, index: 1, bytes: mixed.remove(0) },
        ]
        .into_iter()
        .collect();
        assert_eq!(reconstruct(&available, params).unwrap(), shards(&[7, 21, 42]));
    }
}
