use std::fmt;

#[derive(Debug)]
pub enum CodingError {
    InvalidParameter(&'static str),
    Singular,
    WrongSize { expected: usize, actual: usize },
}

impl fmt::Display for CodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParameter(msg) => write!(f, "invalid coding parameter: {msg}"),
            Self::Singular => write!(f, "coding matrix is singular"),
            Self::WrongSize { expected, actual } => {
                write!(f, "wrong shard size: expected {expected}, got {actual}")
            }
        }
    }
}

impl std::error::Error for CodingError {}

fn field_tables() -> ([u8; 256], [u8; 256]) {
    let mut log = [0u8; 256];
    let mut exp = [0u8; 256];
    let mut value = 1u8;
    for i in 0..255 {
        exp[i] = value;
        log[value as usize] = i as u8;
        value = multiply(value, 2);
    }
    exp[255] = exp[0];
    (log, exp)
}

fn multiply(a: u8, b: u8) -> u8 {
    let mut aa = a as u16;
    let mut bb = b;
    let mut result = 0u16;
    while bb != 0 {
        if bb & 1 != 0 {
            result ^= aa;
        }
        let carry = aa & 0x80;
        aa <<= 1;
        if carry != 0 {
            aa ^= 0x11d;
        }
        bb >>= 1;
    }
    result as u8
}

pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        0
    } else {
        let (log, exp) = field_tables();
        let sum = log[a as usize] as u16 + log[b as usize] as u16;
        exp[(sum % 255) as usize]
    }
}

pub fn div(a: u8, b: u8) -> u8 {
    assert!(b != 0, "division by zero in GF(256)");
    if a == 0 {
        return 0;
    }
    let (log, exp) = field_tables();
    let la = log[a as usize] as i16;
    let lb = log[b as usize] as i16;
    exp[((la - lb).rem_euclid(255)) as usize]
}

fn inverse(a: u8) -> u8 {
    div(1, a)
}

pub fn cauchy_coefficient(row: usize, column: usize, data_shards: usize) -> u8 {
    assert!(row >= data_shards);
    let x = (row - data_shards) as u8;
    let y = column as u8;
    inverse(x ^ y)
}

pub fn coefficient(row: usize, column: usize, data_shards: usize) -> u8 {
    if row < data_shards {
        if row == column { 1 } else { 0 }
    } else {
        cauchy_coefficient(row, column, data_shards)
    }
}

pub fn encode(data: &[Vec<u8>], parity_count: usize) -> Result<Vec<Vec<u8>>, CodingError> {
    let k = data.len();
    if k == 0 || k + parity_count > 256 {
        return Err(CodingError::InvalidParameter("need 1..=256 total shards"));
    }
    let shard_len = data.first().map_or(0, Vec::len);
    if data.iter().any(|shard| shard.len() != shard_len) {
        return Err(CodingError::InvalidParameter("data shards must have equal padded length"));
    }
    let n = k + parity_count;
    let mut output = data.to_vec();
    for row in k..n {
        let mut parity = vec![0u8; shard_len];
        for (column, shard) in data.iter().enumerate() {
            let factor = cauchy_coefficient(row, column, k);
            for (out, byte) in parity.iter_mut().zip(shard) {
                *out ^= mul(factor, *byte);
            }
        }
        output.push(parity);
    }
    Ok(output)
}

fn solve_matrix(mut matrix: Vec<Vec<u8>>, mut values: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>, CodingError> {
    let k = matrix.len();
    if values.len() != k || matrix.iter().any(|row| row.len() != k) {
        return Err(CodingError::InvalidParameter("malformed coding matrix"));
    }
    let shard_len = values.first().map_or(0, Vec::len);
    if values.iter().any(|v| v.len() != shard_len) {
        return Err(CodingError::InvalidParameter("uneven witness shards"));
    }

    for col in 0..k {
        let pivot = (col..k).find(|row| matrix[*row][col] != 0).ok_or(CodingError::Singular)?;
        matrix.swap(col, pivot);
        values.swap(col, pivot);
        let pivot_value = matrix[col][col];
        let pivot_inverse = inverse(pivot_value);
        for byte in &mut matrix[col] {
            *byte = mul(*byte, pivot_inverse);
        }
        for value in &mut values[col] {
            *value = mul(*value, pivot_inverse);
        }
        for row in 0..k {
            if row == col {
                continue;
            }
            let factor = matrix[row][col];
            if factor == 0 {
                continue;
            }
            for c in 0..k {
                matrix[row][c] ^= mul(factor, matrix[col][c]);
            }
            for (target, source) in values[row].iter_mut().zip(&values[col]) {
                *target ^= mul(factor, *source);
            }
        }
    }
    Ok(values)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Witness {
    pub index: usize,
    pub bytes: Vec<u8>,
}

pub fn reconstruct_data(k: usize, n: usize, shard_len: usize, witnesses: &[Witness]) -> Result<Vec<Vec<u8>>, CodingError> {
    if k == 0 || n < k || n > 256 {
        return Err(CodingError::InvalidParameter("invalid shard counts"));
    }
    if witnesses.len() < k {
        return Err(CodingError::InvalidParameter("fewer witnesses than data shards"));
    }
    let unique: std::collections::BTreeSet<usize> = witnesses.iter().map(|w| w.index).collect();
    if unique.len() != witnesses.len() || witnesses.iter().any(|w| w.index >= n) {
        return Err(CodingError::InvalidParameter("witnesses must be unique valid indices"));
    }
    for witness in witnesses {
        if witness.bytes.len() != shard_len {
            return Err(CodingError::WrongSize { expected: shard_len, actual: witness.bytes.len() });
        }
    }
    let matrix = witnesses
        .iter()
        .take(k)
        .map(|w| (0..k).map(|column| coefficient(w.index, column, k)).collect::<Vec<u8>>())
        .collect();
    let values = witnesses.iter().take(k).map(|w| w.bytes.clone()).collect();
    solve_matrix(matrix, values)
}

pub fn reconstruct_missing(k: usize, n: usize, shard_len: usize, witnesses: &[Witness]) -> Result<Vec<Vec<u8>>, CodingError> {
    let data = reconstruct_data(k, n, shard_len, witnesses)?;
    encode(&data, n - k)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconstructs_single_and_multiple_missing() {
        let data = vec![vec![1u8, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];
        let all = encode(&data, 3).unwrap();
        for missing in [vec![0], vec![0, 2], vec![2, 5], vec![3, 4, 5]] {
            let witnesses: Vec<_> = (0..6)
                .filter(|index| !missing.contains(index))
                .map(|index| Witness { index, bytes: all[index].clone() })
                .collect();
            let recovered = reconstruct_missing(3, 6, 3, &witnesses).unwrap();
            for index in missing {
                assert_eq!(recovered[index], all[index]);
            }
        }
    }

    #[test]
    fn rejects_bit_flipped_witness_by_cross_check() {
        let data = vec![vec![10, 20], vec![30, 40], vec![50, 60]];
        let mut all = encode(&data, 2).unwrap();
        all[0][0] ^= 1;
        let witnesses: Vec<_> = (0..5).map(|index| Witness { index, bytes: all[index].clone() }).collect();
        let recovered = reconstruct_missing(3, 5, 2, &witnesses).unwrap();
        assert_ne!(&recovered[0], &data[0]);
        assert_ne!(&recovered[1], &data[1]);
    }
}
