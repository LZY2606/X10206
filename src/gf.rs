pub fn mul(a: u8, b: u8) -> u8 {
    let mut result = 0u8;
    let mut left = a;
    let mut right = b;
    for _ in 0..8 {
        if right & 1 != 0 {
            result ^= left;
        }
        let high = left & 0x80 != 0;
        left <<= 1;
        if high {
            left ^= 0x1d;
        }
        right >>= 1;
    }
    result
}

pub fn inv(value: u8) -> Option<u8> {
    if value == 0 {
        return None;
    }
    let mut candidate = 1u16;
    while candidate <= 255 {
        if mul(value, candidate as u8) == 1 {
            return Some(candidate as u8);
        }
        candidate += 1;
    }
    None
}

pub fn invert_matrix(matrix: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    let size = matrix.len();
    if size == 0 || matrix.iter().any(|row| row.len() != size) {
        return None;
    }
    let mut augmented = Vec::with_capacity(size);
    for row_index in 0..size {
        let mut row = Vec::with_capacity(size * 2);
        row.extend_from_slice(&matrix[row_index]);
        row.extend((0..size).map(|column| u8::from(column == row_index)));
        augmented.push(row);
    }

    for column in 0..size {
        let pivot = (column..size).find(|row| augmented[*row][column] != 0)?;
        augmented.swap(column, pivot);
        let pivot_value = augmented[column][column];
        let pivot_inverse = inv(pivot_value)?;
        for item in &mut augmented[column] {
            *item = mul(*item, pivot_inverse);
        }
        for row in 0..size {
            if row == column {
                continue;
            }
            let factor = augmented[row][column];
            if factor == 0 {
                continue;
            }
            for target in 0..size * 2 {
                let subtract = mul(factor, augmented[column][target]);
                augmented[row][target] ^= subtract;
            }
        }
    }

    Some(
        augmented
            .into_iter()
            .map(|row| row[size..].to_vec())
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inverse_recovers_identity_rows() {
        let matrix = vec![vec![1, 2], vec![3, 4]];
        let inverse = invert_matrix(&matrix).unwrap();
        assert_eq!(mul(inverse[0][0], 1) ^ mul(inverse[0][1], 3), 1);
        assert_eq!(mul(inverse[0][0], 2) ^ mul(inverse[0][1], 4), 0);
        assert_eq!(mul(inverse[1][0], 1) ^ mul(inverse[1][1], 3), 0);
        assert_eq!(mul(inverse[1][0], 2) ^ mul(inverse[1][1], 4), 1);
    }
}
