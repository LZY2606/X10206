//! GF(2^8) arithmetic with the 0x11d reduction polynomial, plus small
//! dense-matrix helpers used by the Reed-Solomon codec.

use std::sync::OnceLock;

const POLY: u16 = 0x11d;

struct Tables {
    exp: [u8; 512],
    log: [u8; 256],
}

fn tables() -> &'static Tables {
    static TABLES: OnceLock<Tables> = OnceLock::new();
    TABLES.get_or_init(|| {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for i in 0..255usize {
            exp[i] = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= POLY;
            }
        }
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }
        Tables { exp, log }
    })
}

pub fn add(a: u8, b: u8) -> u8 {
    a ^ b
}

pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let t = tables();
    t.exp[t.log[a as usize] as usize + t.log[b as usize] as usize]
}

pub fn inv(a: u8) -> u8 {
    assert!(a != 0, "no multiplicative inverse for 0");
    let t = tables();
    t.exp[255 - t.log[a as usize] as usize]
}

pub fn div(a: u8, b: u8) -> u8 {
    assert!(b != 0, "division by zero in GF(2^8)");
    if a == 0 {
        return 0;
    }
    mul(a, inv(b))
}

/// Invert a square matrix in place over GF(2^8) using Gauss-Jordan
/// elimination. Returns `None` when the matrix is singular.
pub fn matrix_invert(matrix: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    let n = matrix.len();
    assert!(n > 0 && matrix.iter().all(|r| r.len() == n));
    let mut aug: Vec<Vec<u8>> = matrix
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let mut r = row.clone();
            r.resize(2 * n, 0);
            r[n + i] = 1;
            r
        })
        .collect();
    for col in 0..n {
        let pivot = (col..n).find(|&r| aug[r][col] != 0)?;
        aug.swap(col, pivot);
        let inv_pivot = inv(aug[col][col]);
        for j in 0..2 * n {
            aug[col][j] = mul(aug[col][j], inv_pivot);
        }
        for r in 0..n {
            if r != col && aug[r][col] != 0 {
                let factor = aug[r][col];
                for j in 0..2 * n {
                    aug[r][j] = add(aug[r][j], mul(factor, aug[col][j]));
                }
            }
        }
    }
    Some(aug.into_iter().map(|r| r[n..].to_vec()).collect())
}

/// Multiply matrix `m` (rows x k) by vector `v` (k) over GF(2^8).
pub fn mat_vec_mul(m: &[Vec<u8>], v: &[u8]) -> Vec<u8> {
    m.iter()
        .map(|row| {
            row.iter()
                .zip(v.iter())
                .fold(0u8, |acc, (&a, &b)| add(acc, mul(a, b)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_inv_roundtrip() {
        for a in 1..=255u8 {
            assert_eq!(mul(a, inv(a)), 1, "a={a}");
        }
    }

    #[test]
    fn div_is_mul_inverse() {
        assert_eq!(div(100, 7), mul(100, inv(7)));
        assert_eq!(div(0, 5), 0);
    }

    #[test]
    fn matrix_inverse_identity_product() {
        let m = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 10]];
        let inv_m = matrix_invert(&m).expect("invertible");
        for (i, row) in m.iter().enumerate() {
            let col: Vec<u8> = inv_m.iter().map(|r| r[i]).collect();
            let prod = mat_vec_mul(&m, &col);
            let mut expected = vec![0u8; 3];
            expected[i] = 1;
            assert_eq!(prod, expected);
            let _ = row;
        }
    }

    #[test]
    fn singular_matrix_not_inverted() {
        let m = vec![vec![1, 1], vec![1, 1]];
        assert!(matrix_invert(&m).is_none());
    }
}
