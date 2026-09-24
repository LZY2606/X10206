//! GF(2^8) arithmetic used by the small-field Reed-Solomon codec.
//!
//! Primitive polynomial: x^8 + x^4 + x^3 + x^2 + 1 (0x11D), generator 2.

use std::sync::OnceLock;

static LOG: OnceLock<[u8; 256]> = OnceLock::new();
static EXP: OnceLock<[u8; 512]> = OnceLock::new();

fn tables() -> (&'static [u8; 256], &'static [u8; 512]) {
    let log = LOG.get_or_init(|| {
        let mut t = [0u8; 256];
        let mut x: u16 = 1;
        for i in 0..255 {
            t[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= 0x11D;
            }
        }
        t
    });
    let exp = EXP.get_or_init(|| {
        let mut t = [0u8; 512];
        let mut x: u16 = 1;
        for i in 0..512 {
            t[i] = x as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= 0x11D;
            }
        }
        t
    });
    (log, exp)
}

#[inline]
pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let (log, exp) = tables();
    let v = log[a as usize] as u16 + log[b as usize] as u16;
    exp[v as usize]
}

#[inline]
pub fn inv(a: u8) -> u8 {
    assert!(a != 0, "zero has no inverse");
    let (log, exp) = tables();
    exp[255 - log[a as usize] as usize]
}

#[inline]
pub fn div(a: u8, b: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    let (log, exp) = tables();
    let v = log[a as usize] as i16 - log[b as usize] as i16;
    exp[if v < 0 { v + 255 } else { v } as usize]
}

/// Systematic Cauchy generator matrix with `k + m` rows and `k` columns.
/// Rows 0..k are the identity; every square sub-matrix formed by any k rows
/// is invertible over GF(2^8).
pub fn cauchy_systematic(k: usize, m: usize) -> Vec<Vec<u8>> {
    assert!(k >= 1 && m >= 1 && 2 * k + m <= 256, "unsupported shard layout");
    let mut mat = vec![vec![0u8; k]; k + m];
    for i in 0..k {
        mat[i][i] = 1;
    }
    for p in 0..m {
        let x = (k + p) as u8;
        for j in 0..k {
            let y = 255u8 - j as u8;
            mat[k + p][j] = inv(x ^ y);
        }
    }
    mat
}

/// Invert an n x n matrix over GF(2^8) using Gauss-Jordan elimination.
pub fn invert_matrix(a: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    let n = a.len();
    let mut aug = vec![vec![0u8; 2 * n]; n];
    for i in 0..n {
        aug[i][..n].copy_from_slice(&a[i]);
        aug[i][n + i] = 1;
    }
    for col in 0..n {
        let pivot = (col..n).find(|&r| aug[r][col] != 0)?;
        aug.swap(col, pivot);
        let scale = inv(aug[col][col]);
        for c in col..2 * n {
            aug[col][c] = mul(aug[col][c], scale);
        }
        for r in 0..n {
            if r != col && aug[r][col] != 0 {
                let factor = aug[r][col];
                for c in col..2 * n {
                    aug[r][c] ^= mul(factor, aug[col][c]);
                }
            }
        }
    }
    Some(aug.iter().map(|row| row[n..].to_vec()).collect())
}
