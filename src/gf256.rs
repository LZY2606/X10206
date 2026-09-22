//! GF(2^8) arithmetic over the primitive polynomial x^8+x^4+x^3+x^2+1 (0x11d).
//! Used by the small-field Cauchy-matrix Reed-Solomon codec.

pub const FIELD_SIZE: usize = 256;

fn cl_mul(mut a: u8, mut b: u8) -> u8 {
    let mut z: u16 = 0;
    let mut aa: u16 = a as u16;
    for _ in 0..8 {
        if b & 1 != 0 {
            z ^= aa;
        }
        let hi = aa & 0x80;
        aa <<= 1;
        if hi != 0 {
            aa ^= 0x011d;
        }
        b >>= 1;
    }
    z as u8
}

fn build_tables() -> ([u8; 512], [u8; 256]) {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut x: u16 = 1;
    for i in 0..255 {
        exp[i] = x as u8;
        log[x as usize] = i as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= 0x011d;
        }
    }
    for i in 255..512 {
        exp[i] = exp[i - 255];
    }
    (exp, log)
}

thread_local! {
    static TABLES: ([u8; 512], [u8; 256]) = build_tables();
}

pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    TABLES.with(|(exp, log)| {
        let la = log[a as usize] as u16;
        let lb = log[b as usize] as u16;
        exp[(la + lb) as usize]
    })
}

pub fn div(a: u8, b: u8) -> u8 {
    assert_ne!(b, 0, "division by zero in GF(256)");
    if a == 0 {
        return 0;
    }
    TABLES.with(|(exp, log)| {
        let la = log[a as usize] as i16;
        let lb = log[b as usize] as i16;
        let mut e = la - lb;
        if e < 0 {
            e += 255;
        }
        exp[e as usize]
    })
}

pub fn inv(a: u8) -> u8 {
    assert_ne!(a, 0, "inverse of zero in GF(256)");
    div(1, a)
}

/// Cauchy matrix entry: 1 / (x_i XOR y_j), with x_i = i and y_j = n-k+j.
pub fn cauchy_entry(i: usize, j: usize, n: usize, k: usize) -> u8 {
    let x = i as u8;
    let y = (n - k + j) as u8;
    let d = x ^ y;
    assert_ne!(d, 0, "Cauchy X set and Y set must be disjoint");
    inv(d)
}

/// Solve A * x = b over GF(2^8) using Gauss-Jordan elimination.
/// `matrix` is n x n (rows*n), `rhs` length n. Returns None when singular.
pub fn solve(matrix: &[u8], rhs: &[u8]) -> Option<Vec<u8>> {
    let n = rhs.len();
    debug_assert_eq!(matrix.len(), n * n);
    let mut a = vec![0u8; n * (n + 1)];
    for i in 0..n {
        a[i * (n + 1)..i * (n + 1) + n].copy_from_slice(&matrix[i * n..(i + 1) * n]);
        a[i * (n + 1) + n] = rhs[i];
    }
    for col in 0..n {
        let pivot = (col..n).find(|&r| a[r * (n + 1) + col] != 0)?;
        if pivot != col {
            for c in 0..n + 1 {
                a.swap(col * (n + 1) + c, pivot * (n + 1) + c);
            }
        }
        let p = a[col * (n + 1) + col];
        let pinv = inv(p);
        for c in col..n + 1 {
            a[col * (n + 1) + c] = mul(a[col * (n + 1) + c], pinv);
        }
        for r in 0..n {
            if r != col {
                let factor = a[r * (n + 1) + col];
                if factor != 0 {
                    for c in col..n + 1 {
                        let v = a[col * (n + 1) + c];
                        a[r * (n + 1) + c] ^= mul(factor, v);
                    }
                }
            }
        }
    }
    Some((0..n).map(|i| a[i * (n + 1) + n]).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_table_matches_grade_school() {
        for a in 0u16..256 {
            for b in 0u16..256 {
                assert_eq!(mul(a as u8, b as u8), cl_mul(a as u8, b as u8));
            }
        }
    }

    #[test]
    fn inverse_roundtrip() {
        for a in 1u8..=255 {
            assert_eq!(mul(a, inv(a)), 1);
        }
    }
}
