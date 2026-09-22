//! Galois field GF(2^8) with primitive polynomial 0x11d (x^8 + x^4 + x^3 + x^2 + 1).

#[derive(Clone)]
pub struct Gf256 {
    /// exp[i] = g^i for i in 0..511 (doubled table so wrap-around adds are cheap).
    exp: [u8; 512],
    /// log[a] = discrete log of non-zero a.
    log: [u8; 256],
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
        Gf256 { exp, log }
    }

    #[inline]
    pub fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }
        let la = self.log[a as usize] as usize;
        let lb = self.log[b as usize] as usize;
        self.exp[la + lb]
    }

    #[inline]
    pub fn inv(&self, a: u8) -> u8 {
        debug_assert_ne!(a, 0, "inverse of zero is undefined");
        self.exp[255 - self.log[a as usize] as usize]
    }

    #[inline]
    pub fn div(&self, a: u8, b: u8) -> u8 {
        debug_assert_ne!(b, 0, "division by zero");
        if a == 0 {
            return 0;
        }
        let la = self.log[a as usize] as i32;
        let lb = self.log[b as usize] as i32;
        let mut d = la - lb;
        if d < 0 {
            d += 255;
        }
        self.exp[d as usize]
    }
}

impl Default for Gf256 {
    fn default() -> Self {
        Self::new()
    }
}

/// Invert a square matrix over GF(2^8). Returns None when the matrix is singular.
pub fn invert(gf: &Gf256, m: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    let n = m.len();
    for row in m {
        if row.len() != n {
            return None;
        }
    }
    let mut aug: Vec<Vec<u8>> = m
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let mut r = Vec::with_capacity(2 * n);
            r.extend_from_slice(row);
            r.extend(std::iter::repeat_n(0u8, n));
            r[n + i] = 1;
            r
        })
        .collect();

    for col in 0..n {
        let pivot = (col..n).find(|&r| aug[r][col] != 0)?;
        aug.swap(col, pivot);
        let piv = aug[col][col];
        if piv != 1 {
            let pinv = gf.inv(piv);
            for c in col..2 * n {
                aug[col][c] = gf.mul(aug[col][c], pinv);
            }
        }
        for r in 0..n {
            if r != col && aug[r][col] != 0 {
                let factor = aug[r][col];
                for c in col..2 * n {
                    let sub = gf.mul(factor, aug[col][c]);
                    aug[r][c] ^= sub;
                }
            }
        }
    }
    Some(aug.into_iter().map(|row| row[n..].to_vec()).collect())
}

/// Multiply matrix by column vector: result[i] = xor_j m[i][j] * v[j].
pub fn mat_vec(gf: &Gf256, m: &[Vec<u8>], v: &[u8]) -> Vec<u8> {
    m.iter()
        .map(|row| {
            row.iter()
                .zip(v)
                .fold(0u8, |acc, (&c, &x)| acc ^ gf.mul(c, x))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiplication_identities() {
        let gf = Gf256::new();
        for a in 0u16..256 {
            let a = a as u8;
            assert_eq!(gf.mul(a, 1), a);
            assert_eq!(gf.mul(a, 0), 0);
            if a != 0 {
                assert_eq!(gf.mul(a, gf.inv(a)), 1);
                assert_eq!(gf.div(a, a), 1);
                assert_eq!(gf.div(0, a), 0);
            }
        }
    }

    #[test]
    fn inverse_roundtrip() {
        let gf = Gf256::new();
        let m = vec![
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![7, 8, 99],
        ];
        let inv = invert(&gf, &m).unwrap();
        let prod: Vec<Vec<u8>> = m
            .iter()
            .map(|row| {
                (0..3)
                    .map(|c| {
                        (0..3).fold(0u8, |acc, k| acc ^ gf.mul(row[k], inv[k][c]))
                    })
                    .collect()
            })
            .collect();
        for r in 0..3 {
            for c in 0..3 {
                assert_eq!(prod[r][c], if r == c { 1 } else { 0 });
            }
        }
    }

    #[test]
    fn singular_detected() {
        let gf = Gf256::new();
        let m = vec![vec![1, 2], vec![2, 4]];
        assert!(invert(&gf, &m).is_none());
    }
}
