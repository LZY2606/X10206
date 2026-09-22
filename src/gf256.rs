//! GF(2^8) arithmetic using the standard AES/RJ256 primitive polynomial 0x11D.
//!
//! All Reed-Solomon coding in this crate happens over this field. The tables
//! are fully deterministic so every candidate reconstruction is reproducible.

pub struct Field {
    exp: [u8; 512],
    log: [u8; 256],
}

impl Default for Field {
    fn default() -> Self {
        Self::new()
    }
}

impl Field {
    pub fn new() -> Self {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for i in 0..255 {
            exp[i] = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= 0x11D;
            }
        }
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }
        Field { exp, log }
    }

    #[inline]
    pub fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            let la = self.log[a as usize] as u16;
            let lb = self.log[b as usize] as u16;
            self.exp[(la + lb) as usize]
        }
    }

    #[inline]
    pub fn inv(&self, a: u8) -> u8 {
        debug_assert!(a != 0, "zero has no inverse");
        self.exp[255 - self.log[a as usize] as usize]
    }

    #[inline]
    pub fn div(&self, a: u8, b: u8) -> u8 {
        debug_assert!(b != 0, "division by zero");
        if a == 0 {
            return 0;
        }
        let la = self.log[a as usize] as i16;
        let lb = self.log[b as usize] as i16;
        let mut e = la - lb;
        if e < 0 {
            e += 255;
        }
        self.exp[e as usize]
    }
}

/// Invert a square matrix over GF(2^8). Returns the inverse, or `None` when
/// singular. Gauss-Jordan elimination with an explicit identity pivot block.
pub fn invert(field: &Field, matrix: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    let k = matrix.len();
    if k == 0 || matrix.iter().any(|r| r.len() != k) {
        return None;
    }
    let mut m: Vec<Vec<u8>> = matrix.to_vec();
    let mut inv = vec![vec![0u8; k]; k];
    for (i, row) in inv.iter_mut().enumerate() {
        row[i] = 1;
    }
    for col in 0..k {
        let pivot = (col..k).find(|&r| m[r][col] != 0)?;
        if pivot != col {
            m.swap(pivot, col);
            inv.swap(pivot, col);
        }
        let p = m[col][col];
        let pinv = field.inv(p);
        for j in 0..k {
            m[col][j] = field.mul(m[col][j], pinv);
            inv[col][j] = field.mul(inv[col][j], pinv);
        }
        for r in 0..k {
            if r == col || m[r][col] == 0 {
                continue;
            }
            let factor = m[r][col];
            for j in 0..k {
                m[r][j] ^= field.mul(factor, m[col][j]);
                inv[r][j] ^= field.mul(factor, inv[col][j]);
            }
        }
    }
    Some(inv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiplication_tables_are_consistent() {
        let f = Field::new();
        for a in 0u16..256 {
            for &b in &[1u16, 2, 3, 17, 255] {
                let x = f.mul(a as u8, b as u8);
                if b != 0 {
                    assert_eq!(f.div(x, b as u8), a as u8);
                }
            }
        }
    }

    #[test]
    fn inverse_matches_identity() {
        let f = Field::new();
        let m = vec![vec![1u8, 2, 3], vec![0, 1, 4], vec![5, 6, 0]];
        let inv = invert(&f, &m).unwrap();
        for i in 0..3 {
            for j in 0..3 {
                let mut acc = 0u8;
                for t in 0..3 {
                    acc ^= f.mul(m[i][t], inv[t][j]);
                }
                assert_eq!(acc, if i == j { 1 } else { 0 });
            }
        }
    }
}
