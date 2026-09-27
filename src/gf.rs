//! GF(2^8) arithmetic with the primitive polynomial x^8+x^4+x^3+x^2+1 (0x11D).
//! This is the small finite field used by every fixture and by the codec.

pub const FIELD_SIZE: usize = 256;

pub struct Tables {
    pub exp: [u8; 512],
    pub log: [u8; 256],
}

impl Tables {
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
        Tables { exp, log }
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
        debug_assert!(a != 0, "no inverse for zero");
        self.exp[255 - self.log[a as usize] as usize]
    }

    #[inline]
    pub fn div(&self, a: u8, b: u8) -> u8 {
        if a == 0 {
            0
        } else {
            self.mul(a, self.inv(b))
        }
    }
}

impl Default for Tables {
    fn default() -> Self {
        Self::new()
    }
}

/// Invert a square matrix over GF(256) using Gauss-Jordan elimination.
/// Returns None when the matrix is singular.
pub fn invert(t: &Tables, mut a: Vec<Vec<u8>>) -> Option<Vec<Vec<u8>>> {
    let n = a.len();
    if a.iter().any(|r| r.len() != n) {
        return None;
    }
    let mut inv = vec![vec![0u8; n]; n];
    for (i, row) in inv.iter_mut().enumerate() {
        row[i] = 1;
    }
    for col in 0..n {
        let pivot = (col..n).find(|&r| a[r][col] != 0)?;
        if pivot != col {
            a.swap(pivot, col);
            inv.swap(pivot, col);
        }
        let p = a[col][col];
        let pinv = t.inv(p);
        for j in 0..n {
            a[col][j] = t.mul(a[col][j], pinv);
            inv[col][j] = t.mul(inv[col][j], pinv);
        }
        for r in 0..n {
            if r == col {
                continue;
            }
            let factor = a[r][col];
            if factor == 0 {
                continue;
            }
            for j in 0..n {
                a[r][j] ^= t.mul(factor, a[col][j]);
                inv[r][j] ^= t.mul(factor, inv[col][j]);
            }
        }
    }
    Some(inv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_roundtrip() {
        let t = Tables::new();
        assert_eq!(t.mul(0, 99), 0);
        for a in 1..=255u16 {
            let a = a as u8;
            assert_eq!(t.mul(a, t.inv(a)), 1);
            assert_eq!(t.div(a, a), 1);
        }
    }

    #[test]
    fn invert_identity_and_singular() {
        let t = Tables::new();
        let id = vec![vec![1, 0], vec![0, 1]];
        assert_eq!(invert(&t, id.clone()), Some(id));
        let singular = vec![vec![1, 1], vec![1, 1]];
        assert_eq!(invert(&t, singular), None);
        let m = vec![vec![2, 3], vec![4, 5]];
        let mi = invert(&t, m.clone()).unwrap();
        let n = m.len();
        let mut prod = vec![vec![0u8; n]; n];
        for i in 0..n {
            for j in 0..n {
                for k in 0..n {
                    prod[i][j] ^= t.mul(m[i][k], mi[k][j]);
                }
            }
        }
        assert_eq!(prod, vec![vec![1, 0], vec![0, 1]]);
    }
}
