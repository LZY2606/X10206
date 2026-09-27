//! GF(2^8) arithmetic with tables, plus matrix inversion over the field.

#[derive(Clone)]
pub struct Gf {
    exp: [u8; 512],
    log: [u8; 256],
}

impl Gf {
    /// `poly` is the irreducible polynomial including the x^8 bit, e.g. 0x11d.
    pub fn new(poly: u16) -> Gf {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for i in 0..255usize {
            exp[i] = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= poly;
            }
        }
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }
        Gf { exp, log }
    }

    pub fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            self.exp[self.log[a as usize] as usize + self.log[b as usize] as usize]
        }
    }

    pub fn div(&self, a: u8, b: u8) -> u8 {
        assert_ne!(b, 0, "gf division by zero");
        if a == 0 {
            0
        } else {
            let l = self.log[a as usize] as usize + 255 - self.log[b as usize] as usize;
            self.exp[l % 255]
        }
    }

    pub fn inv(&self, a: u8) -> u8 {
        self.div(1, a)
    }

    pub fn pow(&self, a: u8, n: usize) -> u8 {
        if n == 0 {
            return 1;
        }
        if a == 0 {
            return 0;
        }
        self.exp[(self.log[a as usize] as usize * n) % 255]
    }
}

/// Invert a square matrix over the field. Returns None if singular.
pub fn mat_inv(gf: &Gf, m: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    let n = m.len();
    let mut aug: Vec<Vec<u8>> = m
        .iter()
        .map(|r| {
            let mut row = r.clone();
            row.resize(2 * n, 0);
            row
        })
        .collect();
    for (i, row) in aug.iter_mut().enumerate() {
        row[n + i] = 1;
    }
    for col in 0..n {
        let pivot = (col..n).find(|&r| aug[r][col] != 0)?;
        aug.swap(col, pivot);
        let inv = gf.inv(aug[col][col]);
        for j in 0..2 * n {
            aug[col][j] = gf.mul(aug[col][j], inv);
        }
        for r in 0..n {
            if r != col && aug[r][col] != 0 {
                let f = aug[r][col];
                for j in 0..2 * n {
                    aug[r][j] ^= gf.mul(f, aug[col][j]);
                }
            }
        }
    }
    Some(aug.into_iter().map(|r| r[n..].to_vec()).collect())
}

pub fn mat_mul(gf: &Gf, a: &[Vec<u8>], b: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let rows = a.len();
    let cols = b[0].len();
    let inner = b.len();
    let mut out = vec![vec![0u8; cols]; rows];
    for r in 0..rows {
        for i in 0..inner {
            let coef = a[r][i];
            if coef == 0 {
                continue;
            }
            for c in 0..cols {
                out[r][c] ^= gf.mul(coef, b[i][c]);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf_mul_div_roundtrip() {
        let gf = Gf::new(0x11d);
        for a in 1..=255u8 {
            for b in [1u8, 7, 53, 200, 255] {
                assert_eq!(gf.div(gf.mul(a, b), b), a);
            }
            assert_eq!(gf.mul(a, gf.inv(a)), 1);
        }
    }

    #[test]
    fn mat_inv_identity_product() {
        let gf = Gf::new(0x11d);
        let m = vec![
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![7, 8, 10],
        ];
        let inv = mat_inv(&gf, &m).unwrap();
        let prod = mat_mul(&gf, &m, &inv);
        for r in 0..3 {
            for c in 0..3 {
                assert_eq!(prod[r][c], if r == c { 1 } else { 0 });
            }
        }
    }
}
