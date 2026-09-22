//! GF(2^8) arithmetic, polynomial 0x11d, generator 2.
//! Small, table-driven finite field used by the versioned encoding params.

pub const POLY: u16 = 0x11d;

#[derive(Clone)]
pub struct Gf {
    exp: [u8; 512],
    log: [u8; 256],
}

impl Default for Gf {
    fn default() -> Self {
        Self::new()
    }
}

impl Gf {
    pub fn new() -> Gf {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for i in 0..255 {
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
        assert!(b != 0, "gf div by zero");
        if a == 0 {
            0
        } else {
            let d = self.log[a as usize] as i32 - self.log[b as usize] as i32;
            self.exp[d.rem_euclid(255) as usize]
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
        let l = self.log[a as usize] as usize;
        self.exp[(l * n) % 255]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_div_inverse() {
        let gf = Gf::new();
        for a in 1..=255u8 {
            assert_eq!(gf.mul(a, gf.inv(a)), 1);
            for b in [1u8, 3, 0x53, 0xff] {
                let p = gf.mul(a, b);
                assert_eq!(gf.div(p, b), a);
            }
        }
    }

    #[test]
    fn pow_matches_repeated_mul() {
        let gf = Gf::new();
        for a in [2u8, 7, 0xca] {
            let mut acc = 1u8;
            for n in 0..20 {
                assert_eq!(gf.pow(a, n), acc);
                acc = gf.mul(acc, a);
            }
        }
    }
}
