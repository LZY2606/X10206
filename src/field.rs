//! GF(2^8) arithmetic, polynomial 0x11d, generator 2.
//! Small finite field used by the erasure coding fixtures.

use std::sync::OnceLock;

pub struct Gf {
    exp: [u8; 512],
    log: [u8; 256],
}

static GF: OnceLock<Gf> = OnceLock::new();

pub fn gf() -> &'static Gf {
    GF.get_or_init(Gf::new)
}

impl Gf {
    fn new() -> Gf {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for i in 0..255usize {
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
        Gf { exp, log }
    }

    pub fn add(&self, a: u8, b: u8) -> u8 {
        a ^ b
    }

    pub fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }
        self.exp[self.log[a as usize] as usize + self.log[b as usize] as usize]
    }

    pub fn div(&self, a: u8, b: u8) -> u8 {
        assert_ne!(b, 0, "gf div by zero");
        if a == 0 {
            return 0;
        }
        let d = self.log[a as usize] as i32 - self.log[b as usize] as i32;
        self.exp[(d.rem_euclid(255)) as usize]
    }

    pub fn pow(&self, a: u8, mut n: u32) -> u8 {
        if n == 0 {
            return 1;
        }
        if a == 0 {
            return 0;
        }
        let mut acc = 1u8;
        let mut base = a;
        while n > 0 {
            if n & 1 == 1 {
                acc = self.mul(acc, base);
            }
            base = self.mul(base, base);
            n >>= 1;
        }
        acc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_div_inverse() {
        let g = gf();
        for a in 1..=255u8 {
            for b in [1u8, 7, 129, 255] {
                assert_eq!(g.div(g.mul(a, b), b), a);
            }
        }
    }

    #[test]
    fn pow_cycles() {
        let g = gf();
        assert_eq!(g.pow(2, 255), 1);
        assert_eq!(g.pow(0, 0), 1);
        assert_eq!(g.pow(3, 4), g.mul(g.mul(3, 3), g.mul(3, 3)));
    }
}
