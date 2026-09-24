//! GF(2^8) arithmetic over the primitive polynomial x^8+x^4+x^3+x^2+1 (0x11d).
//!
//! The chamber deliberately keeps the finite field small so fixtures and
//! review screens stay legible; every byte of every shard is one field
//! element. Tables are built once lazily and used vector-wide.

pub const FIELD_SIZE: usize = 256;

pub struct Gf256 {
    pub exp: [u8; 2 * FIELD_SIZE - 2],
    pub log: [u8; FIELD_SIZE],
}

impl Gf256 {
    pub fn new() -> Self {
        let mut exp = [0u8; 2 * FIELD_SIZE - 2];
        let mut log = [0u8; FIELD_SIZE];
        let mut x: u16 = 1;
        for i in 0..(FIELD_SIZE - 1) {
            exp[i] = x as u8;
            exp[i + FIELD_SIZE - 1] = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= 0x11d;
            }
        }
        Gf256 { exp, log }
    }

    #[inline]
    pub fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            let ia = self.log[a as usize] as usize;
            let ib = self.log[b as usize] as usize;
            self.exp[ia + ib]
        }
    }

    #[inline]
    pub fn inv(&self, a: u8) -> u8 {
        debug_assert_ne!(a, 0, "no inverse for zero");
        self.exp[FIELD_SIZE - 1 - self.log[a as usize] as usize]
    }

    /// c = a * s + b (field scale-add), the core encoding primitive.
    #[inline]
    pub fn mul_add(&self, c: &mut [u8], a: &[u8], s: u8, b: &[u8]) {
        for i in 0..c.len() {
            c[i] = b[i] ^ self.mul(a[i], s);
        }
    }
}

impl Default for Gf256 {
    fn default() -> Self {
        Gf256::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_exp_roundtrip() {
        let gf = Gf256::new();
        for a in 1u16..256 {
            let a = a as u8;
            assert_eq!(gf.exp[gf.log[a as usize] as usize], a);
        }
    }

    #[test]
    fn inverse_identity() {
        let gf = Gf256::new();
        for a in 1u16..256 {
            let a = a as u8;
            assert_eq!(gf.mul(a, gf.inv(a)), 1);
        }
    }

    #[test]
    fn multiply_zero() {
        let gf = Gf256::new();
        assert_eq!(gf.mul(0, 200), 0);
        assert_eq!(gf.mul(200, 0), 0);
    }
}
