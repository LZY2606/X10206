//! GF(2^8) arithmetic over the primitive polynomial 0x11d.
//!
//! The small finite field used by every fixture and by the demo data so
//! that encoding / decoding can be inspected byte by byte in tests.

pub struct Gf256 {
    pub exp: [u8; 512],
    pub log: [u8; 256],
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
            0
        } else {
            let la = self.log[a as usize] as u16;
            let lb = self.log[b as usize] as u16;
            self.exp[(la + lb) as usize]
        }
    }

    #[inline]
    pub fn inv(&self, a: u8) -> u8 {
        debug_assert!(a != 0, "inverse of zero");
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

    #[inline]
    pub fn pow(&self, base: u8, mut e: u32) -> u8 {
        if base == 0 {
            return 0;
        }
        let mut result = 1u8;
        let mut b = base;
        while e > 0 {
            if e & 1 == 1 {
                result = self.mul(result, b);
            }
            b = self.mul(b, b);
            e >>= 1;
        }
        result
    }
}

impl Default for Gf256 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiplication_tables_round_trip() {
        let gf = Gf256::new();
        for a in 1u16..=255 {
            let a = a as u8;
            assert_eq!(gf.div(gf.mul(a, 200), 200), a);
            assert_eq!(gf.mul(a, gf.inv(a)), 1);
        }
        assert_eq!(gf.mul(0, 99), 0);
        assert_eq!(gf.div(0, 99), 0);
    }
}
