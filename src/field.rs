//! GF(2^8) arithmetic with the AES polynomial (0x11d reduction, low byte 0x1b).

pub struct Gf256 {
    exp: [u8; 512],
    log: [u8; 256],
}

impl Gf256 {
    pub fn new() -> Self {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for tos in 0..255 {
            exp[tos] = x as u8;
            log[x as usize] = tos as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= 0x11d;
            }
        }
        for tos in 255..512 {
            exp[tos] = exp[tos - 255];
        }
        Gf256 { exp, log }
    }

    pub fn add(&self, a: u8, b: u8) -> u8 {
        a ^ b
    }

    pub fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            self.exp[self.log[a as usize] as usize + self.log[b as usize] as usize]
        }
    }

    pub fn div(&self, a: u8, b: u8) -> u8 {
        assert!(b != 0, "division by zero in GF(2^8)");
        if a == 0 {
            0
        } else {
            let d = self.log[a as usize] as i32 - self.log[b as usize] as i32;
            self.exp[d.rem_euclid(255) as usize]
        }
    }

    pub fn inv(&self, a: u8) -> u8 {
        assert!(a != 0, "inverse of zero in GF(2^8)");
        self.exp[255 - self.log[a as usize] as usize]
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
    fn mul_div_roundtrip() {
        let gf = Gf256::new();
        for a in 1..=255u8 {
            for b in [1u8, 7, 53, 200, 255] {
                assert_eq!(gf.div(gf.mul(a, b), b), a);
            }
        }
    }

    #[test]
    fn inv_roundtrip() {
        let gf = Gf256::new();
        for a in 1..=255u8 {
            assert_eq!(gf.mul(a, gf.inv(a)), 1);
        }
    }
}
