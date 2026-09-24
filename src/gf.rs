//! GF(2^8) arithmetic with the primitive polynomial x^8+x^4+x^3+x^2+1 (0x11d).

pub struct Gf {
    exp: [u8; 512],
    log: [u8; 256],
}

impl Gf {
    pub fn new() -> Gf {
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

    pub fn exp_of(&self, i: u8) -> u8 {
        self.exp[i as usize]
    }

    pub fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            self.exp[self.log[a as usize] as usize + self.log[b as usize] as usize]
        }
    }

    pub fn inv(&self, a: u8) -> u8 {
        assert!(a != 0, "division by zero in GF(256)");
        self.exp[255 - self.log[a as usize] as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_inv_roundtrip() {
        let gf = Gf::new();
        for a in 1..=255u8 {
            assert_eq!(gf.mul(a, gf.inv(a)), 1);
        }
        assert_eq!(gf.mul(0, 7), 0);
        assert_eq!(gf.mul(53, 0), 0);
    }
}
