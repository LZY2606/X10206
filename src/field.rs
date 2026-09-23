//! GF(2^8) arithmetic. The field polynomial is part of the versioned
//! encoding parameters, so tables are built per-polynomial.

#[derive(Clone, Debug)]
pub struct Field {
    pub poly: u16,
    exp: [u8; 512],
    log: [u8; 256],
}

impl Field {
    pub fn new(poly: u16) -> Self {
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
        Field { poly, exp, log }
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
        assert!(b != 0, "gf div by zero");
        if a == 0 {
            0
        } else {
            let l = self.log[a as usize] as i32 - self.log[b as usize] as i32;
            self.exp[l.rem_euclid(255) as usize]
        }
    }

    pub fn inv(&self, a: u8) -> u8 {
        assert!(a != 0, "gf inv of zero");
        self.exp[255 - self.log[a as usize] as usize]
    }

    pub fn pow(&self, a: u8, mut n: u32) -> u8 {
        if n == 0 {
            return 1;
        }
        if a == 0 {
            return 0;
        }
        let mut result = 1u8;
        let mut base = a;
        while n > 0 {
            if n & 1 == 1 {
                result = self.mul(result, base);
            }
            base = self.mul(base, base);
            n >>= 1;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_div_inverse() {
        let f = Field::new(0x11d);
        for a in 1..=255u8 {
            assert_eq!(f.mul(a, f.inv(a)), 1);
            for b in [1u8, 7, 129, 200] {
                assert_eq!(f.div(f.mul(a, b), b), a);
            }
        }
    }
}
