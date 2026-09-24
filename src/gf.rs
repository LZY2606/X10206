//! GF(2^8) 有限域运算，本原多项式 0x11d，生成元 0x02。

pub struct Gf256 {
    exp: [u8; 512],
    log: [u8; 256],
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
        assert!(b != 0, "GF(256) 除零");
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

    pub fn pow(&self, a: u8, n: u32) -> u8 {
        if n == 0 {
            return 1;
        }
        if a == 0 {
            return 0;
        }
        let l = self.log[a as usize] as u32 * n;
        self.exp[(l % 255) as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_div_inverse() {
        let gf = Gf256::new();
        for a in [1u8, 2, 7, 0x53, 0xff] {
            for b in [1u8, 3, 0x11, 0xfe] {
                let p = gf.mul(a, b);
                assert_eq!(gf.div(p, b), a, "a={} b={}", a, b);
                assert_eq!(gf.mul(a, b), gf.mul(b, a));
            }
        }
        assert_eq!(gf.mul(0, 5), 0);
        assert_eq!(gf.mul(9, 1), 9);
        for a in 1..=255u8 {
            assert_eq!(gf.mul(a, gf.inv(a)), 1, "inv({})", a);
        }
    }

    #[test]
    fn pow_basics() {
        let gf = Gf256::new();
        assert_eq!(gf.pow(0, 0), 1);
        assert_eq!(gf.pow(0, 5), 0);
        assert_eq!(gf.pow(2, 8), gf.mul(gf.pow(2, 4), gf.pow(2, 4)));
    }
}
