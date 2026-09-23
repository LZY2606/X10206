//! GF(2^8) 有限域运算，生成多项式 x^8 + x^4 + x^3 + x^2 + 1 (0x11d)。
//! 小有限域 fixture 与生产编码共用同一套表驱动实现。

pub const FIELD_POLY: u16 = 0x11d;

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
                x ^= FIELD_POLY;
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
            let la = self.log[a as usize] as usize;
            let lb = self.log[b as usize] as usize;
            self.exp[la + lb]
        }
    }

    #[inline]
    pub fn inv(&self, a: u8) -> u8 {
        assert!(a != 0, "0 has no inverse");
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

impl Default for Gf256 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_roundtrip() {
        let gf = Gf256::new();
        for a in 1u32..=255 {
            let ai = gf.inv(a as u8);
            assert_eq!(gf.mul(a as u8, ai), 1, "inverse failed for {a}");
        }
    }

    #[test]
    fn known_muls() {
        let gf = Gf256::new();
        // 0x53 * 0xca = 0x01 是 AES 域上的著名恒等式
        assert_eq!(gf.mul(0x53, 0xca), 0x01);
        assert_eq!(gf.div(0x01, 0x53), 0xca);
        assert_eq!(gf.mul(0, 123), 0);
    }
}
