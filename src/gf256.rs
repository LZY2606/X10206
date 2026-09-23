//! GF(2^8) 有限域运算，本原多项式 x^8+x^4+x^3+x^2+1 (0x11D)。
//! 小有限域 fixture 使用：k,m 均很小，解码采用逐字节高斯消元。

pub const PRIMITIVE: u16 = 0x11D;

#[derive(Clone, Copy)]
pub struct Gf {
    pub exp: [u8; 512],
    pub log: [u8; 256],
}

impl Gf {
    pub fn new() -> Self {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for i in 0..255 {
            exp[i] = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= PRIMITIVE;
            }
        }
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }
        Gf { exp, log }
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
        debug_assert!(a != 0);
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

    /// alpha^e
    #[inline]
    pub fn pow(&self, e: usize) -> u8 {
        self.exp[e % 255]
    }
}

impl Default for Gf {
    fn default() -> Self {
        Self::new()
    }
}
