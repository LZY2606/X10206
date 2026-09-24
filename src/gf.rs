//! 小阶有限域 GF(2^w) 算术（w <= 8），由版本化编码参数指定。

#[derive(Clone, Debug)]
pub struct Field {
    pub bits: u8,
    pub poly: u16,
    exp: Vec<u8>,
    log: Vec<u8>,
}

impl Field {
    /// `poly` 为本原多项式（含最高位），例如 GF(2^8) 的 0x11d、GF(2^4) 的 0x13。
    pub fn new(bits: u8, poly: u16) -> Self {
        assert!(bits >= 2 && bits <= 8, "field bits out of range");
        let size = 1usize << bits;
        let order = size - 1;
        let mut exp = vec![0u8; size];
        let mut log = vec![0u8; size];
        let mut x: u16 = 1;
        for i in 0..order {
            exp[i] = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & (size as u16) != 0 {
                x ^= poly;
            }
            x &= (size - 1) as u16;
        }
        assert_eq!(x, 1, "polynomial {poly:#x} is not primitive for GF(2^{bits})");
        Field { bits, poly, exp, log }
    }

    pub fn order(&self) -> usize {
        (1usize << self.bits) - 1
    }

    pub fn add(&self, a: u8, b: u8) -> u8 {
        a ^ b
    }

    pub fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }
        let order = self.order();
        let s = self.log[a as usize] as usize + self.log[b as usize] as usize;
        self.exp[if s >= order { s - order } else { s }]
    }

    pub fn div(&self, a: u8, b: u8) -> u8 {
        assert!(b != 0, "division by zero in GF");
        if a == 0 {
            return 0;
        }
        let order = self.order() as i32;
        let d = self.log[a as usize] as i32 - self.log[b as usize] as i32;
        let d = if d < 0 { d + order } else { d } as usize;
        self.exp[d]
    }

    pub fn inv(&self, a: u8) -> u8 {
        self.div(1, a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf256_mul_div_roundtrip() {
        let f = Field::new(8, 0x11d);
        for a in 1..=255u8 {
            for b in [1u8, 3, 7, 129, 255] {
                assert_eq!(f.div(f.mul(a, b), b), a);
            }
        }
    }

    #[test]
    fn gf16_mul_div_roundtrip() {
        let f = Field::new(4, 0x13);
        for a in 1..16u8 {
            for b in 1..16u8 {
                assert_eq!(f.div(f.mul(a, b), b), a);
                assert!(f.mul(a, b) < 16);
            }
        }
    }
}
