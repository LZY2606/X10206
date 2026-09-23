//! 小有限域 GF(2^n)，供 Reed-Solomon 编解码使用。
//!
//! - GF(16)：每个符号 4 bit，测试 fixture 用（符号取值 0..=15，仍存在 `u8` 中）。
//! - GF(256)：每个符号 1 byte，生产数据用。
//!
//! 加减法是异或；乘法 / 除法由生成元的指数对数表完成。

use std::sync::Arc;

#[derive(Clone)]
pub struct Field {
    pub bits: u32,
    pub modulus: u16,
    size: usize,
    exp: Vec<u8>,
    log: Vec<i32>,
}

impl Field {
    /// `bits` 目前支持 4 与 8。`primitive` 为不可约多项式（不含最高项 x^bits）。
    /// GF(16): x^4+x+1 = 0b0011；GF(256): x^8+x^4+x^3+x^2+1 = 0x11d（不含 x^8 即 0x1d）。
    pub fn new(bits: u32, primitive: u16) -> Arc<Field> {
        assert!(matches!(bits, 4 | 8), "只支持 GF(16) 与 GF(256)");
        let size = 1usize << bits;
        let mut exp = vec![0u8; 2 * size];
        let mut log = vec![-1i32; size];
        let mut x: u16 = 1;
        for i in 0..(size - 1) {
            assert!(log[x as usize] == -1, "生成元 2 的阶不足，多项式不可约性有误");
            exp[i] = x as u8;
            log[x as usize] = i as i32;
            x <<= 1;
            if x & (1 << bits) != 0 {
                x ^= primitive | (1 << bits);
            }
        }
        for i in (size - 1)..(2 * size - 1) {
            exp[i] = exp[i - (size - 1)];
        }
        Arc::new(Field { bits, modulus: primitive, size, exp, log })
    }

    pub fn gf16() -> Arc<Field> {
        Field::new(4, 0b0011)
    }

    pub fn gf256() -> Arc<Field> {
        Field::new(8, 0x11d ^ 0x100)
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn valid_symbol(&self, x: u8) -> bool {
        (x as usize) < self.size
    }

    #[inline]
    pub fn add(&self, a: u8, b: u8) -> u8 {
        a ^ b
    }

    #[inline]
    pub fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }
        let la = self.log[a as usize];
        let lb = self.log[b as usize];
        let e = (la + lb) as usize % (self.size - 1);
        self.exp[e]
    }

    #[inline]
    pub fn pow(&self, a: u8, mut exp: usize) -> u8 {
        if a == 0 {
            return if exp == 0 { 1 } else { 0 };
        }
        if exp == 0 {
            return 1;
        }
        let la = self.log[a as usize];
        exp %= self.size - 1;
        let e = (la as usize * exp) % (self.size - 1);
        self.exp[e]
    }

    #[inline]
    pub fn inv(&self, a: u8) -> u8 {
        assert!(a != 0, "0 无逆元");
        let la = self.log[a as usize] as usize;
        let e = (self.size - 1 - la) % (self.size - 1);
        self.exp[e]
    }

    #[inline]
    pub fn div(&self, a: u8, b: u8) -> u8 {
        self.mul(a, self.inv(b))
    }

    pub fn check_symbols(&self, data: &[u8]) -> bool {
        data.iter().all(|&s| self.valid_symbol(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field_axioms(f: &Field, nonzero: &[u8]) {
        for &a in nonzero {
            assert_eq!(f.add(a, 0), a);
            assert_eq!(f.add(a, a), 0);
            assert_eq!(f.mul(a, 1), a);
            assert_eq!(f.mul(a, f.inv(a)), 1);
            assert_eq!(f.div(a, a), 1);
            for &b in nonzero {
                assert_eq!(f.mul(a, b), f.mul(b, a));
                assert_eq!(f.mul(f.add(a, b), 3), f.add(f.mul(a, 3), f.mul(b, 3)));
            }
        }
    }

    #[test]
    fn gf16_axioms() {
        let f = Field::gf16();
        let v: Vec<u8> = (1..16).collect();
        field_axioms(&f, &v);
    }

    #[test]
    fn gf256_axioms() {
        let f = Field::gf256();
        let v: Vec<u8> = (1..=255).collect();
        field_axioms(&f, &v);
    }
}
