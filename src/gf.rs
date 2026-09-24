//! GF(2^8) 有限域运算，约化多项式 0x11d，生成元 2。

use std::sync::OnceLock;

pub struct Field {
    exp: [u8; 512],
    log: [u8; 256],
}

impl Field {
    fn new() -> Self {
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
        for i in 255..512usize {
            exp[i] = exp[i - 255];
        }
        Field { exp, log }
    }

    pub fn add(&self, a: u8, b: u8) -> u8 {
        a ^ b
    }

    pub fn sub(&self, a: u8, b: u8) -> u8 {
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
        assert_ne!(b, 0, "GF 除数不能为 0");
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

    pub fn pow(&self, a: u8, n: usize) -> u8 {
        if n == 0 {
            return 1;
        }
        if a == 0 {
            return 0;
        }
        let e = (self.log[a as usize] as usize * n) % 255;
        self.exp[e]
    }
}

static GF: OnceLock<Field> = OnceLock::new();

pub fn gf() -> &'static Field {
    GF.get_or_init(Field::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_div_roundtrip() {
        let f = gf();
        for a in [1u8, 2, 7, 53, 200, 255] {
            for b in [1u8, 3, 19, 128, 254] {
                let p = f.mul(a, b);
                assert_eq!(f.div(p, b), a, "a={a} b={b}");
            }
        }
    }

    #[test]
    fn add_is_xor_and_self_inverse() {
        let f = gf();
        assert_eq!(f.add(0x53, 0xca), 0x99);
        assert_eq!(f.sub(0x53, 0x53), 0);
    }

    #[test]
    fn pow_matches_repeated_mul() {
        let f = gf();
        let mut acc = 1u8;
        for _ in 0..7 {
            acc = f.mul(acc, 5);
        }
        assert_eq!(f.pow(5, 7), acc);
    }
}
