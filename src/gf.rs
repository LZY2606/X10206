//! GF(2^w), w = 1..=8, 使用生成元 2 与原根多项式构造对数表/指数表。
//! 元素用 u16 表示（0 .. 2^w-1），字节逐元素运算。

#[derive(Clone, Debug)]
pub struct Gf {
    pub w: u8,
    pub size: u32,
    pub modulus: u32,
    pub exp: Vec<u16>,
    pub log: Vec<u16>,
}

/// 各位宽对应的原根多项式（无 x^w 系数的低位部分）。
/// w=1: x+1 (0b1)；其余为经典本原多项式。
fn primitive_poly(w: u8) -> u32 {
    match w {
        1 => 0b1,
        2 => 0b11,           // x^2 + x + 1
        3 => 0b1011,         // x^3 + x + 1
        4 => 0b10011,        // x^4 + x + 1
        5 => 0b100101,       // x^5 + x^2 + 1
        6 => 0b1000011,      // x^6 + x + 1
        7 => 0b10001001,     // x^7 + x^3 + 1
        8 => 0b100011101,    // x^8 + x^4 + x^3 + x^2 + 1
        _ => panic!("unsupported GF width {w}"),
    }
}

impl Gf {
    pub fn new(w: u8) -> Self {
        assert!((1..=8).contains(&w), "w must be in 1..=8");
        let size = 1u32 << w;
        let modulus = size | primitive_poly(w);
        let mask = size - 1;

        if w == 1 {
            // GF(2)：生成元 1（== -1）。指数表 [0,1,1,...]。
            let mut exp = vec![0u16; 2 * size as usize + 1];
            let mut log = vec![0u16; size as usize];
            exp[0] = 1;
            exp[1] = 1;
            log[0] = 0;
            log[1] = 0;
            for i in 2..exp.len() {
                exp[i] = 1;
            }
            return Gf { w, size, modulus, exp, log };
        }

        let mut exp = vec![0u16; 2 * size as usize];
        let mut log = vec![0u16; size as usize];
        let mut x: u32 = 1;
        for i in 0..(size - 1) {
            exp[i as usize] = x as u16;
            log[x as usize] = i as u16;
            x <<= 1;
            if x & size != 0 {
                x ^= modulus;
            }
            x &= mask;
        }
        for i in 0..(size - 1) {
            exp[(size - 1 + i) as usize] = exp[i as usize];
        }
        Gf { w, size, modulus, exp, log }
    }

    #[inline]
    pub fn add(&self, a: u16, b: u16) -> u16 {
        a ^ b
    }

    #[inline]
    pub fn mul(&self, a: u16, b: u16) -> u16 {
        if a == 0 || b == 0 {
            0
        } else {
            let la = self.log[a as usize] as u32;
            let lb = self.log[b as usize] as u32;
            self.exp[(la + lb) as usize]
        }
    }

    #[inline]
    pub fn inv(&self, a: u16) -> u16 {
        assert!(a != 0, "zero has no inverse");
        let la = self.log[a as usize] as u32;
        self.exp[(self.size - 1 - la) as usize]
    }

    #[inline]
    pub fn div(&self, a: u16, b: u16) -> u16 {
        self.mul(a, self.inv(b))
    }

    /// 单字节向量点积：r = sum row[j] * vec[j]。
    pub fn dot(&self, row: &[u16], vec: &[u8]) -> u8 {
        let mut acc = 0u16;
        for (a, b) in row.iter().zip(vec.iter()) {
            acc ^= self.mul(*a, *b as u16);
        }
        acc as u8
    }

    pub fn dot_u16(&self, row: &[u16], vec: &[u16]) -> u16 {
        let mut acc = 0u16;
        for (a, b) in row.iter().zip(vec.iter()) {
            acc ^= self.mul(*a, *b);
        }
        acc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_close_for_all_widths() {
        for w in 1..=8u8 {
            let gf = Gf::new(w);
            let n = gf.size;
            for a in 0..n as u16 {
                if a != 0 {
                    assert_eq!(gf.mul(a, gf.inv(a)), 1, "w={w} a={a}");
                }
                assert_eq!(gf.mul(a, 1), a);
                assert_eq!(gf.add(a, a), 0);
            }
        }
    }

    #[test]
    fn distributive_law() {
        let gf = Gf::new(4);
        for a in 0..16u16 {
            for b in 0..16u16 {
                for c in 0..16u16 {
                    assert_eq!(gf.mul(a, gf.add(b, c)), gf.add(gf.mul(a, b), gf.mul(a, c)));
                }
            }
        }
    }
}
