//! 小阶有限域 GF(2^w) 运算，支持按本原多项式构造（fixture 用 GF(2^4)，生产用 GF(2^8)）。

#[derive(Clone, Debug)]
pub struct Field {
    pub degree: u8,
    pub order: usize,
    exp: Vec<u16>,
    log: Vec<u16>,
}

impl Field {
    /// `prim_poly` 需包含最高次项比特，例如 GF(2^4) 用 0b1_0011，GF(2^8) 用 0x11d。
    pub fn new(degree: u8, prim_poly: u16) -> anyhow::Result<Field> {
        anyhow::ensure!((2..=12).contains(&degree), "不支持的域阶 degree={degree}");
        let order = 1usize << degree;
        let mask = (order - 1) as u16;
        let mut exp = vec![0u16; 2 * (order - 1)];
        let mut log = vec![0u16; order];
        let mut x: u16 = 1;
        for (i, slot) in exp.iter_mut().enumerate().take(order - 1) {
            *slot = x;
            log[x as usize] = i as u16;
            x <<= 1;
            if x as usize & order != 0 {
                x ^= prim_poly;
            }
            x &= mask;
        }
        anyhow::ensure!(x == 1, "本原多项式 {prim_poly:#x} 下 2 不是本原元");
        for i in 0..(order - 1) {
            exp[i + order - 1] = exp[i];
        }
        Ok(Field { degree, order, exp, log })
    }

    pub fn add(&self, a: u16, b: u16) -> u16 {
        a ^ b
    }

    pub fn mul(&self, a: u16, b: u16) -> u16 {
        if a == 0 || b == 0 {
            0
        } else {
            self.exp[self.log[a as usize] as usize + self.log[b as usize] as usize]
        }
    }

    pub fn inv(&self, a: u16) -> u16 {
        debug_assert!(a != 0);
        self.exp[self.order - 1 - self.log[a as usize] as usize]
    }
}

/// 版本化编码参数：codec 字符串 -> 有限域。
pub fn field_for_codec(codec: &str) -> anyhow::Result<Field> {
    match codec {
        "rs-gf16-v1" => Field::new(4, 0b1_0011),
        "rs-gf256-v1" => Field::new(8, 0x11d),
        other => anyhow::bail!("未知编码版本: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf16_mul_inv_roundtrip() {
        let f = Field::new(4, 0b1_0011).unwrap();
        for a in 1..16u16 {
            assert_eq!(f.mul(a, f.inv(a)), 1);
        }
        assert_eq!(f.mul(3, 5), 15);
    }

    #[test]
    fn gf256_mul_inv_roundtrip() {
        let f = Field::new(8, 0x11d).unwrap();
        for a in 1..256u16 {
            assert_eq!(f.mul(a, f.inv(a)), 1);
        }
    }
}
