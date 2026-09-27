//! GF(2^8) 有限域运算。编码参数按版本选择不可约多项式与生成元。

#[derive(Clone)]
pub struct Field {
    exp: [u8; 512],
    log: [u8; 256],
}

fn mul_raw(mut a: u16, mut b: u16, poly: u16) -> u16 {
    let mut r: u16 = 0;
    while b > 0 {
        if b & 1 == 1 {
            r ^= a;
        }
        b >>= 1;
        a <<= 1;
        if a & 0x100 != 0 {
            a ^= poly;
        }
    }
    r & 0xff
}

impl Field {
    pub fn new(poly: u16, generator: u8) -> Field {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for i in 0..255usize {
            exp[i] = x as u8;
            log[x as usize] = i as u8;
            x = mul_raw(x, generator as u16, poly);
        }
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }
        Field { exp, log }
    }

    pub fn add(a: u8, b: u8) -> u8 {
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
        assert!(b != 0, "GF div by zero");
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
        let f = Field::new(0x11d, 2);
        for a in 1..=255u8 {
            assert_eq!(f.mul(a, f.inv(a)), 1, "a={a}");
        }
        assert_eq!(f.mul(0x53, 0xca), f.div(0x53, f.inv(0xca)));
        assert_eq!(Field::add(0x57, 0x83), 0xd4);
    }

    #[test]
    fn generator_cycles() {
        let f = Field::new(0x11d, 2);
        assert_eq!(f.pow(2, 255), 1);
        assert_ne!(f.pow(2, 254), 1);
        let g = Field::new(0x11b, 3);
        assert_eq!(g.pow(3, 255), 1);
    }
}
