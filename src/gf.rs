//! GF(2^w) 有限域运算，支持 w=4（小有限域 fixture）与 w=8。

#[derive(Clone, Debug)]
pub struct Field {
    pub w: u8,
    pub size: usize,
    exp: Vec<u8>,
    log: Vec<u8>,
}

impl Field {
    pub fn new(w: u8) -> Self {
        let prim: u16 = match w {
            4 => 0b10011,        // x^4 + x + 1
            8 => 0b1_0001_1101,  // x^8 + x^4 + x^3 + x + 1
            _ => panic!("不支持的有限域宽度: {w}"),
        };
        let size = 1usize << w;
        let mut exp = vec![0u8; size * 2];
        let mut log = vec![0u8; size];
        let mut x: u16 = 1;
        for i in 0..(size - 1) {
            exp[i] = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & (size as u16) != 0 {
                x ^= prim;
            }
        }
        for i in (size - 1)..(size * 2) {
            exp[i] = exp[i - (size - 1)];
        }
        Field { w, size, exp, log }
    }

    pub fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            self.exp[self.log[a as usize] as usize + self.log[b as usize] as usize]
        }
    }

    pub fn inv(&self, a: u8) -> u8 {
        assert!(a != 0, "0 没有乘法逆元");
        self.exp[self.size - 1 - self.log[a as usize] as usize]
    }

    /// 字节串 -> 域元素序列。w=8 时一一对应；w=4 时每字节拆成高/低两个半字节。
    pub fn unpack(&self, bytes: &[u8]) -> Vec<u8> {
        match self.w {
            8 => bytes.to_vec(),
            4 => {
                let mut out = Vec::with_capacity(bytes.len() * 2);
                for b in bytes {
                    out.push(b >> 4);
                    out.push(b & 0x0f);
                }
                out
            }
            _ => unreachable!(),
        }
    }

    /// 域元素序列 -> 字节串。
    pub fn pack(&self, elems: &[u8]) -> Vec<u8> {
        match self.w {
            8 => elems.to_vec(),
            4 => {
                assert!(elems.len() % 2 == 0, "元素个数必须为偶数");
                elems
                    .chunks_exact(2)
                    .map(|c| (c[0] << 4) | c[1])
                    .collect()
            }
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf16_known_values() {
        let f = Field::new(4);
        // α * α^3 = α^4 = α + 1 = 3 (mod x^4+x+1)
        assert_eq!(f.mul(2, 8), 3);
        // 3 = α^4，故 3*3 = α^8 = α^2 + 1 = 5
        assert_eq!(f.mul(3, 3), 5);
        for a in 1..16u8 {
            assert_eq!(f.mul(a, f.inv(a)), 1, "inv 校验失败: {a}");
        }
    }

    #[test]
    fn gf256_roundtrip() {
        let f = Field::new(8);
        for a in 1..=255u8 {
            assert_eq!(f.mul(a, f.inv(a)), 1);
        }
    }

    #[test]
    fn pack_unpack_roundtrip() {
        let f = Field::new(4);
        let bytes = vec![0xab, 0xcd, 0x01];
        assert_eq!(f.pack(&f.unpack(&bytes)), bytes);
        let f8 = Field::new(8);
        assert_eq!(f8.pack(&f8.unpack(&bytes)), bytes);
    }
}
