//! GF(2^8) 小有限域算术（生成元 0x03，经典 GF(256) 对数表）。
//!
//! 纠删码 fixture 与编解码都在这个字节域上完成：
//! 每一个字节被视为域中的一个元素，条带 shard 为固定长度的字节向量。

#[rustfmt::skip]
const EXP: [u8; 512] = {
    let mut table = [0u8; 512];
    let mut x: u16 = 1;
    let mut i = 0;
    while i < 255 {
        table[i] = x as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= 0x11d;
        }
        i += 1;
    }
    let mut j = 255;
    while j < 512 {
        table[j] = table[j - 255];
        j += 1;
    }
    table
};

const LOG: [u8; 256] = {
    let mut table = [0u8; 256];
    let mut i = 0;
    while i < 255 {
        table[EXP[i] as usize] = i as u8;
        i += 1;
    }
    table
};

#[inline]
pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        0
    } else {
        let l = LOG[a as usize] as u16 + LOG[b as usize] as u16;
        EXP[(l % 255) as usize]
    }
}

#[inline]
pub fn inv(a: u8) -> u8 {
    assert!(a != 0, "zero has no inverse");
    EXP[255 - LOG[a as usize] as usize]
}

#[inline]
pub fn div(a: u8, b: u8) -> u8 {
    assert!(b != 0, "division by zero");
    if a == 0 {
        0
    } else {
        let l = LOG[a as usize] as i16 - LOG[b as usize] as i16;
        let l = if l < 0 { l + 255 } else { l };
        EXP[l as usize]
    }
}

/// c += a * b（GF 向量乘加）。
pub fn addmul(c: &mut [u8], a: u8, b: &[u8]) {
    for (ci, bi) in c.iter_mut().zip(b) {
        *ci ^= mul(a, *bi);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_inverse_roundtrip() {
        for a in 1u8..=255 {
            assert_eq!(mul(a, inv(a)), 1);
            assert_eq!(div(a, a), 1);
            assert_eq!(mul(mul(a, 7), inv(7)), a);
        }
    }

    #[test]
    fn zero_rules() {
        assert_eq!(mul(0, 255), 0);
        assert_eq!(mul(255, 0), 0);
        assert_eq!(div(0, 255), 0);
    }
}
