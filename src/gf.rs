#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Gf256(pub u8);

const POLY: u16 = 0x11d;

pub fn multiply(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let mut result = 0u16;
    let mut value = a as u16;
    let mut other = b;
    while other != 0 {
        if other & 1 != 0 {
            result ^= value;
        }
        let high = value & 0x80;
        value <<= 1;
        if high != 0 {
            value ^= POLY;
        }
        other >>= 1;
    }
    result as u8
}

pub fn inverse(value: u8) -> Option<u8> {
    if value == 0 {
        return None;
    }
    (1..=255u16).find(|candidate| multiply(value, *candidate as u8) == 1).map(|v| v as u8)
}

pub fn power(mut base: u8, mut exponent: usize) -> u8 {
    let mut result = 1u8;
    while exponent > 0 {
        if exponent & 1 != 0 {
            result = multiply(result, base);
        }
        base = multiply(base, base);
        exponent >>= 1;
    }
    result
}
