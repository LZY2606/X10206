//! GF(2^8) arithmetic with primitive polynomial 0x11d
//! (x^8 + x^4 + x^3 + x^2 + 1), generator 2.

use std::sync::OnceLock;

static TABLES: OnceLock<([u8; 512], [u8; 256])> = OnceLock::new();

fn tables() -> &'static ([u8; 512], [u8; 256]) {
    TABLES.get_or_init(|| {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for i in 0..256 {
            exp[i] = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= 0x11d;
            }
        }
        for i in 256..512 {
            exp[i] = exp[i - 255];
        }
        (exp, log)
    })
}

#[inline]
pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let (exp, log) = tables();
    let s = log[a as usize] as u16 + log[b as usize] as u16;
    exp[(s % 255) as usize]
}

#[inline]
pub fn inv(a: u8) -> u8 {
    let (exp, log) = tables();
    exp[(255 - log[a as usize] as usize) % 255]
}

#[inline]
pub fn div(a: u8, b: u8) -> u8 {
    if a == 0 {
        0
    } else {
        mul(a, inv(b))
    }
}
