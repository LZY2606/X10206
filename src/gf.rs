//! GF(2^8) 有限域运算，生成元 2，不可约多项式 0x11d。

const POLY: u16 = 0x11d;

pub struct Tables {
    pub exp: [u8; 512],
    pub log: [u8; 256],
}

const fn build_tables() -> Tables {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut x: u16 = 1;
    let mut i: usize = 0;
    while i < 255 {
        exp[i] = x as u8;
        log[x as usize] = i as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= POLY;
        }
        i += 1;
    }
    let mut j = 255;
    while j < 512 {
        exp[j] = exp[j - 255];
        j += 1;
    }
    Tables { exp, log }
}

pub static TABLES: Tables = build_tables();

pub fn add(a: u8, b: u8) -> u8 {
    a ^ b
}

pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    TABLES.exp[TABLES.log[a as usize] as usize + TABLES.log[b as usize] as usize]
}

pub fn div(a: u8, b: u8) -> u8 {
    assert!(b != 0, "GF(256) 除零");
    if a == 0 {
        return 0;
    }
    let d = TABLES.log[a as usize] as i32 - TABLES.log[b as usize] as i32;
    TABLES.exp[((d + 255) % 255) as usize]
}

pub fn inv(a: u8) -> u8 {
    assert!(a != 0, "GF(256) 对零求逆");
    TABLES.exp[255 - TABLES.log[a as usize] as usize]
}

pub fn pow(a: u8, mut p: usize) -> u8 {
    if p == 0 {
        return 1;
    }
    if a == 0 {
        return 0;
    }
    let mut result = 1u8;
    let mut base = a;
    while p > 0 {
        if p & 1 == 1 {
            result = mul(result, base);
        }
        base = mul(base, base);
        p >>= 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_are_well_formed() {
        assert_eq!(TABLES.exp[0], 1);
        assert_eq!(TABLES.exp[255], 1);
        for (i, e) in TABLES.exp.iter().enumerate().take(255) {
            if *e != 0 {
                assert_eq!(TABLES.log[*e as usize] as usize, i);
            }
        }
    }

    #[test]
    fn mul_div_roundtrip() {
        for a in 0u16..=255 {
            for &b in &[1u16, 2, 7, 42, 128, 255] {
                let (a, b) = (a as u8, b as u8);
                assert_eq!(div(mul(a, b), b), a);
                if a != 0 {
                    assert_eq!(mul(a, inv(a)), 1);
                }
            }
        }
    }

    #[test]
    fn pow_basic() {
        assert_eq!(pow(0, 0), 1);
        assert_eq!(pow(2, 8), 1);
        assert_eq!(pow(3, 255), 1);
    }
}
