//! GF(2^8) 算术，约化多项式 0x11d，本原元 2。

const POLY: u16 = 0x11d;

const fn build_exp() -> [u8; 512] {
    let mut table = [0u8; 512];
    let mut x: u16 = 1;
    let mut i = 0usize;
    while i < 255 {
        table[i] = x as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= POLY;
        }
        i += 1;
    }
    while i < 512 {
        table[i] = table[i - 255];
        i += 1;
    }
    table
}

const fn build_log() -> [u8; 256] {
    let exp = build_exp();
    let mut table = [0u8; 256];
    let mut i = 0usize;
    while i < 255 {
        table[exp[i] as usize] = i as u8;
        i += 1;
    }
    table
}

pub static EXP: [u8; 512] = build_exp();
pub static LOG: [u8; 256] = build_log();

pub fn add(a: u8, b: u8) -> u8 {
    a ^ b
}

pub fn sub(a: u8, b: u8) -> u8 {
    a ^ b
}

pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        0
    } else {
        EXP[LOG[a as usize] as usize + LOG[b as usize] as usize]
    }
}

pub fn div(a: u8, b: u8) -> u8 {
    assert!(b != 0, "GF(2^8) 除零");
    if a == 0 {
        0
    } else {
        let la = LOG[a as usize] as i32;
        let lb = LOG[b as usize] as i32;
        EXP[((la - lb + 255) % 255) as usize]
    }
}

pub fn inv(a: u8) -> u8 {
    div(1, a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_div_inverse() {
        for a in 1..=255u8 {
            assert_eq!(mul(a, inv(a)), 1);
            for b in [1u8, 3, 7, 129, 255] {
                assert_eq!(div(mul(a, b), b), a);
            }
        }
    }

    #[test]
    fn exp_log_tables_consistent() {
        assert_eq!(EXP[0], 1);
        assert_eq!(EXP[255], 1);
        for i in 0..255usize {
            assert_eq!(LOG[EXP[i] as usize] as usize, i);
        }
    }
}
