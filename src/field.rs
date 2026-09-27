//! GF(2^8) arithmetic, irreducible polynomial 0x11d, generator 2.
use std::sync::OnceLock;

const POLY: u16 = 0x11d;

struct Tables {
    exp: [u8; 512],
    log: [u8; 256],
}

fn tables() -> &'static Tables {
    static T: OnceLock<Tables> = OnceLock::new();
    T.get_or_init(|| {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for i in 0..255usize {
            exp[i] = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= POLY;
            }
        }
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }
        Tables { exp, log }
    })
}

pub fn add(a: u8, b: u8) -> u8 {
    a ^ b
}

pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let t = tables();
    t.exp[t.log[a as usize] as usize + t.log[b as usize] as usize]
}

pub fn div(a: u8, b: u8) -> u8 {
    assert!(b != 0, "GF division by zero");
    if a == 0 {
        return 0;
    }
    let t = tables();
    let d = t.log[a as usize] as i32 - t.log[b as usize] as i32;
    t.exp[d.rem_euclid(255) as usize]
}

pub fn inv(a: u8) -> u8 {
    div(1, a)
}

pub fn pow(a: u8, mut e: u32) -> u8 {
    let mut acc = 1u8;
    let mut base = a;
    while e > 0 {
        if e & 1 == 1 {
            acc = mul(acc, base);
        }
        base = mul(base, base);
        e >>= 1;
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_laws() {
        for a in [0u8, 1, 2, 7, 129, 255] {
            for b in [0u8, 1, 3, 200] {
                assert_eq!(add(a, b), a ^ b);
                if b != 0 {
                    assert_eq!(div(mul(a, b), b), a);
                }
            }
        }
        assert_eq!(mul(2, 128), 0x1d); // reduction by polynomial
        for a in 1..=255u8 {
            assert_eq!(mul(a, inv(a)), 1);
        }
    }
}
