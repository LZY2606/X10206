
//! GF(2^8) 有限域运算，生成多项式 x^8 + x^4 + x^3 + x^2 + 1 (0x11d)。

const GENERATOR: u16 = 0x11d;

const fn build_exp() -> ([u8; 512], [u8; 256], [u8; 256], [[u8; 256]; 256]) {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut inv = [0u8; 256];
    let mut mul = [[0u8; 256]; 256];

    let mut x: u16 = 1;
    let mut i = 0usize;
    while i < 255 {
        exp[i] = x as u8;
        log[x as usize] = i as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= GENERATOR;
        }
        i += 1;
    }
    let mut j = 255;
    while j < 512 {
        exp[j] = exp[j - 255];
        j += 1;
    }

    inv[0] = 0;
    let mut a = 1usize;
    while a < 256 {
        inv[a] = exp[255 - log[a] as usize];
        a += 1;
    }

    let mut p = 0usize;
    while p < 256 {
        let mut q = 0usize;
        while q < 256 {
            mul[p][q] = if p == 0 || q == 0 {
                0
            } else {
                exp[log[p] as usize + log[q] as usize]
            };
            q += 1;
        }
        p += 1;
    }

    (exp, log, inv, mul)
}

static TABLES: ([u8; 512], [u8; 256], [u8; 256], [[u8; 256]; 256]) = build_exp();

#[inline]
pub fn mul(a: u8, b: u8) -> u8 {
    TABLES.3[a as usize][b as usize]
}

#[inline]
pub fn inv(a: u8) -> u8 {
    TABLES.2[a as usize]
}

#[inline]
pub fn div(a: u8, b: u8) -> u8 {
    debug_assert_ne!(b, 0);
    if a == 0 {
        0
    } else {
        let log = &TABLES.1;
        let exp = &TABLES.0;
        exp[(log[a as usize] as i16 - log[b as usize] as i16 + 255) as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inverse_and_mul_roundtrip() {
        for a in 1u16..=255 {
            let ai = inv(a as u8);
            assert_eq!(mul(a as u8, ai), 1, "a={a}");
            assert_eq!(div(1, a as u8), ai);
        }
    }

    #[test]
    fn distributive() {
        for a in 0u16..256 {
            for b in 0u16..256 {
                for c in 0u16..256 {
                    let lhs = mul(a as u8, b as u8) ^ mul(a as u8, c as u8);
                    let rhs = mul(a as u8, b as u8 ^ c as u8);
                    assert_eq!(lhs, rhs);
                }
            }
        }
    }

    #[test]
    fn zero_rules() {
        assert_eq!(mul(0, 200), 0);
        assert_eq!(mul(200, 0), 0);
        assert_eq!(div(0, 200), 0);
    }
}
