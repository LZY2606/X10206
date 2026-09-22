//! GF(2^8) arithmetic with primitive polynomial 0x11d (x^8 + x^4 + x^3 + x^2 + 1).

fn build_tables() -> ([u8; 256], [u8; 256]) {
    // exp[i] = alpha^i for i in 0..=255 (exp[255] == exp[0] == 1).
    let mut exp = [0u8; 256];
    let mut log = [0u8; 256];
    let mut x: u16 = 1;
    for i in 0..256 {
        exp[i] = x as u8;
        if i != 255 {
            log[x as usize] = i as u8;
        }
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= 0x11d;
        }
    }
    (exp, log)
}

thread_local! {
    static TABLES: ([u8; 256], [u8; 256]) = build_tables();
}

pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    TABLES.with(|(exp, log)| {
        let la = log[a as usize] as u16;
        let lb = log[b as usize] as u16;
        exp[((la + lb) % 255) as usize]
    })
}

pub fn inv(a: u8) -> u8 {
    debug_assert!(a != 0);
    TABLES.with(|(exp, log)| exp[255 - log[a as usize] as usize])
}

pub fn div(a: u8, b: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    debug_assert!(b != 0);
    TABLES.with(|(exp, log)| {
        let la = log[a as usize] as i16;
        let lb = log[b as usize] as i16;
        let mut s = la - lb;
        if s < 0 {
            s += 255;
        }
        exp[s as usize]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_roundtrip() {
        for a in 1u16..=255 {
            let a = a as u8;
            assert_eq!(mul(a, inv(a)), 1);
        }
    }

    #[test]
    fn known_values() {
        assert_eq!(mul(2, 2), 4);
        assert_eq!(mul(3, 3), 5); // 0b11 * 0b11 mod 0x11d
        assert_eq!(div(mul(0x53, 0xca), 0xca), 0x53);
    }
}
