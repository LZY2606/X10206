//! GF(2^8) 有限域运算，多项式 0x11d，生成元 2。
use std::sync::OnceLock;

struct Tables {
    exp: [u8; 512],
    log: [u8; 256],
}

static TABLES: OnceLock<Tables> = OnceLock::new();

fn tables() -> &'static Tables {
    TABLES.get_or_init(|| {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for i in 0..255usize {
            exp[i] = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= 0x11d;
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
    assert!(b != 0, "gf div by zero");
    if a == 0 {
        return 0;
    }
    let t = tables();
    t.exp[(t.log[a as usize] as usize + 255 - t.log[b as usize] as usize) % 255]
}

pub fn inv(a: u8) -> u8 {
    div(1, a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_inv_roundtrip() {
        for a in 1..=255u8 {
            assert_eq!(mul(a, inv(a)), 1);
        }
        assert_eq!(add(0x53, 0xca), 0x99);
        assert_eq!(div(0, 7), 0);
    }
}
