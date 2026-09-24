//! GF(2^8) arithmetic with the standard Reed-Solomon generator polynomial 0x11D.
//!
//! Multiplication uses cached log/antilog tables so recovery over many
//! candidate shard sets stays fast. Values are bytes interpreted as field
//! elements.

use std::sync::OnceLock;

const PRIMITIVE: u16 = 0x11D;

struct Tables {
    log: [u8; 256],
    antilog: [u8; 256],
}

fn tables() -> &'static Tables {
    static TABLES: OnceLock<Tables> = OnceLock::new();
    TABLES.get_or_init(|| {
        let mut log = [0u8; 256];
        let mut antilog = [0u8; 256];
        let mut x: u16 = 1;
        for i in 0..255 {
            antilog[i] = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= PRIMITIVE;
            }
        }
        Tables { log, antilog }
    })
}

#[inline]
pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let t = tables();
    let la = t.log[a as usize] as u16;
    let lb = t.log[b as usize] as u16;
    t.antilog[((la + lb) % 255) as usize]
}

#[inline]
pub fn inv(a: u8) -> u8 {
    assert!(a != 0, "zero has no multiplicative inverse");
    let t = tables();
    t.antilog[(255 - t.log[a as usize] as u16) as usize]
}

#[inline]
pub fn div(a: u8, b: u8) -> u8 {
    assert!(b != 0, "division by zero");
    if a == 0 {
        return 0;
    }
    let t = tables();
    let la = t.log[a as usize] as u16;
    let lb = t.log[b as usize] as u16;
    t.antilog[((la + 255 - lb) % 255) as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inverse_roundtrip() {
        for a in 1u8..=255 {
            assert_eq!(mul(a, inv(a)), 1, "a={a}");
        }
    }

    #[test]
    fn known_products() {
        assert_eq!(mul(2, 2), 4);
        assert_eq!(mul(0, 200), 0);
        assert_eq!(div(6, 3), 2);
    }
}
