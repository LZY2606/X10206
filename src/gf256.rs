//! GF(2^8) arithmetic with the Reed-Solomon primitive polynomial 0x11d.
//!
//! The generator is 2, so exp/log tables cover the whole nonzero field.

#[derive(Clone, Copy, Debug)]
pub struct Gf256;

static mut EXP: [u8; 512] = [0u8; 512];
static mut LOG: [u8; 256] = [0u8; 256];
static INIT_STATE: std::sync::Once = std::sync::Once::new();

impl Gf256 {
    pub fn init() {
        // SAFETY: tables are u8 arrays written once before any concurrent read.
        unsafe {
            INIT_STATE.call_once(|| {
                let mut x: u16 = 1;
                for i in 0..255u16 {
                    EXP[i as usize] = x as u8;
                    LOG[x as usize] = i as u8;
                    x <<= 1;
                    if x & 0x100 != 0 {
                        x ^= 0x11d;
                    }
                }
                for i in 255..512u16 {
                    EXP[i as usize] = EXP[(i - 255) as usize];
                }
            });
        }
    }

    #[inline]
    pub fn mul(a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }
        unsafe {
            let la = LOG[a as usize] as u16;
            let lb = LOG[b as usize] as u16;
            EXP[(la + lb) as usize]
        }
    }

    #[inline]
    pub fn inv(a: u8) -> u8 {
        debug_assert!(a != 0, "zero has no inverse");
        unsafe { EXP[(255 - LOG[a as usize] as u16) as usize] }
    }

    #[inline]
    pub fn div(a: u8, b: u8) -> u8 {
        if a == 0 {
            return 0;
        }
        debug_assert!(b != 0);
        unsafe {
            let la = LOG[a as usize] as i32;
            let lb = LOG[b as usize] as i32;
            let mut e = la - lb;
            if e < 0 {
                e += 255;
            }
            EXP[e as usize]
        }
    }

    #[inline]
    pub fn pow(base: u8, exp: u32) -> u8 {
        if base == 0 {
            return 0;
        }
        unsafe {
            let l = LOG[base as usize] as u32;
            EXP[((l * exp) % 255) as usize]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_round_trip() {
        Gf256::init();
        for a in 1u8..=255u8 {
            assert_eq!(Gf256::mul(a, Gf256::inv(a)), 1, "inverse of {a}");
        }
        assert_eq!(Gf256::mul(2, 2), 4);
        // 2^8 reduces through 0x11d -> 0x1d
        assert_eq!(Gf256::pow(2, 8), 0x1d);
        assert_eq!(Gf256::div(Gf256::mul(7, 123), 123), 7);
    }
}
