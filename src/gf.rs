//! GF(2^8) arithmetic over the AES field polynomial 0x11D.
//!
//! The whole recovery bay works on a tiny finite field so that test fixtures
//! stay human-readable and every byte can be verified independently.

const MODULUS: u16 = 0x11D;

/// `exp[i]` = primitive element 2 raised to the i-th power (cyclic period 255).
#[derive(Debug, Clone)]
pub struct GfTables {
    pub exp: [u8; 512],
    pub log: [u8; 256],
}

impl GfTables {
    /// Build the log/antilog tables. log(0) is left as zero and must never be
    /// looked up by the callers.
    pub fn init() -> Self {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for i in 0..255 {
            exp[i] = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= MODULUS;
            }
        }
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }
        GfTables { exp, log }
    }

    #[inline]
    pub fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            let la = self.log[a as usize] as usize;
            let lb = self.log[b as usize] as usize;
            self.exp[la + lb]
        }
    }

    #[inline]
    pub fn inv(&self, a: u8) -> u8 {
        debug_assert!(a != 0, "inverse of zero");
        let l = self.log[a as usize] as usize;
        self.exp[255 - l]
    }

    #[inline]
    pub fn div(&self, a: u8, b: u8) -> u8 {
        if a == 0 {
            0
        } else {
            self.mul(a, self.inv(b))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_roundtrip() {
        let t = GfTables::init();
        for a in 1u16..=255 {
            let a = a as u8;
            assert_eq!(t.mul(a, t.inv(a)), 1, "a={a}");
            assert_eq!(t.mul(a, 0), 0);
            assert_eq!(t.mul(0, a), 0);
            assert_eq!(t.div(a, a), 1);
        }
        // 0x57 * 0x83 = 0xc1 in the AES field.
        assert_eq!(t.mul(0x57, 0x83), 0xc1);
    }
}
