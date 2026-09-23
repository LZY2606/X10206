//! Arithmetic in GF(2^8) with primitive polynomial 0x11d (x^8+x^4+x^3+x^2+1).
//! Used by the Cauchy Reed-Solomon coding layer.

const MUL: u16 = 0x11d;

pub fn add(a: u8, b: u8) -> u8 {
    a ^ b
}

pub fn mul(mut a: u8, mut b: u8) -> u8 {
    let mut acc: u16 = 0;
    while b != 0 {
        if b & 1 != 0 {
            acc ^= a as u16;
        }
        let hi = a & 0x80 != 0;
        a <<= 1;
        if hi {
            a ^= (MUL & 0xff) as u8;
        }
        b >>= 1;
    }
    acc as u8
}

pub fn inv(a: u8) -> Option<u8> {
    if a == 0 {
        return None;
    }
    let mut r = 1u8;
    let mut base = a;
    let mut exp = 254u16;
    while exp > 0 {
        if exp & 1 != 0 {
            r = mul(r, base);
        }
        base = mul(base, base);
        exp >>= 1;
    }
    Some(r)
}

pub fn div(a: u8, b: u8) -> Option<u8> {
    inv(b).map(|bi| mul(a, bi))
}

pub fn dot(xs: &[u8], ys: &[u8]) -> u8 {
    let mut acc = 0u8;
    for (x, y) in xs.iter().zip(ys.iter()) {
        acc ^= mul(*x, *y);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inverse_roundtrip() {
        for a in 1u16..=255 {
            let a = a as u8;
            assert_eq!(mul(a, inv(a).unwrap()), 1, "inverse failed for {a}");
        }
    }

    #[test]
    fn field_laws() {
        for a in 1u16..=255 {
            let a = a as u8;
            for b in [0u8, 1, 7, 255, 123] {
                assert_eq!(mul(a, b), mul(b, a));
                assert_eq!(mul(a, add(a, b)) ^ mul(a, a), mul(a, b));
            }
        }
        assert_eq!(mul(0, 123), 0);
        assert_eq!(mul(7, 1), 7);
        assert_eq!(div(6, 3).map(|q| mul(q, 3)), Some(6));
    }
}
