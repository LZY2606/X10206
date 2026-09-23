//! GF(2^8) arithmetic with the AES polynomial 0x11b.
//! Tables are built lazily at first use; the field is small enough that
//! table-driven mul/div is essentially free.

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
                x ^= 0x11b;
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
    assert!(b != 0, "gf division by zero");
    if a == 0 {
        return 0;
    }
    let t = tables();
    let d = t.log[a as usize] as i32 - t.log[b as usize] as i32;
    t.exp[d.rem_euclid(255) as usize]
}

/// alpha^e where alpha = 0x02 is the generator.
pub fn pow_alpha(e: u32) -> u8 {
    tables().exp[(e % 255) as usize]
}

/// Invert a square matrix over GF(2^8) via Gaussian elimination.
pub fn mat_invert(m: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    let n = m.len();
    let mut a: Vec<Vec<u8>> = m
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let mut r = row.clone();
            r.extend((0..n).map(|j| if i == j { 1 } else { 0 }));
            r
        })
        .collect();
    for col in 0..n {
        let pivot = (col..n).find(|&r| a[r][col] != 0)?;
        a.swap(col, pivot);
        let inv_p = div(1, a[col][col]);
        for j in 0..2 * n {
            a[col][j] = mul(a[col][j], inv_p);
        }
        for r in 0..n {
            if r != col && a[r][col] != 0 {
                let f = a[r][col];
                for j in 0..2 * n {
                    a[r][j] = add(a[r][j], mul(f, a[col][j]));
                }
            }
        }
    }
    Some(a.into_iter().map(|r| r[n..].to_vec()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_div_roundtrip() {
        for a in [1u8, 2, 7, 53, 200, 255] {
            for b in [1u8, 3, 99, 254] {
                assert_eq!(div(mul(a, b), b), a);
            }
        }
    }

    #[test]
    fn invert_identity() {
        let id = vec![vec![1, 0], vec![0, 1]];
        assert_eq!(mat_invert(&id), Some(id));
    }
}
