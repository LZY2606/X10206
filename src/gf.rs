//! GF(2^8) arithmetic, irreducible polynomial 0x11d, generator 0x02.

const POLY: u16 = 0x11d;

pub struct Tables {
    pub exp: [u8; 512],
    pub log: [u8; 256],
}

pub static TABLES: std::sync::OnceLock<Tables> = std::sync::OnceLock::new();

pub fn tables() -> &'static Tables {
    TABLES.get_or_init(|| {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for i in 0..255 {
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
    assert!(b != 0, "gf div by zero");
    if a == 0 {
        return 0;
    }
    let t = tables();
    let l = t.log[a as usize] as i32 - t.log[b as usize] as i32;
    t.exp[(l.rem_euclid(255)) as usize]
}

pub fn inv(a: u8) -> u8 {
    assert!(a != 0, "gf inv of zero");
    let t = tables();
    t.exp[255 - t.log[a as usize] as usize]
}

pub fn pow(a: u8, n: u32) -> u8 {
    if n == 0 {
        return 1;
    }
    if a == 0 {
        return 0;
    }
    let t = tables();
    let l = (t.log[a as usize] as u64 * n as u64) % 255;
    t.exp[l as usize]
}

/// Invert a square matrix over GF(2^8) via Gauss-Jordan. Returns None if singular.
pub fn mat_invert(m: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    let n = m.len();
    let mut aug: Vec<Vec<u8>> = m
        .iter()
        .enumerate()
        .map(|(r, row)| {
            let mut v = row.clone();
            v.extend((0..n).map(|c| if c == r { 1 } else { 0 }));
            v
        })
        .collect();
    for col in 0..n {
        let pivot = (col..n).find(|&r| aug[r][col] != 0)?;
        aug.swap(col, pivot);
        let inv_p = inv(aug[col][col]);
        for c in 0..2 * n {
            aug[col][c] = mul(aug[col][c], inv_p);
        }
        for r in 0..n {
            if r != col && aug[r][col] != 0 {
                let f = aug[r][col];
                for c in 0..2 * n {
                    aug[r][c] = add(aug[r][c], mul(f, aug[col][c]));
                }
            }
        }
    }
    Some(aug.into_iter().map(|row| row[n..].to_vec()).collect())
}

/// Multiply matrix (rows x cols) by vector of shard bytes column-wise.
pub fn mat_mul_vec(mat: &[Vec<u8>], shards: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let shard_len = shards[0].len();
    mat.iter()
        .map(|row| {
            let mut out = vec![0u8; shard_len];
            for (coef, shard) in row.iter().zip(shards.iter()) {
                if *coef == 0 {
                    continue;
                }
                if *coef == 1 {
                    for (o, s) in out.iter_mut().zip(shard.iter()) {
                        *o ^= s;
                    }
                } else {
                    for (o, s) in out.iter_mut().zip(shard.iter()) {
                        *o ^= mul(*coef, *s);
                    }
                }
            }
            out
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_laws() {
        assert_eq!(mul(0, 5), 0);
        assert_eq!(mul(1, 7), 7);
        for a in [1u8, 2, 53, 200, 255] {
            assert_eq!(mul(a, inv(a)), 1);
            assert_eq!(div(a, a), 1);
        }
        assert_eq!(pow(2, 8), 0x1d);
    }

    #[test]
    fn matrix_inverse_roundtrip() {
        let m = vec![vec![1, 0, 0], vec![1, 1, 1], vec![1, 2, 4]];
        let inv = mat_invert(&m).unwrap();
        let prod: Vec<Vec<u8>> = (0..3)
            .map(|r| {
                (0..3)
                    .map(|c| {
                        (0..3).fold(0u8, |acc, i| add(acc, mul(m[r][i], inv[i][c])))
                    })
                    .collect()
            })
            .collect();
        assert_eq!(prod, vec![vec![1, 0, 0], vec![0, 1, 0], vec![0, 0, 1]]);
    }
}
