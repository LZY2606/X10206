//! GF(2^8) 小有限域运算，生成多项式 x^8 + x^4 + x^3 + x + 1 (0x11d)。
//! 所有擦除码计算都在这个域内完成；fixture 使用小分片以便穷举验证。

const POLY: u16 = 0x11d;

const fn build_tables() -> ([u8; 512], [u8; 256]) {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut x: u16 = 1;
    let mut i = 0;
    while i < 255 {
        exp[i] = x as u8;
        log[x as usize] = i as u8;
        let mut y = x << 1;
        if y & 0x100 != 0 {
            y ^= POLY;
        }
        x = y;
        i += 1;
    }
    let mut j = 255;
    while j < 512 {
        exp[j] = exp[j - 255];
        j += 1;
    }
    (exp, log)
}

const TABLES: ([u8; 512], [u8; 256]) = build_tables();

/// 域内乘法。
pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let la = TABLES.1[a as usize] as u16;
    let lb = TABLES.1[b as usize] as u16;
    TABLES.0[(la + lb) as usize]
}

/// 域内求逆，0 没有逆元（返回 None）。
pub fn inv(a: u8) -> Option<u8> {
    if a == 0 {
        return None;
    }
    let l = TABLES.1[a as usize] as usize;
    Some(TABLES.0[255 - l])
}

/// 域内除法 a/b。
pub fn div(a: u8, b: u8) -> Option<u8> {
    if b == 0 {
        return None;
    }
    if a == 0 {
        return Some(0);
    }
    let la = TABLES.1[a as usize] as i32;
    let lb = TABLES.1[b as usize] as i32;
    let mut e = la - lb;
    if e < 0 {
        e += 255;
    }
    Some(TABLES.0[e as usize])
}

/// 高斯-若尔当求逆：输入 n×n 行优先矩阵，奇异时返回 None。
pub fn invert(matrix: &[u8], n: usize) -> Option<Vec<u8>> {
    let mut a = vec![0u8; n * n * 2];
    for r in 0..n {
        for c in 0..n {
            a[r * 2 * n + c] = matrix[r * n + c];
        }
        a[r * 2 * n + n + r] = 1;
    }
    let width = 2 * n;
    for col in 0..n {
        let pivot = (col..n).find(|&r| a[r * width + col] != 0)?;
        if pivot != col {
            for c in 0..width {
                a.swap(col * width + c, pivot * width + c);
            }
        }
        let p = a[col * width + col];
        let pinv = inv(p)?;
        for c in 0..width {
            a[col * width + c] = mul(a[col * width + c], pinv);
        }
        for r in 0..n {
            if r == col {
                continue;
            }
            let factor = a[r * width + col];
            if factor == 0 {
                continue;
            }
            for c in 0..width {
                let v = a[col * width + c];
                a[r * width + c] ^= mul(factor, v);
            }
        }
    }
    let mut out = vec![0u8; n * n];
    for r in 0..n {
        out[r * n..r * n + n].copy_from_slice(&a[r * width + n..r * width + 2 * n]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_identity_and_inverse() {
        for a in 1u8..=255 {
            assert_eq!(mul(a, 1), a);
            let ai = inv(a).unwrap();
            assert_eq!(mul(a, ai), 1);
            assert_eq!(div(1, a), Some(ai));
        }
        assert_eq!(mul(0, 54), 0);
        assert_eq!(inv(0), None);
        assert_eq!(div(0, 5), Some(0));
        assert_eq!(div(5, 0), None);
    }

    #[test]
    fn invert_roundtrip() {
        // 单位阵
        let id = [1u8, 0, 0, 0, 1, 0, 0, 0, 1];
        assert_eq!(invert(&id, 3).unwrap(), id);
        // 可逆随机阵与其逆相乘应为单位阵
        let m = [1u8, 2, 3, 4, 5, 6, 7, 8, 10];
        let mi = invert(&m, 3).unwrap();
        let mut prod = vec![0u8; 9];
        for r in 0..3 {
            for c in 0..3 {
                let mut acc = 0u8;
                for k in 0..3 {
                    acc ^= mul(m[r * 3 + k], mi[k * 3 + c]);
                }
                prod[r * 3 + c] = acc;
            }
        }
        assert_eq!(prod, id);
        // 奇异阵
        let singular = [1u8, 2, 3, 4, 5, 6, 5, 7, 9]; // 行3 = 行1 ^ 行2
        assert!(invert(&singular, 3).is_none());
    }
}
