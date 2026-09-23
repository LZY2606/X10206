//! GF(2^8) 有限域运算，不可约多项式 x^8 + x^4 + x^3 + x + 1 (0x11b)。

use std::sync::OnceLock;

struct Tables {
    exp: [u8; 512],
    log: [u8; 256],
}

fn build_tables() -> Tables {
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
}

fn tables() -> &'static Tables {
    static TABLES: OnceLock<Tables> = OnceLock::new();
    TABLES.get_or_init(build_tables)
}

/// 域加法（异或）。
pub fn add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// 域乘法。
pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let t = tables();
    t.exp[t.log[a as usize] as usize + t.log[b as usize] as usize]
}

/// 域除法（b 不得为 0）。
pub fn div(a: u8, b: u8) -> u8 {
    assert!(b != 0, "GF(256) division by zero");
    if a == 0 {
        return 0;
    }
    let t = tables();
    let d = t.log[a as usize] as i32 - t.log[b as usize] as i32;
    t.exp[d.rem_euclid(255) as usize]
}

/// 生成元的幂：alpha^i。
pub fn exp(i: u8) -> u8 {
    tables().exp[i as usize]
}

/// 高斯消元求解方阵线性系统 A * X = B（按列多右端）。
/// 返回 None 表示矩阵奇异。
pub fn solve(matrix: &[Vec<u8>], rhs: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    let n = matrix.len();
    if n == 0 || rhs.len() != n || matrix.iter().any(|r| r.len() != n) {
        return None;
    }
    let width = rhs[0].len();
    if rhs.iter().any(|r| r.len() != width) {
        return None;
    }
    let mut a: Vec<Vec<u8>> = matrix.to_vec();
    let mut b: Vec<Vec<u8>> = rhs.to_vec();
    for col in 0..n {
        let pivot = (col..n).find(|&r| a[r][col] != 0)?;
        a.swap(col, pivot);
        b.swap(col, pivot);
        let inv = div(1, a[col][col]);
        for j in col..n {
            a[col][j] = mul(a[col][j], inv);
        }
        for v in b[col].iter_mut() {
            *v = mul(*v, inv);
        }
        for row in 0..n {
            if row != col && a[row][col] != 0 {
                let factor = a[row][col];
                for j in col..n {
                    a[row][j] = add(a[row][j], mul(factor, a[col][j]));
                }
                for j in 0..width {
                    b[row][j] = add(b[row][j], mul(factor, b[col][j]));
                }
            }
        }
    }
    Some(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_laws() {
        for a in [0u8, 1, 2, 7, 53, 200, 255] {
            for b in [0u8, 1, 3, 91, 255] {
                assert_eq!(add(a, b), a ^ b);
                assert_eq!(mul(a, b), mul(b, a));
                if b != 0 {
                    assert_eq!(div(mul(a, b), b), a);
                }
            }
        }
        assert_eq!(mul(0x57, 0x83), 0xc1); // AES 经典示例
    }

    #[test]
    fn solve_identity() {
        let m = vec![vec![1, 0], vec![0, 1]];
        let rhs = vec![vec![5, 6], vec![7, 8]];
        assert_eq!(solve(&m, &rhs), Some(rhs));
    }
}
