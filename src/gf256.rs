//! GF(2^8) 有限域运算，生成多项式 0x11d，生成元 2。

fn build_tables() -> ([u8; 256], [u8; 256]) {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut x: u16 = 1;
    for i in 0..255 {
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
    (exp, log)
}

pub fn mul(a: u8, b: u8) -> u8 {
    let (exp, log) = build_tables();
    if a == 0 || b == 0 {
        0
    } else {
        exp[(log[a as usize] as usize) + (log[b as usize] as usize)]
    }
}

pub fn inv(a: u8) -> u8 {
    assert!(a != 0, "0 has no inverse");
    let (exp, log) = build_tables();
    exp[255 - log[a as usize] as usize]
}

/// 对一行数据进行高斯约化：把 pivot 列系数变为 1，并消去其他行。
/// matrix 为 rows*n 行优先，rhs 为 rows*sh_size 行优先。
pub fn gauss_solve(matrix: &mut [u8], rhs: &mut [u8], rows: usize, n: usize, sh_size: usize) {
    let mut row = 0;
    for col in 0..n {
        let pivot = (row..rows).find(|&r| matrix[r * n + col] != 0);
        match pivot {
            None => continue,
            Some(p) if p != row => {
                for c in 0..n {
                    matrix.swap(row * n + c, p * n + c);
                }
                rhs[row * sh_size..(row + 1) * sh_size].swap_with_slice(
                    &mut rhs[p * sh_size..(p + 1) * sh_size],
                );
            }
            _ => {}
        }
        let factor = inv(matrix[row * n + col]);
        for c in col..n {
            matrix[row * n + c] = mul(matrix[row * n + c], factor);
        }
        for b in 0..sh_size {
            rhs[row * sh_size + b] = mul(rhs[row * sh_size + b], factor);
        }
        for r in 0..rows {
            if r == row {
                continue;
            }
            let factor = matrix[r * n + col];
            if factor == 0 {
                continue;
            }
            for c in col..n {
                matrix[r * n + c] ^= mul(factor, matrix[row * n + c]);
            }
            for b in 0..sh_size {
                rhs[r * sh_size + b] ^= mul(factor, rhs[row * sh_size + b]);
            }
        }
        row += 1;
        if row == rows {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_and_inv_roundtrip() {
        for a in 1u8..=255 {
            assert_eq!(mul(a, inv(a)), 1);
        }
        assert_eq!(mul(0, 99), 0);
    }

    #[test]
    fn solve_identity_like() {
        let n = 3;
        let mut m = vec![1u8, 0, 2, 0, 3, 1, 4, 0, 0];
        let sh = 2;
        let mut rhs = vec![10u8, 20, 30, 40, 50, 60];
        gauss_solve(&mut m, &mut rhs, n, n, sh);
        for r in 0..n {
            for c in 0..n {
                assert_eq!(m[r * n + c], u8::from(r == c));
            }
        }
        let rows: Vec<&[u8]> = rhs.chunks(sh).collect();
        for b in 0..sh {
            assert_eq!(
                rows[0][b] ^ mul(2, rows[2][b]),
                vec![10u8, 20][b]
            );
        }
    }
}
