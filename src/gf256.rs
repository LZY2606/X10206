//! GF(2^8) 小有限域与系统型 Reed-Solomon 纠删码。
//!
//! 生成多项式 x^8 + x^4 + x^3 + x^2 + 1 (0x11d)，
//! shard i 的编码行采用 Vandermonde 行 (1, alpha^i, alpha^(2i), ...)，
//! 其中数据块行天然为单位向量，因此本编码是系统型的。

use std::sync::OnceLock;

pub const PRIMITIVE: u16 = 0x11d;

pub struct Tables {
    pub exp: [u8; 512],
    pub log: [u8; 256],
}

static TABLES: OnceLock<Tables> = OnceLock::new();

fn tables() -> &'static Tables {
    TABLES.get_or_init(|| {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut x: u16 = 1;
    for i in 0..255 {
        exp[i] = x as u8;
        log[x as usize] = i as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= PRIMITIVE;
        }
    }
    for i in 255..512 {
        exp[i] = exp[i - 255];
    }
    Tables { exp, log }
    })
}

#[inline]
pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        0
    } else {
        let t = tables();
        let la = t.log[a as usize] as u16;
        let lb = t.log[b as usize] as u16;
        t.exp[(la + lb) as usize]
    }
}

#[inline]
pub fn inv(a: u8) -> u8 {
    debug_assert!(a != 0);
    let t = tables();
    t.exp[255 - t.log[a as usize] as usize]
}

/// alpha^p
#[inline]
pub fn alpha_pow(p: usize) -> u8 {
    tables().exp[p % 255]
}

/// 编码矩阵第 row 行第 col 列元素：alpha^(row*col)。
/// 数据 shard 行 (row < k) 退化为单位矩阵，故为系统型编码。
#[inline]
pub fn coding_entry(row: usize, col: usize) -> u8 {
    alpha_pow(row * col)
}

/// 矩阵（按行展开）在 GF(256) 上求逆。矩阵不可逆时返回 None。
pub fn invert(matrix: &[u8], n: usize) -> Option<Vec<u8>> {
    let mut aug = vec![0u8; n * 2 * n];
    for r in 0..n {
        for c in 0..n {
            aug[r * 2 * n + c] = matrix[r * n + c];
            aug[r * 2 * n + n + c] = if r == c { 1 } else { 0 };
        }
    }
    let width = 2 * n;
    for col in 0..n {
        let pivot = (col..n).find(|&r| aug[r * width + col] != 0)?;
        if pivot != col {
            for c in 0..width {
                aug.swap(col * width + c, pivot * width + c);
            }
        }
        let pinv = inv(aug[col * width + col]);
        for c in 0..width {
            let v = aug[col * width + c];
            aug[col * width + c] = mul(v, pinv);
        }
        for r in 0..n {
            if r != col {
                let factor = aug[r * width + col];
                if factor != 0 {
                    for c in 0..width {
                        let sub = mul(factor, aug[col * width + c]);
                        aug[r * width + c] ^= sub;
                    }
                }
            }
        }
    }
    let mut out = vec![0u8; n * n];
    for r in 0..n {
        out[r * n..r * n + n].copy_from_slice(&aug[r * width + n..r * width + 2 * n]);
    }
    Some(out)
}

/// 由 k 个 shard（每个长度 shard_size）重建全部 n 个 shard。
///
/// `present` 为长度 k 的 shard 编号（0..n，互不相同，按升序），
/// `blocks` 与 `present` 对齐。返回全部 n 个 shard（按编号升序）。
pub fn reconstruct(
    present: &[usize],
    blocks: &[Vec<u8>],
    k: usize,
    n: usize,
    shard_size: usize,
) -> Option<Vec<Vec<u8>>> {
    debug_assert_eq!(present.len(), k);
    debug_assert_eq!(blocks.len(), k);
    debug_assert!(blocks.iter().all(|b| b.len() == shard_size));

    // A: 参与 shard 的编码行（k x k）。
    let mut a = vec![0u8; k * k];
    for (r, &si) in present.iter().enumerate() {
        for c in 0..k {
            a[r * k + c] = coding_entry(si, c);
        }
    }
    // 求逆 A^-1：数据向量 D = A^-1 * S。
    let a_inv = invert(&a, k)?;

    let mut data = vec![vec![0u8; shard_size]; k];
    for r in 0..k {
        for i in 0..k {
            let coeff = a_inv[r * k + i];
            if coeff == 0 {
                continue;
            }
            let src = &blocks[i];
            let dst = &mut data[r];
            for (d, &s) in dst.iter_mut().zip(src.iter()) {
                *d ^= mul(coeff, s);
            }
        }
    }

    // 用完整编码矩阵重新生成全部 n 个 shard，参与 shard 也重新计算以便审计。
    let mut all = vec![vec![0u8; shard_size]; n];
    for si in 0..n {
        for c in 0..k {
            let coeff = coding_entry(si, c);
            if coeff == 0 {
                continue;
            }
            let src = &data[c];
            let dst = &mut all[si];
            for (d, &s) in dst.iter_mut().zip(src.iter()) {
                *d ^= mul(coeff, s);
            }
        }
    }
    Some(all)
}

/// 正向系统型编码：k 个数据 shard -> 全部 n 个 shard。
pub fn encode(data: &[Vec<u8>], n: usize, shard_size: usize) -> Vec<Vec<u8>> {
    let k = data.len();
    let present: Vec<usize> = (0..k).collect();
    reconstruct(&present, data, k, n, shard_size).expect("data rows always invertible")
}
