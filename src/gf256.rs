//! GF(2^8) Reed-Solomon / Cauchy 矩阵运算。
//!
//! 不可约多项式 x^8+x^4+x^3+x^2+1 (0x11d)，生成元 2（与 QR 码同一有限域）。
//! 校验块使用 Cauchy 矩阵编码，任意 k 行都可逆，因此任意 k 个 shard 均可重建。

use std::sync::OnceLock;

static EXP: OnceLock<Vec<u8>> = OnceLock::new();
static LOG: OnceLock<Vec<u8>> = OnceLock::new();

fn tables() -> (&'static [u8], &'static [u8]) {
    let exp = EXP.get_or_init(|| {
        let mut t = vec![0u8; 512];
        let mut x = 1u16;
        for e in t.iter_mut() {
            *e = x as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= 0x11d;
            }
        }
        t
    });
    let log = LOG.get_or_init(|| {
        let mut t = vec![0u8; 256];
        for (i, &v) in exp.iter().take(255).enumerate() {
            t[v as usize] = i as u8;
        }
        t
    });
    (exp, log)
}

#[inline]
pub fn add(a: u8, b: u8) -> u8 {
    a ^ b
}

#[inline]
pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let (exp, log) = tables();
    let la = log[a as usize] as u16;
    let lb = log[b as usize] as u16;
    exp[((la + lb) % 255) as usize]
}

#[inline]
pub fn inv(a: u8) -> u8 {
    assert!(a != 0, "0 无逆元");
    let (exp, log) = tables();
    exp[(255 - log[a as usize] as usize) % 255]
}

#[inline]
pub fn div(a: u8, b: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    let (exp, log) = tables();
    let la = log[a as usize] as i16;
    let lb = log[b as usize] as i16;
    exp[((la - lb).rem_euclid(255)) as usize]
}

/// 校验块系数行：`k` 个数据块、`m` 个校验块。
/// 数据行是单位阵；校验行取 Cauchy 矩阵 1/(x_j XOR y_i)，
/// 其中 y_i = i, x_j = m + j，保证任意 k 行满秩。
pub fn code_row(k: usize, m: usize, global_index: usize) -> Vec<u8> {
    assert!(global_index < k + m);
    if global_index < k {
        let mut row = vec![0u8; k];
        row[global_index] = 1;
        row
    } else {
        let i = global_index - k;
        assert!(i < m);
        (0..k)
            .map(|j| {
                let x = (m + j) as u8;
                let y = i as u8;
                inv(x ^ y)
            })
            .collect()
    }
}

/// 在 GF(256) 上对 n x n 矩阵求逆；奇异时返回 None。
pub fn invert(matrix: &[Vec<u8>], n: usize) -> Option<Vec<Vec<u8>>> {
    let mut aug = vec![vec![0u8; 2 * n]; n];
    for (r, row) in matrix.iter().enumerate() {
        aug[r][..n].copy_from_slice(row);
        aug[r][n + r] = 1;
    }
    for col in 0..n {
        let pivot = (col..n).find(|&r| aug[r][col] != 0)?;
        aug.swap(col, pivot);
        let p = inv(aug[col][col]);
        for c in col..2 * n {
            aug[col][c] = mul(aug[col][c], p);
        }
        for r in 0..n {
            if r != col && aug[r][col] != 0 {
                let factor = aug[r][col];
                for c in col..2 * n {
                    aug[r][c] ^= mul(factor, aug[col][c]);
                }
            }
        }
    }
    Some(aug.iter().map(|r| r[n..].to_vec()).collect())
}

/// 由 `available`（(全局 shard 编号, 字节)）重建 `missing_global_indices`。
/// 返回 (全局编号 -> 重建字节)。所有 shard 必须等长，可用数必须 >= k。
pub fn reconstruct(
    k: usize,
    m: usize,
    shard_len: usize,
    available: &[(usize, Vec<u8>)],
    missing_global_indices: &[usize],
) -> Option<Vec<(usize, Vec<u8>)>> {
    if available.len() < k {
        return None;
    }
    let chosen: Vec<(usize, Vec<u8>)> = available.iter().take(k).cloned().collect();
    let encode_rows: Vec<Vec<u8>> = chosen
        .iter()
        .map(|(idx, _)| code_row(k, m, *idx))
        .collect();
    let a_inv = invert(&encode_rows, k)?;

    let mut out = Vec::new();
    for &missing in missing_global_indices {
        let coef = code_row(k, m, missing);
        // data_row[j] = sum_t coef[t] * a_inv[t][j]，即“数据基底上的系数行”。
        let mut data_row = vec![0u8; k];
        for (t, &c) in coef.iter().enumerate() {
            if c == 0 {
                continue;
            }
            for j in 0..k {
                data_row[j] ^= mul(c, a_inv[t][j]);
            }
        }
        let mut bytes = vec![0u8; shard_len];
        for (pos, chunk) in bytes.iter_mut().enumerate() {
            let mut acc = 0u8;
            for (j, (_, data)) in chosen.iter().enumerate() {
                acc ^= mul(data_row[j], data[pos]);
            }
            *chunk = acc;
        }
        out.push((missing, bytes));
    }
    Some(out)
}

/// 编码全部数据块，返回 m 个校验块字节。数据块需等长。
pub fn parity(k: usize, m: usize, data_shards: &[Vec<u8>]) -> Vec<Vec<u8>> {
    assert_eq!(data_shards.len(), k);
    let len = data_shards.first().map(|d| d.len()).unwrap_or(0);
    (0..m)
        .map(|i| {
            let row = code_row(k, m, k + i);
            let mut bytes = vec![0u8; len];
            for (pos, chunk) in bytes.iter_mut().enumerate() {
                let mut acc = 0u8;
                for j in 0..k {
                    acc ^= mul(row[j], data_shards[j][pos]);
                }
                *chunk = acc;
            }
            bytes
        })
        .collect()
}
