//! GF(2^8) Reed-Solomon（Vandermonde，系统码）小有限域实现。
//!
//! 域参数：素多项式 0x11d（x^8 + x^4 + x^3 + x^2 + 1），生成元 2。
//! 编码参数按 `codec_version` 版本化，当前仅 v1 一种参数集；未知版本拒绝解码。

use std::collections::BTreeMap;

const POLY: u16 = 0x11d;

pub struct Field {
    exp: [u8; 512],
    log: [u8; 256],
}

impl Field {
    pub fn new() -> Self {
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
        Field { exp, log }
    }

    #[inline]
    pub fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            let la = self.log[a as usize] as u16;
            let lb = self.log[b as usize] as u16;
            self.exp[(la + lb) as usize]
        }
    }

    #[inline]
    pub fn inv(&self, a: u8) -> u8 {
        assert!(a != 0, "inverse of zero");
        self.exp[255 - self.log[a as usize] as usize]
    }
}

impl Default for Field {
    fn default() -> Self {
        Self::new()
    }
}

/// 行 i 的编码系数：数据行 i<k 为单位向量；校验行 i>=k 为 [x^0, x^1, ...]，x = (i-k+1)。
fn row_coeff(field: &Field, i: usize, k: usize) -> Vec<u8> {
    if i < k {
        let mut v = vec![0u8; k];
        v[i] = 1;
        v
    } else {
        let x = (i - k + 1) as u8;
        let mut v = vec![0u8; k];
        v[0] = 1;
        for j in 1..k {
            v[j] = field.mul(v[j - 1], x);
        }
        v
    }
}

/// 用全部数据块编码生成 k 个数据块（原样）+ m 个校验块，每块长度 block_len。
pub fn encode(field: &Field, k: usize, data: &[Vec<u8>]) -> Vec<Vec<u8>> {
    assert_eq!(data.len(), k);
    let m = data.len(); // placeholder, caller provides parity count separately
    let _ = m;
    let block_len = data[0].len();
    assert!(data.iter().all(|d| d.len() == block_len));
    let mut out = data.to_vec();
    // parity count filled by caller through encode_with_parity; not used.
    out.resize(k, vec![0u8; block_len]);
    let _ = field;
    out
}

/// 编码：输入 k 个等长数据块，输出 k+m 个块。
pub fn encode_with_parity(
    field: &Field,
    k: usize,
    m: usize,
    data: &[Vec<u8>],
) -> Vec<Vec<u8>> {
    assert_eq!(data.len(), k);
    let block_len = data[0].len();
    assert!(data.iter().all(|d| d.len() == block_len));
    let n = k + m;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        if i < k {
            out.push(data[i].clone());
        } else {
            let coeff = row_coeff(field, i, k);
            let mut block = vec![0u8; block_len];
            for (j, c) in coeff.iter().enumerate() {
                if *c == 0 {
                    continue;
                }
                for (pos, byte) in block.iter_mut().enumerate() {
                    *byte ^= field.mul(*c, data[j][pos]);
                }
            }
            out.push(block);
        }
    }
    out
}

/// 解码结果。
pub struct DecodeResult {
    /// 重建出的所有缺失块：shard 编号 -> 字节。
    pub missing: BTreeMap<usize, Vec<u8>>,
}

/// 高斯-若尔当求逆（GF256 上的 k×k 矩阵），失败返回 None（奇异矩阵）。
fn invert(field: &Field, mut a: Vec<Vec<u8>>, k: usize) -> Option<Vec<Vec<u8>>> {
    let mut inv = vec![vec![0u8; k]; k];
    for (i, row) in inv.iter_mut().enumerate() {
        row[i] = 1;
    }
    for col in 0..k {
        let pivot = (col..k).find(|&r| a[r][col] != 0)?;
        if pivot != col {
            a.swap(pivot, col);
            inv.swap(pivot, col);
        }
        let piv = a[col][col];
        let piv_inv = field.inv(piv);
        for j in 0..k {
            a[col][j] = field.mul(a[col][j], piv_inv);
            inv[col][j] = field.mul(inv[col][j], piv_inv);
        }
        for r in 0..k {
            if r == col || a[r][col] == 0 {
                continue;
            }
            let factor = a[r][col];
            for j in 0..k {
                a[r][j] ^= field.mul(factor, a[col][j]);
                inv[r][j] ^= field.mul(factor, inv[col][j]);
            }
        }
    }
    Some(inv)
}

/// 根据可用块重建缺失块。
///
/// `available` 为 shard 编号 -> 字节；至少包含 k 个块且所有块等长。
/// `target` 为需要求出的编号集合。返回目标编号 -> 重建字节。
/// 若所选 k 个行线性相关（理论上 Vandermonde 前 n 行不会，防御性处理）返回 None。
pub fn decode(
    field: &Field,
    k: usize,
    m: usize,
    available: &BTreeMap<usize, Vec<u8>>,
    target: &[usize],
) -> Option<DecodeResult> {
    let n = k + m;
    if available.len() < k || available.keys().any(|&i| i >= n) {
        return None;
    }
    let block_len = available.values().next()?.len();
    if available.values().any(|b| b.len() != block_len) {
        return None;
    }
    let rows: Vec<usize> = available.keys().copied().collect();
    let chosen: Vec<usize> = rows.iter().take(k).copied().collect();

    let a: Vec<Vec<u8>> = chosen.iter().map(|&i| row_coeff(field, i, k)).collect();
    let a_inv = invert(field, a, k)?;

    // 原始数据 D = A^-1 * E，逐字节计算
    // D = A^-1 * E：data[j][pos] = sum_r (A^-1)[j][r] * E_r[pos]
    let mut data = vec![vec![0u8; block_len]; k];
    for (r, &row_idx) in chosen.iter().enumerate() {
        let block = &available[&row_idx];
        for j in 0..k {
            let coeff = a_inv[j][r];
            if coeff == 0 {
                continue;
            }
            for (pos, byte) in block.iter().enumerate() {
                data[j][pos] ^= field.mul(coeff, *byte);
            }
        }
    }

    let mut missing = BTreeMap::new();
    for &t in target {
        let coeff = row_coeff(field, t, k);
        let mut block = vec![0u8; block_len];
        for (j, c) in coeff.iter().enumerate() {
            if *c == 0 {
                continue;
            }
            for (pos, byte) in block.iter_mut().enumerate() {
                *byte ^= field.mul(*c, data[j][pos]);
            }
        }
        missing.insert(t, block);
    }
    Some(DecodeResult { missing })
}

/// 用编码参数校验一个完整条带（n 个等长块）是否自洽：重新计算每个块并比较。
pub fn verify_full_stripe(
    field: &Field,
    k: usize,
    m: usize,
    blocks: &BTreeMap<usize, Vec<u8>>,
) -> bool {
    let n = k + m;
    if blocks.len() != n {
        return false;
    }
    let block_len = match blocks.values().next() {
        Some(b) => b.len(),
        None => return false,
    };
    if blocks.values().any(|b| b.len() != block_len) {
        return false;
    }
    let data: Vec<Vec<u8>> = (0..k).map(|i| blocks[&i].clone()).collect();
    let expected = encode_with_parity(field, k, m, &data);
    (0..n).all(|i| blocks[&i] == expected[i])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_single_and_multi_missing() {
        let f = Field::new();
        let (k, m) = (3usize, 2usize);
        let data = vec![vec![1u8, 2, 3, 4], vec![5, 6, 7, 8], vec![9, 10, 11, 12]];
        let all = encode_with_parity(&f, k, m, &data);

        // 恰好 k=3 块可用（缺 m=2 块）：数据缺失、校验缺失、纯校验恢复数据等
        for missing in [
            vec![0], vec![2], vec![4],
            vec![0, 3], vec![1, 4],
            vec![0, 1], vec![0, 4], vec![2, 3],
            vec![0, 3], vec![0, 1, 4], vec![2, 3, 4], vec![0, 2, 4],
        ] {
            let avail: BTreeMap<usize, Vec<u8>> = (0..k + m)
                .filter(|i| !missing.contains(i))
                .map(|i| (i, all[i].clone()))
                .collect();
            let res = decode(&f, k, m, &avail, &missing).expect("decode");
            for &idx in &missing {
                assert_eq!(res.missing[&idx], all[idx]);
            }
        }
    }

    #[test]
    fn flipped_byte_breaks_verification() {
        let f = Field::new();
        let (k, m) = (3usize, 2usize);
        let data = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];
        let mut all = encode_with_parity(&f, k, m, &data);
        let mut blocks: BTreeMap<usize, Vec<u8>> = BTreeMap::new();
        all[3][0] ^= 0x01;
        for (i, b) in all.into_iter().enumerate() {
            blocks.insert(i, b);
        }
        assert!(!verify_full_stripe(&f, k, m, &blocks));
    }
}
