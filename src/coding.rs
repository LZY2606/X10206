//! Cauchy Reed-Solomon over GF(256)。
//!
//! 编码矩阵：前 k 行为单位阵（data shard），后 m 行为 Cauchy 子阵
//! `C[i][j] = 1 / (x_i XOR y_j)`，固定 `x_i = i`、`y_j = k + j`，
//! 保证任意 k 行组成的方阵都可逆（GF(256) 上 Cauchy 子阵恒可逆）。

use crate::gf::Gf256;

#[inline]
pub fn cauchy_coef(gf: &Gf256, parity_i: usize, data_j: usize, k: usize) -> u8 {
    let x = parity_i as u8;
    let y = (k + data_j) as u8;
    gf.inv(x ^ y)
}

pub fn cauchy_row(gf: &Gf256, parity_i: usize, k: usize) -> Vec<u8> {
    (0..k).map(|j| cauchy_coef(gf, parity_i, j, k)).collect()
}

/// 由 k 块 data 计算 m 块 parity。
pub fn encode(gf: &Gf256, data: &[Vec<u8>], m: usize) -> Vec<Vec<u8>> {
    let k = data.len();
    assert!(k >= 1 && m >= 1 && k + m <= 256);
    let shard_len = data.first().map(|v| v.len()).unwrap_or(0);
    assert!(data.iter().all(|d| d.len() == shard_len));
    let mut out = Vec::with_capacity(m);
    for i in 0..m {
        let row = cauchy_row(gf, i, k);
        let mut parity = vec![0u8; shard_len];
        for (j, d) in data.iter().enumerate() {
            let c = row[j];
            if c == 0 {
                continue;
            }
            for (p, &b) in parity.iter_mut().zip(d) {
                *p ^= gf.mul(c, b);
            }
        }
        out.push(parity);
    }
    out
}

/// 对增广矩阵 `[mat | rhs]` 做 Gauss-Jordan 消元，`mat` 为 n×n。
/// 成功时返回解向量。
pub fn solve(gf: &Gf256, mat: &[u8], rhs: &[u8], n: usize) -> Option<Vec<u8>> {
    assert_eq!(mat.len(), n * n);
    assert_eq!(rhs.len(), n);
    let mut a = vec![0u8; n * (n + 1)];
    for r in 0..n {
        a[r * (n + 1)..r * (n + 1) + n].copy_from_slice(&mat[r * n..(r + 1) * n]);
        a[r * (n + 1) + n] = rhs[r];
    }
    for col in 0..n {
        let pivot = (col..n).find(|&r| a[r * (n + 1) + col] != 0)?;
        if pivot != col {
            for c in 0..n + 1 {
                a.swap(col * (n + 1) + c, pivot * (n + 1) + c);
            }
        }
        let pv = a[col * (n + 1) + col];
        if pv != 1 {
            let pinv = gf.inv(pv);
            for c in col..n + 1 {
                let v = a[col * (n + 1) + c];
                a[col * (n + 1) + c] = gf.mul(v, pinv);
            }
        }
        for r in 0..n {
            if r == col {
                continue;
            }
            let f = a[r * (n + 1) + col];
            if f == 0 {
                continue;
            }
            for c in col..n + 1 {
                let vc = a[col * (n + 1) + c];
                let vr = a[r * (n + 1) + c];
                a[r * (n + 1) + c] = vr ^ gf.mul(f, vc);
            }
        }
    }
    Some((0..n).map(|r| a[r * (n + 1) + n]).collect())
}

/// 求 n×n 矩阵的逆（Gauss-Jordan）。
pub fn invert(gf: &Gf256, mat: &[u8], n: usize) -> Option<Vec<u8>> {
    let mut a = vec![0u8; n * 2 * n];
    for r in 0..n {
        for c in 0..n {
            a[r * 2 * n + c] = mat[r * n + c];
        }
        a[r * 2 * n + n + r] = 1;
    }
    for col in 0..n {
        let pivot = (col..n).find(|&r| a[r * 2 * n + col] != 0)?;
        if pivot != col {
            for c in 0..2 * n {
                a.swap(col * 2 * n + c, pivot * 2 * n + c);
            }
        }
        let pinv = gf.inv(a[col * 2 * n + col]);
        for c in col..2 * n {
            let v = a[col * 2 * n + c];
            a[col * 2 * n + c] = gf.mul(v, pinv);
        }
        for r in 0..n {
            if r == col {
                continue;
            }
            let f = a[r * 2 * n + col];
            if f == 0 {
                continue;
            }
            for c in col..2 * n {
                let vc = a[col * 2 * n + c];
                let vr = a[r * 2 * n + c];
                a[r * 2 * n + c] = vr ^ gf.mul(f, vc);
            }
        }
    }
    let mut inv = vec![0u8; n * n];
    for r in 0..n {
        inv[r * n..(r + 1) * n].copy_from_slice(&a[r * 2 * n + n..r * 2 * n + 2 * n]);
    }
    Some(inv)
}

fn coef_row(gf: &Gf256, idx: usize, k: usize) -> Vec<u8> {
    if idx < k {
        let mut row = vec![0u8; k];
        row[idx] = 1;
        row
    } else {
        cauchy_row(gf, idx - k, k)
    }
}

/// 由至少 k 个可用 shard 重建全部 n 个 shard。
///
/// 选择编号最小的 k 个可用行求逆解出 data，再用全部可用 shard 校验。
/// 任意校验不一致都会返回 `Err(冲突 shard 编号)`，调用方据此记录损坏证据。
pub fn reconstruct(
    gf: &Gf256,
    k: usize,
    m: usize,
    shard_len: usize,
    available: &[(usize, &[u8])],
) -> Result<Vec<Vec<u8>>, Vec<usize>> {
    let n = k + m;
    assert!(k >= 1 && m >= 1 && n <= 256);
    if available.len() < k {
        return Err(vec![]);
    }
    for (idx, bytes) in available {
        if *idx >= n || bytes.len() != shard_len {
            return Err(vec![*idx]);
        }
    }
    let mut chosen: Vec<usize> = available.iter().take(k).map(|(i, _)| *i).collect();
    chosen.sort_unstable();
    let chosen = chosen;

    let mut mat = vec![0u8; k * k];
    for (r, &idx) in chosen.iter().enumerate() {
        let row = coef_row(gf, idx, k);
        mat[r * k..(r + 1) * k].copy_from_slice(&row);
    }
    let inv = match invert(&gf, &mat, k) {
        Some(v) => v,
        None => return Err(chosen),
    };

    let mut y: Vec<&[u8]> = Vec::with_capacity(k);
    for &idx in &chosen {
        y.push(
            available
                .iter()
                .find(|(i, _)| *i == idx)
                .map(|(_, b)| *b)
                .unwrap(),
        );
    }

    let mut data: Vec<Vec<u8>> = (0..k).map(|_| vec![0u8; shard_len]).collect();
    for byte in 0..shard_len {
        let mut rhs = [0u8; 256];
        let rhs = &mut rhs[..k];
        for (r, b) in y.iter().enumerate() {
            rhs[r] = b[byte];
        }
        let mut d = [0u8; 256];
        let d = &mut d[..k];
        for j in 0..k {
            let mut acc = 0u8;
            for r in 0..k {
                acc ^= gf.mul(inv[j * k + r], rhs[r]);
            }
            d[j] = acc;
        }
        for j in 0..k {
            data[j][byte] = d[j];
        }
    }

    let mut full: Vec<Vec<u8>> = Vec::with_capacity(n);
    for idx in 0..n {
        if idx < k {
            full.push(data[idx].clone());
        } else {
            let row = cauchy_row(gf, idx - k, k);
            let mut parity = vec![0u8; shard_len];
            for j in 0..k {
                let c = row[j];
                if c == 0 {
                    continue;
                }
                for (p, &b) in parity.iter_mut().zip(&data[j]) {
                    *p ^= gf.mul(c, b);
                }
            }
            full.push(parity);
        }
    }

    let mut conflicts = Vec::new();
    for (idx, bytes) in available {
        if full[*idx] != bytes.as_ref() {
            conflicts.push(*idx);
        }
    }
    if conflicts.is_empty() {
        Ok(full)
    } else {
        conflicts.sort_unstable();
        Err(conflicts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let gf = Gf256::new();
        let (k, m) = (3, 2);
        let data = vec![vec![1u8, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];
        let parity = encode(&gf, &data, m);
        let all = [data.clone(), parity].concat();

        // 恰好 k 块：两块 data + 一块 parity
        let avail: Vec<(usize, &[u8])> = vec![(0, &all[0]), (2, &all[2]), (3, &all[3])];
        let rec = reconstruct(&gf, k, m, 3, &avail).unwrap();
        assert_eq!(rec, all);

        // 只有 parity + data 的其它组合
        let avail: Vec<(usize, &[u8])> = vec![(1, &all[1]), (3, &all[3]), (4, &all[4])];
        let rec = reconstruct(&gf, k, m, 3, &avail).unwrap();
        assert_eq!(rec, all);
    }

    #[test]
    fn detects_bit_flip() {
        let gf = Gf256::new();
        let (k, m) = (2, 2);
        let data = vec![vec![10u8, 20], vec![30, 40]];
        let parity = encode(&gf, &data, m);
        let mut all = [data, parity].concat();
        all[3][0] ^= 0x01;
        let avail: Vec<(usize, &[u8])> =
            vec![(0, &all[0]), (1, &all[1]), (3, &all[3])];
        let err = reconstruct(&gf, k, m, 2, &avail).unwrap_err();
        assert!(err.contains(&3));
    }

    #[test]
    fn below_threshold_fails() {
        let gf = Gf256::new();
        let data = vec![vec![1u8]];
        let parity = encode(&gf, &data, 2);
        let all = [data, parity].concat();
        let avail: Vec<(usize, &[u8])> = vec![(2, &all[2])];
        assert!(reconstruct(&gf, 1, 2, 1, &avail).is_err());
    }
}
