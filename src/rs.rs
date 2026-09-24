//! Reed-Solomon 风格纠删码：Vandermonde 矩阵 + 高斯消元求逆。
//! k 个数据分片 + m 个校验分片，任意 k 块即可重建全部 k+m 块。

use crate::gf::Gf256;

/// rows x cols 的 Vandermonde 矩阵，第 r 行以域元素 r 为底。
pub fn vandermonde(gf: &Gf256, rows: usize, cols: usize) -> Vec<Vec<u8>> {
    assert!(rows <= 256, "分片总数超出 GF(256) 容量");
    (0..rows)
        .map(|r| {
            let x = r as u8;
            (0..cols).map(|c| gf.pow(x, c as u32)).collect()
        })
        .collect()
}

/// 高斯-约当消元求逆，矩阵不可逆时返回 None。
pub fn invert(gf: &Gf256, matrix: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    let n = matrix.len();
    let mut a: Vec<Vec<u8>> = matrix.to_vec();
    let mut inv: Vec<Vec<u8>> = (0..n)
        .map(|i| (0..n).map(|j| if i == j { 1 } else { 0 }).collect())
        .collect();
    for col in 0..n {
        let pivot = (col..n).find(|&r| a[r][col] != 0)?;
        a.swap(col, pivot);
        inv.swap(col, pivot);
        let p = a[col][col];
        for j in 0..n {
            a[col][j] = gf.div(a[col][j], p);
            inv[col][j] = gf.div(inv[col][j], p);
        }
        for r in 0..n {
            if r != col && a[r][col] != 0 {
                let f = a[r][col];
                for j in 0..n {
                    a[r][j] ^= gf.mul(f, a[col][j]);
                    inv[r][j] ^= gf.mul(f, inv[col][j]);
                }
            }
        }
    }
    Some(inv)
}

/// 由 k 个数据分片编码出全部 k+m 个分片。
pub fn encode(gf: &Gf256, k: usize, m: usize, data: &[Vec<u8>]) -> Vec<Vec<u8>> {
    assert_eq!(data.len(), k);
    let shard_len = data[0].len();
    assert!(data.iter().all(|d| d.len() == shard_len));
    let mat = vandermonde(gf, k + m, k);
    let mut out = vec![vec![0u8; shard_len]; k + m];
    for r in 0..k + m {
        for (j, d) in data.iter().enumerate() {
            let coef = mat[r][j];
            if coef == 0 {
                continue;
            }
            for (pos, b) in out[r].iter_mut().enumerate() {
                *b ^= gf.mul(coef, d[pos]);
            }
        }
    }
    out
}

/// 用至少 k 个现存分片重建全部 k+m 个分片。
/// `present` 为 (分片编号, 字节)，编号必须落在 0..k+m。
pub fn reconstruct(
    gf: &Gf256,
    k: usize,
    m: usize,
    present: &[(usize, Vec<u8>)],
    shard_len: usize,
) -> Option<Vec<Vec<u8>>> {
    let total = k + m;
    if present.len() < k {
        return None;
    }
    let mut sel: Vec<&(usize, Vec<u8>)> = present.iter().collect();
    sel.sort_by_key(|(idx, _)| *idx);
    sel.dedup_by_key(|(idx, _)| *idx);
    if sel.len() < k {
        return None;
    }
    let sel = &sel[..k];
    for (idx, bytes) in sel {
        if *idx >= total || bytes.len() != shard_len {
            return None;
        }
    }
    let full = vandermonde(gf, total, k);
    let sub: Vec<Vec<u8>> = sel.iter().map(|(idx, _)| full[*idx].clone()).collect();
    let inv = invert(gf, &sub)?;
    let mut data = vec![vec![0u8; shard_len]; k];
    for j in 0..k {
        for (c, (_, bytes)) in sel.iter().enumerate() {
            let coef = inv[j][c];
            if coef == 0 {
                continue;
            }
            for (pos, b) in data[j].iter_mut().enumerate() {
                *b ^= gf.mul(coef, bytes[pos]);
            }
        }
    }
    Some(encode(gf, k, m, &data))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(k: usize, len: usize) -> Vec<Vec<u8>> {
        (0..k)
            .map(|j| (0..len).map(|i| (j * 37 + i * 11 + 3) as u8).collect())
            .collect()
    }

    #[test]
    fn roundtrip_all_k_subsets() {
        let gf = Gf256::new();
        let (k, m, len) = (3usize, 2usize, 16usize);
        let data = sample(k, len);
        let shards = encode(&gf, k, m, &data);
        assert_eq!(shards.len(), k + m);
        assert_eq!(&shards[..k], &data[..], " Vandermonde 首行为单位行");
        // 枚举所有 5 选 3 的组合
        for a in 0..5 {
            for b in a + 1..5 {
                for c in b + 1..5 {
                    let present: Vec<(usize, Vec<u8>)> =
                        [a, b, c].iter().map(|&i| (i, shards[i].clone())).collect();
                    let rebuilt = reconstruct(&gf, k, m, &present, len).expect("应可重建");
                    assert_eq!(rebuilt, shards, "子集 [{},{},{}]", a, b, c);
                }
            }
        }
    }

    #[test]
    fn below_threshold_fails() {
        let gf = Gf256::new();
        let (k, m, len) = (3usize, 1usize, 8usize);
        let data = sample(k, len);
        let shards = encode(&gf, k, m, &data);
        let present: Vec<(usize, Vec<u8>)> =
            [0usize, 1].iter().map(|&i| (i, shards[i].clone())).collect();
        assert!(reconstruct(&gf, k, m, &present, len).is_none());
    }
}
