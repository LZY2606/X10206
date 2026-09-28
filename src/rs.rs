//! Reed-Solomon 编解码：Vandermonde 矩阵 + 高斯消元求逆。
//! shard 的每个字节视为一个域元素（GF(2^4) fixture 中字节取值 0..=15）。

use crate::field::Field;

#[derive(Clone, Debug)]
pub struct Rs {
    pub field: Field,
    pub k: usize,
    pub m: usize,
    matrix: Vec<Vec<u16>>, // (k+m) x k 的 Vandermonde 矩阵
}

impl Rs {
    pub fn new(field: Field, k: usize, m: usize) -> anyhow::Result<Rs> {
        anyhow::ensure!(k >= 1, "k 必须 >= 1");
        anyhow::ensure!(k + m <= field.order, "k+m 超出域大小 {}", field.order);
        let mut matrix = Vec::with_capacity(k + m);
        for row in 0..(k + m) {
            let point = row as u16;
            let mut r = Vec::with_capacity(k);
            let mut cur = 1u16;
            for _ in 0..k {
                r.push(cur);
                cur = field.mul(cur, point);
            }
            matrix.push(r);
        }
        Ok(Rs { field, k, m, matrix })
    }

    /// 输入 k 个 data shard，输出全部 k+m 个 shard。
    pub fn encode(&self, data: &[Vec<u8>]) -> anyhow::Result<Vec<Vec<u8>>> {
        anyhow::ensure!(data.len() == self.k, "encode 需要 {} 个 data shard", self.k);
        let shard_len = data[0].len();
        anyhow::ensure!(data.iter().all(|s| s.len() == shard_len), "data shard 长度不一致");
        let mut out = vec![vec![0u8; shard_len]; self.k + self.m];
        for (r, row) in self.matrix.iter().enumerate() {
            for (j, &coef) in row.iter().enumerate() {
                if coef == 0 {
                    continue;
                }
                for pos in 0..shard_len {
                    let v = self.field.mul(coef, data[j][pos] as u16);
                    out[r][pos] ^= v as u8;
                }
            }
        }
        Ok(out)
    }

    /// 用至少 k 个现存 shard（任意编号）重建全部 k+m 个 shard。
    /// 确定性：总是按编号升序取前 k 个作为解码集。
    pub fn reconstruct(&self, present: &[(usize, Vec<u8>)]) -> anyhow::Result<Vec<Vec<u8>>> {
        anyhow::ensure!(present.len() >= self.k, "现存 shard 不足 k={}", self.k);
        let mut sorted: Vec<&(usize, Vec<u8>)> = present.iter().collect();
        sorted.sort_by_key(|(idx, _)| *idx);
        let shard_len = sorted[0].1.len();
        anyhow::ensure!(
            sorted.iter().all(|(_, s)| s.len() == shard_len),
            "现存 shard 长度不一致"
        );
        let decode = &sorted[..self.k];
        let square: Vec<Vec<u16>> = decode.iter().map(|(idx, _)| self.matrix[*idx].clone()).collect();
        let inv = mat_invert(&self.field, &square)
            .ok_or_else(|| anyhow::anyhow!("解码矩阵不可逆"))?;
        let mut data = vec![vec![0u8; shard_len]; self.k];
        for (j, row) in inv.iter().enumerate() {
            for (t, &coef) in row.iter().enumerate() {
                if coef == 0 {
                    continue;
                }
                for pos in 0..shard_len {
                    let v = self.field.mul(coef, decode[t].1[pos] as u16);
                    data[j][pos] ^= v as u8;
                }
            }
        }
        self.encode(&data)
    }
}

/// 高斯消元求逆；奇异矩阵返回 None。
pub fn mat_invert(f: &Field, m: &[Vec<u16>]) -> Option<Vec<Vec<u16>>> {
    let n = m.len();
    let mut aug: Vec<Vec<u16>> = m
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let mut r = row.clone();
            r.extend((0..n).map(|j| if i == j { 1 } else { 0 }));
            r
        })
        .collect();
    for col in 0..n {
        let pivot = (col..n).find(|&r| aug[r][col] != 0)?;
        aug.swap(col, pivot);
        let inv = f.inv(aug[col][col]);
        for c in 0..(2 * n) {
            aug[col][c] = f.mul(aug[col][c], inv);
        }
        for r in 0..n {
            if r != col && aug[r][col] != 0 {
                let factor = aug[r][col];
                for c in 0..(2 * n) {
                    aug[r][c] = f.add(aug[r][c], f.mul(factor, aug[col][c]));
                }
            }
        }
    }
    Some(aug.into_iter().map(|row| row[n..].to_vec()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::Field;

    fn gf16() -> Field {
        Field::new(4, 0b1_0011).unwrap()
    }

    #[test]
    fn encode_reconstruct_roundtrip() {
        let rs = Rs::new(gf16(), 3, 2).unwrap();
        let data: Vec<Vec<u8>> = (0..3)
            .map(|j| (0..8).map(|p| ((j * 5 + p * 3 + 1) % 16) as u8).collect())
            .collect();
        let full = rs.encode(&data).unwrap();
        assert_eq!(full.len(), 5);
        // 丢掉 idx 1 和 idx 4，用 0,2,3 重建
        let present: Vec<(usize, Vec<u8>)> = [0usize, 2, 3]
            .iter()
            .map(|&i| (i, full[i].clone()))
            .collect();
        let rebuilt = rs.reconstruct(&present).unwrap();
        assert_eq!(rebuilt, full);
    }

    #[test]
    fn gf256_roundtrip() {
        let rs = Rs::new(Field::new(8, 0x11d).unwrap(), 4, 2).unwrap();
        let data: Vec<Vec<u8>> = (0..4)
            .map(|j| (0..16).map(|p| (j * 31 + p * 17) as u8).collect())
            .collect();
        let full = rs.encode(&data).unwrap();
        let present: Vec<(usize, Vec<u8>)> = [1usize, 2, 4, 5]
            .iter()
            .map(|&i| (i, full[i].clone()))
            .collect();
        assert_eq!(rs.reconstruct(&present).unwrap(), full);
    }
}
