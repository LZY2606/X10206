//! Reed-Solomon 编解码：k 个数据 shard + m 个校验 shard，系统码形式。
//! 数据 shard 行取单位矩阵行，校验 shard 行取 Vandermonde 行 [1, x, x^2, ...]。

use crate::field;

#[derive(Clone, Debug)]
pub struct ReedSolomon {
    pub k: usize,
    pub m: usize,
}

impl ReedSolomon {
    pub fn new(k: usize, m: usize) -> Self {
        assert!(k > 0, "k 必须为正");
        assert!(k + m <= 255, "shard 总数超出 GF(2^8) 容量");
        Self { k, m }
    }

    pub fn shard_count(&self) -> usize {
        self.k + self.m
    }

    /// 编码矩阵第 idx 行。
    fn row(&self, idx: usize) -> Vec<u8> {
        assert!(idx < self.shard_count());
        if idx < self.k {
            let mut row = vec![0u8; self.k];
            row[idx] = 1;
            row
        } else {
            let x = (idx - self.k + 1) as u8;
            let mut row = Vec::with_capacity(self.k);
            let mut power = 1u8;
            for _ in 0..self.k {
                row.push(power);
                power = field::mul(power, x);
            }
            row
        }
    }

    /// 由 k 个数据 shard 计算 m 个校验 shard。
    pub fn encode_parity(&self, data: &[Vec<u8>]) -> Vec<Vec<u8>> {
        assert_eq!(data.len(), self.k);
        (0..self.m)
            .map(|j| mat_vec_mul(&self.row(self.k + j), data))
            .collect()
    }

    /// 由任意至少 k 个 shard 重建全部 k+m 个 shard。
    /// `present` 为 (shard_idx, bytes)，长度必须一致。
    pub fn reconstruct(&self, present: &[(usize, Vec<u8>)]) -> Option<Vec<Vec<u8>>> {
        if present.len() < self.k {
            return None;
        }
        let mut sorted: Vec<&(usize, Vec<u8>)> = present.iter().collect();
        sorted.sort_by_key(|(idx, _)| *idx);
        let chosen = &sorted[..self.k];
        let matrix: Vec<Vec<u8>> = chosen.iter().map(|(idx, _)| self.row(*idx)).collect();
        let inverse = invert_matrix(&matrix)?;
        let shards: Vec<&Vec<u8>> = chosen.iter().map(|(_, bytes)| bytes).collect();
        let data: Vec<Vec<u8>> = inverse.iter().map(|row| mat_vec_mul(row, &shards)).collect();
        let mut all = Vec::with_capacity(self.shard_count());
        for idx in 0..self.shard_count() {
            all.push(mat_vec_mul(&self.row(idx), &data.iter().cloned().collect::<Vec<_>>()));
        }
        Some(all)
    }
}

fn mat_vec_mul(row: &[u8], shards: &[Vec<u8>]) -> Vec<u8> {
    let len = shards[0].len();
    let mut out = vec![0u8; len];
    for (coef, shard) in row.iter().zip(shards.iter()) {
        if *coef == 0 {
            continue;
        }
        for (o, b) in out.iter_mut().zip(shard.iter()) {
            *o ^= field::mul(*coef, *b);
        }
    }
    out
}

/// GF(2^8) 上的高斯-约当求逆；奇异时返回 None。
fn invert_matrix(matrix: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    let n = matrix.len();
    let mut aug: Vec<Vec<u8>> = matrix
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
        let inv = field::inv(aug[col][col]);
        for v in aug[col].iter_mut() {
            *v = field::mul(*v, inv);
        }
        for row in 0..n {
            if row != col && aug[row][col] != 0 {
                let factor = aug[row][col];
                for c in 0..2 * n {
                    let sub = field::mul(factor, aug[col][c]);
                    aug[row][c] = field::sub(aug[row][c], sub);
                }
            }
        }
    }
    Some(aug.into_iter().map(|row| row[n..].to_vec()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(k: usize, m: usize, len: usize) -> (ReedSolomon, Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let rs = ReedSolomon::new(k, m);
        let data: Vec<Vec<u8>> = (0..k)
            .map(|i| (0..len).map(|j| (i * 31 + j * 17 + 5) as u8).collect())
            .collect();
        let parity = rs.encode_parity(&data);
        let mut all = data.clone();
        all.extend(parity);
        (rs, data, all)
    }

    #[test]
    fn roundtrip_all_present() {
        let (rs, _, all) = sample(4, 2, 16);
        let present: Vec<(usize, Vec<u8>)> = all.iter().cloned().enumerate().collect();
        let rebuilt = rs.reconstruct(&present).unwrap();
        assert_eq!(rebuilt, all);
    }

    #[test]
    fn roundtrip_with_erasures() {
        let (rs, _, all) = sample(4, 3, 16);
        // 丢失 0、2、5 号，剩 4 个（恰为 k）。
        let present: Vec<(usize, Vec<u8>)> = [1usize, 3, 4, 6]
            .iter()
            .map(|&i| (i, all[i].clone()))
            .collect();
        let rebuilt = rs.reconstruct(&present).unwrap();
        assert_eq!(rebuilt, all);
    }

    #[test]
    fn below_threshold_fails() {
        let (rs, _, all) = sample(4, 2, 8);
        let present: Vec<(usize, Vec<u8>)> = all[..3].iter().cloned().enumerate().collect();
        assert!(rs.reconstruct(&present).is_none());
    }
}
