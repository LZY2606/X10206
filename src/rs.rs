//! Reed-Solomon 系统码：生成矩阵 [I; C]，C 为柯西矩阵，保证任意 k 行可逆（MDS）。

use crate::gf::Field;

#[derive(Clone, Debug)]
pub struct RsCode {
    pub k: usize,
    pub m: usize,
    pub field: Field,
}

impl RsCode {
    pub fn new(k: usize, m: usize, field: Field) -> anyhow::Result<Self> {
        anyhow::ensure!(k >= 1 && m >= 1, "k/m 必须为正整数");
        anyhow::ensure!(k + m <= field.size, "k+m 超出有限域大小 {}", field.size);
        Ok(Self { k, m, field })
    }

    pub fn shard_count(&self) -> usize {
        self.k + self.m
    }

    /// 生成矩阵第 idx 行。数据块 idx<k 为单位行；校验块为柯西行 1/(x+y_i)，
    /// x 取 k..k+m，y_i 取 0..k，两集合不相交，任意 k 行方阵可逆。
    pub fn row(&self, idx: usize) -> Vec<u8> {
        if idx < self.k {
            let mut r = vec![0u8; self.k];
            r[idx] = 1;
            r
        } else {
            let x = idx as u8;
            (0..self.k)
                .map(|i| self.field.inv(x ^ (i as u8)))
                .collect()
        }
    }

    /// 由 k 个数据向量（每个为域元素序列）编码出全部 k+m 个 shard。
    pub fn encode(&self, data: &[Vec<u8>]) -> Vec<Vec<u8>> {
        assert_eq!(data.len(), self.k, "需要恰好 k 个数据向量");
        let len = data[0].len();
        assert!(data.iter().all(|d| d.len() == len), "数据向量长度不一致");
        (0..self.shard_count())
            .map(|idx| {
                let row = self.row(idx);
                let mut out = vec![0u8; len];
                for (j, d) in data.iter().enumerate() {
                    let c = row[j];
                    if c == 0 {
                        continue;
                    }
                    for (o, &v) in out.iter_mut().zip(d.iter()) {
                        *o ^= self.field.mul(c, v);
                    }
                }
                out
            })
            .collect()
    }

    /// 给定至少 k 个 (shard_index, 元素序列)，重建全部 k+m 个 shard。
    /// 选取编号最小的 k 个，保证确定性。
    pub fn reconstruct(&self, present: &[(usize, Vec<u8>)]) -> Option<Vec<Vec<u8>>> {
        if present.len() < self.k {
            return None;
        }
        let mut sel: Vec<&(usize, Vec<u8>)> = present.iter().collect();
        sel.sort_by_key(|(idx, _)| *idx);
        sel.dedup_by_key(|(idx, _)| *idx);
        if sel.len() < self.k {
            return None;
        }
        let sel = &sel[..self.k];
        let len = sel[0].1.len();
        if sel.iter().any(|(_, v)| v.len() != len) {
            return None;
        }
        let mat: Vec<Vec<u8>> = sel.iter().map(|(idx, _)| self.row(*idx)).collect();
        let inv = invert(&self.field, &mat)?;
        let mut data = vec![vec![0u8; len]; self.k];
        for (r, inv_row) in inv.iter().enumerate() {
            for (j, (_, vals)) in sel.iter().enumerate() {
                let c = inv_row[j];
                if c == 0 {
                    continue;
                }
                for (o, &v) in data[r].iter_mut().zip(vals.iter()) {
                    *o ^= self.field.mul(c, v);
                }
            }
        }
        Some(self.encode(&data))
    }
}

/// GF(2^w) 上的高斯-约当求逆。
pub fn invert(field: &Field, mat: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    let n = mat.len();
    let mut a: Vec<Vec<u8>> = mat.to_vec();
    let mut inv: Vec<Vec<u8>> = (0..n)
        .map(|i| {
            let mut r = vec![0u8; n];
            r[i] = 1;
            r
        })
        .collect();
    for col in 0..n {
        let pivot = (col..n).find(|&r| a[r][col] != 0)?;
        a.swap(col, pivot);
        inv.swap(col, pivot);
        let pinv = field.inv(a[col][col]);
        for c in 0..n {
            a[col][c] = field.mul(a[col][c], pinv);
            inv[col][c] = field.mul(inv[col][c], pinv);
        }
        for r in 0..n {
            if r == col {
                continue;
            }
            let f = a[r][col];
            if f == 0 {
                continue;
            }
            for c in 0..n {
                a[r][c] ^= field.mul(f, a[col][c]);
                inv[r][c] ^= field.mul(f, inv[col][c]);
            }
        }
    }
    Some(inv)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_code() -> RsCode {
        RsCode::new(3, 2, Field::new(4)).unwrap()
    }

    #[test]
    fn roundtrip_all_erasure_patterns() {
        let code = sample_code();
        let data: Vec<Vec<u8>> = vec![
            vec![1, 2, 3, 4, 5, 6],
            vec![15, 14, 13, 12, 11, 10],
            vec![0, 5, 10, 15, 1, 6],
        ];
        let shards = code.encode(&data);
        let n = code.shard_count();
        // 枚举所有丢失 m 块的组合
        for a in 0..n {
            for b in (a + 1)..n {
                let present: Vec<(usize, Vec<u8>)> = (0..n)
                    .filter(|&i| i != a && i != b)
                    .map(|i| (i, shards[i].clone()))
                    .collect();
                let rebuilt = code.reconstruct(&present).expect("k=3 在场应可重建");
                assert_eq!(rebuilt, shards, "丢失 {a},{b} 时重建不符");
            }
        }
    }

    #[test]
    fn below_threshold_fails() {
        let code = sample_code();
        let data: Vec<Vec<u8>> = vec![vec![1, 2], vec![3, 4], vec![5, 6]];
        let shards = code.encode(&data);
        let present = vec![(0usize, shards[0].clone()), (3, shards[3].clone())];
        assert!(code.reconstruct(&present).is_none());
    }
}
