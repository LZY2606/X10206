//! Cauchy Reed-Solomon：数据行为单位阵，校验行为 Cauchy 子矩阵。
//! 任意 k 个 shard 的行构成可逆子矩阵（GF 上 Cauchy 子矩阵恒满秩）。

use crate::gf::Gf;

#[derive(Clone, Debug)]
pub struct Code {
    pub gf: Gf,
    pub k: usize,
    pub m: usize,
    pub n: usize,
    /// n x k 编码矩阵（前 k 行为单位阵）。
    pub enc: Vec<Vec<u16>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    NotEnoughShards { have: usize, need: usize },
    SingularMatrix,
    LengthMismatch,
}

pub struct DecodeOutcome {
    /// 重建出的 n 个 shard（完整码字）。
    pub codeword: Vec<Vec<u8>>,
    /// 用于求逆的 shard 编号（恰好 k 个）。
    pub basis: Vec<usize>,
    /// 存在但与重算码字不一致的 shard 编号。
    pub inconsistent: Vec<usize>,
}

impl Code {
    pub fn new(w: u8, k: usize, m: usize) -> Self {
        let gf = Gf::new(w);
        assert!(k >= 1 && m >= 1);
        let n = k + m;
        assert!(
            (n as u32) <= gf.size,
            "k+m={n} 超过 GF(2^{w}) 的元素数 {}",
            gf.size
        );
        let mut enc = vec![vec![0u16; k]; n];
        for (i, row) in enc.iter_mut().enumerate().take(k) {
            row[i] = 1;
        }
        // 校验行：C[i][j] = 1 / (x_i XOR y_j)，x_i=i，y_j=m+j，两组互不相交。
        for i in 0..m {
            for j in 0..k {
                let denom = (i as u16) ^ ((m + j) as u16);
                enc[k + i][j] = gf.inv(denom);
            }
        }
        Code { gf, k, m, n, enc }
    }

    pub fn encode(&self, data: &[Vec<u8>]) -> Vec<Vec<u8>> {
        assert_eq!(data.len(), self.k);
        let len = data[0].len();
        for d in data {
            assert_eq!(d.len(), len, "data shard 长度必须一致");
        }
        let mut out = Vec::with_capacity(self.n);
        for row in &self.enc {
            let mut shard = vec![0u8; len];
            for (t, cell) in shard.iter_mut().enumerate() {
                let mut acc = 0u16;
                for (j, coeff) in row.iter().enumerate() {
                    acc ^= self.gf.mul(*coeff, data[j][t] as u16);
                }
                *cell = acc as u8;
            }
            out.push(shard);
        }
        out
    }

    /// 矩阵求逆（GF 上 Gauss-Jordan）。
    fn invert(&self, matrix: &[Vec<u16>]) -> Option<Vec<Vec<u16>>> {
        let k = self.k;
        let mut aug = vec![vec![0u16; 2 * k]; k];
        for i in 0..k {
            for j in 0..k {
                aug[i][j] = matrix[i][j];
            }
            aug[i][k + i] = 1;
        }
        for col in 0..k {
            let pivot = (col..k).find(|&r| aug[r][col] != 0)?;
            aug.swap(col, pivot);
            let p = aug[col][col];
            let pinv = self.gf.inv(p);
            for c in 0..2 * k {
                aug[col][c] = self.gf.mul(aug[col][c], pinv);
            }
            for r in 0..k {
                if r != col && aug[r][col] != 0 {
                    let factor = aug[r][col];
                    for c in 0..2 * k {
                        let sub = self.gf.mul(factor, aug[col][c]);
                        aug[r][c] ^= sub;
                    }
                }
            }
        }
        let mut inv = vec![vec![0u16; k]; k];
        for i in 0..k {
            inv[i].copy_from_slice(&aug[i][k..]);
        }
        Some(inv)
    }

    /// 给定 (shard编号, 字节) 列表重建完整码字，并检查多余 shard 是否自洽。
    pub fn try_decode(&self, present: &[(usize, &[u8])]) -> Result<DecodeOutcome, DecodeError> {
        if present.len() < self.k {
            return Err(DecodeError::NotEnoughShards {
                have: present.len(),
                need: self.k,
            });
        }
        let mut sorted: Vec<(usize, &[u8])> = present.iter().map(|&(i, b)| (i, b)).collect();
        sorted.sort_by_key(|(i, _)| *i);
        let len = sorted[0].1.len();
        if sorted.iter().any(|(_, b)| b.len() != len) {
            return Err(DecodeError::LengthMismatch);
        }

        // 取编号最小的 k 个作为求逆基。
        let basis: Vec<usize> = sorted[..self.k].iter().map(|(i, _)| *i).collect();
        let rows: Vec<Vec<u16>> = basis
            .iter()
            .map(|&idx| self.enc[idx].clone())
            .collect();
        let inv = self.invert(&rows).ok_or(DecodeError::SingularMatrix)?;

        // data[t] = inv * present_basis。
        let mut data = vec![vec![0u8; len]; self.k];
        for t in 0..len {
            for i in 0..self.k {
                let mut acc = 0u16;
                for j in 0..self.k {
                    acc ^= self.gf.mul(inv[i][j], sorted[j].1[t] as u16);
                }
                data[i][t] = acc as u8;
            }
        }
        let codeword = self.encode(&data);

        let mut inconsistent = Vec::new();
        for &(idx, bytes) in sorted.iter().skip(self.k) {
            if bytes != codeword[idx].as_slice() {
                inconsistent.push(idx);
            }
        }
        Ok(DecodeOutcome { codeword, basis, inconsistent })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_each_subset_gf4() {
        let code = Code::new(4, 3, 2);
        let data = vec![vec![1, 9, 7], vec![2, 3, 14], vec![15, 0, 4]];
        let all = code.encode(&data);
        for missing in 0..5 {
            let present: Vec<(usize, &[u8])> = all
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != missing)
                .map(|(i, b)| (i, b.as_slice()))
                .collect();
            let out = code.try_decode(&present).unwrap();
            assert!(out.inconsistent.is_empty());
            assert_eq!(out.codeword, all);
        }
    }

    #[test]
    fn detects_bit_flip_in_extra_shard() {
        let code = Code::new(4, 3, 2);
        let data = vec![vec![1, 9], vec![2, 3], vec![15, 0]];
        let mut all = code.encode(&data);
        all[4][0] ^= 1;
        let present: Vec<(usize, &[u8])> =
            all.iter().enumerate().map(|(i, b)| (i, b.as_slice())).collect();
        let out = code.try_decode(&present).unwrap();
        assert_eq!(out.inconsistent, vec![4]);
    }
}
