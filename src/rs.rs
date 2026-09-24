//! Reed-Solomon 系统码：k 个数据 shard + m 个校验 shard，矩阵在 GF(2^w) 上运算。

use crate::gf::Field;

#[derive(Clone, Debug)]
pub struct Matrix {
    pub rows: usize,
    pub cols: usize,
    pub data: Vec<u8>,
}

impl Matrix {
    pub fn new(rows: usize, cols: usize) -> Self {
        Matrix { rows, cols, data: vec![0; rows * cols] }
    }

    pub fn get(&self, r: usize, c: usize) -> u8 {
        self.data[r * self.cols + c]
    }

    pub fn set(&mut self, r: usize, c: usize, v: u8) {
        self.data[r * self.cols + c] = v;
    }

    /// 第 r 行为 [1, x, x^2, ...]，x = r+1（避开与单位阵行重复）。
    pub fn vandermonde(rows: usize, cols: usize, f: &Field) -> Self {
        let mut m = Matrix::new(rows, cols);
        for r in 0..rows {
            let x = (r + 1) as u8;
            let mut term = 1u8;
            for c in 0..cols {
                m.set(r, c, term);
                term = f.mul(term, x);
            }
        }
        m
    }

    pub fn sub_rows(&self, rows: &[usize]) -> Matrix {
        let mut out = Matrix::new(rows.len(), self.cols);
        for (i, &r) in rows.iter().enumerate() {
            for c in 0..self.cols {
                out.set(i, c, self.get(r, c));
            }
        }
        out
    }

    pub fn mul(&self, f: &Field, rhs: &Matrix) -> Matrix {
        assert_eq!(self.cols, rhs.rows);
        let mut out = Matrix::new(self.rows, rhs.cols);
        for i in 0..self.rows {
            for t in 0..self.cols {
                let a = self.get(i, t);
                if a == 0 {
                    continue;
                }
                for j in 0..rhs.cols {
                    let v = out.get(i, j) ^ f.mul(a, rhs.get(t, j));
                    out.set(i, j, v);
                }
            }
        }
        out
    }

    /// 高斯-约当消元求逆；奇异矩阵返回 None。
    pub fn invert(&self, f: &Field) -> Option<Matrix> {
        assert_eq!(self.rows, self.cols);
        let n = self.rows;
        let mut a = self.clone();
        let mut inv = Matrix::new(n, n);
        for i in 0..n {
            inv.set(i, i, 1);
        }
        for col in 0..n {
            let mut pivot = None;
            for r in col..n {
                if a.get(r, col) != 0 {
                    pivot = Some(r);
                    break;
                }
            }
            let pivot = pivot?;
            if pivot != col {
                for c in 0..n {
                    let t = a.get(col, c);
                    a.set(col, c, a.get(pivot, c));
                    a.set(pivot, c, t);
                    let t = inv.get(col, c);
                    inv.set(col, c, inv.get(pivot, c));
                    inv.set(pivot, c, t);
                }
            }
            let scale = f.inv(a.get(col, col));
            for c in 0..n {
                a.set(col, c, f.mul(a.get(col, c), scale));
                inv.set(col, c, f.mul(inv.get(col, c), scale));
            }
            for r in 0..n {
                if r == col {
                    continue;
                }
                let factor = a.get(r, col);
                if factor == 0 {
                    continue;
                }
                for c in 0..n {
                    let v = a.get(r, c) ^ f.mul(factor, a.get(col, c));
                    a.set(r, c, v);
                    let v = inv.get(r, c) ^ f.mul(factor, inv.get(col, c));
                    inv.set(r, c, v);
                }
            }
        }
        Some(inv)
    }
}

/// (k+m) x k 编码矩阵：上 k 行单位阵，下 m 行 Vandermonde。
pub fn encoding_matrix(k: usize, m: usize, f: &Field) -> Matrix {
    let mut enc = Matrix::new(k + m, k);
    for i in 0..k {
        enc.set(i, i, 1);
    }
    let v = Matrix::vandermonde(m, k, f);
    for r in 0..m {
        for c in 0..k {
            enc.set(k + r, c, v.get(r, c));
        }
    }
    enc
}

/// 由 k 个数据 shard 计算全部 k+m 个 shard。
pub fn encode(f: &Field, k: usize, m: usize, data: &[Vec<u8>]) -> Vec<Vec<u8>> {
    assert_eq!(data.len(), k);
    let shard_size = data[0].len();
    let enc = encoding_matrix(k, m, f);
    let mut out = vec![vec![0u8; shard_size]; k + m];
    for r in 0..k + m {
        for d in 0..k {
            let coef = enc.get(r, d);
            if coef == 0 {
                continue;
            }
            for b in 0..shard_size {
                out[r][b] ^= f.mul(coef, data[d][b]);
            }
        }
    }
    out
}

/// 用任意 k 个 shard（索引 + 内容）重建全部 k+m 个 shard。
pub fn decode(f: &Field, k: usize, m: usize, present: &[(usize, Vec<u8>)]) -> Option<Vec<Vec<u8>>> {
    if present.len() != k {
        return None;
    }
    let shard_size = present[0].1.len();
    if present.iter().any(|p| p.1.len() != shard_size) {
        return None;
    }
    let enc = encoding_matrix(k, m, f);
    let idx: Vec<usize> = present.iter().map(|p| p.0).collect();
    let sub = enc.sub_rows(&idx);
    let inv = sub.invert(f)?;
    let mut data = vec![vec![0u8; shard_size]; k];
    for d in 0..k {
        for t in 0..k {
            let coef = inv.get(d, t);
            if coef == 0 {
                continue;
            }
            for b in 0..shard_size {
                data[d][b] ^= f.mul(coef, present[t].1[b]);
            }
        }
    }
    Some(encode(f, k, m, &data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip_gf256() {
        let f = Field::new(8, 0x11d);
        let (k, m) = (4usize, 2usize);
        let data: Vec<Vec<u8>> = (0..k)
            .map(|i| (0..16).map(|b| (i * 31 + b * 7 + 3) as u8).collect())
            .collect();
        let full = encode(&f, k, m, &data);
        assert_eq!(&full[..k], &data[..]);
        // 任意 k 个 shard 可重建
        let present: Vec<(usize, Vec<u8>)> = vec![0, 2, 4, 5].into_iter().map(|i| (i, full[i].clone())).collect();
        let rebuilt = decode(&f, k, m, &present).unwrap();
        assert_eq!(rebuilt, full);
    }

    #[test]
    fn encode_decode_roundtrip_gf16() {
        let f = Field::new(4, 0x13);
        let (k, m) = (2usize, 1usize);
        let data: Vec<Vec<u8>> = vec![vec![1, 4], vec![0, 0]];
        let full = encode(&f, k, m, &data);
        assert_eq!(full[2], vec![1, 4]);
        let present = vec![(0usize, full[0].clone()), (2usize, full[2].clone())];
        let rebuilt = decode(&f, k, m, &present).unwrap();
        assert_eq!(rebuilt, full);
    }
}
