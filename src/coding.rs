//! 版本化 Reed-Solomon（Cauchy 系统化）编解码。
//! v1: matrix[i][j] = 1 / (x_i XOR y_j)，x_i=i, y_j=order/2+j 之类的不相交取值。
//! 前 k 行做行变换化为单位矩阵，得到系统化生成矩阵。

use crate::gf::Field;
use serde::{Deserialize, Serialize};

pub const LATEST_CODEC_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CodecVersion {
    V1,
}

impl CodecVersion {
    pub fn number(self) -> u32 {
        match self {
            CodecVersion::V1 => 1,
        }
    }

    pub fn from_number(n: u32) -> Option<CodecVersion> {
        match n {
            1 => Some(CodecVersion::V1),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Coding {
    pub field: Field,
    pub k: usize,
    pub m: usize,
    pub matrix: Vec<Vec<u8>>,
}

impl Coding {
    pub fn new(field: Field, k: usize, m: usize) -> Result<Coding, String> {
        if k == 0 || m == 0 {
            return Err("k 与 m 必须大于 0".into());
        }
        let n = k + m;
        if n == 0 || n + k > field.order() {
            return Err(format!(
                "{} 域要求 2k+m <= {}，收到 k={} m={}",
                field.name(),
                field.order(),
                k,
                m
            ));
        }
        let mut base = vec![vec![0u8; k]; n];
        // x_i = i (0..n)，y_j = n + j，二者不相交且互不相等。
        for i in 0..n {
            for j in 0..k {
                let xor = (i as u8) ^ ((n + j) as u8);
                if xor == 0 {
                    return Err("Cauchy 参数冲突".into());
                }
                base[i][j] = field.inv(xor);
            }
        }
        // 对前 k 行求逆，把全矩阵左乘 B^{-1}，使前 k 行成为单位矩阵。
        let top: Vec<Vec<u8>> = base[..k].to_vec();
        let inv_top = invert_matrix(field, &top)?;
        let mut matrix = vec![vec![0u8; k]; n];
        for r in 0..n {
            for c in 0..k {
                let mut acc = 0u8;
                for t in 0..k {
                    acc ^= field.mul(base[r][t], inv_top[t][c]);
                }
                matrix[r][c] = acc;
            }
        }
        Ok(Coding { field, k, m, matrix })
    }

    pub fn n(&self) -> usize {
        self.k + self.m
    }

    /// data: k 个符号向量（长度一致）。返回 n 个 shard 符号向量。
    pub fn encode_symbols(&self, data: &[Vec<u8>]) -> Vec<Vec<u8>> {
        assert_eq!(data.len(), self.k);
        let len = data[0].len();
        self.matrix
            .iter()
            .map(|row| {
                let mut out = vec![0u8; len];
                for (j, d) in data.iter().enumerate() {
                    self.field.fmadd(row[j], d, &mut out);
                }
                out
            })
            .collect()
    }

    /// 字节级编码，data 为 k 个等长字节块。
    pub fn encode_bytes(&self, data: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let packed: Vec<Vec<u8>> = data.iter().map(|d| self.field.pack(d)).collect();
        self.encode_symbols(&packed)
            .into_iter()
            .map(|s| self.field.unpack(&s))
            .collect()
    }

    /// 给定 shard 编号 -> 符号向量，重建全部 n 个 shard 的符号向量。
    pub fn reconstruct_symbols(
        &self,
        available: &[(usize, Vec<u8>)],
    ) -> Result<Vec<Vec<u8>>, String> {
        if available.len() < self.k {
            return Err(format!(
                "可用块 {} 少于恢复下限 k={}",
                available.len(),
                self.k
            ));
        }
        let mut chosen: Vec<(usize, Vec<u8>)> = available.to_vec();
        chosen.sort_by_key(|(i, _)| *i);
        chosen.truncate(self.k);

        let len = chosen[0].1.len();
        if chosen.iter().any(|(_, s)| s.len() != len) {
            return Err("参与重建的块长度不一致".into());
        }

        // 增广矩阵 A (k x (k + len))，前 k 列为系数，后面为可用块负载。
        let mut aug = vec![vec![0u8]; self.k];
        for (row, (idx, symbols)) in chosen.iter().enumerate() {
            let mut r = self.matrix[*idx].clone();
            r.extend_from_slice(symbols);
            aug[row] = r;
        }

        // Gauss-Jordan 消元（GF 上带部分主元）。
        for col in 0..self.k {
            let pivot = (col..self.k)
                .find(|&r| aug[r][col] != 0)
                .ok_or_else(|| "系数矩阵奇异，无法求解".to_string())?;
            aug.swap(col, pivot);
            let p = aug[col][col];
            if p != 1 {
                let pinv = self.field.inv(p);
                for v in aug[col].iter_mut() {
                    *v = self.field.mul(*v, pinv);
                }
            }
            for r in 0..self.k {
                if r != col && aug[r][col] != 0 {
                    let factor = aug[r][col];
                    for c in col..(self.k + len) {
                        aug[r][c] ^= self.field.mul(factor, aug[col][c]);
                    }
                }
            }
        }

        // 解出原始数据符号 d_0..d_k。
        let data: Vec<Vec<u8>> = (0..self.k)
            .map(|r| aug[r][self.k..].to_vec())
            .collect();
        Ok(self.encode_symbols(&data))
    }

    pub fn reconstruct_bytes(
        &self,
        available: &[(usize, Vec<u8>)],
    ) -> Result<Vec<Vec<u8>>, String> {
        let packed: Vec<(usize, Vec<u8>)> = available
            .iter()
            .map(|(i, b)| (*i, self.field.pack(b)))
            .collect();
        self.reconstruct_symbols(&packed)
            .map(|syms| syms.iter().map(|s| self.field.unpack(s)).collect())
    }
}

/// GF 上方阵求逆（Gauss-Jordan）。
pub fn invert_matrix(field: Field, m: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
    let k = m.len();
    if k == 0 || m.iter().any(|r| r.len() != k) {
        return Err("矩阵必须为非空方阵".into());
    }
    let mut aug = vec![vec![0u8; k * 2]; k];
    for r in 0..k {
        aug[r][..k].copy_from_slice(&m[r]);
        aug[r][k + r] = 1;
    }
    for col in 0..k {
        let pivot = (col..k)
            .find(|&r| aug[r][col] != 0)
            .ok_or_else(|| "矩阵不可逆".to_string())?;
        aug.swap(col, pivot);
        let p = aug[col][col];
        if p != 1 {
            let pinv = field.inv(p);
            for v in aug[col].iter_mut() {
                *v = field.mul(*v, pinv);
            }
        }
        for r in 0..k {
            if r != col && aug[r][col] != 0 {
                let factor = aug[r][col];
                for c in col..k * 2 {
                    aug[r][c] ^= field.mul(factor, aug[col][c]);
                }
            }
        }
    }
    Ok(aug.iter().map(|r| r[k..].to_vec()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systematic_rows_are_identity() {
        for f in [Field::Gf256, Field::Gf16] {
            let c = Coding::new(f, 3, 2).unwrap();
            for i in 0..3 {
                for j in 0..3 {
                    assert_eq!(c.matrix[i][j], if i == j { 1 } else { 0 });
                }
            }
        }
    }

    #[test]
    fn roundtrip_single_and_multi_missing() {
        for f in [Field::Gf256, Field::Gf16] {
            let c = Coding::new(f, 3, 3).unwrap();
            let data = vec![vec![1u8, 9, 55], vec![200, 7, 12], vec![44, 201, 3]];
            let all = c.encode_bytes(&data);
            // 单块缺失
            let avail: Vec<(usize, Vec<u8>)> =
                all.iter().enumerate().filter(|(i, _)| *i != 4).map(|(i, b)| (i, b.clone())).collect();
            let rec = c.reconstruct_bytes(&avail).unwrap();
            assert_eq!(rec, all);
            // 多块缺失（含 data+parity）
            let avail: Vec<(usize, Vec<u8>)> =
                all.iter().enumerate().filter(|(i, _)| !matches!(i, 0 | 3 | 5)).map(|(i, b)| (i, b.clone())).collect();
            assert_eq!(avail.len(), 3);
            let rec = c.reconstruct_bytes(&avail).unwrap();
            assert_eq!(rec, all);
        }
    }

    #[test]
    fn boundary_k_available() {
        let c = Coding::new(Field::Gf16, 2, 2).unwrap();
        let data = vec![vec![10u8, 20], vec![30, 40]];
        let all = c.encode_bytes(&data);
        let avail = vec![(2usize, all[2].clone()), (3usize, all[3].clone())];
        let rec = c.reconstruct_bytes(&avail).unwrap();
        assert_eq!(rec, all);
    }

    #[test]
    fn corrupt_shard_detected_by_redundancy() {
        let c = Coding::new(Field::Gf16, 2, 2).unwrap();
        let data = vec![vec![10u8, 20], vec![30, 40]];
        let mut all = c.encode_bytes(&data);
        all[0][0] ^= 0xff;
        // 用编号 0,1,2 重建会得到与 shard3 不一致的结果（由引擎层比对）。
        let avail: Vec<(usize, Vec<u8>)> = all[0..3].iter().enumerate().map(|(i, b)| (i, b.clone())).collect();
        let rec = c.reconstruct_bytes(&avail).unwrap();
        assert_ne!(rec[3], all[3]);
    }
}
