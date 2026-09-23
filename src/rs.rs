//! Reed-Solomon systematic encoding over GF(2^8) with versioned parameters.

use crate::field::Field;
use serde::{Deserialize, Serialize};

/// Versioned encoding parameters stored in the manifest.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncodingParams {
    pub version: u32,
    pub k: usize,          // data shards per stripe
    pub m: usize,          // parity shards per stripe
    pub field_poly: u16,   // GF(2^8) reduction polynomial
    pub stripe_size: usize, // bytes per shard fragment per stripe
}

pub const SUPPORTED_VERSION: u32 = 1;

impl EncodingParams {
    pub fn total(&self) -> usize {
        self.k + self.m
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != SUPPORTED_VERSION {
            return Err(format!("不支持的编码版本 {}", self.version));
        }
        if self.k == 0 || self.k + self.m > 255 {
            return Err("k/m 超出有限域容量".into());
        }
        if self.stripe_size == 0 {
            return Err("stripe_size 不能为 0".into());
        }
        Ok(())
    }
}

type Matrix = Vec<Vec<u8>>;

fn mat_mul(f: &Field, a: &Matrix, b: &Matrix) -> Matrix {
    let rows = a.len();
    let cols = b[0].len();
    let inner = b.len();
    let mut out = vec![vec![0u8; cols]; rows];
    for r in 0..rows {
        for c in 0..cols {
            let mut acc = 0u8;
            for i in 0..inner {
                acc = f.add(acc, f.mul(a[r][i], b[i][c]));
            }
            out[r][c] = acc;
        }
    }
    out
}

/// Gauss-Jordan inversion over the field. Returns None if singular.
fn mat_invert(f: &Field, m: &Matrix) -> Option<Matrix> {
    let n = m.len();
    let mut aug: Vec<Vec<u8>> = m
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
        for j in 0..2 * n {
            aug[col][j] = f.mul(aug[col][j], inv);
        }
        for r in 0..n {
            if r != col && aug[r][col] != 0 {
                let factor = aug[r][col];
                for j in 0..2 * n {
                    aug[r][j] = f.add(aug[r][j], f.mul(factor, aug[col][j]));
                }
            }
        }
    }
    Some(aug.into_iter().map(|row| row[n..].to_vec()).collect())
}

/// Systematic encoder/decoder for one parameter set.
pub struct Coder {
    pub params: EncodingParams,
    field: Field,
    /// (k+m) x k matrix; top k rows are the identity.
    enc: Matrix,
}

impl Coder {
    pub fn new(params: EncodingParams) -> Result<Self, String> {
        params.validate()?;
        let field = Field::new(params.field_poly);
        let n = params.total();
        let k = params.k;
        // Vandermonde rows over distinct evaluation points 0..n-1.
        let vand: Matrix = (0..n)
            .map(|i| {
                let x = i as u8;
                (0..k).map(|p| field.pow(x, p as u32)).collect()
            })
            .collect();
        let top: Matrix = vand[..k].to_vec();
        let top_inv = mat_invert(&field, &top).ok_or("编码矩阵奇异")?;
        let enc = mat_mul(&field, &vand, &top_inv);
        Ok(Coder { params, field, enc })
    }

    /// Encode k data fragments into the full k+m stripe row.
    pub fn encode(&self, data: &[&[u8]]) -> Result<Vec<Vec<u8>>, String> {
        let k = self.params.k;
        if data.len() != k {
            return Err("encode 需要恰好 k 个数据分片".into());
        }
        let size = self.params.stripe_size;
        if data.iter().any(|d| d.len() != size) {
            return Err("分片长度与 stripe_size 不符".into());
        }
        let n = self.params.total();
        let mut out = vec![vec![0u8; size]; n];
        for row in 0..n {
            for (d, frag) in data.iter().enumerate() {
                let coef = self.enc[row][d];
                if coef == 0 {
                    continue;
                }
                for (b, &v) in out[row].iter_mut().zip(frag.iter()) {
                    *b = self.field.add(*b, self.field.mul(coef, v));
                }
            }
        }
        Ok(out)
    }

    /// Rebuild the full stripe row from `present` (index, fragment) pairs.
    /// Requires at least k fragments; all must have stripe_size length.
    pub fn decode(&self, present: &[(usize, Vec<u8>)]) -> Result<Vec<Vec<u8>>, String> {
        let k = self.params.k;
        let size = self.params.stripe_size;
        if present.len() < k {
            return Err(format!("可用分片 {} 小于恢复下限 {}", present.len(), k));
        }
        if present.iter().any(|(_, f)| f.len() != size) {
            return Err("分片长度与 stripe_size 不符".into());
        }
        let sub: Matrix = present[..k].iter().map(|(i, _)| self.enc[*i].clone()).collect();
        let inv = mat_invert(&self.field, &sub).ok_or("解码矩阵奇异")?;
        // data[d] = sum_j inv[d][j] * present[j]
        let mut data = vec![vec![0u8; size]; k];
        for d in 0..k {
            for (j, (_, frag)) in present[..k].iter().enumerate() {
                let coef = inv[d][j];
                if coef == 0 {
                    continue;
                }
                for (b, &v) in data[d].iter_mut().zip(frag.iter()) {
                    *b = self.field.add(*b, self.field.mul(coef, v));
                }
            }
        }
        let refs: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();
        self.encode(&refs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> EncodingParams {
        EncodingParams { version: 1, k: 3, m: 2, field_poly: 0x11d, stripe_size: 4 }
    }

    #[test]
    fn roundtrip_with_erasures() {
        let coder = Coder::new(params()).unwrap();
        let data: Vec<Vec<u8>> = (0..3).map(|i| vec![i as u8 + 1; 4]).collect();
        let refs: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();
        let row = coder.encode(&refs).unwrap();
        assert_eq!(&row[..3], &data[..]);
        // lose shards 0 and 4
        let present: Vec<(usize, Vec<u8>)> = [(1usize, row[1].clone()), (2, row[2].clone()), (3, row[3].clone())].to_vec();
        let rebuilt = coder.decode(&present).unwrap();
        assert_eq!(rebuilt, row);
    }
}
