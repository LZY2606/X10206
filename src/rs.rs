//! 系统化 Reed-Solomon：前 k 行为数据块（恒等），后 m 行为 Vandermonde 校验行。

use crate::gf;

#[derive(Clone)]
pub struct RsCodec {
    pub version: u32,
    pub k: usize,
    pub m: usize,
    matrix: Vec<Vec<u8>>,
}

impl RsCodec {
    pub fn for_version(version: u32, k: usize, m: usize) -> Result<Self, String> {
        if version != 1 {
            return Err(format!("不支持的编码版本: {version}"));
        }
        if k == 0 || m == 0 || k + m > 256 {
            return Err(format!("非法的编码参数 k={k} m={m}"));
        }
        let mut matrix = vec![vec![0u8; k]; k + m];
        for r in 0..k {
            matrix[r][r] = 1;
        }
        for r in k..k + m {
            for c in 0..k {
                matrix[r][c] = gf::pow(r as u8, c);
            }
        }
        Ok(Self {
            version,
            k,
            m,
            matrix,
        })
    }

    pub fn shard_count(&self) -> usize {
        self.k + self.m
    }

    pub fn encode(&self, data: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
        if data.len() != self.k {
            return Err(format!("数据块数量 {} 与 k={} 不符", data.len(), self.k));
        }
        let len = data[0].len();
        if len == 0 || data.iter().any(|d| d.len() != len) {
            return Err("数据块长度为空或不一致".into());
        }
        let mut out = vec![vec![0u8; len]; self.k + self.m];
        for (r, row) in self.matrix.iter().enumerate() {
            for (c, &coef) in row.iter().enumerate() {
                if coef == 0 {
                    continue;
                }
                for (i, out_byte) in out[r].iter_mut().enumerate() {
                    *out_byte ^= gf::mul(coef, data[c][i]);
                }
            }
        }
        Ok(out)
    }

    /// 任意 >= k 个不同编号的 shard 即可重建全部 k+m 块。
    /// 输入数组按 shard 编号排列，缺失项为 None。
    pub fn reconstruct(&self, shards: &[Option<Vec<u8>>]) -> Result<Vec<Vec<u8>>, String> {
        if shards.len() != self.k + self.m {
            return Err("shard 数量与编码参数不符".into());
        }
        let present: Vec<usize> = (0..shards.len()).filter(|&i| shards[i].is_some()).collect();
        if present.len() < self.k {
            return Err(format!("可用 shard 不足: {} < k={}", present.len(), self.k));
        }
        let chosen: Vec<usize> = present.iter().take(self.k).copied().collect();
        let len = shards[chosen[0]].as_ref().unwrap().len();
        for &i in &chosen {
            if shards[i].as_ref().unwrap().len() != len {
                return Err("参与计算的 shard 长度不一致".into());
            }
        }
        let sub: Vec<Vec<u8>> = chosen.iter().map(|&i| self.matrix[i].clone()).collect();
        let inv = invert(&sub)?;
        let mut data = vec![vec![0u8; len]; self.k];
        for (r, row) in inv.iter().enumerate() {
            for (c, &coef) in row.iter().enumerate() {
                if coef == 0 {
                    continue;
                }
                let source = shards[chosen[c]].as_ref().unwrap();
                for i in 0..len {
                    data[r][i] ^= gf::mul(coef, source[i]);
                }
            }
        }
        self.encode(&data)
    }
}

/// GF(256) 上的高斯-若尔当矩阵求逆。
pub fn invert(matrix: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
    let n = matrix.len();
    if matrix.iter().any(|r| r.len() != n) {
        return Err("矩阵非方阵".into());
    }
    let mut a = matrix.to_vec();
    let mut inv = vec![vec![0u8; n]; n];
    for i in 0..n {
        inv[i][i] = 1;
    }
    for col in 0..n {
        let pivot = (col..n).find(|&r| a[r][col] != 0);
        let pivot = pivot.ok_or_else(|| "编码子矩阵奇异，无法重建".to_string())?;
        a.swap(col, pivot);
        inv.swap(col, pivot);
        let d = gf::inv(a[col][col]);
        for c in 0..n {
            a[col][c] = gf::mul(a[col][c], d);
            inv[col][c] = gf::mul(inv[col][c], d);
        }
        for r in 0..n {
            if r == col {
                continue;
            }
            let factor = a[r][col];
            if factor == 0 {
                continue;
            }
            for c in 0..n {
                a[r][c] ^= gf::mul(factor, a[col][c]);
                inv[r][c] ^= gf::mul(factor, inv[col][c]);
            }
        }
    }
    Ok(inv)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(k: usize, m: usize, len: usize) -> Vec<Vec<u8>> {
        (0..k)
            .map(|r| (0..len).map(|i| ((r * 37 + i * 11 + 3) % 251) as u8).collect())
            .collect()
    }

    #[test]
    fn encode_is_systematic() {
        let codec = RsCodec::for_version(1, 3, 2).unwrap();
        let data = sample(3, 2, 7);
        let shards = codec.encode(&data).unwrap();
        for i in 0..3 {
            assert_eq!(shards[i], data[i]);
        }
    }

    #[test]
    fn reconstruct_single_and_multi_missing() {
        let (k, m) = (3, 2);
        let codec = RsCodec::for_version(1, k, m).unwrap();
        let data = sample(k, m, 8);
        let full = codec.encode(&data).unwrap();
        for missing in [vec![2], vec![3, 4], vec![0, 2], vec![1, 2, 4]] {
            let mut input: Vec<Option<Vec<u8>>> =
                full.iter().map(|s| Some(s.clone())).collect();
            for &idx in &missing {
                input[idx] = None;
            }
            let got = codec.reconstruct(&input).unwrap();
            assert_eq!(got, full, "缺失 {:?} 时重建不一致", missing);
        }
    }

    #[test]
    fn boundary_and_insufficient() {
        let codec = RsCodec::for_version(1, 3, 2).unwrap();
        let data = sample(3, 2, 5);
        let full = codec.encode(&data).unwrap();
        let mut input: Vec<Option<Vec<u8>>> = full.iter().map(|s| Some(s.clone())).collect();
        input[3] = None;
        input[4] = None;
        assert_eq!(codec.reconstruct(&input).unwrap(), full);
        input[2] = None;
        assert!(codec.reconstruct(&input).is_err());
    }

    #[test]
    fn inverted_submatrix_decodes_data() {
        let codec = RsCodec::for_version(1, 2, 2).unwrap();
        let data = sample(2, 2, 4);
        let full = codec.encode(&data).unwrap();
        let sub = vec![codec.matrix[0].clone(), codec.matrix[2].clone()];
        let inv = invert(&sub).unwrap();
        let mut decoded = vec![vec![0u8; 4]; 2];
        for r in 0..2 {
            for c in 0..2 {
                for i in 0..4 {
                    decoded[r][i] ^= gf::mul(inv[r][c], full[[0usize, 2][c]][i]);
                }
            }
        }
        assert_eq!(decoded, data);
    }
}
