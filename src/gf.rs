//! 小有限域上的 Cauchy 矩阵 Reed-Solomon。
//!
//! 生产参数使用 GF(2^8)；测试 fixture 使用 GF(2^4) 以便枚举肉眼可验。
//! 一个字节存一个符号；GF(2^4) 只用低 4 bit。

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GfError {
    UnsupportedField,
    BadParams,
    NotEnoughShards,
    LengthMismatch,
    Inconsistent,
    Singular,
}

impl std::fmt::Display for GfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            GfError::UnsupportedField => "不支持的有限域",
            GfError::BadParams => "编码参数非法（要求 k>=1, m>=0, 2k+m <= 域大小）",
            GfError::NotEnoughShards => "可用 shard 少于恢复下限 k",
            GfError::LengthMismatch => "参与 shard 长度不一致",
            GfError::Inconsistent => "已知 shard 之间互相矛盾",
            GfError::Singular => "编码矩阵奇异",
        };
        f.write_str(s)
    }
}

impl std::error::Error for GfError {}

pub struct GfField {
    pub bits: u32,
    pub size: usize,
    exp: Vec<u8>,
    log: Vec<u8>,
}

impl GfField {
    pub fn new(bits: u32) -> Result<Self, GfError> {
        if bits != 4 && bits != 8 {
            return Err(GfError::UnsupportedField);
        }
        let size = 1usize << bits;
        let poly: u32 = if bits == 4 { 0x13 } else { 0x11d };
        let mut exp = vec![0u8; 2 * (size - 1)];
        let mut log = vec![0u8; size];
        let mut x: u32 = 1;
        for i in 0..size - 1 {
            exp[i] = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & (size as u32) != 0 {
                x ^= poly;
            }
        }
        for i in size - 1..2 * (size - 1) {
            exp[i] = exp[i - (size - 1)];
        }
        Ok(GfField { bits, size, exp, log })
    }

    #[inline]
    pub fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }
        let la = self.log[a as usize] as usize;
        let lb = self.log[b as usize] as usize;
        self.exp[(la + lb) % (self.size - 1)]
    }

    #[inline]
    pub fn inv(&self, a: u8) -> u8 {
        debug_assert!(a != 0);
        self.exp[self.size - 1 - self.log[a as usize] as usize]
    }

    #[inline]
    pub fn div(&self, a: u8, b: u8) -> u8 {
        if a == 0 {
            return 0;
        }
        let la = self.log[a as usize] as usize;
        let lb = self.log[b as usize] as usize;
        let m = self.size - 1;
        self.exp[(la + m - lb) % m]
    }

    /// Cauchy 矩阵元素 C[p][j] = 1 / (x_p XOR y_j)，
    /// x_p = p，y_j = n + j，保证两组互不相交且异或非零。
    fn cauchy(&self, p: usize, j: usize, n: usize) -> u8 {
        let x = p as u32;
        let y = (n + j) as u32;
        self.inv((x ^ y) as u8)
    }

    /// 由 k 个数据 shard 生成全部 k+m 个 shard。
    pub fn encode(&self, k: usize, m: usize, data: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, GfError> {
        if k < 1 || m == usize::MAX || data.len() != k {
            return Err(GfError::BadParams);
        }
        if 2 * k + m > self.size {
            return Err(GfError::BadParams);
        }
        let len = data.first().map(|d| d.len()).unwrap_or(0);
        if data.iter().any(|d| d.len() != len) {
            return Err(GfError::LengthMismatch);
        }
        let n = k + m;
        let mut out: Vec<Vec<u8>> = data.iter().cloned().collect();
        for p in k..n {
            let mut parity = vec![0u8; len];
            for (j, d) in data.iter().enumerate() {
                let c = self.cauchy(p, j, n);
                if c == 0 {
                    return Err(GfError::Singular);
                }
                for t in 0..len {
                    parity[t] ^= self.mul(c, d[t]);
                }
            }
            out.push(parity);
        }
        Ok(out)
    }

    /// 已知任意 >=k 个位置的 shard，重建全部 k+m 个 shard。
    /// 已知 shard 之间若矛盾（超过 k 个且不满足同一码词）返回 Inconsistent。
    pub fn reconstruct(
        &self,
        k: usize,
        m: usize,
        known: &[(usize, Vec<u8>)],
    ) -> Result<Vec<Vec<u8>>, GfError> {
        if k < 1 || 2 * k + m > self.size {
            return Err(GfError::BadParams);
        }
        let n = k + m;
        if known.len() < k {
            return Err(GfError::NotEnoughShards);
        }
        if known.iter().any(|(p, _)| *p >= n) {
            return Err(GfError::BadParams);
        }
        let len = known[0].1.len();
        if known.iter().any(|(_, b)| b.len() != len) {
            return Err(GfError::LengthMismatch);
        }
        let mask = (self.size - 1) as u8;

        let row = |p: usize, j: usize| -> u8 {
            if p < k {
                if p == j {
                    1
                } else {
                    0
                }
            } else {
                self.cauchy(p, j, n)
            }
        };

        // 用前 k 个已知 shard 求逆矩阵：[A|I] -> [I|A^-1]
        let base = &known[..k];
        let mut a: Vec<Vec<u8>> = vec![vec![0u8; 2 * k]; k];
        for r in 0..k {
            let p = base[r].0;
            for j in 0..k {
                a[r][j] = row(p, j) & mask;
            }
            a[r][k + r] = 1;
        }
        for col in 0..k {
            let pivot = (col..k)
                .find(|&r| a[r][col] != 0)
                .ok_or(GfError::Singular)?;
            a.swap(col, pivot);
            let pinv = self.inv(a[col][col]);
            for c in 0..2 * k {
                a[col][c] = self.mul(a[col][c], pinv);
            }
            for r in 0..k {
                if r != col && a[r][col] != 0 {
                    let factor = a[r][col];
                    for c in 0..2 * k {
                        a[r][c] ^= self.mul(factor, a[col][c]);
                    }
                }
            }
        }

        let mut data: Vec<Vec<u8>> = vec![vec![0u8; len]; k];
        for j in 0..k {
            for (r, (_, bytes)) in base.iter().enumerate() {
                let coef = a[j][k + r];
                if coef == 0 {
                    continue;
                }
                for t in 0..len {
                    data[j][t] ^= self.mul(coef, bytes[t]);
                }
            }
        }

        let mut full = self.encode(k, m, &data)?;
        // 所有已知 shard 必须落在同一码词上。
        for (p, bytes) in known {
            if full[*p] != *bytes {
                return Err(GfError::Inconsistent);
            }
        }
        // 回填已知字节（encode 结果理论上相同，保持来源字节原样）。
        for (p, bytes) in known {
            full[*p] = bytes.clone();
        }
        Ok(full)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf16_roundtrip_any_k_positions() {
        let f = GfField::new(4).unwrap();
        let data = vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8]];
        let all = f.encode(2, 2, &data).unwrap();
        for missing in [vec![2, 3], vec![0, 3], vec![1, 2], vec![0, 1]] {
            let known: Vec<_> = (0..4)
                .filter(|p| !missing.contains(p))
                .map(|p| (p, all[p].clone()))
                .collect();
            let rec = f.reconstruct(2, 2, &known).unwrap();
            assert_eq!(rec, all);
        }
    }

    #[test]
    fn gf8_roundtrip() {
        let f = GfField::new(8).unwrap();
        let data: Vec<Vec<u8>> = (0..3).map(|j| (0..16).map(|t| (j * 31 + t) as u8).collect()).collect();
        let all = f.encode(3, 2, &data).unwrap();
        let known = vec![(0usize, all[0].clone()), (2usize, all[2].clone()), (4usize, all[4].clone())];
        assert_eq!(f.reconstruct(3, 2, &known).unwrap(), all);
    }

    #[test]
    fn contradiction_detected() {
        let f = GfField::new(4).unwrap();
        let data = vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8]];
        let mut all = f.encode(2, 1, &data).unwrap();
        all[2][0] ^= 0x9;
        let known = vec![(0, all[0].clone()), (1, all[1].clone()), (2, all[2].clone())];
        assert_eq!(f.reconstruct(2, 1, &known).err(), Some(GfError::Inconsistent));
    }
}
