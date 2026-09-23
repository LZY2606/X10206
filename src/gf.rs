//! GF(2^8) 有限域算术与 Vandermonde Reed-Solomon 编解码（小有限域，适合 fixture）。
//!
//! 本原多项式 x^8 + x^4 + x^3 + x^2 + 1（0x11d），生成元 2。

const POLY: u16 = 0x11d;

#[derive(Clone)]
pub struct Tables {
    pub exp: [u8; 512],
    pub log: [u8; 256],
}

pub fn tables() -> Tables {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut x: u16 = 1;
    for i in 0..255 {
        exp[i] = x as u8;
        log[x as usize] = i as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= POLY;
        }
    }
    for i in 255..512 {
        exp[i] = exp[i - 255];
    }
    Tables { exp, log }
}

impl Tables {
    pub fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            let la = self.log[a as usize] as usize;
            let lb = self.log[b as usize] as usize;
            self.exp[la + lb]
        }
    }

    pub fn inv(&self, a: u8) -> u8 {
        assert!(a != 0, "0 has no inverse");
        self.exp[255 - self.log[a as usize] as usize]
    }

    /// GF(2^8) 上的矩阵求逆（高斯-约当消元），失败返回 None（矩阵奇异）。
    pub fn invert(&self, m: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
        let n = m.len();
        if n == 0 || m.iter().any(|r| r.len() != n) {
            return None;
        }
        let mut a: Vec<Vec<u8>> = m.to_vec();
        let mut inv: Vec<Vec<u8>> = (0..n).map(|i| {
            let mut r = vec![0u8; n];
            r[i] = 1;
            r
        }).collect();

        for col in 0..n {
            let pivot = (col..n).find(|&r| a[r][col] != 0)?;
            if pivot != col {
                a.swap(pivot, col);
                inv.swap(pivot, col);
            }
            let p = a[col][col];
            let pinv = self.inv(p);
            for j in 0..n {
                a[col][j] = self.mul(a[col][j], pinv);
                inv[col][j] = self.mul(inv[col][j], pinv);
            }
            for r in 0..n {
                if r == col {
                    continue;
                }
                let factor = a[r][col];
                if factor == 0 {
                    continue;
                }
                for j in 0..n {
                    a[r][j] ^= self.mul(factor, a[col][j]);
                    inv[r][j] ^= self.mul(factor, inv[col][j]);
                }
            }
        }
        Some(inv)
    }
}

/// Reed-Solomon 编解码器：k 个数据块，m 个校验块。
pub struct ReedSolomon {
    pub k: usize,
    pub m: usize,
    pub t: Tables,
    /// n x k 编码矩阵（前 k 行为单位阵）。
    pub enc: Vec<Vec<u8>>,
}

impl ReedSolomon {
    pub fn new(k: usize, m: usize) -> Self {
        assert!(k >= 1 && m >= 1 && k + m <= 256, "k>=1,m>=1,k+m<=256");
        let t = tables();
        let n = k + m;
        let mut enc = vec![vec![0u8; k]; n];
        for i in 0..k {
            enc[i][i] = 1;
        }
        // 校验行：Vandermonde alpha^(r*j)，alpha=2，r 从 1 起避免与单位行重复。
        for r in 0..m {
            for j in 0..k {
                enc[k + r][j] = t.exp[(r + 1) * j % 255];
            }
        }
        ReedSolomon { k, m, t, enc }
    }

    pub fn n(&self) -> usize {
        self.k + self.m
    }

    /// 由 k 个等长数据块计算 m 个校验块。
    pub fn encode(&self, data: &[Vec<u8>]) -> Vec<Vec<u8>> {
        assert_eq!(data.len(), self.k);
        let shard_len = data[0].len();
        assert!(data.iter().all(|d| d.len() == shard_len), "data shard length mismatch");
        let mut parity = vec![vec![0u8; shard_len]; self.m];
        for r in 0..self.m {
            for j in 0..self.k {
                let coef = self.enc[self.k + r][j];
                if coef == 0 {
                    continue;
                }
                let out = &mut parity[r];
                let dj = &data[j];
                if coef == 1 {
                    for (o, v) in out.iter_mut().zip(dj) {
                        *o ^= *v;
                    }
                } else {
                    for (o, v) in out.iter_mut().zip(dj) {
                        *o ^= self.t.mul(coef, *v);
                    }
                }
            }
        }
        parity
    }

    /// 从 (shard_index -> 字节) 的已知块重建全部 k 个数据块。
    /// 已知块至少 k 个且索引合法；内部取编号最小的 k 个求解（任意 k 行均可逆）。
    pub fn reconstruct(&self, known: &[(usize, Vec<u8>)]) -> Option<Vec<Vec<u8>>> {
        if known.len() < self.k || known.iter().any(|(i, _)| *i >= self.n()) {
            return None;
        }
        let mut positions: Vec<usize> = known.iter().map(|(i, _)| *i).collect();
        positions.sort_unstable();
        positions.dedup();
        if positions.len() < self.k {
            return None;
        }
        positions.truncate(self.k);
        let shard_len = known[0].1.len();
        if known.iter().any(|(_, b)| b.len() != shard_len) {
            return None;
        }
        let by_idx: std::collections::HashMap<usize, &Vec<u8>> =
            known.iter().map(|(i, b)| (*i, b)).collect();

        // A 为选中的 k 个编码行；数据 D 满足 A * D_rows = known。
        let a: Vec<Vec<u8>> = positions.iter().map(|p| self.enc[*p].clone()).collect();
        let a_inv = self.t.invert(&a)?;
        let mut data = vec![vec![0u8; shard_len]; self.k];
        for row in 0..self.k {
            for (col, &p) in positions.iter().enumerate() {
                let coef = a_inv[row][col];
                if coef == 0 {
                    continue;
                }
                let src = by_idx[&p];
                let dst = &mut data[row];
                if coef == 1 {
                    for (d, s) in dst.iter_mut().zip(src) {
                        *d ^= *s;
                    }
                } else {
                    for (d, s) in dst.iter_mut().zip(src) {
                        *d ^= self.t.mul(coef, *s);
                    }
                }
            }
        }
        Some(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_k3_m2_single_and_multi_missing() {
        let rs = ReedSolomon::new(3, 2);
        let data = vec![vec![1u8, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];
        let parity = rs.encode(&data);
        let all: Vec<Vec<u8>> = data.iter().chain(parity.iter()).cloned().collect();

        for missing in [vec![0usize], vec![2], vec![3], vec![0, 1], vec![0, 4], vec![3, 4]] {
            let known: Vec<(usize, Vec<u8>)> = (0..5)
                .filter(|i| !missing.contains(i))
                .map(|i| (i, all[i].clone()))
                .collect();
            let recovered = rs.reconstruct(&known).expect("reconstruct");
            assert_eq!(recovered, data, "missing {:?}", missing);
        }
    }

    #[test]
    fn boundary_exactly_k_shards() {
        let rs = ReedSolomon::new(2, 2);
        let data = vec![vec![10u8, 20], vec![30, 40]];
        let parity = rs.encode(&data);
        // 恰好 k=2：两个校验块
        let known = vec![(2usize, parity[0].clone()), (3, parity[1].clone())];
        assert_eq!(rs.reconstruct(&known).unwrap(), data);
        // 只有 k-1 块不可恢复
        assert!(rs.reconstruct(&[(2usize, parity[0].clone())]).is_none());
    }

    #[test]
    fn flipped_byte_is_detected_via_digest_outside_gf() {
        // GF 层不做校验：翻转字节后重建得到错误数据（由上层摘要拒绝）。
        let rs = ReedSolomon::new(2, 1);
        let data = vec![vec![1u8, 2], vec![3, 4]];
        let parity = rs.encode(&data);
        let mut bad = data[1].clone();
        bad[0] ^= 0xFF;
        let known = vec![(0usize, data[0].clone()), (1, bad)];
        let out = rs.reconstruct(&known).unwrap();
        assert_ne!(out[1], data[1]);
        let _ = parity;
    }
}
