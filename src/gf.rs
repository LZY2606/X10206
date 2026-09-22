//! GF(2^8) 有限域与 Cauchy Reed-Solomon 编解码（小有限域，适用于离线审阅 fixture）。
//!
//! 生成多项式 0x11d（x^8 + x^4 + x^3 + x^2 + 1）。编码矩阵采用 Cauchy 矩阵：
//! 第 (k+p) 行第 j 列系数为 1 / (x_p XOR j)，其中 x_p = k + p。
//! 数据行 0..k 为单位阵。要求 k + m <= 255，避免 Cauchy 坐标重复。
//!
//! 解码不做"贪心猜"：由调用方枚举恰好 k 个现有块的子集调用
//! [`Gf256::reconstruct`]，再用 [`Gf256::verify_row`] 逐块核对，
//! 从而能明确指出哪些块与方程一致、哪些是编码矛盾证据。

pub struct Gf256 {
    pub exp: [u8; 512],
    pub log: [u8; 256],
}

pub const DEFAULT_POLY: u16 = 0x11d;

impl Gf256 {
    pub fn new(poly: u16) -> Self {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for i in 0..255 {
            exp[i] = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= poly;
            }
        }
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }
        Gf256 { exp, log }
    }

    #[inline]
    pub fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }
        let la = self.log[a as usize] as u16;
        let lb = self.log[b as usize] as u16;
        self.exp[(la + lb) as usize]
    }

    #[inline]
    pub fn inv(&self, a: u8) -> u8 {
        debug_assert!(a != 0, "0 has no inverse in GF(256)");
        self.exp[255 - self.log[a as usize] as usize]
    }

    #[inline]
    pub fn div(&self, a: u8, b: u8) -> u8 {
        self.mul(a, self.inv(b))
    }

    /// 编码矩阵第 row 行（row in 0..k+m），长度 k 的系数向量。
    pub fn generator_row(&self, k: u8, m: u8, row: u8) -> Vec<u8> {
        assert!((k as u16) + (m as u16) <= 255, "field too small for k+m shards");
        assert!(row < k + m, "row out of range");
        let mut out = Vec::with_capacity(k as usize);
        if row < k {
            for j in 0..k {
                out.push(if j == row { 1 } else { 0 });
            }
        } else {
            for j in 0..k {
                out.push(self.inv(row ^ j));
            }
        }
        out
    }

    /// 由 k 个数据块计算全部 m 个 parity 块。
    pub fn encode_parity(&self, k: u8, m: u8, data: &[Vec<u8>]) -> Vec<Vec<u8>> {
        assert_eq!(data.len(), k as usize);
        let len = data.first().map(|d| d.len()).unwrap_or(0);
        assert!(data.iter().all(|d| d.len() == len), "unequal data shard lengths");
        let mut parity = Vec::with_capacity(m as usize);
        for p in 0..m {
            let coefs = self.generator_row(k, m, k + p);
            let mut out = vec![0u8; len];
            for (j, coef) in coefs.iter().enumerate() {
                if *coef == 0 {
                    continue;
                }
                let dj = &data[j];
                for b in 0..len {
                    out[b] ^= self.mul(*coef, dj[b]);
                }
            }
            parity.push(out);
        }
        parity
    }

    /// 在 GF(256) 上求方阵逆（高斯-约旦消元）。奇异返回 None。
    pub fn invert_matrix(&self, mat: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
        let n = mat.len();
        let mut aug = vec![vec![0u8; 2 * n]; n];
        for i in 0..n {
            aug[i][..n].copy_from_slice(&mat[i]);
            aug[i][n + i] = 1;
        }
        for col in 0..n {
            let pivot = (col..n).find(|&r| aug[r][col] != 0)?;
            aug.swap(col, pivot);
            let pinv = self.inv(aug[col][col]);
            for c in col..2 * n {
                aug[col][c] = self.mul(aug[col][c], pinv);
            }
            for r in 0..n {
                if r != col && aug[r][col] != 0 {
                    let factor = aug[r][col];
                    for c in col..2 * n {
                        let v = self.mul(factor, aug[col][c]);
                        aug[r][c] ^= v;
                    }
                }
            }
        }
        Some(aug.iter().map(|row| row[n..].to_vec()).collect())
    }

    /// 给定恰好 k 个现有块（(行号, 字节)，可含 data/parity），重建全部 k+m 块。
    /// 矩阵奇异返回 None。不校验其它未参与块——由调用方用 verify_row 核对。
    pub fn reconstruct(
        &self,
        k: u8,
        m: u8,
        stripe_len: usize,
        chosen: &[(u8, Vec<u8>)],
    ) -> Option<Vec<Vec<u8>>> {
        assert_eq!(chosen.len(), k as usize, "must select exactly k shards");
        let n = k as usize + m as usize;
        let mat: Vec<Vec<u8>> = chosen
            .iter()
            .map(|(r, _)| self.generator_row(k, m, *r))
            .collect();
        let inv_mat = self.invert_matrix(&mat)?;

        let mut data: Vec<Vec<u8>> = vec![vec![0u8; stripe_len]; k as usize];
        for (l, (_, bytes)) in chosen.iter().enumerate() {
            assert_eq!(bytes.len(), stripe_len, "shard length mismatch in subset");
            for j in 0..k as usize {
                let coef = inv_mat[j][l];
                if coef == 0 {
                    continue;
                }
                for b in 0..stripe_len {
                    data[j][b] ^= self.mul(coef, bytes[b]);
                }
            }
        }

        let mut all = Vec::with_capacity(n);
        for i in 0..n as u8 {
            if (i as usize) < k as usize {
                all.push(data[i as usize].clone());
            } else {
                let coefs = self.generator_row(k, m, i);
                let mut out = vec![0u8; stripe_len];
                for j in 0..k as usize {
                    let coef = coefs[j];
                    if coef == 0 {
                        continue;
                    }
                    for b in 0..stripe_len {
                        out[b] ^= self.mul(coef, data[j][b]);
                    }
                }
                all.push(out);
            }
        }
        Some(all)
    }

    /// 用重建数据计算第 row 行应有的字节。
    pub fn expected_row(&self, k: u8, m: u8, data: &[Vec<u8>], row: u8) -> Vec<u8> {
        let coefs = self.generator_row(k, m, row);
        let len = data[0].len();
        let mut out = vec![0u8; len];
        for (j, coef) in coefs.iter().enumerate() {
            if *coef == 0 {
                continue;
            }
            for b in 0..len {
                out[b] ^= self.mul(*coef, data[j][b]);
            }
        }
        out
    }

    /// 逐字节核对某现有块是否与重建数据一致。
    pub fn verify_row(&self, k: u8, m: u8, data: &[Vec<u8>], row: u8, bytes: &[u8]) -> bool {
        if bytes.len() != data[0].len() {
            return false;
        }
        self.expected_row(k, m, data, row) == bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> (u8, u8, Vec<Vec<u8>>) {
        let gf = Gf256::new(DEFAULT_POLY);
        let (k, m) = (3u8, 2u8);
        let data = vec![vec![1u8, 9, 50], vec![2, 8, 51], vec![3, 7, 52]];
        let parity = gf.encode_parity(k, m, &data);
        let mut all = data;
        all.extend(parity);
        (k, m, all)
    }

    #[test]
    fn single_and_multi_loss_roundtrip() {
        let gf = Gf256::new(DEFAULT_POLY);
        let (k, m, all) = sample();
        let present = |drop: &[usize]| -> Vec<(u8, Vec<u8>)> {
            all.iter()
                .enumerate()
                .filter(|(i, _)| !drop.contains(i))
                .map(|(i, b)| (i as u8, b.clone()))
                .collect()
        };
        // 缺 1 个 parity：取任意 k 块子集即可重建
        let rec = gf.reconstruct(k, m, 3, &present(&[1, 4])).unwrap();
        assert_eq!(rec, all);
        // 恰好下限 k：缺两个 data
        let rec = gf.reconstruct(k, m, 3, &present(&[0, 2])).unwrap();
        assert_eq!(rec, all);
        // 下限且只剩 data
        let rec = gf.reconstruct(k, m, 3, &present(&[3, 4])).unwrap();
        assert_eq!(rec, all);
    }

    #[test]
    fn detects_bit_flip() {
        let gf = Gf256::new(DEFAULT_POLY);
        let (k, m, mut all) = sample();
        all[0][0] ^= 0x01;
        // 含坏块的子集重建后，坏块无法通过验证；避开坏块的子集可以。
        let bad_subset: Vec<(u8, Vec<u8>)> =
            vec![(0, all[0].clone()), (1, all[1].clone()), (2, all[2].clone())];
        let full = gf.reconstruct(k, m, 3, &bad_subset).unwrap();
        assert!(!gf.verify_row(k, m, &full[..3], 3, &all[3]));

        let good_subset: Vec<(u8, Vec<u8>)> =
            vec![(1, all[1].clone()), (2, all[2].clone()), (3, all[3].clone())];
        let full = gf.reconstruct(k, m, 3, &good_subset).unwrap();
        assert!(!gf.verify_row(k, m, &full[..3], 0, &all[0]));
        assert!(gf.verify_row(k, m, &full[..3], 4, &all[4]));
    }

    #[test]
    fn invert_identity() {
        let gf = Gf256::new(DEFAULT_POLY);
        let id = vec![vec![1, 0, 0], vec![0, 1, 0], vec![0, 0, 1]];
        assert_eq!(gf.invert_matrix(&id).unwrap(), id);
    }
}
