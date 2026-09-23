//! GF(2^8) Reed-Solomon, codec version `rs-gf256-v1`.
//!
//! Systematic Vandermonde layout: global shard indices `0..k` are data
//! shards (identity rows); indices `k..n` are parity rows `[x_i^j]`
//! evaluated at distinct non-zero field points. Any `k` rows invert.

pub const CODEC_VERSION: &str = "rs-gf256-v1";

const POLY: u16 = 0x11d;

pub struct Gf256 {
    log: [u8; 256],
    exp: [u8; 512],
}

impl Gf256 {
    pub fn new() -> Self {
        let mut log = [0u8; 256];
        let mut exp = [0u8; 512];
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
        Gf256 { log, exp }
    }

    #[inline]
    pub fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            let la = self.log[a as usize] as usize;
            let lb = self.log[b as usize] as usize;
            self.exp[la + lb]
        }
    }

    #[inline]
    pub fn inv(&self, a: u8) -> u8 {
        debug_assert!(a != 0);
        self.exp[255 - self.log[a as usize] as usize]
    }

    #[inline]
    pub fn pow_gen(&self, exponent: usize) -> u8 {
        self.exp[exponent % 255]
    }

    /// Evaluation point for parity row of global shard index `i >= k`.
    fn parity_point(&self, i: usize, k: usize) -> u8 {
        self.exp[(i - k + 1) % 255]
    }

    /// One matrix row for global shard index `i`.
    pub fn row(&self, i: usize, k: usize) -> Vec<u8> {
        let mut r = vec![0u8; k];
        if i < k {
            r[i] = 1;
        } else {
            let x = self.parity_point(i, k);
            r[0] = 1;
            for j in 1..k {
                r[j] = self.mul(r[j - 1], x);
            }
        }
        r
    }

    /// Encode `k` equal-length data shards into `n` shards (systematic).
    pub fn encode(&self, data: &[Vec<u8>], n: usize) -> Vec<Vec<u8>> {
        let k = data.len();
        let len = data[0].len();
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            if i < k {
                out.push(data[i].clone());
                continue;
            }
            let row = self.row(i, k);
            let mut buf = vec![0u8; len];
            for p in 0..len {
                let mut acc = 0u8;
                for j in 0..k {
                    acc ^= self.mul(row[j], data[j][p]);
                }
                buf[p] = acc;
            }
            out.push(buf);
        }
        out
    }

    /// Invert a square matrix over GF(2^8). Returns `None` if singular.
    fn invert(&self, m: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
        let k = m.len();
        let mut a: Vec<Vec<u8>> = m.to_vec();
        let mut inv = vec![vec![0u8; k]; k];
        for i in 0..k {
            inv[i][i] = 1;
        }
        for col in 0..k {
            let pivot = (col..k).find(|&r| a[r][col] != 0)?;
            if pivot != col {
                a.swap(pivot, col);
                inv.swap(pivot, col);
            }
            let p = a[col][col];
            let pinv = self.inv(p);
            for j in 0..k {
                a[col][j] = self.mul(a[col][j], pinv);
                inv[col][j] = self.mul(inv[col][j], pinv);
            }
            for r in 0..k {
                if r == col {
                    continue;
                }
                let f = a[r][col];
                if f == 0 {
                    continue;
                }
                for j in 0..k {
                    a[r][j] ^= self.mul(f, a[col][j]);
                    inv[r][j] ^= self.mul(f, inv[col][j]);
                }
            }
        }
        Some(inv)
    }

    /// Reconstruct all `n` shards from `rows`/`values` (exactly `k` entries).
    pub fn reconstruct(
        &self,
        rows: &[usize],
        values: &[Vec<u8>],
        k: usize,
        n: usize,
    ) -> Option<Vec<Vec<u8>>> {
        if rows.len() != k || values.len() != k {
            return None;
        }
        let len = values[0].len();
        if values.iter().any(|v| v.len() != len) {
            return None;
        }
        let a: Vec<Vec<u8>> = rows.iter().map(|&i| self.row(i, k)).collect();
        let inv = self.invert(&a)?;

        let mut data = vec![vec![0u8; len]; k];
        for j in 0..k {
            for p in 0..len {
                let mut acc = 0u8;
                for t in 0..k {
                    acc ^= self.mul(inv[j][t], values[t][p]);
                }
                data[j][p] = acc;
            }
        }
        Some(self.encode(&data, n))
    }
}

impl Default for Gf256 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_then_reconstruct_each_subset() {
        let gf = Gf256::new();
        let data = vec![vec![1u8, 2, 3, 4], vec![5, 6, 7, 8]];
        let all = gf.encode(&data, 4);
        for missing in 0..4 {
            let keep: Vec<usize> = (0..4).filter(|&i| i != missing).collect();
            let vals: Vec<Vec<u8>> = keep.iter().map(|&i| all[i].clone()).collect();
            let rec = gf.reconstruct(&keep, &vals, 2, 4).unwrap();
            assert_eq!(rec, all);
        }
    }

    #[test]
    fn parity_subset_recovers_data() {
        let gf = Gf256::new();
        let data = vec![vec![9u8, 9, 9], vec![1, 2, 3]];
        let all = gf.encode(&data, 5);
        let keep = vec![3usize, 4];
        let vals = vec![all[3].clone(), all[4].clone()];
        let rec = gf.reconstruct(&keep, &vals, 2, 5).unwrap();
        assert_eq!(&rec[..2], data.as_slice());
    }
}
