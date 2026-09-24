//! Version 1 erasure coding: Reed-Solomon over GF(2^8).
//!
//! Field: primitive polynomial 0x11d (x^8 + x^4 + x^3 + x^2 + 1), generator 2.
//! Encoding matrix (n = data + parity rows, k columns):
//!   rows 0..k      -> identity (systematic data shards)
//!   rows k..n      -> Cauchy coefficients 1 / (x_i XOR y_j),
//!                     x_i = i, y_j = 0x80 + j.
//! Any k rows of this matrix form an invertible linear system, which lets us
//! rebuild arbitrary missing shards (data or parity) from any k survivors.

pub const CODEC_VERSION_V1: u32 = 1;
pub const MAX_TOTAL_SHARDS: usize = 128;

#[derive(Clone, Copy)]
pub struct Gf256 {
    exp: [u8; 512],
    log: [u8; 256],
}

impl Gf256 {
    pub fn new() -> Self {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for i in 0..255u16 {
            exp[i as usize] = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= 0x11d;
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
        assert!(a != 0, "GF(256): inverse of zero");
        self.exp[255 - self.log[a as usize] as usize]
    }

    pub fn div(&self, a: u8, b: u8) -> u8 {
        if a == 0 {
            return 0;
        }
        let la = self.log[a as usize] as i16;
        let lb = self.log[b as usize] as i16;
        let mut e = la - lb;
        if e < 0 {
            e += 255;
        }
        self.exp[e as usize]
    }

    /// n x k encoding matrix (systematic + Cauchy parity).
    pub fn encoding_matrix(&self, k: usize, n: usize) -> Vec<Vec<u8>> {
        assert!(n <= MAX_TOTAL_SHARDS, "v1 supports at most {MAX_TOTAL_SHARDS} shards");
        assert!(k >= 1 && n >= k);
        let mut mat = vec![vec![0u8; k]; n];
        for j in 0..k {
            mat[j][j] = 1;
        }
        for i in k..n {
            for j in 0..k {
                mat[i][j] = self.inv((i as u8) ^ (0x80 | j as u8));
            }
        }
        mat
    }

    /// Invert a square matrix over GF(256) using Gauss-Jordan elimination.
    pub fn invert(&self, m: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
        let s = m.len();
        let mut a = m.to_vec();
        let mut inv = vec![vec![0u8; s]; s];
        for i in 0..s {
            inv[i][i] = 1;
        }
        for col in 0..s {
            let pivot = (col..s).find(|&r| a[r][col] != 0)?;
            a.swap(col, pivot);
            inv.swap(col, pivot);
            let p = a[col][col];
            let pinv = self.inv(p);
            for c in 0..s {
                a[col][c] = self.mul(a[col][c], pinv);
                inv[col][c] = self.mul(inv[col][c], pinv);
            }
            for r in 0..s {
                if r == col || a[r][col] == 0 {
                    continue;
                }
                let f = a[r][col];
                for c in 0..s {
                    a[r][c] ^= self.mul(f, a[col][c]);
                    inv[r][c] ^= self.mul(f, inv[col][c]);
                }
            }
        }
        Some(inv)
    }

    /// Reconstruct all n stripe blocks from the selected survivor rows.
    ///
    /// `survivors`: (original row index, block bytes) with exactly k entries.
    /// Returns n blocks of length `block_len`.
    pub fn reconstruct(
        &self,
        k: usize,
        n: usize,
        block_len: usize,
        survivors: &[(usize, Vec<u8>)],
    ) -> Option<Vec<Vec<u8>>> {
        if survivors.len() != k || survivors.iter().any(|(_, b)| b.len() != block_len) {
            return None;
        }
        let enc = self.encoding_matrix(k, n);
        let sub: Vec<Vec<u8>> = survivors.iter().map(|(idx, _)| enc[*idx].clone()).collect();
        let inv = self.invert(&sub)?;
        let mut data = vec![vec![0u8; block_len]; k];
        for (s, (_, block)) in survivors.iter().enumerate() {
            for (p, drow) in data.iter_mut().enumerate() {
                let coef = inv[p][s];
                if coef == 0 {
                    continue;
                }
                for t in 0..block_len {
                    drow[t] ^= self.mul(coef, block[t]);
                }
            }
        }
        let mut out = vec![vec![0u8; block_len]; n];
        for i in 0..n {
            for j in 0..k {
                let coef = enc[i][j];
                if coef == 0 {
                    continue;
                }
                for t in 0..block_len {
                    out[i][t] ^= self.mul(coef, data[j][t]);
                }
            }
        }
        Some(out)
    }
}

impl Default for Gf256 {
    fn default() -> Self {
        Self::new()
    }
}

/// Encode k data blocks into n blocks (first k are the original data).
pub fn encode_stripe(gf: &Gf256, k: usize, n: usize, data: &[Vec<u8>]) -> Vec<Vec<u8>> {
    assert_eq!(data.len(), k);
    let len = data[0].len();
    assert!(data.iter().all(|b| b.len() == len));
    let mat = gf.encoding_matrix(k, n);
    let mut out = vec![vec![0u8; len]; n];
    for i in 0..n {
        for j in 0..k {
            let coef = mat[i][j];
            if coef == 0 {
                continue;
            }
            for t in 0..len {
                out[i][t] ^= gf.mul(coef, data[j][t]);
            }
        }
    }
    out
}
