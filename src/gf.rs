//! GF(2^8) finite field arithmetic and systematic Reed-Solomon coding.
//!
//! Field polynomial: x^8 + x^4 + x^3 + x^2 + 1 (0x11d), generator 0x03.
//! Parity row `r` uses the Cauchy entry `1 / (data_col XOR parity_base(r))`,
//! which guarantees that any selection of coding rows is invertible (MDS).

const PRIM: u16 = 0x11d;

#[derive(Clone, Copy, Debug)]
pub struct Gf256 {
    log: [u8; 256],
    exp: [u8; 512],
}

impl Gf256 {
    fn new() -> Self {
        let mut log = [0u8; 256];
        let mut exp = [0u8; 512];
        let mut x: u16 = 1;
        for i in 0..255u16 {
            exp[i as usize] = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= PRIM;
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
            let i = self.log[a as usize] as u16 + self.log[b as usize] as u16;
            self.exp[i as usize]
        }
    }

    #[inline]
    pub fn inv(&self, a: u8) -> u8 {
        debug_assert!(a != 0);
        self.exp[255 - self.log[a as usize] as usize]
    }

    #[inline]
    pub fn div(&self, a: u8, b: u8) -> u8 {
        if a == 0 {
            0
        } else {
            self.mul(a, self.inv(b))
        }
    }

    /// Cauchy coding coefficient for parity row `r`, data column `c`.
    #[inline]
    pub fn cauchy(&self, r: usize, c: usize) -> u8 {
        let data_tag = c as u8;
        let parity_tag = (0x80u8 ^ (r as u8)) as u8;
        let x = data_tag ^ parity_tag;
        debug_assert!(x != 0, "cauchy tag collision r={r} c={c}");
        self.inv(x)
    }

    /// Gauss-Jordan inverse of a square GF(2^8) matrix.
    pub fn invert(&self, mut m: Vec<Vec<u8>>) -> Option<Vec<Vec<u8>>> {
        let n = m.len();
        let mut inv = vec![vec![0u8; n]; n];
        for i in 0..n {
            inv[i][i] = 1;
        }
        for col in 0..n {
            let pivot = (col..n).find(|&r| m[r][col] != 0)?;
            if pivot != col {
                m.swap(pivot, col);
                inv.swap(pivot, col);
            }
            let p = m[col][col];
            let pinv = self.inv(p);
            for j in 0..n {
                m[col][j] = self.mul(m[col][j], pinv);
                inv[col][j] = self.mul(inv[col][j], pinv);
            }
            for r in 0..n {
                if r == col {
                    continue;
                }
                let f = m[r][col];
                if f == 0 {
                    continue;
                }
                for j in 0..n {
                    m[r][j] ^= self.mul(f, m[col][j]);
                    inv[r][j] ^= self.mul(f, inv[col][j]);
                }
            }
        }
        Some(inv)
    }
}

once_cell::sync::Lazy!(pub static ref GF: Gf256 = Gf256::new());

/// Encode `data` (k shards, equal length) into parity shards (Cauchy RS).
pub fn encode(data: &[Vec<u8>], parity_count: usize) -> Vec<Vec<u8>> {
    let k = data.len();
    let len = data.iter().map(|s| s.len()).max().unwrap_or(0);
    let mut parity = vec![vec![0u8; len]; parity_count];
    let gf = &*GF;
    for r in 0..parity_count {
        for (off, byte) in parity[r].iter_mut().enumerate() {
            let mut acc = 0u8;
            for c in 0..k {
                let d = data[c].get(off).copied().unwrap_or(0);
                acc ^= gf.mul(gf.cauchy(r, c), d);
            }
            *byte = acc;
        }
    }
    parity
}

/// Rebuild missing shards of one stripe.
///
/// `known` maps shard index (0..k data, k..k+p parity) to received bytes.
/// Exactly `k` shards must be provided; all other indices are reconstructed.
/// Shards are padded to `stripe_len` with zero bytes.
pub fn decode(
    known: &[(usize, Vec<u8>)],
    k: usize,
    p: usize,
    stripe_len: usize,
) -> anyhow::Result<Vec<Vec<u8>>> {
    let total = k + p;
    if known.len() != k {
        anyhow::bail!("decode needs exactly {k} known shards, got {}", known.len());
    }
    let mut present = vec![false; total];
    for &(idx, _) in known {
        if idx >= total {
            anyhow::bail!("shard index {idx} out of range 0..{total}");
        }
        if present[idx] {
            anyhow::bail!("duplicate shard index {idx} in decode input");
        }
        present[idx] = true;
    }
    let known_idx: Vec<usize> = known.iter().map(|(i, _)| *i).collect();
    let missing: Vec<usize> = (0..total).filter(|i| !present[*i]).collect();
    let gf = &*GF;

    // Coding sub-matrix A: rows are the known shard indices (identity for data
    // rows, Cauchy rows for parity rows), columns are the missing shards.
    let mut a = vec![vec![0u8; k]; k];
    for (row, &idx) in known_idx.iter().enumerate() {
        if idx < k {
            a[row][idx] = 1;
        } else {
            let r = idx - k;
            for c in 0..k {
                a[row][c] = gf.cauchy(r, c);
            }
        }
    }
    let a_inv = gf
        .invert(a)
        .ok_or_else(|| anyhow::anyhow!("coding sub-matrix singular"))?;

    let mut known_padded: Vec<Vec<u8>> = known
        .iter()
        .map(|(_, bytes)| {
            let mut v = vec![0u8; stripe_len];
            v[..bytes.len().min(stripe_len)].copy_from_slice(&bytes[..bytes.len().min(stripe_len)]);
            v
        })
        .collect();

    let mut out = vec![vec![0u8; stripe_len]; total];
    // Reconstruct data shards first: D_missing = A^-1 * known.
    for (mi, &m_idx) in missing.iter().enumerate() {
        if m_idx >= k {
            continue;
        }
        let shard = &mut out[m_idx];
        for (row, coeff) in a_inv[m_idx].iter().enumerate() {
            if *coeff == 0 {
                continue;
            }
            for (off, b) in shard.iter_mut().enumerate() {
                *b ^= gf.mul(*coeff, known_padded[row][off]);
            }
        }
    }
    // Reconstructed data shards placed into the data vector for parity work.
    let mut data: Vec<Vec<u8>> = Vec::with_capacity(k);
    let mut data_by_missing = vec![usize::MAX; k];
    for c in 0..k {
        if present[c] {
            data.push(std::mem::take(&mut known_padded[known_idx.iter().position(|i| *i == c).unwrap()]));
        } else {
            data_by_missing[c] = missing.iter().position(|i| *i == c).unwrap();
            data.push(std::mem::take(&mut out[c]));
        }
    }
    // Parity shards: either already known or encoded from data.
    for idx in k..total {
        if present[idx] {
            let pos = known_idx.iter().position(|i| *i == idx).unwrap();
            let mut v = vec![0u8; stripe_len];
            v[..known[pos].1.len().min(stripe_len)]
                .copy_from_slice(&known[pos].1[..known[pos].1.len().min(stripe_len)]);
            out[idx] = v;
        } else {
            let r = idx - k;
            let mut shard = vec![0u8; stripe_len];
            for (off, byte) in shard.iter_mut().enumerate() {
                let mut acc = 0u8;
                for c in 0..k {
                    acc ^= gf.mul(gf.cauchy(r, c), data[c][off]);
                }
                *byte = acc;
            }
            out[idx] = shard;
        }
    }
    Ok(out)
}
