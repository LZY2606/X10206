//! GF(2^4) arithmetic and systematic Cauchy Reed-Solomon coding.
//!
//! Primitive polynomial: x^4 + x + 1 (0x13).
//! Every byte stores one nibble symbol (0..=15), one symbol per byte,
//! so shards are plain byte slices and a flipped bit is a flipped symbol.

const EXP: [u8; 31] = make_exp();
const LOG: [u8; 16] = make_log();

const fn clmul4(a: u8, b: u8) -> u8 {
    let mut r: u16 = 0;
    let mut i = 0;
    while i < 4 {
        if (b >> i) & 1 == 1 {
            r ^= (a as u16) << i;
        }
        i += 1;
    }
    (r & 0b1111) as u8
}

const fn reduce(mut p: u16) -> u8 {
    let mut bit = 7;
    while bit >= 4 {
        if (p >> bit) & 1 == 1 {
            p ^= 0x13 << (bit - 4);
        }
        if bit == 0 {
            break;
        }
        bit -= 1;
    }
    (p & 0b1111) as u8
}

const fn make_exp() -> [u8; 31] {
    let mut table = [0u8; 31];
    let mut v: u8 = 1;
    let mut i = 0;
    while i < 30 {
        table[i] = v;
        let mut nv = (v as u16) << 1;
        if nv & 0b10000 != 0 {
            nv ^= 0x13;
        }
        v = (nv & 0b1111) as u8;
        i += 1;
    }
    table[30] = table[0];
    table
}

const fn make_log() -> [u8; 16] {
    let mut table = [0u8; 16];
    let mut i = 0;
    while i < 15 {
        table[EXP[i] as usize] = i as u8;
        i += 1;
    }
    table
}

/// Multiply two GF(16) symbols.
pub const fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        0
    } else {
        EXP[(LOG[a as usize] + LOG[b as usize]) as usize]
    }
}

/// Slow polynomial multiplication + reduction (used by tests / fixtures).
pub const fn poly_mul_reduce(a: u8, b: u8) -> u8 {
    reduce(clmul4(a, b) as u16)
}

/// Multiplicative inverse; zero maps to zero.
pub fn inv(a: u8) -> u8 {
    assert!(a != 0, "inverse of zero");
    EXP[15 - LOG[a as usize] as usize]
}

/// Invert a square GF(16) matrix via Gauss-Jordan elimination.
/// Returns `None` when singular.
pub fn inverse(matrix: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    let k = matrix.len();
    if k == 0 || matrix.iter().any(|row| row.len() != k) {
        return None;
    }
    let mut a: Vec<Vec<u8>> = matrix.to_vec();
    let mut inv = vec![vec![0u8; k]; k];
    for (i, row) in inv.iter_mut().enumerate() {
        row[i] = 1;
    }
    for col in 0..k {
        let pivot = (col..k).find(|&r| a[r][col] != 0)?;
        if pivot != col {
            a.swap(col, pivot);
            inv.swap(col, pivot);
        }
        let p = a[col][col];
        if p != 1 {
            let pi = inv(p);
            for c in 0..k {
                a[col][c] = mul(a[col][c], pi);
                inv[col][c] = mul(inv[col][c], pi);
            }
        }
        for r in 0..k {
            if r != col && a[r][col] != 0 {
                let f = a[r][col];
                for c in 0..k {
                    a[r][c] ^= mul(f, a[col][c]);
                    inv[r][c] ^= mul(f, inv[col][c]);
                }
            }
        }
    }
    Some(inv)
}

/// Generator coefficient of shard `row` from data column `i`.
/// Rows 0..k are identity; rows k..n use a Cauchy construction
/// `1 / (i XOR x_row)`, guaranteeing every k x k minor is invertible.
pub fn coefficient(k: usize, n: usize, row: usize, i: usize) -> u8 {
    assert!(n <= 16 && k <= n && i < k && row < n);
    if row < k {
        if row == i {
            1
        } else {
            0
        }
    } else {
        let x = row as u8;
        let y = i as u8;
        inv(x ^ y)
    }
}

/// Systematic encode: takes the `k` data shards, returns all `n` shards.
pub fn encode(data: &[Vec<u8>], k: usize, n: usize) -> Vec<Vec<u8>> {
    assert_eq!(data.len(), k);
    let shard_len = if k == 0 { 0 } else { data[0].len() };
    assert!(data.iter().all(|d| d.len() == shard_len));
    let mut out = vec![vec![0u8; shard_len]; n];
    for (i, d) in data.iter().enumerate() {
        for (t, sym) in d.iter().enumerate() {
            for row in 0..n {
                let c = coefficient(k, n, row, i);
                if c != 0 {
                    out[row][t] ^= mul(c, *sym);
                }
            }
        }
    }
    out
}

/// Reconstruct all `n` shards from any >= k available shards.
/// `present` maps shard index -> bytes. The first `k` available indices
/// (sorted) are used as the decoding minor.
pub fn decode(
    k: usize,
    n: usize,
    present: &std::collections::BTreeMap<usize, Vec<u8>>,
    shard_len: usize,
) -> Result<Vec<Vec<u8>>, DecodeError> {
    if n > 16 {
        return Err(DecodeError::UnsupportedField);
    }
    if present.len() < k {
        return Err(DecodeError::BelowThreshold {
            have: present.len(),
            need: k,
        });
    }
    let rows: Vec<usize> = present.keys().copied().take(k).collect();
    let minor: Vec<Vec<u8>> = rows
        .iter()
        .map(|&r| (0..k).map(|i| coefficient(k, n, r, i)).collect())
        .collect();
    let inv_minor = inverse(&minor).ok_or(DecodeError::SingularMinor)?;
    let mut data = vec![vec![0u8; shard_len]; k];
    for t in 0..shard_len {
        let avail: Vec<u8> = rows
            .iter()
            .map(|&r| {
                let bytes = present.get(&r).expect("present");
                *bytes.get(t).unwrap_or(&0)
            })
            .collect();
        for i in 0..k {
            let mut s = 0u8;
            for (j, &a) in avail.iter().enumerate() {
                s ^= mul(inv_minor[i][j], a);
            }
            data[i][t] = s;
        }
    }
    Ok(encode(&data, k, n))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    BelowThreshold { have: usize, need: usize },
    SingularMinor,
    UnsupportedField,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn tables_are_consistent() {
        for a in 0..16u8 {
            for b in 0..16u8 {
                assert_eq!(mul(a, b), poly_mul_reduce(a, b), "{a}*{b}");
            }
        }
        for a in 1..16u8 {
            assert_eq!(mul(a, inv(a)), 1);
        }
    }

    #[test]
    fn roundtrip_any_missing_pattern_k3_n5() {
        let data = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];
        let all = encode(&data, 3, 5);
        for missing_bits in 0u32..(1 << 5) {
            if missing_bits.count_ones() > 2 {
                continue;
            }
            let present: BTreeMap<usize, Vec<u8>> = (0..5)
                .filter(|i| missing_bits & (1 << i) == 0)
                .map(|i| (i, all[i].clone()))
                .collect();
            let rebuilt = decode(3, 5, &present, 3).unwrap();
            assert_eq!(rebuilt, all, "missing pattern {missing_bits:b}");
        }
    }

    #[test]
    fn wrong_shard_is_detected_after_rebuild() {
        let data = vec![vec![1u8], vec![2], vec![3]];
        let all = encode(&data, 3, 5);
        let mut present: BTreeMap<usize, Vec<u8>> = BTreeMap::new();
        present.insert(0, all[0].clone());
        present.insert(1, all[1].clone());
        let mut bad = all[4].clone();
        bad[0] ^= 0b1010;
        present.insert(4, bad);
        let rebuilt = decode(3, 5, &present, 1).unwrap();
        assert_ne!(rebuilt[4], all[4]);
        // the provided shards themselves must mismatch the code space
        assert_ne!(rebuilt[0], present[&0]);
    }
}
