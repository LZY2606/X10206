//! Versioned Reed–Solomon encoding over GF(2^8).
//!
//! Two encoding parameter versions are kept on purpose: ingested payloads
//! carry the version they were written with, and reconstruction must use
//! the same coefficients rather than whatever the current default is.
//!
//! Layout of a stripe: shard indices `0..k` are data shards, `k..k+m` are
//! parity shards. All blocks of one stripe have identical byte length.

use crate::gf::Gf256;

/// Currently supported encoding-parameter versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodecVersion {
    /// Vandermonde parity rows: row r of parity uses alpha^(r*(d+1)).
    V1 = 1,
    /// Cauchy parity rows for k+m <= 256.
    V2 = 2,
}

impl CodecVersion {
    pub fn from_u8(v: u8) -> Option<CodecVersion> {
        match v {
            1 => Some(CodecVersion::V1),
            2 => Some(CodecVersion::V2),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Validate stripe geometry for a codec version.
pub fn validate_geometry(version: CodecVersion, k: u8, m: u8) -> Result<(), String> {
    if k == 0 {
        return Err("k must be > 0".into());
    }
    if m == 0 {
        return Err("m must be > 0".into());
    }
    let total = k as usize + m as usize;
    if total > 256 {
        return Err("k+m must be <= 256 over GF(2^8)".into());
    }
    if matches!(version, CodecVersion::V2) && total > 255 {
        return Err("cauchy layout needs k+m <= 255 (disjoint x/y sets)".into());
    }
    Ok(())
}

/// One coefficient row of the (k+m) x k generator matrix.
fn generator_row(gf: &Gf256, version: CodecVersion, index: u8, k: u8) -> Vec<u8> {
    let k = k as usize;
    let mut row = vec![0u8; k];
    if (index as usize) < k {
        row[index as usize] = 1;
        return row;
    }
    match version {
        CodecVersion::V1 => {
            // Vandermonde: parity row r (0-based among parity) evaluates
            // data column d at alpha^(r*(d+1)); any distinct non-zero
            // evaluation points give invertible kxk submatrices.
            let r = (index as usize) - k;
            for d in 0..k {
                let e = r * (d + 1);
                row[d] = gf.exp[e];
            }
        }
        CodecVersion::V2 => {
            // Cauchy row: M[r, d] = 1 / (x_r ^ y_d), with
            // x_r = k+r, y_d = d. With k+m <= 255 every shard index is a
            // distinct field element so x_r never equals any y_d.
            let total = 0u8; // unused; x is derived from absolute index
            let _ = total;
            let x = index; // parity shards use their absolute index >= k
            for d in 0..k {
                let y = d as u8;
                row[d] = gf.inv(x ^ y);
            }
        }
    }
    row
}

/// Encode all parity blocks from the `k` data blocks (blocks equal length).
pub fn encode(
    gf: &Gf256,
    version: CodecVersion,
    k: u8,
    m: u8,
    blocks: &mut [Vec<u8>],
) -> Result<(), String> {
    validate_geometry(version, k, m)?;
    let ku = k as usize;
    let total = ku + m as usize;
    if blocks.len() != total {
        return Err(format!("expected {total} blocks, got {}", blocks.len()));
    }
    let len = blocks[0].len();
    if blocks[..ku].iter().any(|b| b.len() != len) || len == 0 {
        return Err("data blocks must be non-empty and equal length".into());
    }
    for b in blocks.iter_mut() {
        b.resize(len, 0);
    }
    for idx in ku..total {
        let row = generator_row(gf, version, idx as u8, k);
        let mut out = vec![0u8; len];
        for d in 0..ku {
            gf.mul_add(&mut out, &blocks[d], row[d], &out);
        }
        blocks[idx] = out;
    }
    Ok(())
}

/// Rebuild missing blocks given at least `k` known `(index, block)` pairs.
///
/// Solves the linear system formed by the known generator rows with
/// Gauss–Jordan elimination, then regenerates every block (data and
/// parity) so callers can cross-check parity they also hold.
pub fn decode(
    gf: &Gf256,
    version: CodecVersion,
    k: u8,
    m: u8,
    known: &[(u8, Vec<u8>)],
) -> Result<Vec<Vec<u8>>, String> {
    validate_geometry(version, k, m)?;
    let ku = k as usize;
    if known.len() < ku {
        return Err(format!(
            "need at least {ku} known shards, have {}",
            known.len()
        ));
    }
    let mut indices: Vec<u8> = known.iter().map(|(i, _)| *i).collect();
    indices.sort_unstable();
    indices.dedup();
    if indices.len() != known.len() {
        return Err("known shard indices must be unique".into());
    }
    if indices.iter().any(|&i| i >= k + m) {
        return Err("known shard index out of stripe range".into());
    }
    let len = known[0].1.len();
    if len == 0 || known.iter().any(|(_, b)| b.len() != len) {
        return Err("known blocks must be non-empty and equal length".into());
    }

    // Augmented matrix: k coefficient rows + block bytes as RHS columns.
    let mut matrix: Vec<Vec<u8>> = indices[..ku]
        .iter()
        .map(|&idx| {
            let mut row = generator_row(gf, version, idx, k);
            row.extend_from_slice(&known.iter().find(|(i, _)| i == idx).unwrap().1);
            row
        })
        .collect();

    for col in 0..ku {
        // Find a pivot row with non-zero coefficient at `col`.
        let pivot = (col..ku)
            .find(|&r| matrix[r][col] != 0)
            .ok_or_else(|| format!("singular encoding submatrix at column {col}"))?;
        matrix.swap(pivot, col);
        let inv = gf.inv(matrix[col][col]);
        for c in col..(ku + len) {
            matrix[col][c] = gf.mul(matrix[col][c], inv);
        }
        for r in 0..ku {
            if r != col && matrix[r][col] != 0 {
                let factor = matrix[r][col];
                for c in col..(ku + len) {
                    matrix[r][c] ^= gf.mul(matrix[col][c], factor);
                }
            }
        }
    }

    let mut data: Vec<Vec<u8>> = (0..ku)
        .map(|d| matrix[d][ku..ku + len].to_vec())
        .collect();
    let total = ku + m as usize;
    data.resize(total, Vec::new());
    encode(gf, version, k, m, &mut data)?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_data(k: usize, len: usize) -> Vec<Vec<u8>> {
        (0..k).map(|d| (0..len).map(|i| ((d * 31 + i * 7) & 0xff) as u8).collect()).collect()
    }

    #[test]
    fn encode_decode_roundtrip_v1() {
        let gf = Gf256::new();
        let (k, m) = (3u8, 2);
        let mut blocks = sample_data(k as usize, 16);
        blocks.resize(k as usize + m as usize, vec![]);
        encode(&gf, CodecVersion::V1, k, m, &mut blocks).unwrap();
        for missing in [vec![0], vec![2], vec![4], vec![0, 4], vec![0, 1, 2]] {
            let known: Vec<(u8, Vec<u8>)> = (0..k + m)
                .filter(|i| !missing.contains(i))
                .map(|i| (i, blocks[i as usize].clone()))
                .collect();
            let recovered = decode(&gf, CodecVersion::V1, k, m, &known).unwrap();
            for &i in &missing {
                assert_eq!(recovered[i as usize], blocks[i as usize]);
            }
        }
    }

    #[test]
    fn encode_decode_roundtrip_v2() {
        let gf = Gf256::new();
        let (k, m) = (4u8, 3);
        let mut blocks = sample_data(k as usize, 20);
        blocks.resize(k as usize + m as usize, vec![]);
        encode(&gf, CodecVersion::V2, k, m, &mut blocks).unwrap();
        let known: Vec<(u8, Vec<u8>)> = [0u8, 2, 4, 6].iter().map(|&i| (i, blocks[i as usize].clone())).collect();
        let recovered = decode(&gf, CodecVersion::V2, k, m, &known).unwrap();
        for i in 0..(k + m) {
            assert_eq!(recovered[i as usize], blocks[i as usize]);
        }
    }

    #[test]
    fn corrupted_parity_detected_after_rebuild() {
        let gf = Gf256::new();
        let (k, m) = (3u8, 2);
        let mut blocks = sample_data(k as usize, 8);
        blocks.resize(5, vec![]);
        encode(&gf, CodecVersion::V1, k, m, &mut blocks).unwrap();
        let mut known: Vec<(u8, Vec<u8>)> =
            vec![(0, blocks[0].clone()), (2, blocks[2].clone()), (3, blocks[3].clone())];
        known[2].1[0] ^= 0x01;
        let recovered = decode(&gf, CodecVersion::V1, k, m, &known).unwrap();
        // Rebuilt parity 3 must disagree with the flipped candidate.
        assert_ne!(recovered[3], known[2].1);
        assert_eq!(recovered[3], blocks[3]);
    }
}
