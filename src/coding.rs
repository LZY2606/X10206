//! 系统化 Reed-Solomon：前 `k` 块为数据块（单位阵行），后 `m` 块为校验块
//! （Vandermonde 行）。GF 乘法结构保证任意 `k` 个不同编号的行满秩。

use std::sync::Arc;

use crate::field::Field;

/// 数据列 `col`（0..k）在校验行 `pi`（0..m）上的系数：(col+1)^pi。
pub fn parity_coeff(field: &Field, pi: usize, col: usize) -> u8 {
    field.pow((col + 1) as u8, pi)
}

/// 某个 slot 的行向量（长度 k）。
pub fn slot_row(field: &Field, k: usize, slot: usize) -> Vec<u8> {
    let mut row = vec![0u8; k];
    if slot < k {
        row[slot] = 1;
    } else {
        let pi = slot - k;
        for (col, r) in row.iter_mut().enumerate() {
            *r = parity_coeff(field, pi, col);
        }
    }
    row
}

/// 由数据块（每块长度 `shardsize` 个符号）生成 m 个校验块。
pub fn encode(field: &Field, data: &[Vec<u8>], m: usize) -> Vec<Vec<u8>> {
    let k = data.len();
    assert!(k > 0, "k 必须为正");
    let size = data[0].len();
    for d in data {
        assert_eq!(d.len(), size, "数据块长度不一致");
        assert!(field.check_symbols(d), "出现域外符号");
    }
    let coeff: Vec<Vec<u8>> = (0..m)
        .map(|pi| (0..k).map(|col| parity_coeff(field, pi, col)).collect())
        .collect();
    let mut parity = vec![vec![0u8; size]; m];
    for off in 0..size {
        for pi in 0..m {
            let mut acc = 0u8;
            for col in 0..k {
                acc = field.add(acc, field.mul(coeff[pi][col], data[col][off]));
            }
            parity[pi][off] = acc;
        }
    }
    parity
}

/// 对单个符号列做高斯-若尔当消元。矩阵 `a` 为 r×k，右侧为 `b`（长度 r）。
/// 返回：
/// - `Ok(data)`：长度 k，且超定情形下所有冗余行必须自洽；
/// - `Err(reason)`：秩不足或行之间矛盾（证据）。
fn solve_column(field: &Field, a: &[Vec<u8>], b: &[u8]) -> Result<Vec<u8>, String> {
    let r = a.len();
    let k = a[0].len();
    let mut mat: Vec<Vec<u8>> = a.to_vec();
    let mut rhs = b.to_vec();
    let mut pivot_row = vec![usize::MAX; k];
    let mut row = 0usize;
    for col in 0..k {
        let mut piv = None;
        for rr in row..r {
            if mat[rr][col] != 0 {
                piv = Some(rr);
                break;
            }
        }
        let Some(p) = piv else { continue };
        mat.swap(row, p);
        rhs.swap(row, p);
        let inv = field.inv(mat[row][col]);
        for c in 0..k {
            mat[row][c] = field.mul(mat[row][c], inv);
        }
        rhs[row] = field.mul(rhs[row], inv);
        for rr in 0..r {
            if rr != row && mat[rr][col] != 0 {
                let f = mat[rr][col];
                for c in 0..k {
                    mat[rr][c] = field.add(mat[rr][c], field.mul(f, mat[row][c]));
                }
                rhs[rr] = field.add(rhs[rr], field.mul(f, rhs[row]));
            }
        }
        pivot_row[col] = row;
        row += 1;
    }
    // 冗余行必须全部归零且右侧为 0，否则证据互相矛盾。
    for rr in row..r {
        if rhs[rr] != 0 || mat[rr].iter().any(|&x| x != 0) {
            return Err("overdetermined rows disagree".to_string());
        }
    }
    if pivot_row.iter().any(|&p| p == usize::MAX) {
        return Err("rank deficient".to_string());
    }
    let mut data = vec![0u8; k];
    for (col, &pr) in pivot_row.iter().enumerate() {
        data[col] = rhs[pr];
    }
    Ok(data)
}

/// 由一组（slot, 内容）重建全部数据块。
///
/// - 至少需要 k 个不同 slot；
/// - 超定（>k）时冗余块必须与解一致，否则返回矛盾证据。
pub fn reconstruct(
    field: &Field,
    k: usize,
    shard_size: usize,
    present: &[(usize, Vec<u8>)],
) -> Result<Vec<Vec<u8>>, String> {
    let mut slots: Vec<usize> = present.iter().map(|(s, _)| *s).collect();
    slots.sort_unstable();
    slots.dedup();
    if slots.len() < k {
        return Err(format!("only {} distinct slots, need {}", slots.len(), k));
    }
    for (s, bytes) in present {
        if bytes.len() != shard_size {
            return Err(format!("slot {s} length {} != shard size {shard_size}", bytes.len()));
        }
        if !field.check_symbols(bytes) {
            return Err(format!("slot {s} contains out-of-field symbols"));
        }
    }
    let rows: Vec<Vec<u8>> = slots.iter().map(|&s| slot_row(field, k, s)).collect();
    let by_slot: std::collections::HashMap<usize, &Vec<u8>> =
        present.iter().map(|(s, b)| (*s, b)).collect();
    let mut data = vec![vec![0u8; shard_size]; k];
    for off in 0..shard_size {
        let rhs: Vec<u8> = slots.iter().map(|s| by_slot[s][off]).collect();
        match solve_column(field, &rows, &rhs) {
            Ok(col) => {
                for (i, v) in col.into_iter().enumerate() {
                    data[i][off] = v;
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(data)
}

/// 根据重建数据校验整条 stripe：每个已知块都必须与重新计算值逐符号一致。
/// 返回重新计算出的全部 n=k+m 块。
pub fn verify_full(
    field: &Field,
    data: &[Vec<u8>],
    m: usize,
    present: &[(usize, Vec<u8>)],
) -> Result<Vec<Vec<u8>>, String> {
    let k = data.len();
    let parity = encode(field, data, m);
    let mut all = data.to_vec();
    all.extend(parity);
    for (s, bytes) in present {
        if all[*s] != *bytes {
            return Err(format!("recomputed slot {s} disagrees with evidence"));
        }
    }
    Ok(all)
}

/// 编码参数（版本化 manifest 中的 `coding` 段）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodingParams {
    pub field_bits: u32,
    pub k: usize,
    pub m: usize,
    pub shard_size: usize,
}

impl CodingParams {
    pub fn field(&self) -> Arc<Field> {
        match self.field_bits {
            4 => Field::gf16(),
            8 => Field::gf256(),
            b => panic!("不支持的域位宽 {b}"),
        }
    }

    pub fn n(&self) -> usize {
        self.k + self.m
    }

    pub fn validate(&self) -> Result<(), String> {
        if !matches!(self.field_bits, 4 | 8) {
            return Err("field_bits 只支持 4 或 8".into());
        }
        if self.k == 0 || self.m == 0 {
            return Err("k,m 必须为正".into());
        }
        if self.n() > (1usize << self.field_bits) - 1 {
            return Err("k+m 超过域内可用非零行数".into());
        }
        if self.shard_size == 0 {
            return Err("shard_size 必须为正".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_gf16() {
        let f = Field::gf16();
        let data = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];
        let parity = encode(&f, &data, 2);
        let all: Vec<(usize, Vec<u8>)> = data
            .iter()
            .cloned()
            .chain(parity.iter().cloned())
            .enumerate()
            .collect();
        // 恰好达到下限 k=3：缺 2 块。
        for missing in [vec![3, 4], vec![0, 1], vec![1, 3], vec![0, 4]] {
            let present: Vec<(usize, Vec<u8>)> = all
                .iter()
                .filter(|(s, _)| !missing.contains(s))
                .cloned()
                .collect();
            let rec = reconstruct(&f, 3, 3, &present).unwrap();
            assert_eq!(rec, data);
        }
        // 超定自洽。
        let mut present = all.clone();
        present.pop();
        let rec = reconstruct(&f, 3, 3, &present).unwrap();
        assert_eq!(rec, data);
    }

    #[test]
    fn bit_flip_is_detected() {
        let f = Field::gf16();
        let data = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];
        let parity = encode(&f, &data, 2);
        let mut all: Vec<(usize, Vec<u8>)> = data
            .iter()
            .cloned()
            .chain(parity.iter().cloned())
            .enumerate()
            .collect();
        all[3].1[0] ^= 0b1;
        let present: Vec<(usize, Vec<u8>)> = all[1..].to_vec();
        let err = reconstruct(&f, 3, 3, &present).unwrap_err();
        assert!(err.contains("disagree") || err.contains("rank"));
    }

    #[test]
    fn gf256_roundtrip() {
        let f = Field::gf256();
        let data: Vec<Vec<u8>> = (0..4)
            .map(|i| (0..32).map(|j| ((i * 37 + j * 7) % 256) as u8).collect())
            .collect();
        let parity = encode(&f, &data, 2);
        let mut present: Vec<(usize, Vec<u8>)> =
            data[..2].iter().cloned().enumerate().collect();
        present.push((4, parity[0].clone()));
        present.push((5, parity[1].clone()));
        let rec = reconstruct(&f, 4, 32, &present).unwrap();
        assert_eq!(rec, data);
    }
}
