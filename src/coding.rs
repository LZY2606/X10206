//! 版本化纠删码：GF(2^4) / GF(2^8) 上的系统 Cauchy 码。
//!
//! 版本 1 的编码参数由 [`CodeParams`] 描述。数据分片编号 0..k，
//! 校验分片编号 k..k+m；分片总数 n=k+m。任意 k 个不同编号的分片
//! 均可通过高斯-若尔当消元重建整条 stripe（Cauchy 结构保证任意
//! k 行线性无关）。

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};

/// 有限域 GF(2^width)，width 仅支持 4 与 8。
#[derive(Clone)]
pub struct Gf {
    pub width: u32,
    pub q: usize,
    pub exp: Vec<u16>,
    pub log: Vec<u16>,
}

/// 生成 GF(2^width) 的指数/对数表。
///
/// - GF(2^8) 使用经典原多项式 x^8+x^4+x^3+x^2+1（0x11d），本原元 3；
/// - GF(2^4) 使用原多项式 x^4+x+1（0x13），本原元 2。
fn build_tables(width: u32) -> (Vec<u16>, Vec<u16>) {
    let (primitive, generator): (u32, u32) = match width {
        4 => (0x13, 2),
        8 => (0x11d, 3),
        _ => panic!("unsupported field width {width}"),
    };
    let q = 1usize << width;
    let mask = (q - 1) as u32;
    let mut exp = vec![0u16; q];
    let mut log = vec![0u16; q];
    let mut x: u32 = 1;
    for i in 0..(q - 1) {
        exp[i] = x as u16;
        log[x as usize] = i as u16;
        x <<= 1;
        if x & q as u32 != 0 {
            x ^= primitive;
        }
        x &= mask;
    }
    exp[q - 1] = exp[0];
    (exp, log)
}

impl Gf {
    pub fn new(width: u32) -> Result<Self> {
        if width != 4 && width != 8 {
            bail!("仅支持 GF(2^4) 与 GF(2^8)，收到 GF(2^{width})");
        }
        let (exp, log) = build_tables(width);
        Ok(Self {
            width,
            q: 1usize << width,
            exp,
            log,
        })
    }

    #[inline]
    pub fn mul(&self, a: u16, b: u16) -> u16 {
        if a == 0 || b == 0 {
            return 0;
        }
        let la = self.log[a as usize] as usize;
        let lb = self.log[b as usize] as usize;
        let s = (la + lb) % (self.q - 1);
        self.exp[s]
    }

    #[inline]
    pub fn inv(&self, a: u16) -> u16 {
        debug_assert!(a != 0);
        let la = self.log[a as usize] as usize;
        self.exp[(self.q - 1 - la) % (self.q - 1)]
    }

    #[inline]
    pub fn div(&self, a: u16, b: u16) -> u16 {
        debug_assert!(b != 0);
        self.mul(a, self.inv(b))
    }
}

/// 版本 1 编码参数。字段顺序与取值同时参与摘要与清单签名。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodeParams {
    pub code_version: u32,
    pub field: String,
    pub k: usize,
    pub m: usize,
}

impl CodeParams {
    pub fn new(field: &str, k: usize, m: usize) -> Result<Self> {
        let width = match field {
            "gf16" => 4u32,
            "gf256" => 8u32,
            other => bail!("未知有限域 {other}"),
        };
        if k == 0 {
            bail!("k 必须为正");
        }
        if m == 0 {
            bail!("m 必须为正");
        }
        if k + m > (1usize << width) {
            bail!("k+m={} 超过 {} 的元素数 {}", k + m, field, 1usize << width);
        }
        Ok(Self {
            code_version: 1,
            field: field.to_string(),
            k,
            m,
        })
    }

    pub fn width(&self) -> u32 {
        if self.field == "gf16" {
            4
        } else {
            8
        }
    }

    pub fn n(&self) -> usize {
        self.k + self.m
    }

    /// 第 `row` 个分片（编号 row）在系统 Cauchy 矩阵中的一行。
    ///
    /// - 数据行 0..k 为单位阵；
    /// - 校验行 r (r>=k) 满足 `G[r][c] = 1 / (x_r XOR y_c)`，
    ///   其中 `x_r = r + 1`，`y_c = q - 1 - c`，两者永不相等，
    ///   因此分母恒非零。
    pub fn generator_row(&self, gf: &Gf, row: usize) -> Vec<u16> {
        let k = self.k;
        assert!(row < self.n());
        if row < k {
            let mut v = vec![0u16; k];
            v[row] = 1;
            v
        } else {
            let q = gf.q as u16;
            let x = (row + 1) as u16;
            (0..k)
                .map(|c| {
                    let y = (q - 1) - c as u16;
                    gf.inv(x ^ y)
                })
                .collect()
        }
    }

    /// 把 stripe 的原始字节展开成符号（GF256 每字节一符号，GF16 每字节两 nibble）。
    pub fn bytes_to_symbols(&self, data: &[u8]) -> Vec<u16> {
        match self.width() {
            8 => data.iter().map(|&b| b as u16).collect(),
            _ => data
                .iter()
                .flat_map(|&b| [b >> 4, b & 0x0f])
                .collect(),
        }
    }

    /// 符号流压回字节。GF16 符号数必须为偶数（编码时已保证）。
    pub fn symbols_to_bytes(&self, syms: &[u16]) -> Vec<u8> {
        match self.width() {
            8 => syms.iter().map(|&s| s as u8).collect(),
            _ => {
                assert!(syms.len() % 2 == 0, "GF16 符号数必须成对");
                syms.chunks(2)
                    .map(|p| ((p[0] << 4) | (p[1] & 0x0f)) as u8)
                    .collect()
            }
        }
    }
}

/// 一条 stripe 在分片层面的布局：每分片 `shard_len` 字节，共 `symbols` 个符号。
#[derive(Debug, Clone)]
pub struct StripeLayout {
    pub shard_len: usize,
    pub symbols: usize,
}

/// 根据 stripe 原始数据长度计算布局（含确定性零填充）。
pub fn layout_for(params: &CodeParams, raw_len: usize) -> StripeLayout {
    match params.width() {
        8 => StripeLayout {
            shard_len: raw_len.div_ceil(params.k),
            symbols: raw_len.div_ceil(params.k),
        },
        _ => {
            // 每字节 2 个 nibble；每分片符号数必须为偶数以便压回字节。
            let nibbles = raw_len * 2;
            let per = nibbles.div_ceil(params.k);
            let per = if per % 2 == 1 { per + 1 } else { per };
            StripeLayout {
                shard_len: per / 2,
                symbols: per,
            }
        }
    }
}

/// 用参数生成 stripe 全部分片（含填充）。
pub fn encode(params: &CodeParams, gf: &Gf, raw: &[u8]) -> Vec<Vec<u8>> {
    let layout = layout_for(params, raw.len());
    let mut symbols = params.bytes_to_symbols(raw);
    symbols.resize(layout.symbols * params.k, 0);
    let mut shards = Vec::with_capacity(params.n());
    for row in 0..params.n() {
        let coeffs = params.generator_row(gf, row);
        let mut out = vec![0u16; layout.symbols];
        for (c, &coef) in coeffs.iter().enumerate() {
            if coef == 0 {
                continue;
            }
            let src = &symbols[c * layout.symbols..(c + 1) * layout.symbols];
            for (o, &s) in out.iter_mut().zip(src) {
                *o ^= gf.mul(coef, s);
            }
        }
        shards.push(params.symbols_to_bytes(&out));
    }
    shards
}

/// 参与重建的一个已知分片：`index` 为分片编号，`bytes` 为其字节。
pub struct HeldShard {
    pub index: usize,
    pub bytes: Vec<u8>,
}

/// 高斯-若尔当消元：从任意 k 个不同编号分片重建 stripe 全部符号。
///
/// 返回 `k * symbols` 个数据符号（行优先），以及消元后各行对应的分片编号。
/// 若选取的分片线性相关（正常 Cauchy 参数不会发生），返回错误。
pub fn decode_symbols(
    params: &CodeParams,
    gf: &Gf,
    held: &[HeldShard],
    shard_len: usize,
) -> Result<(Vec<u16>, Vec<usize>)> {
    if held.len() < params.k {
        bail!("仅有 {} 个分片，低于恢复下限 {}", held.len(), params.k);
    }
    let symbols = match params.width() {
        8 => shard_len,
        _ => shard_len * 2,
    };
    let k = params.k;
    let chosen: Vec<&HeldShard> = held.iter().take(k).collect();
    let mut idx: Vec<usize> = chosen.iter().map(|h| h.index).collect();
    let mut rows: Vec<Vec<u16>> = idx
        .iter()
        .map(|&i| params.generator_row(gf, i))
        .collect();
    // 增广部分：每列符号位置单独消元，先只做系数矩阵求逆，再乘右侧。
    let mut aug: Vec<Vec<u16>> = chosen
        .iter()
        .map(|h| {
            let mut s = params.bytes_to_symbols(&h.bytes);
            s.resize(symbols, 0);
            s
        })
        .collect();

    // 前向/消元：把 rows 化为单位阵，aug 同步变换。
    for col in 0..k {
        let pivot = (col..k).find(|&r| rows[r][col] != 0);
        let pivot = match pivot {
            Some(p) => p,
            None => bail!("系数矩阵秩不足，分片集合无法重建"),
        };
        rows.swap(col, pivot);
        aug.swap(col, pivot);
        idx.swap(col, pivot);
        let inv = gf.inv(rows[col][col]);
        for c in 0..k {
            rows[col][c] = gf.mul(rows[col][c], inv);
        }
        for t in 0..symbols {
            aug[col][t] = gf.mul(aug[col][t], inv);
        }
        for r in 0..k {
            if r == col {
                continue;
            }
            let factor = rows[r][col];
            if factor == 0 {
                continue;
            }
            for c in 0..k {
                rows[r][c] ^= gf.mul(factor, rows[col][c]);
            }
            for t in 0..symbols {
                aug[r][t] ^= gf.mul(factor, aug[col][t]);
            }
        }
    }

    // rows 现为单位阵；aug 第 c 行即数据分片 c 的符号。
    let mut data_symbols = vec![0u16; k * symbols];
    for c in 0..k {
        data_symbols[c * symbols..(c + 1) * symbols].copy_from_slice(&aug[c]);
    }
    Ok((data_symbols, idx))
}

/// 重建 stripe 原始数据符号，并可同时计算缺失分片的字节内容。
///
/// `missing` 为需要输出字节的分片编号（通常为缺失编号全集）。
pub fn rebuild(
    params: &CodeParams,
    gf: &Gf,
    held: &[HeldShard],
    shard_len: usize,
    missing: &[usize],
) -> Result<RebuiltStripe> {
    let layout = layout_for(
        params,
        match params.width() {
            8 => shard_len * params.k,
            _ => shard_len * 2 * params.k / 2,
        },
    );
    let (data_symbols, used) = decode_symbols(params, gf, held, shard_len)?;
    let symbols = layout.symbols;
    let mut rebuilt = Vec::new();
    for &row in missing {
        let coeffs = params.generator_row(gf, row);
        let mut out = vec![0u16; symbols];
        for (c, &coef) in coeffs.iter().enumerate() {
            if coef == 0 {
                continue;
            }
            let src = &data_symbols[c * symbols..(c + 1) * symbols];
            for (o, &s) in out.iter_mut().zip(src) {
                *o ^= gf.mul(coef, s);
            }
        }
        rebuilt.push((row, params.symbols_to_bytes(&out)));
    }
    let data_bytes = params.symbols_to_bytes(&data_symbols);
    Ok(RebuiltStripe {
        data_symbols,
        data_bytes,
        rebuilt_shards: rebuilt,
        used_indices: used,
    })
}

/// 一次重建的完整产物。
pub struct RebuiltStripe {
    /// k * symbols 个数据符号。
    pub data_symbols: Vec<u16>,
    /// 含填充的 stripe 字节。
    pub data_bytes: Vec<u8>,
    /// 缺失编号 -> 重算出的分片字节。
    pub rebuilt_shards: Vec<(usize, Vec<u8>)>,
    /// 实际进入消元的 k 个分片编号（held 顺序的前 k 个）。
    pub used_indices: Vec<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(field: &str, k: usize, m: usize, data: &[u8]) {
        let params = CodeParams::new(field, k, m).unwrap();
        let gf = Gf::new(params.width()).unwrap();
        let shards = encode(&params, &gf, data);
        assert_eq!(shards.len(), params.n());
        let layout = layout_for(&params, data.len());
        // 任意 k 个分片都能重建。
        for drop in 0..params.n() {
            let held: Vec<HeldShard> = shards
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != drop)
                .take(k)
                .map(|(i, b)| HeldShard {
                    index: i,
                    bytes: b.clone(),
                })
                .collect();
            let out = rebuild(&params, &gf, &held, layout.shard_len, &[drop]).unwrap();
            assert_eq!(out.rebuilt_shards[0].1, shards[drop]);
            assert_eq!(out.data_bytes[..data.len()], *data);
        }
    }

    #[test]
    fn gf256_single_and_multi_missing_roundtrip() {
        roundtrip("gf256", 3, 2, b"hello stripe recovery cabin!");
        roundtrip("gf256", 3, 2, b"ab");
    }

    #[test]
    fn gf16_roundtrip() {
        roundtrip("gf16", 3, 2, &[0xAB, 0xCD, 0xEF, 0x01, 0x23]);
        roundtrip("gf16", 5, 3, &[0x00, 0xFF, 0x77, 0x42]);
    }

    #[test]
    fn flipped_byte_is_rejected_by_external_check() {
        // 位翻转的分片重建出错误数据：由摘要层（见 recovery 模块）拒绝。
        let params = CodeParams::new("gf256", 2, 2).unwrap();
        let gf = Gf::new(8).unwrap();
        let data = b"abcdefgh";
        let mut shards = encode(&params, &gf, data);
        shards[0][0] ^= 0x01;
        let held: Vec<HeldShard> = (0..2)
            .map(|i| HeldShard {
                index: i,
                bytes: shards[i].clone(),
            })
            .collect();
        let layout = layout_for(&params, data.len());
        let out = rebuild(&params, &gf, &held, layout.shard_len, &[]).unwrap();
        assert_ne!(&out.data_bytes[..data.len()], data);
    }
}
