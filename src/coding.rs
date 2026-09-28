//! 小有限域纠删码：GF(2^8) Reed-Solomon 与单校验 XOR。
//!
//! 所有运算逐字节进行。数据向量 `data[0..k]` 长度必须一致（不足由调用方以零补齐到
//! manifest 声明长度），校验向量与数据等长。

/// GF(256) 算术（生成多项式 0x11D，原生元 2）。
#[derive(Clone, Copy)]
pub struct Gf256 {
    exp: [u8; 512],
    log: [u8; 256],
}

impl Gf256 {
    /// 用生成多项式 0x11D 构造对数/指数表。
    pub fn new() -> Self {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for i in 0..255u16 {
            exp[i as usize] = x as u8;
            log[x as usize] = i as u8;
            // 乘以原生元 2（左移，溢出则异或生成多项式）。
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= 0x11d;
            }
        }
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }
        Self { exp, log }
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
        debug_assert!(a != 0);
        self.exp[255 - self.log[a as usize] as usize]
    }

    #[inline]
    pub fn div(&self, a: u8, b: u8) -> u8 {
        if a == 0 {
            return 0;
        }
        debug_assert!(b != 0);
        self.exp[(self.log[a as usize] as i32 - self.log[b as usize] as i32 + 255) as usize]
    }

    /// 求方阵逆矩阵（GF 上高斯-约旦消元）。奇异矩阵返回 None。
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
            let pi = self.inv(p);
            for j in 0..n {
                a[col][j] = self.mul(a[col][j], pi);
                inv[col][j] = self.mul(inv[col][j], pi);
            }
            for r in 0..n {
                if r == col || a[r][col] == 0 {
                    continue;
                }
                let f = a[r][col];
                for j in 0..n {
                    a[r][j] ^= self.mul(f, a[col][j]);
                    inv[r][j] ^= self.mul(f, inv[col][j]);
                }
            }
        }
        Some(inv)
    }
}

impl Default for Gf256 {
    fn default() -> Self {
        Self::new()
    }
}

use std::collections::BTreeMap;

/// 版本化编码参数。`k` 为数据块数；XOR 固定 1 个校验块，RS 有 `m` 个。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    XorV1 { k: usize },
    RsGf256 { k: usize, m: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// 参与块数量不足：{need} 需 {have} 有。
    TooFew { need: usize, have: usize },
    /// 长度不一致。
    BadLen,
    /// 重算校验与现有校验冲突（位翻转等）。
    ParityMismatch { shard: usize, offset: usize, expected: u8, actual: u8 },
    /// 系数矩阵奇异（fixture 构造错误时才会出现）。
    Singular,
}

pub struct DecodeOutcome {
    /// 长度为 k+parity 的完整 stripe（含重算块）。
    pub shards: Vec<Vec<u8>>,
    /// 参与本次计算的 shard 位置。
    pub participants: Vec<usize>,
    /// 本次重算填补的位置。
    pub reconstructed: Vec<usize>,
}

impl Codec {
    pub fn from_params(code_id: &str, k: usize, m: usize) -> anyhow::Result<Self> {
        match code_id {
            "xor-v1" => {
                anyhow::ensure!(k >= 1, "xor-v1 需要 k>=1");
                anyhow::ensure!(m == 1, "xor-v1 只支持 1 个校验块");
                Ok(Codec::XorV1 { k })
            }
            "rs-gf256-v1" => {
                anyhow::ensure!(k >= 1 && m >= 1, "rs-gf256-v1 需要 k,m>=1");
                Ok(Codec::RsGf256 { k, m })
            }
            other => anyhow::bail!("未知编码版本: {other}"),
        }
    }

    pub fn code_id(&self) -> &'static str {
        match self {
            Codec::XorV1 { .. } => "xor-v1",
            Codec::RsGf256 { .. } => "rs-gf256-v1",
        }
    }

    pub fn k(&self) -> usize {
        match self {
            Codec::XorV1 { k } => *k,
            Codec::RsGf256 { k, .. } => *k,
        }
    }

    pub fn parity_count(&self) -> usize {
        match self {
            Codec::XorV1 { .. } => 1,
            Codec::RsGf256 { m, .. } => *m,
        }
    }

    pub fn total(&self) -> usize {
        self.k() + self.parity_count()
    }

    /// 由完整数据块计算全部校验块。数据块长度必须一致。
    pub fn encode(&self, data: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, DecodeError> {
        let k = self.k();
        if data.len() != k || k == 0 {
            return Err(DecodeError::BadLen);
        }
        let len = data[0].len();
        if data.iter().any(|d| d.len() != len) {
            return Err(DecodeError::BadLen);
        }
        match self {
            Codec::XorV1 { .. } => {
                let mut p = vec![0u8; len];
                for d in data {
                    for (x, y) in p.iter_mut().zip(d) {
                        *x ^= *y;
                    }
                }
                Ok(vec![p])
            }
            Codec::RsGf256 { m, .. } => {
                let gf = Gf256::new();
                let mut parity = vec![vec![0u8; len]; *m];
                for (i, d) in data.iter().enumerate() {
                    // 第 j 行系数为 (2^j)^i。
                    for (j, p) in parity.iter_mut().enumerate() {
                        let c = gf.exp[(j * i) % 255];
                        if c == 0 {
                            continue;
                        }
                        if c == 1 {
                            for (x, y) in p.iter_mut().zip(d) {
                                *x ^= *y;
                            }
                        } else {
                            for (x, y) in p.iter_mut().zip(d) {
                                *x ^= gf.mul(c, *y);
                            }
                        }
                    }
                }
                Ok(parity)
            }
        }
    }

    /// 根据现有块集合重建完整 stripe。`present` 的键为 shard 位置（0..k+m-1）。
    pub fn decode(&self, present: &BTreeMap<usize, Vec<u8>>) -> Result<DecodeOutcome, DecodeError> {
        let (k, pc) = (self.k(), self.parity_count());
        let total = k + pc;
        if present.keys().any(|&p| p >= total) {
            return Err(DecodeError::BadLen);
        }
        let len = present.values().next().map(|v| v.len()).unwrap_or(0);
        if len == 0 || present.values().any(|v| v.len() != len) {
            return Err(DecodeError::BadLen);
        }
        let missing: Vec<usize> = (0..total).filter(|p| !present.contains_key(p)).collect();
        let have = present.len();
        if have < k {
            return Err(DecodeError::TooFew { need: k, have });
        }
        let missing_data: Vec<usize> = missing.iter().copied().filter(|p| *p < k).collect();

        let mut participants: Vec<usize> = present.keys().copied().collect();
        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(total);
        for p in 0..total {
            shards.push(present.get(&p).cloned().unwrap_or_else(|| vec![0u8; len]));
        }

        match self {
            Codec::XorV1 { .. } => {
                if missing.len() > 1 {
                    return Err(DecodeError::TooFew { need: total - 1, have });
                }
                if missing.len() == 1 {
                    let miss = missing[0];
                    let mut acc = vec![0u8; len];
                    for (&p, v) in present {
                        if p == miss {
                            continue;
                        }
                        for (x, y) in acc.iter_mut().zip(v) {
                            *x ^= *y;
                        }
                    }
                    shards[miss] = acc;
                }
                // 全部在场或重算后，用 XOR 恒等式校验。
                let mut x = vec![0u8; len];
                for s in &shards[..total] {
                    for (a, b) in x.iter_mut().zip(s) {
                        *a ^= *b;
                    }
                }
                if let Some(offset) = x.iter().position(|b| *b != 0) {
                    return Err(DecodeError::ParityMismatch {
                        shard: k,
                        offset,
                        expected: shards[k][offset],
                        actual: shards[k][offset] ^ x[offset],
                    });
                }
            }
            Codec::RsGf256 { .. } => {
                let d = missing_data.len();
                let present_parity: Vec<usize> = (k..total).filter(|p| present.contains_key(p)).collect();
                if present_parity.len() < d {
                    return Err(DecodeError::TooFew { need: k, have });
                }
                let gf = Gf256::new();
                if d > 0 {
                    // 确定性选取前 d 个在场校验行。
                    let chosen: Vec<usize> = present_parity[..d].to_vec();
                    // 组装 k×k 方程矩阵：在场数据行是单位行，缺失数据行用所选校验方程。
                    let mut matrix: Vec<Vec<u8>> = Vec::with_capacity(k);
                    let mut rhs_rows: Vec<usize> = Vec::with_capacity(k);
                    let mut ci = 0;
                    for i in 0..k {
                        if present.contains_key(&i) {
                            let mut row = vec![0u8; k];
                            row[i] = 1;
                            matrix.push(row);
                            rhs_rows.push(i);
                        } else {
                            let j = chosen[ci];
                            ci += 1;
                            let mut row = vec![0u8; k];
                            for col in 0..k {
                                row[col] = gf.exp[((j - k) * col) % 255];
                            }
                            matrix.push(row);
                            rhs_rows.push(j);
                        }
                    }
                    let inv = gf.invert(&matrix).ok_or(DecodeError::Singular)?;
                    let mut solved = vec![vec![0u8; len]; k];
                    for byte in 0..len {
                        let y: Vec<u8> = rhs_rows.iter().map(|&p| shards[p][byte]).collect();
                        for (r, ir) in inv.iter().enumerate() {
                            let mut acc = 0u8;
                            for (c, coef) in ir.iter().enumerate() {
                                acc ^= gf.mul(*coef, y[c]);
                            }
                            solved[r][byte] = acc;
                        }
                    }
                    for &i in &missing_data {
                        shards[i] = solved[i].clone();
                    }
                }
                // 重算全部校验，与在场校验逐一核对（覆盖未参与求解的额外校验）。
                let data: Vec<Vec<u8>> = shards[..k].to_vec();
                let recomputed = Codec::RsGf256 { k, m: self.parity_count() }.encode(&data)?;
                for (idx, parity_shard) in (k..total).zip(recomputed) {
                    if let Some(existing) = present.get(&idx) {
                        if let Some(offset) = existing.iter().zip(&parity_shard).position(|(a, b)| a != b) {
                            return Err(DecodeError::ParityMismatch {
                                shard: idx,
                                offset,
                                expected: parity_shard[offset],
                                actual: existing[offset],
                            });
                        }
                    }
                    if !present.contains_key(&idx) {
                        shards[idx] = parity_shard;
                    }
                }
            }
        }

        Ok(DecodeOutcome {
            shards,
            participants: present.keys().copied().collect(),
            reconstructed: missing,
        })
    }
}
