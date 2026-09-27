//! 清单、碎片与分析结果的数据模型。

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 版本化编码参数。不同版本可改变 k/m 与填充长度。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodingParams {
    /// 编码版本；重建严格按该版本的矩阵解释 shard。
    pub code_version: u32,
    /// 数据块数（恢复下限）。
    pub k: usize,
    /// 校验块数。
    pub m: usize,
    /// 每个 shard 的字节长度（含填充）。
    pub shard_len: usize,
}

/// 一个 generation 的对象级信息。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenInfo {
    pub generation: u64,
    /// 拼接全部数据块并去除 `tail_padding` 字节后对象内容的摘要。
    pub object_digest: String,
    /// 末尾填充字节数。
    pub tail_padding: usize,
}

/// manifest 中对单个 shard 在某个 generation 下的承诺。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShardExpectation {
    pub generation: u64,
    pub shard_index: usize,
    pub expected_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub object_id: String,
    pub params: CodingParams,
    pub stripe_count: usize,
    pub generations: Vec<GenInfo>,
    /// 每条 stripe 内每个 shard 在每个 generation 的期望摘要。
    /// 结构：expectations[stripe][shard_index] = Vec<ShardExpectation>
    #[serde(default)]
    pub expectations: Vec<Vec<Vec<ShardExpectation>>>,
}

impl Manifest {
    pub fn gen_info(&self, generation: u64) -> Option<&GenInfo> {
        self.generations.iter().find(|g| g.generation == generation)
    }

    pub fn expected_digest(&self, stripe: usize, index: usize, generation: u64) -> Option<&str> {
        self.expectations
            .get(stripe)?
            .get(index)?
            .iter()
            .find(|e| e.generation == generation)
            .map(|e| e.expected_digest.as_str())
    }
}

/// 导入的原始碎片：保存原始字节与接收来源，永不就地修改。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FragmentInput {
    /// 导入时分配的稳定 ID（来源+序号）。
    pub fragment_id: String,
    pub stripe: usize,
    /// 碎片自述的 shard 编号（可能重复）。
    pub claimed_shard_index: usize,
    /// 碎片自述的 generation（可能混杂）。
    pub claimed_generation: u64,
    pub source: String,
    pub digest: String,
    pub data_b64: String,
}

pub fn decode_fragment(f: &FragmentInput) -> Vec<u8> {
    b64_decode(&f.data_b64).unwrap_or_default()
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

pub fn b64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        s.push(T[((triple >> 18) & 63) as usize] as char);
        s.push(T[((triple >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            s.push(T[((triple >> 6) & 63) as usize] as char);
        } else {
            s.push('=');
        }
        if chunk.len() > 2 {
            s.push(T[(triple & 63) as usize] as char);
        } else {
            s.push('=');
        }
    }
    s
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    fn val(c: u8) -> Result<u8, String> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(format!("非法 base64 字符: {}", c as char)),
        }
    }
    let bytes: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let mut out = Vec::new();
    let mut chunk = [0u8; 4];
    let mut i = 0;
    while i < bytes.len() {
        let mut n = 0;
        let mut pad = 0;
        while n < 4 {
            if i >= bytes.len() {
                return Err("base64 长度非法".into());
            }
            let c = bytes[i];
            i += 1;
            if c == b'=' {
                chunk[n] = 0;
                pad += 1;
            } else {
                chunk[n] = val(c)?;
            }
            n += 1;
        }
        let triple =
            ((chunk[0] as u32) << 18) | ((chunk[1] as u32) << 12) | ((chunk[2] as u32) << 6) | (chunk[3] as u32);
        out.push((triple >> 16) as u8);
        if pad < 2 {
            out.push((triple >> 8) as u8);
        }
        if pad == 0 {
            out.push(triple as u8);
        }
    }
    Ok(out)
}
