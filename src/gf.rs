//! 小有限域运算：GF(2^8)（生产参数）与 GF(2^4)（测试 fixture）。
//! GF(2^4) 下每个字节拆成两个 nibble 符号，保证 k+m <= 2^q 即可使用 Cauchy 矩阵。

use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Field {
    #[serde(rename = "gf256")]
    Gf256,
    #[serde(rename = "gf16")]
    Gf16,
}

impl Field {
    pub fn from_name(s: &str) -> Option<Field> {
        match s {
            "gf256" | "gf2^8" => Some(Field::Gf256),
            "gf16" | "gf2^4" => Some(Field::Gf16),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Field::Gf256 => "gf256",
            Field::Gf16 => "gf16",
        }
    }

    pub fn order(self) -> usize {
        match self {
            Field::Gf256 => 256,
            Field::Gf16 => 16,
        }
    }

    fn poly(self) -> u16 {
        match self {
            Field::Gf256 => 0x11d,
            Field::Gf16 => 0x13,
        }
    }

    fn modulus(self) -> u16 {
        match self {
            Field::Gf256 => 256,
            Field::Gf16 => 16,
        }
    }

    pub fn symbols_per_byte(self) -> usize {
        match self {
            Field::Gf256 => 1,
            Field::Gf16 => 2,
        }
    }

    pub fn symbol_len(self, byte_len: usize) -> usize {
        byte_len * self.symbols_per_byte()
    }

    pub fn byte_len_from_symbols(self, symbols: usize) -> Option<usize> {
        match self {
            Field::Gf256 => Some(symbols),
            Field::Gf16 => {
                if symbols % 2 != 0 {
                    None
                } else {
                    Some(symbols / 2)
                }
            }
        }
    }

    fn tables(self) -> &'static (Vec<u8>, Vec<u8>, Vec<u8>) {
        static GF256_TABLES: OnceLock<(Vec<u8>, Vec<u8>, Vec<u8>)> = OnceLock::new();
        static GF16_TABLES: OnceLock<(Vec<u8>, Vec<u8>, Vec<u8>)> = OnceLock::new();
        match self {
            Field::Gf256 => GF256_TABLES.get_or_init(|| build_tables(0x11d, 256)),
            Field::Gf16 => GF16_TABLES.get_or_init(|| build_tables(0x13, 16)),
        }
    }

    pub fn mul(self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }
        let (log, exp, _) = self.tables();
        match self {
            Field::Gf256 => {
                let la = log[a as usize] as usize;
                let lb = log[b as usize] as usize;
                exp[la + lb]
            }
            Field::Gf16 => {
                let la = log[(a & 0x0f) as usize] as usize;
                let lb = log[(b & 0x0f) as usize] as usize;
                exp[la + lb]
            }
        }
    }

    pub fn inv(self, a: u8) -> u8 {
        let (_, _, inv) = self.tables();
        match self {
            Field::Gf256 => {
                assert!(a != 0);
                inv[a as usize]
            }
            Field::Gf16 => {
                let a = a & 0x0f;
                assert!(a != 0);
                inv[a as usize]
            }
        }
    }

    pub fn div(self, a: u8, b: u8) -> u8 {
        if a == 0 {
            return 0;
        }
        self.mul(a, self.inv(b))
    }

    pub fn pack(self, bytes: &[u8]) -> Vec<u8> {
        match self {
            Field::Gf256 => bytes.to_vec(),
            Field::Gf16 => {
                let mut out = Vec::with_capacity(bytes.len() * 2);
                for &b in bytes {
                    out.push(b >> 4);
                    out.push(b & 0x0f);
                }
                out
            }
        }
    }

    pub fn unpack(self, symbols: &[u8]) -> Vec<u8> {
        match self {
            Field::Gf256 => symbols.to_vec(),
            Field::Gf16 => {
                assert!(symbols.len() % 2 == 0, "gf16 符号数必须为偶数");
                symbols
                    .chunks(2)
                    .map(|p| (p[0] << 4) | (p[1] & 0x0f))
                    .collect()
            }
        }
    }

    /// out[i] ^= mul(scalar, vec[i])
    pub fn fmadd(self, scalar: u8, vec: &[u8], out: &mut [u8]) {
        if scalar == 0 {
            return;
        }
        if scalar == 1 {
            for (o, &v) in out.iter_mut().zip(vec.iter()) {
                *o ^= v;
            }
            return;
        }
        for (o, &v) in out.iter_mut().zip(vec.iter()) {
            *o ^= self.mul(scalar, v);
        }
    }
}

fn build_tables(poly: u16, modulus: u16) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let q = modulus as usize;
    let mut log = vec![0u8; q];
    let mut exp = vec![0u8; q * 2];
    let mut x: u16 = 1;
    for i in 0..(q - 1) {
        exp[i] = x as u8;
        log[x as usize] = i as u8;
        x <<= 1;
        if x & modulus != 0 {
            x ^= poly;
        }
    }
    for i in (q - 1)..(q * 2 - 1) {
        exp[i] = exp[i - (q - 1)];
    }
    let mut inv = vec![0u8; q];
    for a in 1..q {
        inv[a] = exp[(q - 1) - log[a] as usize];
    }
    (log, exp, inv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf_identities() {
        for f in [Field::Gf256, Field::Gf16] {
            for a in 1..f.order() as u8 {
                assert_eq!(f.mul(a, f.inv(a)), 1, "{:?} inv {}", f.name(), a);
                assert_eq!(f.div(a, a), 1);
            }
            assert_eq!(f.unpack(&f.pack(&[0x00, 0xab, 0xf3, 0x7e])), vec![0x00, 0xab, 0xf3, 0x7e]);
        }
    }
}
