//! 测试夹具：小有限域对象 + 可注入各类损坏的来源舱。
#![allow(dead_code)]

use std::fs;
use std::path::PathBuf;

use serde::Serialize;
use stripe_capsule::db::Storage;
use stripe_capsule::gf::{Gf256, DEFAULT_POLY};
use stripe_capsule::hashutil::{sha256_concat, sha256_hex};
use stripe_capsule::types::CodingParams;

pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "stripe-capsule-test-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
    pub fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Serialize, Clone)]
struct FragEntry {
    shard: u32,
    stripe: u32,
    generation: u32,
    length: u64,
    digest: String,
    file: String,
}

#[derive(Serialize)]
struct ManifestOut {
    object_id: String,
    object_digest: Option<String>,
    coding_version: String,
    declared_len: Option<u64>,
    stripe_count: u32,
    fragments: Vec<FragEntry>,
}

pub struct TestBundle {
    pub dir: PathBuf,
    object_id: String,
    version: String,
    stripe_count: u32,
    object_digest: Option<String>,
    declared_len: Option<u64>,
    entries: Vec<(FragEntry, Vec<u8>)>,
}

impl TestBundle {
    pub fn new(root: &std::path::Path, source: &str, object_id: &str, version: &str, stripe_count: u32) -> Self {
        let dir = root.join(source);
        fs::create_dir_all(dir.join("shards")).unwrap();
        TestBundle {
            dir,
            object_id: object_id.into(),
            version: version.into(),
            stripe_count,
            object_digest: None,
            declared_len: None,
            entries: Vec::new(),
        }
    }

    pub fn set_object_digest(&mut self, params: &CodingParams, stripes: &[Vec<Vec<u8>>]) {
        let total = stripes.len() * params.k as usize * params.stripe_bytes;
        let mut blocks = Vec::new();
        for s in stripes {
            for d in s {
                blocks.push(d.clone());
            }
        }
        self.object_digest = Some(sha256_concat(&blocks, Some(total)));
        self.declared_len = Some(total as u64);
    }

    /// 以 manifest 声称内容写一块；可注入位翻转/长度篡改/错误摘要。
    pub fn add(
        &mut self,
        stripe: u32,
        shard: u32,
        gen: u32,
        mut data: Vec<u8>,
        flip: bool,
        declared_len_delta: i64,
        bad_digest: bool,
        file_suffix: Option<&str>,
    ) {
        if flip {
            data[0] ^= 0x01;
        }
        let file = format!(
            "shards/s{stripe}.sh{shard}.g{gen}{}.bin",
            file_suffix.unwrap_or("")
        );
        let digest = if bad_digest {
            sha256_hex(&[0xDE, 0xAD])
        } else {
            sha256_hex(&data)
        };
        let length = (data.len() as i64 + declared_len_delta).max(0) as u64;
        fs::write(self.dir.join(&file), &data).unwrap();
        self.entries.push((
            FragEntry { shard, stripe, generation: gen, length, digest, file },
            data,
        ));
    }

    pub fn write(self) -> PathBuf {
        let manifest = ManifestOut {
            object_id: self.object_id,
            object_digest: self.object_digest,
            coding_version: self.version,
            declared_len: self.declared_len,
            stripe_count: self.stripe_count,
            fragments: self.entries.iter().map(|(e, _)| e.clone()).collect(),
        };
        fs::write(
            self.dir.join("manifest.json"),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();
        self.dir
    }
}

pub fn open_storage(root: &std::path::Path) -> Storage {
    Storage::open(root.join("test.db").to_str().unwrap()).unwrap()
}

pub fn v1_data(seed: u8, stripe_bytes: usize) -> Vec<Vec<u8>> {
    (0..3)
        .map(|j| (0..stripe_bytes)
            .map(|b| seed.wrapping_add(j * 31).wrapping_add(b as u8 * 7))
            .collect())
        .collect()
}

pub fn v1_parity(data: &[Vec<u8>]) -> Vec<Vec<u8>> {
    Gf256::new(DEFAULT_POLY).encode_parity(3, 2, data)
}

pub fn object_row(storage: &mut Storage, object_id: &str) -> stripe_capsule::db::ObjectRow {
    storage
        .list_objects()
        .unwrap()
        .into_iter()
        .find(|o| o.object_id == object_id)
        .unwrap()
}

pub fn stripe_rows(storage: &mut Storage, oid: i64) -> Vec<stripe_capsule::db::StripeRow> {
    storage.list_stripes(oid).unwrap()
}
