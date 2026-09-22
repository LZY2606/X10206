//! Deterministic scenario builder shared by integration tests.
#![allow(dead_code)]
use std::collections::BTreeMap;

use stripe_recovery_pod::coding::{encode, CodingParams};
use stripe_recovery_pod::db::{Paths, Store};
use stripe_recovery_pod::gf::Gf256;
use stripe_recovery_pod::importer::write_bundle;
use stripe_recovery_pod::model::{sha256_hex, Manifest};
use tempfile::TempDir;

pub struct Harness {
    pub tmp: TempDir,
    pub store: Store,
    pub object_id: String,
    pub manifest: Manifest,
    pub shards: Vec<Vec<Vec<u8>>>,
    pub delivered: Vec<(String, usize, usize, u64, Vec<u8>, Option<String>)>,
}

impl Harness {
    pub fn new(k: usize, m: usize, stripe_count: usize, shard_len: usize) -> Self {
        let tmp = TempDir::new().expect("tempdir");
        let paths = Paths::new(tmp.path());
        let store = Store::open(paths).expect("open store");
        let data_len = stripe_count * k * shard_len;
        let mut payload = Vec::with_capacity(data_len);
        let mut state = 0x1234_5678u32;
        while payload.len() < data_len {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            payload.push((state & 0xff) as u8);
        }
        let gf = Gf256::new();
        let params = CodingParams { version: 1, k, n: k + m, shard_len };
        let mut shards = Vec::new();
        for s in 0..stripe_count {
            let mut data = Vec::new();
            for d in 0..k {
                let start = (s * k + d) * shard_len;
                data.push(payload[start..start + shard_len].to_vec());
            }
            shards.push(encode(&gf, params, &data));
        }
        let manifest = Manifest {
            scheme: stripe_recovery_pod::coding::CODING_SCHEME.into(),
            version: 1,
            object_id: "obj-test".into(),
            object_digest_hex: sha256_hex(&payload),
            stripe_count,
            shard_len,
            data_shards: k,
            parity_shards: m,
            generation: 1,
            data_len,
        };
        Harness {
            tmp,
            store,
            object_id: "obj-test".into(),
            manifest,
            shards,
            delivered: Vec::new(),
        }
    }

    /// Deliver a shard with a correct sidecar digest (default).
    pub fn deliver(&mut self, source: &str, s: usize, i: usize, g: u64, bytes: Vec<u8>) {
        let digest = sha256_hex(&bytes);
        self.delivered
            .push((source.into(), s, i, g, bytes, Some(digest)));
    }

    /// Deliver a shard whose sidecar declares `declared` (use for bit flips
    /// caught at the digest gate).
    pub fn deliver_declared(
        &mut self,
        source: &str,
        s: usize,
        i: usize,
        g: u64,
        bytes: Vec<u8>,
        declared: Option<&str>,
    ) {
        self.delivered
            .push((source.into(), s, i, g, bytes, declared.map(String::from)));
    }

    pub fn original(&self, s: usize, i: usize) -> Vec<u8> {
        self.shards[s][i].clone()
    }

    pub fn flipped(&self, s: usize, i: usize, byte: usize, xor: u8) -> Vec<u8> {
        let mut b = self.original(s, i);
        b[byte] ^= xor;
        b
    }

    pub fn import(&self) {
        let by_source = &mut BTreeMap::<String, Vec<(usize, usize, u64, Vec<u8>)>>::new();
        let mut sidecars: BTreeMap<(String, usize, usize, u64), String> = BTreeMap::new();
        for (src, s, i, g, bytes, declared) in &self.delivered {
            by_source
                .entry(src.clone())
                .or_default()
                .push((*s, *i, *g, bytes.clone()));
            if let Some(d) = declared {
                sidecars.insert((src.clone(), *s, *i, *g), d.clone());
            }
        }
        for (src, list) in by_source {
            let sides: BTreeMap<(usize, usize, u64), String> = sidecars
                .iter()
                .filter(|((sname, ..), _)| sname == src)
                .map(|((_, s, i, g), d)| ((*s, *i, *g), d.clone()))
                .collect();
            write_bundle(
                &self.store.paths.incoming,
                src,
                &self.manifest,
                list,
                &sides,
            )
            .expect("write bundle");
        }
        let reports = stripe_recovery_pod::importer::scan_and_import_all(&self.store)
            .expect("import");
        let total: usize = reports.iter().map(|r| r.shards).sum();
        assert_eq!(total, self.delivered.len(), "all shards imported");
    }

    pub fn object(&self) -> stripe_recovery_pod::db::ObjectRow {
        self.store.get_object(&self.object_id).unwrap().unwrap()
    }
}
