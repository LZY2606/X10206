//! Small finite-field fixture builder for integration tests.

use std::fs;
use std::path::{Path, PathBuf};

use stripe_recovery_pod::coding::{self, CodingParams};
use stripe_recovery_pod::digest::{sha256_hex, with_prefix};
use stripe_recovery_pod::manifest::{Manifest, MANIFEST_FORMAT};
use stripe_recovery_pod::store::{BlobStore, FailInjection};
use stripe_recovery_pod::Db;

pub struct Harness {
    #[allow(dead_code)]
    tempdir: tempfile::TempDir,
    pub tmp: PathBuf,
    pub db: std::sync::Arc<Db>,
    pub store: std::sync::Arc<BlobStore>,
    pub failures: std::sync::Arc<FailInjection>,
    pub object_id: String,
    pub params: CodingParams,
    pub stripes: Vec<Vec<u8>>,
    source_seq: usize,
}

impl Harness {
    pub fn new(k: usize, m: usize, size: usize, stripe_count: usize) -> Self {
        let tempdir = tempfile::tempdir().unwrap();
        let root = tempdir.path().to_path_buf();
        let failures = FailInjection::new();
        let store = std::sync::Arc::new(
            BlobStore::open(&root.join("store"), failures.clone()).unwrap(),
        );
        let db = Db::open(&root.join("pod.sqlite")).unwrap();
        let object_id = "test-obj".to_string();
        let params = CodingParams { data_shards: k, parity_shards: m, shard_size: size };

        let mut stripes = Vec::new();
        let mut seed: u8 = 3;
        for _ in 0..stripe_count {
            let mut stripe = vec![0u8; k * size];
            for b in stripe.iter_mut() {
                seed = seed.wrapping_mul(31).wrapping_add(13);
                *b = seed;
            }
            stripes.push(stripe);
        }

        Harness {
            tempdir,
            tmp: root,
            db,
            store,
            failures,
            object_id,
            params,
            stripes,
            source_seq: 0,
        }
    }

    pub fn all_shards(&self, s: usize) -> Vec<Vec<u8>> {
        coding::encode(&self.stripes[s], self.params).unwrap()
    }

    pub fn object_bytes(&self) -> Vec<u8> {
        self.stripes.concat()
    }

    pub fn make_source(
        &mut self,
        generation: u64,
        files: &[(usize, usize, Vec<u8>, Option<String>)],
        digest_mask: impl Fn(usize, usize) -> bool,
    ) -> PathBuf {
        self.source_seq += 1;
        let dir = self.tmp.join(format!("src-{}", self.source_seq));
        fs::create_dir_all(&dir).unwrap();

        let k = self.params.data_shards;
        let n = k + self.params.parity_shards;
        let mut block_digests = std::collections::BTreeMap::new();
        for s in 0..self.stripes.len() {
            let shards = self.all_shards(s);
            for idx in 0..n {
                if digest_mask(s, idx) {
                    block_digests.insert(
                        format!("{}:{}", s, idx),
                        with_prefix(&sha256_hex(&shards[idx])),
                    );
                }
            }
        }
        let object_digest = with_prefix(&sha256_hex(&self.object_bytes()));
        let manifest = Manifest {
            format: MANIFEST_FORMAT.into(),
            manifest_version: 1,
            object_id: self.object_id.clone(),
            generation,
            codec: coding::CODEC_V1.into(),
            data_shards: k,
            parity_shards: self.params.parity_shards,
            shard_size: self.params.shard_size,
            stripe_count: self.stripes.len(),
            object_size: self.object_bytes().len(),
            object_digest,
            block_digests,
        };
        let j = serde_json::to_vec_pretty(&manifest).unwrap();
        fs::write(dir.join(format!("manifest_g{}.json", generation + 1)), j).unwrap();

        for (s, idx, bytes, tag) in files {
            let name = match tag {
                Some(t) => format!("s{}-{}-{}.bin", s, idx, t),
                None => format!("s{}-{}.bin", s, idx),
            };
            fs::write(dir.join(name), bytes).unwrap();
        }
        dir
    }

    pub fn make_complete_source_with_gaps(
        &mut self,
        generation: u64,
        keep: impl Fn(usize, usize) -> bool,
    ) -> PathBuf {
        let mut files = Vec::new();
        let n = self.params.data_shards + self.params.parity_shards;
        for s in 0..self.stripes.len() {
            let shards = self.all_shards(s);
            for idx in 0..n {
                if keep(s, idx) {
                    files.push((s, idx, shards[idx].clone(), None));
                }
            }
        }
        self.make_source(generation, &files, |_, _| true)
    }

    pub fn import(&self, dir: &Path) {
        stripe_recovery_pod::importer::import_dir(&self.db, &self.store, dir).unwrap();
    }

    pub fn run(&self, force: bool) -> stripe_recovery_pod::recovery::RunReport {
        stripe_recovery_pod::recovery::run_recovery(
            &self.db,
            &self.store,
            &self.object_id,
            stripe_recovery_pod::recovery::RecoveryOptions {
                trigger: "test".into(),
                force,
            },
        )
    }

    pub fn status_of(&self, stripe: usize) -> String {
        let conn = self.db.conn.lock().unwrap();
        conn.query_row(
            "SELECT status FROM stripes WHERE object_id=?1 AND stripe_index=?2",
            rusqlite::params![self.object_id, stripe as i64],
            |r| r.get::<_, String>(0),
        )
        .unwrap()
    }

    pub fn feasible_count(&self, stripe: usize) -> usize {
        let conn = self.db.conn.lock().unwrap();
        conn.query_row(
            "SELECT COUNT(*) FROM outcomes
             WHERE object_id=?1 AND stripe_index=?2 AND feasible=1",
            rusqlite::params![self.object_id, stripe as i64],
            |r| r.get::<_, i64>(0),
        )
        .unwrap() as usize
    }

    pub fn data_shard_bytes(&self, stripe: usize, shard: usize) -> Vec<u8> {
        let conn = self.db.conn.lock().unwrap();
        let (hash,): (String,) = conn
            .query_row(
                "SELECT b.blob_hash FROM outcome_blocks b
                 JOIN stripes s ON s.active_outcome_id = b.outcome_id
                 WHERE s.object_id=?1 AND s.stripe_index=?2 AND b.shard_index=?3",
                rusqlite::params![self.object_id, stripe as i64, shard as i64],
                |r| Ok((r.get(0)?,)),
            )
            .unwrap();
        drop(conn);
        self.store.read(&hash).unwrap()
    }
}

pub fn bitflip(bytes: &[u8]) -> Vec<u8> {
    let mut v = bytes.to_vec();
    v[0] ^= 0x80;
    v
}
