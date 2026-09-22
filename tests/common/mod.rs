#![allow(dead_code)]
#![allow(unused_imports)]
//! 小有限域（gf16）测试 fixture 辅助：构造 bundle、故障注入存储与引擎分析。

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub use stripe_recovery_cabin::{
    coding::Coding,
    engine::{assemble_outcomes, Engine, DEFAULT_OBJECT_BUDGET},
    exporter, recovery,
    gf::Field,
    importer,
    model::{sha256_hex, DigestState, ExcludeReason, FragmentInput, Manifest, StripeHealth},
    store::{FaultPoint, FsFault, Store},
};

pub fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "cabin-test-{}-{}-{}",
        tag,
        std::process::id(),
        rand_suffix()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn rand_suffix() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

/// k=2, m=2, stripe_length=4, gf16
pub fn make_manifest(
    object_id: &str,
    stripe_count: usize,
    object_digest: Option<String>,
    object_length: Option<usize>,
) -> Manifest {
    Manifest {
        object_id: object_id.into(),
        codec_version: 1,
        field: "gf16".into(),
        k: 2,
        m: 2,
        stripe_length: 4,
        stripe_count,
        object_length,
        object_digest,
    }
}

pub fn encode(gf_data: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let coding = Coding::new(Field::Gf16, 2, 2).unwrap();
    coding.encode_bytes(gf_data)
}

pub struct ShardFile {
    pub stripe: usize,
    pub shard: usize,
    pub generation: u64,
    pub source: String,
    pub bytes: Vec<u8>,
    pub digest: Option<String>,
    pub suffix: String,
}

impl ShardFile {
    pub fn new(
        stripe: usize,
        shard: usize,
        generation: u64,
        source: &str,
        bytes: Vec<u8>,
        digest: Option<String>,
    ) -> Self {
        ShardFile {
            stripe,
            shard,
            generation,
            source: source.into(),
            bytes,
            digest,
            suffix: String::new(),
        }
    }
    pub fn with_suffix(mut self, s: &str) -> Self {
        self.suffix = s.into();
        self
    }
}

pub fn write_bundle(dir: &Path, manifest: &Manifest, shards: &[ShardFile]) {
    let shards_dir = dir.join("shards");
    std::fs::create_dir_all(&shards_dir).unwrap();
    std::fs::write(
        dir.join("manifest.json"),
        serde_json::to_vec_pretty(manifest).unwrap(),
    )
    .unwrap();
    for s in shards {
        let extra = if s.suffix.is_empty() {
            String::new()
        } else {
            format!("-{}", s.suffix)
        };
        let name = format!("s{}_sh{}_g{}{}", s.stripe, s.shard, s.generation, extra);
        std::fs::write(shards_dir.join(format!("{}.bin", name)), &s.bytes).unwrap();
        if let Some(d) = &s.digest {
            std::fs::write(shards_dir.join(format!("{}.digest", name)), d).unwrap();
        }
        let meta = serde_json::json!({"source": s.source});
        std::fs::write(
            shards_dir.join(format!("{}.meta.json", name)),
            meta.to_string().into_bytes(),
        )
        .unwrap();
    }
}

pub fn import(dir: &Path, store: &Store) {
    importer::import_bundle(store, dir).unwrap();
}

pub fn analyze(
    manifest: &Manifest,
    frags: &[FragmentInput],
    isolated: &BTreeSet<String>,
) -> Vec<stripe_recovery_cabin::model::StripeAnalysis> {
    let engine = Engine::new(manifest).unwrap();
    let mut out = Vec::new();
    for s in 0..manifest.stripe_count {
        let fs: Vec<FragmentInput> = frags.iter().filter(|f| f.stripe == s).cloned().collect();
        out.push(engine.analyze_stripe(
            &manifest.object_id,
            s,
            manifest.stripe_length,
            &fs,
            isolated,
        ));
    }
    out
}

pub fn load_frags(store: &Store, object_id: &str) -> Vec<FragmentInput> {
    store
        .list_fragments(object_id)
        .unwrap()
        .into_iter()
        .map(|p| {
            let bytes = store.read_raw(&p.rel_path).unwrap();
            FragmentInput {
                fragment_id: p.fragment_id,
                object_id: p.object_id,
                stripe: p.stripe as usize,
                shard: p.shard as usize,
                generation: p.generation as u64,
                source: p.source,
                bytes,
                claimed_digest: p.claimed_digest,
                received_at: p.received_at,
            }
        })
        .collect()
}

#[derive(Default)]
struct CounterInner {
    remaining: Option<usize>,
}

pub struct CountingFault {
    point: FaultPoint,
    inner: Mutex<CounterInner>,
}

impl CountingFault {
    pub fn new(point: FaultPoint, fail_first: usize) -> Arc<Self> {
        Arc::new(CountingFault {
            point,
            inner: Mutex::new(CounterInner {
                remaining: Some(fail_first),
            }),
        })
    }
}

impl FsFault for CountingFault {
    fn should_fail(&self, point: FaultPoint, _path: &Path) -> bool {
        if point != self.point {
            return false;
        }
        let mut g = self.inner.lock().unwrap();
        match g.remaining {
            Some(n) if n > 0 => {
                g.remaining = Some(n - 1);
                true
            }
            _ => false,
        }
    }
}

pub fn object_bytes(manifest: &Manifest, frags: &[FragmentInput]) -> (Vec<u8>, String) {
    let analyses = analyze(manifest, frags, &BTreeSet::new());
    let outcomes = assemble_outcomes(manifest, &analyses, DEFAULT_OBJECT_BUDGET).unwrap();
    (
        outcomes[0].bytes.clone(),
        outcomes[0].object_digest.clone(),
    )
}
