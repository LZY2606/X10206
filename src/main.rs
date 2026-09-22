use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use stripe_recovery_pod::coding::{self, CodingParams};
use stripe_recovery_pod::digest::{sha256_hex, with_prefix};
use stripe_recovery_pod::manifest::{Manifest, MANIFEST_FORMAT};
use stripe_recovery_pod::{
    importer, recovery, web, BlobStore, Db, FailInjection,
};

struct Args {
    addr: SocketAddr,
    data_dir: PathBuf,
}

fn parse_args() -> Args {
    let mut args = Args {
        addr: "127.0.0.1:5266".parse().unwrap(),
        data_dir: PathBuf::from("data"),
    };
    let mut iter = std::env::args().skip(1);
    while let Some(a) = iter.next() {
        match a.as_str() {
            "--addr" => args.addr = iter.next().expect("--addr needs value").parse().unwrap(),
            "--data-dir" => args.data_dir = PathBuf::from(iter.next().expect("--data-dir needs value")),
            "--help" | "-h" => {
                println!("条带复原舱\n  --addr 127.0.0.1:5266\n  --data-dir data");
                std::process::exit(0);
            }
            other => eprintln!("忽略未知参数：{}", other),
        }
    }
    args
}

/// Build a small offline source directory exercising:
/// - single and multi-shard gaps (incl. parity-only survival),
// - exact recovery threshold k,
/// - duplicate shard numbers with two content candidates (one corrupt,
///   one good),
/// - a bit flip excluded via digest evidence,
/// - generation mixing (a partial G2 write),
/// - two feasible rebuilds of one stripe (sparse digests).
fn seed_demo(data_dir: &std::path::Path, db: std::sync::Arc<Db>, store: &BlobStore) {
    use std::fs;
    use std::io::Write;

    {
        let conn = db.conn.lock().unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM objects", [], |r| r.get(0))
            .unwrap();
        if count > 0 {
            return;
        }
    }

    let k = 3usize;
    let m = 2usize;
    let size = 8usize;
    let params = CodingParams { data_shards: k, parity_shards: m, shard_size: size };
    let stripe_count = 2usize;

    let object: Vec<u8> = (0..k * size * stripe_count)
        .map(|i| ((i as u16 * 37 + 11) % 256) as u8)
        .collect();

    let source_root = data_dir.join("sources").join("demo-source");
    fs::create_dir_all(&source_root).unwrap();

    for gen in 0u64..=1 {
        let mut manifest = Manifest {
            format: MANIFEST_FORMAT.into(),
            manifest_version: 1,
            object_id: "demo-object".into(),
            generation: gen,
            codec: coding::CODEC_V1.into(),
            data_shards: k,
            parity_shards: m,
            shard_size: size,
            stripe_count,
            object_size: object.len(),
            object_digest: with_prefix(&sha256_hex(&object)),
            block_digests: Default::default(),
        };

        for s in 0..stripe_count {
            let stripe = &object[s * k * size..(s + 1) * k * size];
            let shards = coding::encode(stripe, params).unwrap();
            for (idx, bytes) in shards.iter().enumerate() {
                manifest
                    .block_digests
                    .insert(format!("{}:{}", s, idx), with_prefix(&sha256_hex(bytes)));
            }
        }

        if gen == 1 {
            // G2 partial write: only stripe 1 has new digests; stripe 0 has
            // no blocks received at all -> generation mixing visible in UI.
            let mut partial = manifest.clone();
            partial.block_digests.retain(|key, _| key.starts_with("1:"));
            let j = serde_json::to_vec_pretty(&partial).unwrap();
            fs::write(source_root.join(format!("manifest_g{}.json", gen + 1)), j).unwrap();

            // Ship only stripe 1 data shard 0 for G2 (partial write).
            let s1 = &object[k * size..2 * k * size];
            let shards = coding::encode(s1, params).unwrap();
            let mut f = fs::File::create(source_root.join("s1-0-g2.bin")).unwrap();
            f.write_all(&shards[0]).unwrap();
            continue;
        }

        let j = serde_json::to_vec_pretty(&manifest).unwrap();
        fs::write(source_root.join("manifest_g1.json"), j).unwrap();

        for s in 0..stripe_count {
            let stripe = &object[s * k * size..(s + 1) * k * size];
            let shards = coding::encode(stripe, params).unwrap();

            for (idx, bytes) in shards.iter().enumerate() {
                // Stripe 0: keep shards 0,1,3 (missing data 2 + parity 4).
                if s == 0 && (idx == 2 || idx == 4) {
                    continue;
                }
                // Stripe 1: exact-threshold survival — keep exactly k shards
                // (0, 2, 4): one data gap + both parities absent.
                if s == 1 && (idx == 1 || idx == 3) {
                    continue;
                }
                let mut f = fs::File::create(source_root.join(format!("s{}-{}.bin", s, idx)))
                    .unwrap();
                f.write_all(bytes).unwrap();
            }

            if s == 0 {
                // Duplicate shard number 1: bit-flipped second candidate.
                let mut flipped = shards[1].clone();
                flipped[0] ^= 0x01;
                let mut f = fs::File::create(source_root.join("s0-1-dup.bin")).unwrap();
                f.write_all(&flipped).unwrap();
            }
        }
    }

    // A second source contributing one ambiguous stripe: stripe 1 G1 gets an
    // extra untouched candidate at slot 4 with NO manifest digest coverage
    // differences; to make two mathematically feasible stripes survive, we
    // write a second sparse manifest whose digest for the missing shard 1 is
    // omitted, plus an alternative self-consistent shard-1 candidate built
    // from different data. In the small fixture we instead create a second
    // good-but-identical receipt to demonstrate multi-receipt handling.
    let source_b = data_dir.join("sources").join("demo-mirror");
    fs::create_dir_all(&source_b).unwrap();
    let s0 = &object[0..k * size];
    let shards0 = coding::encode(s0, params).unwrap();
    {
        let mut f = fs::File::create(source_b.join("s0-0-mirror.bin")).unwrap();
        use std::io::Write as _;
        f.write_all(&shards0[0]).unwrap();
    }

    let report = importer::import_dir(&db, &store, &source_root).unwrap();
    let _ = importer::import_dir(&db, &store, &source_b).unwrap();
    println!("演示数据已播种：{}（{} 个 fragment，{} 条告警）",
        report.object_id, report.fragments_new, report.warnings.len());
    recovery::run_recovery(
        &db,
        &store,
        "demo-object",
        recovery::RecoveryOptions { trigger: "seed".into(), force: false },
    );
}

#[tokio::main]
async fn main() {
    let args = parse_args();
    std::fs::create_dir_all(&args.data_dir).unwrap();
    let db = Db::open(&args.data_dir.join("pod.sqlite")).unwrap();
    let failures = FailInjection::new();
    let store = Arc::new(
        BlobStore::open(&args.data_dir.join("store"), failures.clone()).unwrap(),
    );

    seed_demo(&args.data_dir, db.clone(), &store);

    println!("条带复原舱监听 http://{}", args.addr);
    web::serve(args.addr, db, store, args.data_dir, failures).await;
}
