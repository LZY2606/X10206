use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use stripe_recovery_chamber::model::{sha256_hex, Manifest};
use stripe_recovery_chamber::recover::{self, RecoveryConfig};
use stripe_recovery_chamber::rs::EncodingParams;
use stripe_recovery_chamber::store::Store;
use stripe_recovery_chamber::web::{self, AppState};

fn parse_addr() -> SocketAddr {
    let args: Vec<String> = std::env::args().collect();
    let mut addr = "127.0.0.1:5266".to_string();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--addr" && i + 1 < args.len() {
            addr = args[i + 1].clone();
            i += 2;
        } else {
            i += 1;
        }
    }
    addr.parse().expect("无效的 --addr")
}

/// Seed a demo object on first run so the chamber is not empty.
fn seed_demo(store: &Store) {
    if !store.list_objects().map(|o| o.is_empty()).unwrap_or(false) {
        return;
    }
    let encoding = EncodingParams { version: 1, k: 3, m: 2, field_poly: 0x11d, stripe_size: 4 };
    let shard_bytes = 8; // 2 stripes
    let object_length = 3 * shard_bytes;
    let object: Vec<u8> = (0..object_length as u8).map(|b| b.wrapping_mul(7).wrapping_add(3)).collect();
    let coder = stripe_recovery_chamber::rs::Coder::new(encoding.clone()).unwrap();
    let mut shards: Vec<Vec<u8>> = vec![Vec::new(); encoding.total()];
    for stripe in 0..shard_bytes / encoding.stripe_size {
        let base = stripe * encoding.k * encoding.stripe_size;
        let data: Vec<&[u8]> = (0..encoding.k)
            .map(|d| &object[base + d * encoding.stripe_size..base + (d + 1) * encoding.stripe_size])
            .collect();
        let row = coder.encode(&data).unwrap();
        for (i, frag) in row.iter().enumerate() {
            shards[i].extend_from_slice(frag);
        }
    }
    let shard_digests: Vec<String> = shards.iter().map(|s| sha256_hex(s)).collect();
    let manifest = Manifest {
        object_id: "demo-obj".into(),
        encoding,
        shard_bytes,
        object_length,
        object_digest: Some(sha256_hex(&object)),
        shard_digests: Some(shard_digests),
    };
    store.put_manifest(&manifest).unwrap();
    // shard 0..4 from node-a (shard 2 missing), duplicate of 1 from node-b
    // with a bit flip, stale-generation copy of 3 from node-c.
    for (idx, gen, source) in [(0usize, 2u64, "node-a"), (1, 2, "node-a"), (3, 2, "node-a"), (4, 2, "node-a")] {
        store.add_shard("demo-obj", idx, gen, source, &shards[idx]).unwrap();
    }
    let mut flipped = shards[1].clone();
    flipped[0] ^= 0x01;
    store.add_shard("demo-obj", 1, 2, "node-b", &flipped).unwrap();
    let mut stale = shards[3].clone();
    stale[5] ^= 0x40;
    store.add_shard("demo-obj", 3, 1, "node-c", &stale).unwrap();

    let _ = recover::recover_object(store, "demo-obj", &RecoveryConfig::default());
    tracing::info!("seeded demo object demo-obj");
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();
    let addr = parse_addr();
    let data_dir = PathBuf::from("./data");
    let store = Store::open(&data_dir.join("chamber.db")).expect("打开数据库失败");
    seed_demo(&store);
    let state = Arc::new(AppState {
        store,
        export_dir: data_dir.join("exports"),
        config: RecoveryConfig::default(),
    });
    let app = web::router(state);
    let listener = tokio::net::TcpListener::bind(addr).await.expect("绑定端口失败");
    tracing::info!("条带复原舱 listening on http://{}", addr);
    axum::serve(listener, app).await.expect("服务运行失败");
}
