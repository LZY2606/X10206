use std::sync::Arc;

use clap::Parser;
use stripe_recovery_pod::demo::seed_demo_data;
use stripe_recovery_pod::store::Store;
use stripe_recovery_pod::web::router;

/// 条带复原舱 — offline erasure-coded stripe review pod.
#[derive(Parser, Debug)]
#[command(name = "stripe-recovery-pod", version)]
struct Args {
    /// Listen address.
    #[arg(long, default_value = "127.0.0.1:5266")]
    addr: String,
    /// Data directory (SQLite + original blobs + committed + exports).
    #[arg(long, default_value = "data")]
    data_dir: String,
    /// Skip seeding the built-in demo objects.
    #[arg(long, default_value_t = false)]
    no_seed: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let store = Arc::new(Store::open(&args.data_dir)?);

    if !args.no_seed && store.list_objects()?.is_empty() {
        seed_demo_data(&store)?;
        println!("已播种演示对象到 {}", args.data_dir);
    }

    let listener = tokio::net::TcpListener::bind(&args.addr).await?;
    println!("条带复原舱 listening on http://{}", args.addr);
    axum::serve(listener, router(store)).await?;
    Ok(())
}
