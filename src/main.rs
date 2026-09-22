mod coding;
mod demo;
mod engine;
mod export;
mod import;
mod model;
mod store;
mod web;

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "stripe-recovery-bay")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:5266")]
    addr: SocketAddr,
    #[arg(long, default_value = "data")]
    data_dir: PathBuf,
    #[arg(long)]
    import_dir: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();
    let storage = store::Storage::open(&args.data_dir)?;

    let tmp = args.data_dir.join("recovered").join("tmp");
    if tmp.exists() {
        for entry in std::fs::read_dir(&tmp)? {
            let entry = entry?;
            if entry.path().is_file() {
                std::fs::remove_file(entry.path())?;
            }
        }
    }
    storage.reset_interrupted_runs()?;

    if let Some(import_dir) = args.import_dir {
        let imported = import::import_directory(&storage, import_dir, "cli")?;
        for item in imported {
            println!("imported {}: {} fragments", item.object_id, item.fragment_count);
        }
    }
    let seeded = demo::seed_demo(&storage)?;
    if seeded > 0 {
        println!("seeded {seeded} offline demonstration objects");
    }

    let listener = tokio::net::TcpListener::bind(args.addr).await?;
    println!("条带复原舱 listening on http://{}", args.addr);
    axum::serve(listener, web::router(storage)).await
}
