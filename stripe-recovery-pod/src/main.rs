use clap::Parser;
use stripe_recovery_pod::db::{Paths, Store};
use stripe_recovery_pod::recovery::{run_object_recovery, CrashPoint};
use stripe_recovery_pod::{importer, seed, web};
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(name = "stripe-recovery-pod", about = "条带复原舱 — offline stripe recovery review cabin")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:5266")]
    addr: String,
    #[arg(long, default_value = "data")]
    data_dir: String,
    #[arg(long)]
    no_seed: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let paths = Paths::new(&args.data_dir);
    let store = Arc::new(Store::open(paths.clone())?);

    if !args.no_seed && is_data_empty(&paths)? {
        println!("[pod] empty data dir; seeding deterministic demo fixtures…");
        let ids = seed::seed_demo(&paths.incoming)?;
        let reports = importer::scan_and_import_all(&store)?;
        for r in &reports {
            println!(
                "[pod] imported from {}: {} manifest(s), {} shard(s), {} evidence",
                r.source, r.manifests, r.shards, r.evidence
            );
        }
        for id in &ids {
            match run_object_recovery(&store, id, CrashPoint::None) {
                Ok(report) => println!("[pod] {id}: {} — {}", report.status, first_line(&report.detail)),
                Err(e) => println!("[pod] {id}: recovery error: {e}"),
            }
        }
    } else {
        let reports = importer::scan_and_import_all(&store)?;
        for r in &reports {
            if r.shards > 0 || r.manifests > 0 {
                println!(
                    "[pod] imported from {}: {} manifest(s), {} shard(s), {} evidence",
                    r.source, r.manifests, r.shards, r.evidence
                );
            }
        }
    }

    let app = web::router(store);
    let listener = tokio::net::TcpListener::bind(&args.addr).await?;
    println!("[pod] 条带复原舱 listening on http://{}", args.addr);
    axum::serve(listener, app).await?;
    Ok(())
}

fn is_data_empty(paths: &Paths) -> anyhow::Result<bool> {
    if !paths.root.exists() {
        return Ok(true);
    }
    if paths.db.exists() {
        return Ok(false);
    }
    let mut has_content = false;
    if paths.incoming.exists() {
        has_content |= std::fs::read_dir(&paths.incoming)?.next().is_some();
    }
    Ok(!has_content)
}

fn first_line(s: &str) -> &str {
    s.split('\n').next().unwrap_or(s)
}
