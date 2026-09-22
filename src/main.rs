use chamber::{demo, web, Store};
use std::sync::Arc;

struct Args {
    addr: String,
    data_dir: String,
    no_seed: bool,
}

fn parse_args() -> Args {
    let mut args = Args {
        addr: "127.0.0.1:5266".to_string(),
        data_dir: "data".to_string(),
        no_seed: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--addr" => {
                if let Some(v) = it.next() {
                    args.addr = v;
                }
            }
            "--data" => {
                if let Some(v) = it.next() {
                    args.data_dir = v;
                }
            }
            "--no-seed" => args.no_seed = true,
            "--help" | "-h" => {
                println!("用法: chamber [--addr 127.0.0.1:5266] [--data data] [--no-seed]");
                std::process::exit(0);
            }
            other => {
                eprintln!("忽略未知参数: {other}");
            }
        }
    }
    args
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("info"))
        .init();

    let args = parse_args();
    let store = Arc::new(Store::open(&args.data_dir)?);

    if !args.no_seed && chamber::service::list_objects(&store).is_empty() {
        let input = std::path::Path::new(&args.data_dir).join("input");
        demo::seed_demo(&store, &input)?;
        // 预分析演示对象，使首页即显示恢复进度。
        for obj in chamber::service::list_objects(&store) {
            chamber::service::reanalyze_object(&store, &obj)?;
        }
        tracing::info!("已生成并导入演示 fixture 到 {}", input.display());
    }

    let listener = tokio::net::TcpListener::bind(&args.addr).await?;
    tracing::info!("条带复原舱监听 http://{}（数据目录 {}）", args.addr, args.data_dir);
    axum::serve(listener, web::router(store)).await?;
    Ok(())
}
