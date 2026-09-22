//! 条带复原舱 HTTP 服务入口。
//!
//! 用法：cargo run -- --addr 127.0.0.1:5266 [--data ./data]

use std::net::SocketAddr;

use stripe_capsule::api::{router, AppState};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut addr: SocketAddr = "127.0.0.1:5266".parse().unwrap();
    let mut data = std::path::PathBuf::from("data");
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" => {
                addr = args[i + 1].parse()?;
                i += 2;
            }
            "--data" => {
                data = args[i + 1].clone().into();
                i += 2;
            }
            other => {
                eprintln!("未知参数: {other}");
                std::process::exit(2);
            }
        }
    }

    let system = stripe_capsule::init_system(&data)?;
    let state = AppState {
        storage: system.storage,
        data_root: system.data_root,
    };

    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("条带复原舱已启动：http://{addr} （数据目录 {}）", data.display());
    axum::serve(listener, router(state).into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
