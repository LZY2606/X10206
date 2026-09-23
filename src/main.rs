mod seed;

use std::sync::Arc;

use stripe_recovery_bay::model::FaultGate;
use stripe_recovery_bay::recover::Engine;
use stripe_recovery_bay::store::Store;
use stripe_recovery_bay::web;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mut addr = "127.0.0.1:5266".to_string();
    let mut data = "data".to_string();
    let mut seed = true;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--addr" => addr = args.next().expect("--addr 需要值"),
            "--data" => data = args.next().expect("--data 需要值"),
            "--no-seed" => seed = false,
            "--seed" => seed = true,
            "-h" | "--help" => {
                println!("用法: stripe-recovery-bay [--addr 127.0.0.1:5266] [--data data] [--no-seed]");
                return Ok(());
            }
            other => eprintln!("忽略未知参数 {other}"),
        }
    }

    let fault = FaultGate::new();
    let store = Store::open(&data, fault.clone())?;
    if seed && store.list_objects()?.is_empty() {
        println!("数据目录为空，生成演示 fixture ...");
        seed::seed_demo(&data)?;
        // 重新打开以载入新数据。
        drop(store);
        let store = Store::open(&data, fault.clone())?;
        serve(store, addr).await
    } else {
        serve(store, addr).await
    }
}

async fn serve(store: Store, addr: String) -> std::io::Result<()> {
    let engine = Engine::new();
    let app = web::router(store, engine);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("条带复原舱已启动: http://{addr}");
    axum::serve(listener, app).await
}
