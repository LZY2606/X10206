use std::net::SocketAddr;
use std::path::PathBuf;
use stripes_recovery_pod::{demo, store::Store, web};

#[tokio::main]
async fn main() -> anyhow_lite::Result<()> {
    let mut addr: SocketAddr = "127.0.0.1:5266".parse().unwrap();
    let mut data_dir = PathBuf::from("data");
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--addr" => addr = args.next().expect("missing address").parse().expect("invalid address"),
            "--data-dir" => data_dir = PathBuf::from(args.next().expect("missing data dir")),
            other => panic!("unknown argument: {other}"),
        }
    }
    Store::init(&data_dir)?;
    demo::bootstrap_demo_if_empty(&data_dir)?;
    let store = Store::open(&data_dir)?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("条带复原舱 listening on http://{addr}");
    axum::serve(listener, web::router(store)).await?;
    Ok(())
}

mod anyhow_lite {
    pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
}
