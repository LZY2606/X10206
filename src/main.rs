use stripe_recovery_pod::store::Store;
use stripe_recovery_pod::web::{router, AppState};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let mut addr = "127.0.0.1:5266".to_string();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--addr" {
            if let Some(v) = args.next() {
                addr = v;
            }
        }
    }

    let data_dir = PathBuf::from("data");
    std::fs::create_dir_all(&data_dir).expect("create data dir");
    let store = Store::open(&data_dir.join("recovery.db")).expect("open sqlite");
    let state = Arc::new(AppState { store, data_dir });

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("bind addr");
    let local: SocketAddr = listener.local_addr().unwrap();
    eprintln!("条带复原舱 listening on http://{}", local);
    axum::serve(listener, router(state)).await.unwrap();
}
