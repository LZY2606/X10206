use stripe_recovery_bay::{server, store::Store};

#[tokio::main]
async fn main() {
    let mut addr = "127.0.0.1:5266".to_string();
    let mut data_dir = "data".to_string();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--addr" => addr = args.next().expect("--addr 需要参数"),
            "--data" => data_dir = args.next().expect("--data 需要参数"),
            other => {
                eprintln!("未知参数: {}", other);
                std::process::exit(2);
            }
        }
    }
    let store = Store::open(std::path::Path::new(&data_dir)).expect("打开数据目录失败");
    if let Err(e) = server::run(store, &addr).await {
        eprintln!("服务器错误: {}", e);
        std::process::exit(1);
    }
}
