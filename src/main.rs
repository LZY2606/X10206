use stripe_recovery_pod::api::serve;

#[derive(Default)]
struct Args {
    addr: String,
    data_dir: Option<String>,
}

fn parse_args() -> Args {
    let mut args = Args {
        addr: "127.0.0.1:5266".to_string(),
        data_dir: None,
    };
    let mut raw = std::env::args().skip(1);
    while let Some(a) = raw.next() {
        match a.as_str() {
            "--addr" => args.addr = raw.next().expect("--addr 需要值"),
            "--data-dir" => args.data_dir = Some(raw.next().expect("--data-dir 需要值")),
            other if other.starts_with("--addr=") => {
                args.addr = other["--addr=".len()..].to_string();
            }
            other => panic!("未知参数: {other}"),
        }
    }
    args
}

#[tokio::main]
async fn main() {
    let args = parse_args();
    let data_dir = args.data_dir.unwrap_or_else(|| "data".to_string());
    println!("条带复原舱: data_dir={data_dir} addr={}", args.addr);
    serve(&args.addr, &data_dir).await.expect("server error");
}
