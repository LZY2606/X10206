
use stripe_recovery_cabin::{recovery, store, web, demo};
use std::net::SocketAddr;
use std::path::PathBuf;
use store::Store;

struct Args {
    addr: SocketAddr,
    data_dir: PathBuf,
    seed_demo: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        addr: "127.0.0.1:5266".parse().unwrap(),
        data_dir: PathBuf::from("data"),
        seed_demo: false,
    };
    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--addr" => {
                let v = iter.next().ok_or_else(|| "--addr 需要值".to_string())?;
                args.addr = v.parse().map_err(|e| format!("非法地址 {v}: {e}"))?;
            }
            "--data-dir" => {
                let v = iter.next().ok_or_else(|| "--data-dir 需要值".to_string())?;
                args.data_dir = PathBuf::from(v);
            }
            "--seed-demo" => args.seed_demo = true,
            "--help" | "-h" => {
                println!(
                    "条带复原舱\n用法: stripe-recovery-cabin [--addr 127.0.0.1:5266] [--data-dir data] [--seed-demo]"
                );
                std::process::exit(0);
            }
            other => return Err(format!("未知参数: {other}")),
        }
    }
    Ok(args)
}

#[tokio::main]
async fn main() {
    let args = parse_args().unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2);
    });
    std::fs::create_dir_all(&args.data_dir).expect("创建数据目录失败");
    let store = Store::open(&args.data_dir).expect("打开存储失败");

    // 空库时自动播种演示对象（满足打开页面即可看到"条带复原舱"演示数据）。
    let objects = store.list_objects().unwrap_or_default();
    if objects.is_empty() || args.seed_demo {
        match demo::seed_demo(&store, &args.data_dir) {
            Ok(report) => {
                println!(
                    "已导入演示对象 {}（{} 块，来源 {} 个）",
                    report.object_id,
                    report.fragment_count,
                    report.sources.len()
                );
                for w in &report.warnings {
                    println!("  ! {w}");
                }
                if let Err(e) = recovery::run_recovery(&store, "demo-object", true) {
                    eprintln!("演示对象初始恢复失败: {e}");
                }
            }
            Err(e) => eprintln!("演示数据播种失败: {e}"),
        }
    }

    println!("条带复原舱监听 http://{}", args.addr);
    web::serve(store, args.data_dir, args.addr).await;
}
