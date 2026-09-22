//! 条带复原舱（Stripe Recovery Bay）
//!
//! 离线环境对象碎片审阅与版本化纠删码重建。
//! 启动时自动准备演示夹具（inbox/）、导入、分析并服务 Web UI。

mod db;
mod digest;
mod exporter;
mod gf256;
mod importer;
mod model;
mod recovery;
mod web;

use clap::Parser;
use db::Db;
use gf256::Field;
use std::path::PathBuf;
use std::sync::Arc;
use web::AppState;

#[derive(Parser, Debug)]
#[command(name = "stripe_recovery_bay", about = "条带复原舱")]
struct Args {
    /// 监听地址
    #[arg(long, default_value = "127.0.0.1:5266")]
    addr: String,
    /// 项目数据目录（manifest、碎片、数据库、导出均位于其下）
    #[arg(long, default_value = "data")]
    data_dir: PathBuf,
    /// 组合枚举搜索预算
    #[arg(long, default_value_t = recovery::DEFAULT_COMBO_BUDGET)]
    budget: usize,
    /// 启动时跳过演示夹具写入
    #[arg(long, default_value_t = false)]
    no_demo: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    if let Err(e) = run(args).await {
        eprintln!("fatal: {e}");
        std::process::exit(1);
    }
}

async fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = std::fs::canonicalize(&args.data_dir).unwrap_or_else(|_| {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).join(&args.data_dir)
    });
    std::fs::create_dir_all(&data_dir)?;
    let inbox = data_dir.join("inbox");
    let staging = data_dir.join("staging");
    let exports = data_dir.join("exports");
    std::fs::create_dir_all(&inbox)?;
    std::fs::create_dir_all(&staging)?;
    std::fs::create_dir_all(&exports)?;

    let db_path = data_dir.join("bay.sqlite");
    let db = Arc::new(Db::open(db_path.to_str().unwrap())?);
    let field = Arc::new(Field::new());

    if !args.no_demo {
        demo_fixture::ensure_demo_fixture(&inbox)?;
    }

    match importer::import_dir(&db, &inbox) {
        Ok(o) => {
            if o.manifests + o.blocks + o.warnings > 0 {
                println!(
                    "[import] manifests={} blocks={} warnings={}",
                    o.manifests, o.blocks, o.warnings
                );
            }
        }
        Err(e) => eprintln!("[import] 扫描失败: {e}"),
    }

    // 启动即分析所有对象，保证打开页面即可看到恢复进度。
    let objects = db.list_objects()?;
    for o in objects {
        let json = db.get_manifest_json(&o.object_id)?.unwrap();
        let manifest: model::ObjectManifest = serde_json::from_str(&json)?;
        recovery::sweep_staging(&staging);
        let opts = recovery::RecoverOptions { budget: args.budget };
        match recovery::recover_object(&db, &field, &manifest, &staging, &opts, &recovery::NoFail) {
            Ok(s) => println!(
                "[recover] {} committed={}/{} trusted={}",
                o.object_id, s.stripes_committed, s.stripes_total, s.object_trusted
            ),
            Err(e) => eprintln!("[recover] {} 失败: {e}", o.object_id),
        }
    }

    let state = AppState {
        db: db.clone(),
        field: field.clone(),
        data_dir: data_dir.clone(),
        inbox_dir: inbox.clone(),
        staging_dir: staging.clone(),
        exports_dir: exports.clone(),
        budget: args.budget,
    };
    let app = web::router(state);
    let listener = tokio::net::TcpListener::bind(&args.addr).await?;
    println!("条带复原舱已启动: http://{}", args.addr);
    axum::serve(listener, app).await?;
    Ok(())
}

mod demo_fixture;
