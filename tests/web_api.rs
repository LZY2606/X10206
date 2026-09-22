#![allow(dead_code)]
#![allow(unused_imports)]
mod common;

use axum::body::Body;
use axum::Router;
use bytes::Bytes;
use common::*;
use http_body_util::BodyExt;
use std::net::SocketAddr;
use tower::util::ServiceExt;

fn app(store: Store, data: std::path::PathBuf) -> Router {
    stripe_recovery_cabin::web::router(stripe_recovery_cabin::web::AppState {
        store,
        data_dir: std::sync::Arc::new(data),
    })
}

async fn body_string(resp: axum::http::Response<Body>) -> (axum::http::StatusCode, String) {
    let status = resp.status();
    let bytes: Bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

fn json_post(path: &str, body: serde_json::Value) -> axum::http::Request<Body> {
    axum::http::Request::post(path)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn index_has_title() {
    let dir = temp_dir("web");
    let store = Store::open(dir.join("store")).unwrap();
    let router = app(store, dir);
    let resp = router
        .oneshot(axum::http::Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let (status, text) = body_string(resp).await;
    assert_eq!(status, 200);
    assert!(text.contains("条带复原舱"));
}

#[tokio::test]
async fn full_flow_through_http() {
    let dir = temp_dir("webflow");
    let bundle = dir.join("bundle");
    std::fs::create_dir_all(&bundle).unwrap();

    // 用 demo 播种逻辑：直接生成 bundle 后通过 importer 模块导入到 store
    let store = Store::open(dir.join("store")).unwrap();
    let report = stripe_recovery_cabin::demo::seed_demo(&store, &dir).unwrap();
    assert_eq!(report.object_id, "demo-object");
    let router = app(store, dir);

    // 对象列表
    let resp = router
        .clone()
        .oneshot(axum::http::Request::get("/api/objects").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let (_, text) = body_string(resp).await;
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["objects"][0]["object_id"], "demo-object");

    // 详情
    let resp = router
        .clone()
        .oneshot(
            axum::http::Request::get("/api/objects/demo-object")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let (_, text) = body_string(resp).await;
    let detail: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(detail["stripes"].as_array().unwrap().len(), 3);

    // 恢复
    let resp = router
        .clone()
        .oneshot(json_post(
            "/api/objects/demo-object/recover",
            serde_json::json!({"reuse": true}),
        ))
        .await
        .unwrap();
    let (status, text) = body_string(resp).await;
    assert_eq!(status, 200, "{}", text);
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["progress"]["stripes_total"], 3);
    assert_eq!(v["detail"]["outcomes"].as_array().unwrap().len(), 1);

    // 导出
    let resp = router
        .clone()
        .oneshot(json_post(
            "/api/objects/demo-object/export",
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    let (status, text) = body_string(resp).await;
    assert_eq!(status, 200, "{}", text);
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    let out_dir = std::path::PathBuf::from(v["dir"].as_str().unwrap());
    assert!(out_dir.join("manifest.json").exists());
    assert!(out_dir.join("object.bin").exists());

    // 隔离 node-A（stripe0 边界恢复依赖它）后恢复应失败
    let resp = router
        .clone()
        .oneshot(json_post(
            "/api/objects/demo-object/isolate",
            serde_json::json!({"sources": ["node-A"]}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = router
        .clone()
        .oneshot(json_post(
            "/api/objects/demo-object/recover",
            serde_json::json!({"reuse": true}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[allow(dead_code)]
fn _addr() -> SocketAddr {
    "127.0.0.1:5266".parse().unwrap()
}
