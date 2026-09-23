//! Axum HTTP 服务：状态查询、导入、恢复、隔离、导出。
use crate::engine;
use crate::recover::{sha256_hex, StripeReport, StripeStatus};
use crate::store::{Manifest, Store};
use crate::ui;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, Json};
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub struct AppState {
    pub store: Store,
    pub reports: Mutex<HashMap<i64, Vec<StripeReport>>>,
}

type Shared = Arc<AppState>;
type ApiResult<T> = Result<T, (StatusCode, String)>;

fn err500(e: String) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e)
}

pub fn router(store: Store) -> Router {
    let state: Shared = Arc::new(AppState {
        store,
        reports: Mutex::new(HashMap::new()),
    });
    Router::new()
        .route("/", get(index))
        .route("/api/state", get(api_state))
        .route("/api/objects", post(create_object))
        .route("/api/objects/:id/shards", post(add_shard))
        .route("/api/objects/:id/recover", post(recover_handler))
        .route("/api/objects/:id/export", post(export_handler))
        .route("/api/objects/:id/report", get(report_handler))
        .route("/api/quarantine", post(quarantine_handler))
        .route("/api/demo", post(demo_handler))
        .with_state(state)
}

pub async fn run(store: Store, addr: &str) -> Result<(), String> {
    store.cleanup_temp()?;
    let app = router(store);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("绑定 {} 失败: {}", addr, e))?;
    println!("条带复原舱已启动: http://{}", addr);
    axum::serve(listener, app)
        .await
        .map_err(|e| e.to_string())
}

async fn index() -> Html<&'static str> {
    Html(ui::INDEX)
}

fn report_json(r: &StripeReport) -> Value {
    let status = match r.status {
        StripeStatus::Recovered => "已恢复",
        StripeStatus::Ambiguous => "多个可行重建",
        StripeStatus::Unrecoverable => "不可恢复",
    };
    json!({
        "stripe": r.stripe,
        "status": status,
        "attempts": r.attempts,
        "budget_exhausted": r.budget_exhausted,
        "reused": r.reused,
        "committed": r.committed,
        "note": r.note,
        "excluded": r.excluded,
        "reconstructions": r.reconstructions.iter().map(|rec| json!({
            "result_digest": rec.result_digest,
            "recomputed": rec.recomputed,
            "sets": rec.sets,
        })).collect::<Vec<_>>(),
    })
}

async fn api_state(State(s): State<Shared>) -> ApiResult<Json<Value>> {
    let quarantined = s.store.quarantined().map_err(err500)?;
    let mut objects = Vec::new();
    for o in s.store.list_objects().map_err(err500)? {
        let mut stripes = Vec::new();
        for stripe in 0..o.stripes {
            let manifest = s.store.manifest_digests(o.id, stripe).map_err(err500)?;
            let rows = s.store.shards_for(o.id, stripe, false).map_err(err500)?;
            let total = (o.k + o.m) as u32;
            let mut valid_idx = std::collections::BTreeSet::new();
            let mut digest_sets: HashMap<u32, std::collections::BTreeSet<String>> = HashMap::new();
            for r in &rows {
                digest_sets.entry(r.index).or_default().insert(r.digest.clone());
                if manifest.get(&r.index) == Some(&r.digest) {
                    valid_idx.insert(r.index);
                }
            }
            let conflicts: Vec<u32> = digest_sets
                .iter()
                .filter(|(_, ds)| ds.len() > 1)
                .map(|(i, _)| *i)
                .collect();
            let valid = valid_idx.len() as u32;
            let health = if valid >= total {
                "健康"
            } else if valid >= o.k as u32 {
                "可恢复"
            } else {
                "不足"
            };
            let committed = s.store.committed(o.id, stripe).map_err(err500)?;
            stripes.push(json!({
                "stripe": stripe,
                "health": health,
                "valid": valid,
                "total": total,
                "received": rows.len(),
                "conflicts": conflicts,
                "committed": committed.is_some(),
                "committed_digest": committed.map(|c| c.0),
            }));
        }
        objects.push(json!({
            "id": o.id, "name": o.name, "k": o.k, "m": o.m,
            "shard_len": o.shard_len, "stripes": o.stripes, "ec_version": o.ec_version,
            "sources": s.store.sources(o.id).map_err(err500)?,
            "stripes_detail": stripes,
        }));
    }
    Ok(Json(json!({ "objects": objects, "quarantined": quarantined })))
}

async fn create_object(State(s): State<Shared>, Json(m): Json<Manifest>) -> ApiResult<Json<Value>> {
    let id = s.store.create_object(&m).map_err(err500)?;
    Ok(Json(json!({ "id": id })))
}

#[derive(Deserialize)]
struct ShardQuery {
    stripe: u32,
    index: u32,
    generation: Option<u64>,
    source: Option<String>,
}

async fn add_shard(
    State(s): State<Shared>,
    Path(id): Path<i64>,
    Query(q): Query<ShardQuery>,
    body: axum::body::Bytes,
) -> ApiResult<Json<Value>> {
    let source = q.source.unwrap_or_else(|| "unknown".to_string());
    let generation = q.generation.unwrap_or(0);
    let digest = sha256_hex(&body);
    s.store
        .add_shard(id, q.stripe, q.index, generation, &source, &digest, &body)
        .map_err(err500)?;
    Ok(Json(json!({ "digest": digest })))
}

async fn recover_handler(State(s): State<Shared>, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let reports = engine::recover_object(&s.store, id, engine::default_budget()).map_err(err500)?;
    let body: Vec<Value> = reports.iter().map(report_json).collect();
    s.reports.lock().unwrap().insert(id, reports);
    Ok(Json(json!({ "object": id, "stripes": body })))
}

async fn report_handler(State(s): State<Shared>, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let reports = s.reports.lock().unwrap();
    match reports.get(&id) {
        Some(rs) => Ok(Json(json!({ "object": id, "stripes": rs.iter().map(report_json).collect::<Vec<_>>() }))),
        None => Err((StatusCode::NOT_FOUND, "尚无恢复报告".to_string())),
    }
}

async fn export_handler(State(s): State<Shared>, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let dir = engine::export_object(&s.store, id).map_err(err500)?;
    Ok(Json(json!({ "exported": dir.to_string_lossy() })))
}

#[derive(Deserialize)]
struct QuarantineReq {
    source: String,
    quarantined: bool,
}

async fn quarantine_handler(State(s): State<Shared>, Json(q): Json<QuarantineReq>) -> ApiResult<Json<Value>> {
    let affected = engine::set_quarantine(&s.store, &q.source, q.quarantined).map_err(err500)?;
    Ok(Json(json!({ "source": q.source, "quarantined": q.quarantined, "affected_stripes": affected })))
}

async fn demo_handler(State(s): State<Shared>) -> ApiResult<Json<Value>> {
    let id = engine::seed_demo(&s.store).map_err(err500)?;
    Ok(Json(json!({ "id": id })))
}
