//! Axum HTTP layer: object/stripe/shard health, candidate combinations,
//! recovery progress, manual source isolation and atomic export.

use std::sync::Arc;

use axum::{
    extract::{Path as AxumPath, State},
    http::StatusCode,
    response::{Html, IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde_json::json;

use crate::engine::{recover_object, RunOptions};
use crate::export::export_object;
use crate::model::StripeStatus;
use crate::store::Store;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
}

pub fn router(store: Arc<Store>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/state", get(state))
        .route("/api/objects/{id}/recover", post(recover))
        .route("/api/objects/{id}/isolate/{source}", post(isolate))
        .route("/api/objects/{id}/restore/{source}", post(restore))
        .route("/api/objects/{id}/export", post(do_export))
        .with_state(AppState { store })
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

fn err500<E: std::fmt::Display>(e: E) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": e.to_string() })),
    )
}

async fn state(State(app): State<AppState>) -> impl IntoResponse {
    match build_state(&app.store) {
        Ok(v) => Json(v).into_response(),
        Err(e) => err500(e).into_response(),
    }
}

async fn recover(
    State(app): State<AppState>,
    AxumPath(id): AxumPath<String>,
) -> impl IntoResponse {
    match recover_object(&app.store, &id, RunOptions::default()) {
        Ok(outcome) => match build_state(&app.store) {
            Ok(mut v) => {
                v["last_action"] = json!({
                    "kind": "recover",
                    "run_id": outcome.report.run_id,
                    "committed": outcome.report.committed,
                    "ambiguous": outcome.report.ambiguous,
                    "infeasible": outcome.report.infeasible,
                    "reused": outcome.report.reused,
                    "truncated": outcome.report.truncated,
                });
                Json(v).into_response()
            }
            Err(e) => err500(e).into_response(),
        },
        Err(e) => err500(e).into_response(),
    }
}

async fn isolate(
    State(app): State<AppState>,
    AxumPath((id, source)): AxumPath<(String, String)>,
) -> impl IntoResponse {
    if let Err(e) = app.store.isolate_source(&id, &source) {
        return err500(e).into_response();
    }
    // Recompute only the affected object immediately.
    let _ = recover_object(&app.store, &id, RunOptions::default());
    match build_state(&app.store) {
        Ok(mut v) => {
            v["last_action"] = json!({ "kind": "isolate", "source": source });
            Json(v).into_response()
        }
        Err(e) => err500(e).into_response(),
    }
}

async fn restore(
    State(app): State<AppState>,
    AxumPath((id, source)): AxumPath<(String, String)>,
) -> impl IntoResponse {
    if let Err(e) = app.store.restore_source(&id, &source) {
        return err500(e).into_response();
    }
    let _ = recover_object(&app.store, &id, RunOptions::default());
    match build_state(&app.store) {
        Ok(mut v) => {
            v["last_action"] = json!({ "kind": "restore", "source": source });
            Json(v).into_response()
        }
        Err(e) => err500(e).into_response(),
    }
}

async fn do_export(
    State(app): State<AppState>,
    AxumPath(id): AxumPath<String>,
) -> impl IntoResponse {
    match export_object(&app.store, &id, RunOptions::default()) {
        Ok(out) => match build_state(&app.store) {
            Ok(mut v) => {
                v["last_action"] = json!({
                    "kind": "export",
                    "dir": out.dir,
                    "manifest": out.manifest_path,
                    "object_digest": out.object_digest,
                    "bytes": out.bytes_len,
                });
                Json(v).into_response()
            }
            Err(e) => err500(e).into_response(),
        },
        Err(e) => err500(e).into_response(),
    }
}

#[allow(dead_code)]
fn status_str(s: StripeStatus) -> &'static str {
    match s {
        StripeStatus::Unique => "unique",
        StripeStatus::Ambiguous => "ambiguous",
        StripeStatus::Infeasible => "infeasible",
    }
}

fn build_state(store: &Store) -> Result<serde_json::Value, String> {
    let objects = store.list_objects().map_err(|e| e.to_string())?;
    let mut out_objects = Vec::new();

    for object_id in objects {
        let manifest = store
            .get_manifest(&object_id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("missing manifest {object_id}"))?;
        let receipts = store.list_receipts(&object_id).map_err(|e| e.to_string())?;
        let isolated = store.isolated_sources(&object_id).map_err(|e| e.to_string())?;
        let sources = store.all_sources(&object_id).map_err(|e| e.to_string())?;
        let committed = store.committed_stripes(&object_id).map_err(|e| e.to_string())?;

        // Shard-level health grid.
        let mut shard_health = Vec::new();
        for r in &receipts {
            let digest_ok = r.claimed_digest == r.actual_digest;
            let length_ok = r.length as usize == manifest.shard_len;
            let range_ok = (r.stripe as usize) < manifest.stripe_count
                && (r.shard as usize) < (manifest.k + manifest.m);
            let isolated_flag = isolated.iter().any(|s| s == &r.source);
            let health = if isolated_flag {
                "isolated"
            } else if !digest_ok {
                "corrupt"
            } else if !length_ok || !range_ok {
                "invalid"
            } else {
                "healthy"
            };
            shard_health.push(json!({
                "receipt_id": r.id,
                "stripe": r.stripe,
                "shard": r.shard,
                "generation": r.generation,
                "source": r.source,
                "health": health,
                "claimed_digest": r.claimed_digest,
                "actual_digest": r.actual_digest,
                "length": r.length,
            }));
        }

        // Latest run report (candidate combinations, evidence, progress).
        let last_run = store
            .last_run(&object_id)
            .map_err(|e| e.to_string())?
            .map(|(run_id, json_str)| {
                let parsed: serde_json::Value =
                    serde_json::from_str(&json_str).unwrap_or(json!({}));
                json!({ "run_id": run_id, "report": parsed })
            });

        let committed_status: Vec<serde_json::Value> = committed
            .iter()
            .map(|c| {
                json!({
                    "stripe": c.stripe,
                    "status": c.status,
                    "resolved": c.resolved,
                    "solution_count": c.solution_count,
                    "generation": c.generation,
                    "stripe_digest": c.stripe_digest,
                    "data_digest": c.data_digest,
                    "participant_ids": serde_json::from_str::<serde_json::Value>(&c.participant_ids).unwrap_or(json!([])),
                    "witness_ids": serde_json::from_str::<serde_json::Value>(&c.witness_ids).unwrap_or(json!([])),
                })
            })
            .collect();

        let export_path = store.latest_export(&object_id).ok().flatten();

        // Progress from latest run report.
        let mut progress = json!({});
        if let Some(run) = &last_run {
            let rep = &run["report"];
            let total = rep["total"].as_i64().unwrap_or(0);
            let committed_n = rep["committed"].as_i64().unwrap_or(0);
            let resolved_n = rep["stripes"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter(|s| s["resolved"].as_bool().unwrap_or(false))
                        .count() as i64
                })
                .unwrap_or(0);
            let done = committed_n + resolved_n;
            progress = json!({
                "total": total,
                "done": done,
                "reused": rep["reused"],
                "infeasible": rep["infeasible"],
                "ambiguous": rep["ambiguous"],
                "truncated": rep["truncated"],
                "percent": if total > 0 { done * 100 / total } else { 0 },
            });
        }

        out_objects.push(json!({
            "object_id": object_id,
            "manifest": {
                "codec_version": manifest.codec_version,
                "k": manifest.k,
                "m": manifest.m,
                "stripe_count": manifest.stripe_count,
                "shard_len": manifest.shard_len,
                "object_digest": manifest.object_digest,
                "generation": manifest.generation,
            },
            "sources": sources,
            "isolated_sources": isolated,
            "shards": shard_health,
            "committed": committed_status,
            "last_run": last_run,
            "progress": progress,
            "latest_export": export_path,
            "status_label": status_label(&manifest, &last_run),
        }));
    }

    Ok(json!({
        "title": "条带复原舱",
        "search_budget": crate::recovery::SEARCH_BUDGET,
        "objects": out_objects,
    }))
}

fn status_label(
    manifest: &crate::model::Manifest,
    last_run: &Option<serde_json::Value>,
) -> String {
    let Some(run) = last_run else {
        return "未复原".to_string();
    };
    let rep = &run["report"];
    if rep["infeasible"].as_i64().unwrap_or(0) > 0 {
        return "存在不可恢复 stripe".to_string();
    }
    let ambiguous = rep["ambiguous"].as_i64().unwrap_or(0);
    if ambiguous > 0 {
        if manifest.object_digest.is_some() {
            let all_resolved = rep["stripes"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter(|s| s["status"] == "ambiguous")
                        .all(|s| s["resolved"].as_bool().unwrap_or(false))
                })
                .unwrap_or(false);
            if all_resolved {
                return "多答案已由对象摘要裁决".to_string();
            }
        }
        return "存在多个可行答案".to_string();
    }
    "可唯一复原".to_string()
}

