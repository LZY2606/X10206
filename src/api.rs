//! Axum 路由：页面状态聚合、人工隔离来源、恢复、导出。

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::{
    extract::{Path as AxumPath, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::db::Storage;
use crate::engine::enumerate_stripe;
use crate::export::export_object;
use crate::recovery::{
    self, audit_committed, clean_temp_dir, run_recovery, Fault, FaultKind, FsSink,
};
use crate::types::DEFAULT_SEARCH_BUDGET;

#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<Mutex<Storage>>,
    pub data_root: PathBuf,
}

#[derive(Debug, Deserialize)]
pub struct RecoverQuery {
    pub fault: Option<String>,
    pub after: Option<u64>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/state", get(get_state))
        .route("/api/sources/:id/isolate", post(isolate_source))
        .route("/api/recover", post(recover_all))
        .route("/api/objects/:id/export", post(do_export))
        .route("/api/health", get(|| async { Json(json!({"ok": true})) }))
        .with_state(state)
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

#[derive(Serialize)]
struct StateResponse {
    objects: Vec<serde_json::Value>,
    sources: Vec<serde_json::Value>,
    last_run: Option<serde_json::Value>,
    search_budget: u64,
}

async fn get_state(State(state): State<AppState>) -> impl IntoResponse {
    let mut st = state.storage.lock().unwrap();
    let objects = st.list_objects().expect("objects");
    let mut out_objects = Vec::new();
    for object in &objects {
        let stripes = st.list_stripes(object.id).expect("stripes");
        let mut out_stripes = Vec::new();
        for stripe in &stripes {
            let enum_result =
                enumerate_stripe(&mut st, stripe, object.id, DEFAULT_SEARCH_BUDGET);
            let solutions = st.list_solutions(stripe.id).expect("sols");
            let evidence = st.evidence_for_stripe(stripe.id).expect("ev");
            out_stripes.push(json!({
                "id": stripe.id,
                "stripe_idx": stripe.stripe_idx,
                "stripe_len": stripe.stripe_len,
                "status": stripe.status,
                "tier": stripe.tier,
                "max_generation": stripe.max_generation,
                "output_digest": stripe.output_digest,
                "search_combos": stripe.search_combos,
                "budget_exceeded": stripe.budget_exceeded,
                "candidate_count": enum_result.candidates.len(),
                "present_positions": enum_result.present_positions,
                "latest_positions": enum_result.latest_positions,
                "candidates": enum_result.candidates,
                "enumerated_solutions": enum_result.solutions.iter().map(|s| json!({
                    "tier": match s.tier {
                        crate::types::SolutionTier::Trusted => "trusted",
                        crate::types::SolutionTier::Degraded => "degraded",
                    },
                    "generation": s.generation,
                    "output_digest": s.output_digest,
                    "participant_ids": s.participant_ids,
                    "excluded_ids": s.excluded_ids,
                })).collect::<Vec<_>>(),
                "stored_solutions": solutions.iter().map(|s| json!({
                    "id": s.id,
                    "tier": s.tier,
                    "generation": s.generation,
                    "output_digest": s.output_digest,
                    "chosen_subset": s.chosen_subset,
                })).collect::<Vec<_>>(),
                "evidence": evidence.iter().map(|e| json!({
                    "id": e.id, "kind": e.kind, "detail": e.detail, "fragment_id": e.fragment_id
                })).collect::<Vec<_>>(),
            }));
        }
        let frags = st.list_all_fragments(object.id).expect("frags");
        let sources = st.list_sources().expect("sources");
        let source_name = |id: i64| {
            sources.iter().find(|s| s.id == id).map(|s| s.name.clone()).unwrap_or_default()
        };
        out_objects.push(json!({
            "id": object.id,
            "object_id": object.object_id,
            "coding_version": object.coding_version,
            "object_digest": object.object_digest,
            "declared_len": object.declared_len,
            "stripe_count": object.stripe_count,
            "status": object.status,
            "stripes": out_stripes,
            "fragments": frags.iter().map(|f| json!({
                "id": f.id,
                "source": source_name(f.source_id),
                "source_id": f.source_id,
                "stripe": f.stripe_idx,
                "shard": f.shard_idx,
                "generation": f.generation,
                "declared_length": f.declared_length,
                "actual_length": f.actual_length,
                "digest_declared": f.digest_declared,
                "digest_actual": f.digest_actual,
                "health": f.health,
            })).collect::<Vec<_>>(),
        }));
    }
    let sources = st.list_sources().expect("sources");
    let out_sources: Vec<_> = sources
        .iter()
        .map(|s| json!({"id": s.id, "name": s.name, "path": s.path, "isolated": s.isolated}))
        .collect();
    let last_run = st.last_run().expect("run").map(|r| {
        json!({
            "id": r.id, "started_at": r.started_at, "finished_at": r.finished_at,
            "status": r.status, "stripes_total": r.stripes_total,
            "stripes_done": r.stripes_done, "fault_inject": r.fault_inject
        })
    });
    Json(StateResponse {
        objects: out_objects,
        sources: out_sources,
        last_run,
        search_budget: DEFAULT_SEARCH_BUDGET,
    })
}

#[derive(Deserialize)]
struct IsolateBody {
    isolated: bool,
}

async fn isolate_source(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<i64>,
    Json(body): Json<IsolateBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut st = state.storage.lock().unwrap();
    st.set_source_isolated(id, body.isolated).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("更新隔离状态失败: {e}"))
    })?;
    // 隔离/取消隔离都会使受影响 stripe 失效，需要重新计算。
    let reset = st.reset_stripes_for_source(id).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    })?;
    recovery::finalize_objects(&mut st);
    Ok(Json(json!({"reset_stripe_ids": reset, "isolated": body.isolated})))
}

async fn recover_all(
    State(state): State<AppState>,
    Query(q): Query<RecoverQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    clean_temp_dir(&state.data_root).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let fault = q.fault.as_deref().map(|kind| Fault {
        kind: match kind {
            "crash" => FaultKind::Crash,
            _ => FaultKind::DiskWrite,
        },
        stripe_seen: 0,
        fault_after: q.after.unwrap_or(0),
    });

    let result = {
        let mut st = state.storage.lock().unwrap();
        let mut sink =
            FsSink::new(&state.data_root).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        audit_committed(&mut st, &sink);
        run_recovery(&mut st, &mut sink, fault)
    };
    Ok(Json(json!({
        "run_id": result.run_id,
        "total": result.total,
        "done": result.done,
        "status": result.status,
        "fault": result.fault,
    })))
}

async fn do_export(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let path = {
        let mut st = state.storage.lock().unwrap();
        let sink =
            FsSink::new(&state.data_root).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        export_object(&mut st, &sink, &state.data_root, id)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
    };
    Ok(Json(json!({"export_dir": path.to_string_lossy()})))
}
