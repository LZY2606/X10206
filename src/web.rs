//! Axum Web 层：REST API + 内嵌单页（对象 / stripe / shard 健康度 / 候选组合 / 恢复进度）。

use crate::engine::Engine;
use crate::exporter::export_outcome;
use crate::importer::import_bundle;
use crate::model::*;
use crate::recovery::{load_manifest, run_recovery};
use crate::store::Store;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Json};
use axum::routing::{get, post};
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub data_dir: Arc<std::path::PathBuf>,
}

pub async fn serve(store: Store, data_dir: std::path::PathBuf, addr: SocketAddr) {
    let state = AppState {
        store,
        data_dir: Arc::new(data_dir),
    };
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

pub fn router(state: AppState) -> axum::Router {
    axum::Router::new()
        .route("/", get(index))
        .route("/api/objects", get(list_objects))
        .route("/api/objects/:id", get(get_object))
        .route("/api/objects/:id/isolate", post(isolate))
        .route("/api/objects/:id/recover", post(recover))
        .route("/api/objects/:id/export", post(export_obj))
        .route("/api/import", post(import_dir))
        .route("/api/demo", post(seed_demo))
        .with_state(state)
}

pub(crate) async fn index() -> Html<&'static str> {
    Html(include_str!("static/index.html"))
}

pub(crate) struct AppError(String, StatusCode);
impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        (
            self.1,
            Json(serde_json::json!({"error": self.0})),
        )
            .into_response()
    }
}
pub(crate) fn bad(e: impl std::fmt::Display) -> AppError {
    AppError(e.to_string(), StatusCode::BAD_REQUEST)
}

pub(crate) async fn list_objects(State(st): State<AppState>) -> Result<Json<serde_json::Value>, AppError> {
    let ids = st.store.list_objects().map_err(bad)?;
    let mut items = Vec::new();
    for id in ids {
        let m = load_manifest(&st.store, &id).map_err(bad)?;
        let outcomes = st.store.list_outcomes(&id).map(|v| v.len()).unwrap_or(0);
        let exports = st.store.list_exports(&id).map(|v| v.len()).unwrap_or(0);
        items.push(serde_json::json!({
            "object_id": id,
            "field": m.field,
            "codec_version": m.codec_version,
            "k": m.k, "m": m.m,
            "stripe_count": m.stripe_count,
            "stripe_length": m.stripe_length,
            "object_length": m.object_length,
            "has_object_digest": m.object_digest.is_some(),
            "outcomes": outcomes,
            "exports": exports,
        }));
    }
    Ok(Json(serde_json::json!({"objects": items})))
}

pub(crate) fn build_detail(store: &Store, id: &str) -> Result<serde_json::Value, String> {
    let manifest = load_manifest(store, id)?;
    let persisted = store.list_fragments(id)?;
    let isolated = store.isolated_sources(id);
    let engine = Engine::new(&manifest)?;

    let mut all_sources = BTreeSet::new();
    let mut frags: Vec<FragmentInput> = Vec::new();
    let mut frag_json = Vec::new();
    for p in &persisted {
        all_sources.insert(p.source.clone());
        let bytes = store.read_raw(&p.rel_path)?;
        let state = match &p.claimed_digest {
            None => DigestState::NoDigest,
            Some(c) => {
                if c.eq_ignore_ascii_case(&p.recomputed_digest) {
                    DigestState::Verified
                } else {
                    DigestState::DigestMismatch
                }
            }
        };
        frag_json.push(serde_json::json!({
            "fragment_id": p.fragment_id,
            "stripe": p.stripe, "shard": p.shard,
            "generation": p.generation, "source": p.source,
            "length": bytes.len(),
            "expected_length": manifest.stripe_length,
            "length_ok": bytes.len() == manifest.stripe_length,
            "digest_state": state,
            "claimed_digest": p.claimed_digest,
            "recomputed_digest": p.recomputed_digest,
            "isolated": isolated.contains(&p.source),
        }));
        frags.push(FragmentInput {
            fragment_id: p.fragment_id.clone(),
            object_id: p.object_id.clone(),
            stripe: p.stripe as usize,
            shard: p.shard as usize,
            generation: p.generation as u64,
            source: p.source.clone(),
            bytes,
            claimed_digest: p.claimed_digest.clone(),
            received_at: p.received_at.clone(),
        });
    }

    let mut by_stripe: Vec<Vec<FragmentInput>> = vec![Vec::new(); manifest.stripe_count];
    for f in frags {
        if f.stripe < manifest.stripe_count {
            by_stripe[f.stripe].push(f);
        }
    }
    let analyses: Vec<StripeAnalysis> = by_stripe
        .iter()
        .enumerate()
        .map(|(s, fs)| engine.analyze_stripe(id, s, manifest.stripe_length, fs, &isolated))
        .collect();
    let outcomes = store.list_outcomes(id).unwrap_or_default();
    let exports = store.list_exports(id).unwrap_or_default();

    Ok(serde_json::json!({
        "manifest": manifest,
        "fragments": frag_json,
        "sources": all_sources,
        "isolated_sources": isolated,
        "stripes": analyses,
        "outcomes": outcomes.iter().filter_map(|j| serde_json::from_str::<serde_json::Value>(j).ok()).collect::<Vec<_>>(),
        "exports": exports.iter().filter_map(|j| serde_json::from_str::<serde_json::Value>(j).ok()).collect::<Vec<_>>(),
    }))
}

pub(crate) async fn get_object(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let detail = build_detail(&st.store, &id).map_err(bad)?;
    Ok(Json(detail))
}

#[derive(serde::Deserialize)]
pub(crate) struct IsolateReq {
    sources: Vec<String>,
}
pub(crate) async fn isolate(
    State(st): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<IsolateReq>,
) -> Result<Json<serde_json::Value>, AppError> {
    let set: BTreeSet<String> = req.sources.into_iter().collect();
    st.store.set_isolated_sources(&id, &set).map_err(bad)?;
    let detail = build_detail(&st.store, &id).map_err(bad)?;
    Ok(Json(detail))
}

#[derive(serde::Deserialize, Default)]
pub(crate) struct RecoverReq {
    #[serde(default = "default_true")]
    reuse: bool,
}
fn default_true() -> bool {
    true
}
pub(crate) async fn recover(
    State(st): State<AppState>,
    Path(id): Path<String>,
    req: Option<Json<RecoverReq>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let reuse = req.map(|j| j.reuse).unwrap_or(true);
    let store = st.store.clone();
    let oid = id.clone();
    let progress = tokio::task::spawn_blocking(move || run_recovery(&store, &oid, reuse))
        .await
        .map_err(|e| bad(e))?
        .map_err(bad)?;
    let detail = build_detail(&st.store, &id).map_err(bad)?;
    Ok(Json(serde_json::json!({"progress": progress, "detail": detail})))
}

#[derive(serde::Deserialize, Default)]
pub(crate) struct ExportReq {
    outcome_id: Option<String>,
}
pub(crate) async fn export_obj(
    State(st): State<AppState>,
    Path(id): Path<String>,
    req: Option<Json<ExportReq>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let store = st.store.clone();
    let oid = id.clone();
    let outc = req.and_then(|Json(body)| body.outcome_id);
    let result = tokio::task::spawn_blocking(move || {
        export_outcome(&store, &oid, outc.as_deref())
    })
    .await
    .map_err(|e| bad(e))?
    .map_err(bad)?;
    Ok(Json(serde_json::json!({
        "export_id": result.export_id,
        "outcome_id": result.outcome_id,
        "dir": result.dir.display().to_string(),
    })))
}

#[derive(serde::Deserialize)]
pub(crate) struct ImportReq {
    dir: String,
}
pub(crate) async fn import_dir(
    State(st): State<AppState>,
    Json(req): Json<ImportReq>,
) -> Result<Json<serde_json::Value>, AppError> {
    let store = st.store.clone();
    let path = std::path::PathBuf::from(&req.dir);
    let report = tokio::task::spawn_blocking(move || import_bundle(&store, &path))
        .await
        .map_err(|e| bad(e))?
        .map_err(bad)?;
    Ok(Json(serde_json::json!({
        "object_id": report.object_id,
        "fragment_count": report.fragment_count,
        "sources": report.sources,
        "warnings": report.warnings,
    })))
}

pub(crate) async fn seed_demo(State(st): State<AppState>) -> Result<Json<serde_json::Value>, AppError> {
    let store = st.store.clone();
    let data = st.data_dir.clone();
    let report = tokio::task::spawn_blocking(move || crate::demo::seed_demo(&store, &data))
        .await
        .map_err(|e| bad(e))?
        .map_err(bad)?;
    Ok(Json(serde_json::json!({
        "object_id": report.object_id,
        "fragment_count": report.fragment_count,
        "sources": report.sources,
        "warnings": report.warnings,
    })))
}
