use crate::export;
use crate::ingest;
use crate::recover;
use crate::store::Store;
use axum::{extract::State, http::StatusCode, response::{Html, IntoResponse}, routing::{get, post}, Json, Router};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
}

pub fn router(store: Store) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/healthz", get(|| async { "ok" }))
        .route("/api/state", get(state))
        .route("/api/ingest", post(ingest_now))
        .route("/api/recover", post(recover_now))
        .route("/api/export", post(export_now))
        .with_state(AppState { store: Arc::new(store) })
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

async fn state(State(app): State<AppState>) -> Result<Json<serde_json::Value>, AppError> {
    let store = app.store.clone();
    let data = tokio::task::spawn_blocking(move || -> rusqlite::Result<serde_json::Value> {
        let objects = store.object_views()?;
        let selected = objects.first().map(|object| object.id);
        let mut detail = json!(null);
        if let Some(object_pk) = selected {
            detail = json!({
                "object_pk": object_pk,
                "stripes": store.stripe_views(object_pk)?,
                "fragments": store.fragment_views(object_pk)?,
                "runs": store.run_views(object_pk)?,
                "reconstructions": store.reconstruction_views(object_pk)?,
                "sources": store.sources(object_pk)?
            });
        }
        Ok(json!({ "objects": objects, "selected": detail }))
    }).await.unwrap()?;
    Ok(Json(data))
}

async fn ingest_now(State(app): State<AppState>) -> Result<Json<serde_json::Value>, AppError> {
    let store = app.store.clone();
    let report = tokio::task::spawn_blocking(move || ingest::ingest_inbox(&store)).await.unwrap()?;
    Ok(Json(json!({"ok": true, "report": report})))
}

#[derive(Deserialize)]
struct RecoverRequest {
    object_id: String,
    generation: Option<i64>,
    #[serde(default)]
    isolated_sources: Vec<String>,
    #[serde(default = "default_budget")]
    budget: i64,
}

fn default_budget() -> i64 {
    4096
}

async fn recover_now(State(app): State<AppState>, Json(request): Json<RecoverRequest>) -> Result<Json<serde_json::Value>, AppError> {
    let store = app.store.clone();
    let status = tokio::task::spawn_blocking(move || {
        let objects = store.find_object(&request.object_id, request.generation).map_err(|e| std::io::Error::other(e.to_string()))?;
        let mut statuses = Vec::new();
        for object in objects {
            statuses.push(recover::recover_object(&store, &object, &request.isolated_sources, request.budget)?);
        }
        Ok::<Vec<String>, std::io::Error>(statuses)
    }).await.unwrap()?;
    Ok(Json(json!({"ok": true, "status": status})))
}

#[derive(Deserialize)]
struct ExportRequest {
    object_id: String,
    generation: Option<i64>,
}

async fn export_now(State(app): State<AppState>, Json(request): Json<ExportRequest>) -> Result<Json<serde_json::Value>, AppError> {
    let store = app.store.clone();
    let path = tokio::task::spawn_blocking(move || export::export_object(&store, &request.object_id, request.generation)).await.unwrap()?;
    Ok(Json(json!({"ok": true, "export_dir": path})))
}

struct AppError(StatusCode, String);

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        (self.0, Json(json!({"ok": false, "error": self.1}))).into_response()
    }
}

impl From<std::io::Error> for AppError {
    fn from(error: std::io::Error) -> Self {
        AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
    }
}

impl From<rusqlite::Error> for AppError {
    fn from(error: rusqlite::Error) -> Self {
        AppError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
    }
}
