use std::sync::{Arc, Mutex};

use axum::{
    Router,
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
};
use serde::Deserialize;

use crate::engine::{RecoveryOptions, recover_object};
use crate::export::export_object;
use crate::model::{ObjectStatus, StatusResponse};
use crate::store::{Storage, latest_report};

#[derive(Clone)]
pub struct AppState {
    storage: Arc<Mutex<Storage>>,
}

#[derive(Deserialize)]
struct ObjectQuery {
    object_id: String,
}

#[derive(Deserialize)]
struct RecoverQuery {
    object_id: String,
    #[serde(default)]
    isolate: Vec<String>,
    #[serde(default = "default_budget")]
    budget: usize,
}

fn default_budget() -> usize {
    1024
}

pub fn router(storage: Storage) -> Router {
    let state = AppState {
        storage: Arc::new(Mutex::new(storage)),
    };
    Router::new()
        .route("/", get(index))
        .route("/api/status", get(status))
        .route("/api/recover", post(recover))
        .route("/api/export", post(export))
        .with_state(state)
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

async fn status(State(state): State<AppState>) -> axum::Json<StatusResponse> {
    let storage = state.storage.lock().unwrap();
    let manifests = storage.manifests().unwrap();
    let mut objects = Vec::new();
    for manifest in manifests {
        let fragments = storage.fragments(&manifest.object_id).unwrap();
        let latest_run = latest_report(&storage, &manifest.object_id).unwrap();
        objects.push(ObjectStatus {
            object_id: manifest.object_id.clone(),
            manifest,
            fragments,
            latest_run,
        });
    }
    axum::Json(StatusResponse {
        objects,
        data_dir: storage.root().to_string_lossy().to_string(),
    })
}

async fn recover(Query(query): Query<RecoverQuery>, State(state): State<AppState>) -> Result<axum::Json<serde_json::Value>, ApiError> {
    let (manifest, report) = {
        let storage = state.storage.lock().unwrap();
        let manifest = storage
            .manifests()?
            .into_iter()
            .find(|item| item.object_id == query.object_id)
            .ok_or_else(|| ApiError::not_found("object not found"))?;
        let options = RecoveryOptions {
            isolated_sources: query.isolate,
            search_budget: query.budget.max(1),
            before_commit: None,
        };
        let report = recover_object(&storage, &manifest, &options)?;
        (manifest, report)
    };
    Ok(axum::Json(serde_json::json!({
        "manifest": manifest,
        "report": report,
    })))
}

async fn export(Query(query): Query<ObjectQuery>, State(state): State<AppState>) -> Result<axum::Json<serde_json::Value>, ApiError> {
    let path = {
        let storage = state.storage.lock().unwrap();
        let manifest = storage
            .manifests()?
            .into_iter()
            .find(|item| item.object_id == query.object_id)
            .ok_or_else(|| ApiError::not_found("object not found"))?;
        export_object(&storage, &manifest)?
    };
    Ok(axum::Json(serde_json::json!({ "path": path })))
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn not_found(message: &str) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.to_string(),
        }
    }
}

impl From<std::io::Error> for ApiError {
    fn from(value: std::io::Error) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: value.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (
            self.status,
            axum::Json(serde_json::json!({ "error": self.message })),
        )
            .into_response()
    }
}
