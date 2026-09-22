//! Axum web layer: health aggregation, candidate display, source isolation,
//! recompute and export controls. Recovery runs on a blocking task because the
//! store is synchronous.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::{
    extract::{Path as AxumPath, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;

use crate::db::Store;
use crate::exporter::export_object;
use crate::importer::scan_and_import_all;
use crate::recovery::{run_object_recovery, CrashPoint};

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
}

pub fn router(store: Arc<Store>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/api/import", post(api_import))
        .route("/api/objects/{id}/recover", post(recover))
        .route("/api/objects/{id}/export", post(do_export))
        .route("/api/objects/{id}/reset", post(reset))
        .route("/api/sources/{name}/isolate", post(isolate))
        .route("/api/sources/{name}/restore", post(restore))
        .with_state(AppState { store })
}

async fn index() -> Html<&'static str> {
    Html(crate::assets::INDEX_HTML)
}

async fn api_import(State(st): State<AppState>) -> Response {
    let store = st.store.clone();
    let result = tokio::task::spawn_blocking(move || scan_and_import_all(&store)).await;
    match result {
        Ok(Ok(reports)) => Json(serde_json::json!({"ok": true, "sources": reports})).into_response(),
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn recover(AxumPath(id): AxumPath<String>, State(st): State<AppState>) -> Response {
    run_blocking(st.store, move |store| {
        let report = run_object_recovery(store, &id, CrashPoint::None)?;
        Ok(serde_json::to_value(&report.status)
            .unwrap_or(serde_json::json!(report.status)))
    })
    .await
}

async fn reset(AxumPath(id): AxumPath<String>, State(st): State<AppState>) -> Response {
    run_blocking(st.store, move |store| {
        store.reset_object_state(&id)?;
        Ok(serde_json::json!({"reset": id}))
    })
    .await
}

async fn do_export(AxumPath(id): AxumPath<String>, State(st): State<AppState>) -> Response {
    run_blocking(st.store, move |store| {
        let obj = store
            .get_object(&id)?
            .ok_or_else(|| anyhow::anyhow!("unknown object"))?;
        let dir = export_object(store, &obj)?;
        Ok(serde_json::json!({"export_dir": dir.to_string_lossy()}))
    })
    .await
}

async fn isolate(AxumPath(name): AxumPath<String>, State(st): State<AppState>) -> Response {
    let store = st.store.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        store.set_isolated(&name, true, "manually isolated by operator")?;
        // Recompute every object touched by this source; prior committed stripes
        // for those fragments are invalidated.
        let objects = store.list_objects()?;
        let mut affected = Vec::new();
        for obj in objects {
            let stripes = store.invalidate_stripes_for_source(&obj.id, &name)?;
            if !stripes.is_empty() {
                run_object_recovery(&store, &obj.id, CrashPoint::None)?;
                affected.push(serde_json::json!({"object_id": obj.id, "stripes": stripes}));
            }
        }
        Ok(serde_json::json!({"ok": true, "isolated": name, "affected": affected}))
    })
    .await;
    flatten(result)
}

async fn restore(AxumPath(name): AxumPath<String>, State(st): State<AppState>) -> Response {
    let store = st.store.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        store.set_isolated(&name, false, "")?;
        Ok(serde_json::json!({"ok": true, "restored": name}))
    })
    .await;
    flatten(result)
}

async fn run_blocking<F>(store: Arc<Store>, f: F) -> Response
where
    F: FnOnce(&Store) -> anyhow::Result<serde_json::Value> + Send + 'static,
{
    let result = tokio::task::spawn_blocking(move || f(&store)).await;
    flatten(result)
}

fn flatten(
    result: Result<anyhow::Result<serde_json::Value>, tokio::task::JoinError>,
) -> Response {
    match result {
        Ok(Ok(v)) => Json(serde_json::json!({"ok": true, "result": v})).into_response(),
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Serialize)]
struct Health {
    objects: Vec<ObjectHealth>,
    sources: Vec<SourceHealth>,
}

#[derive(Serialize)]
struct SourceHealth {
    name: String,
    isolated: bool,
    note: String,
    fragments: usize,
}

#[derive(Serialize)]
struct ObjectHealth {
    id: String,
    scheme: String,
    version: u32,
    k: usize,
    n: usize,
    stripe_count: usize,
    shard_len: usize,
    data_len: usize,
    manifest_digest: String,
    run_status: String,
    run_detail: String,
    export_dir: Option<String>,
    progress_pct: u8,
    stripes: Vec<StripeHealth>,
    evidence_count: usize,
}

#[derive(Serialize)]
struct StripeHealth {
    stripe: usize,
    status: String,
    generation: Option<i64>,
    detail: String,
    reused: bool,
    shard_health: Vec<ShardHealth>,
    solutions: Vec<SolutionHealth>,
}

#[derive(Serialize)]
struct ShardHealth {
    index: usize,
    candidates: usize,
    clean: usize,
    corrupt: usize,
    wrong_length: usize,
    unverified: usize,
    generations: Vec<i64>,
    sources: Vec<String>,
}

#[derive(Serialize)]
struct SolutionHealth {
    rank: i64,
    generation: i64,
    reconstructed_digest: String,
    combo: serde_json::Value,
    excluded: serde_json::Value,
    chosen: bool,
}

async fn health(State(st): State<AppState>) -> Json<Health> {
    let store = st.store.as_ref();
    let sources_raw = store.list_sources().unwrap_or_default();
    let isolated_names: BTreeSet<String> = sources_raw
        .iter()
        .filter(|(_, iso, _)| *iso)
        .map(|(n, _, _)| n.clone())
        .collect();
    let mut sources = Vec::new();
    for (name, isolated, note) in sources_raw {
        let count = store
            .list_objects()
            .unwrap_or_default()
            .iter()
            .map(|o| store.all_fragments(&o.id).unwrap_or_default())
            .flatten()
            .filter(|f| f.source == name)
            .count();
        sources.push(SourceHealth { name, isolated, note, fragments: count });
    }

    let mut objects = Vec::new();
    for obj in store.list_objects().unwrap_or_default() {
        let evid = store.evidence_for_object(&obj.id).unwrap_or_default();
        let commits = store.list_stripes(&obj.id).unwrap_or_default();
        let mut stripes = Vec::new();
        let mut committed_count = 0u8;
        for stripe_idx in 0..obj.stripe_count {
            let frags = store.fragments_for_stripe(&obj.id, stripe_idx).unwrap_or_default();
            let n = obj.data_shards + obj.parity_shards;
            let mut shard_health = Vec::new();
            for idx in 0..n {
                let group: Vec<_> = frags.iter().filter(|f| f.shard_index == idx).collect();
                let mut gens: BTreeSet<i64> = BTreeSet::new();
                let mut srcs: BTreeSet<String> = BTreeSet::new();
                let mut clean = 0;
                let mut corrupt = 0;
                let mut wrong_length = 0;
                let mut unverified = 0;
                for f in &group {
                    gens.insert(f.generation as i64);
                    srcs.insert(f.source.clone());
                    let isolated_frag = isolated_names.contains(&f.source);
                    if isolated_frag {
                        continue;
                    }
                    if f.length != obj.shard_len {
                        wrong_length += 1;
                    } else if f.digest_verified == 0 {
                        if f.declared_digest.is_some() {
                            corrupt += 1;
                        } else {
                            unverified += 1;
                        }
                    } else {
                        clean += 1;
                    }
                }
                shard_health.push(ShardHealth {
                    index: idx,
                    candidates: group.len(),
                    clean,
                    corrupt,
                    wrong_length,
                    unverified,
                    generations: gens.into_iter().collect(),
                    sources: srcs.into_iter().collect(),
                });
            }

            let commit = commits.iter().find(|c| c.stripe == stripe_idx);
            let status = commit.map(|c| c.status.clone()).unwrap_or_else(|| "pending".into());
            if status == "committed" {
                committed_count += 1;
            }
            let sols = store.list_solutions(&obj.id, stripe_idx).unwrap_or_default();
            let chosen_id = commit.and_then(|c| c.chosen_solution_id);
            let solutions = sols
                .iter()
                .map(|s| SolutionHealth {
                    rank: s.rank_order,
                    generation: s.gen,
                    reconstructed_digest: s.reconstructed_digest.clone(),
                    combo: serde_json::from_str(&s.combo_json).unwrap_or(serde_json::json!([])),
                    excluded: serde_json::from_str(&s.excluded_json)
                        .unwrap_or(serde_json::json!([])),
                    chosen: Some(s.id) == chosen_id,
                })
                .collect();
            stripes.push(StripeHealth {
                stripe: stripe_idx,
                status,
                generation: commit.and_then(|c| c.generation.map(|g| g as i64)),
                detail: commit.map(|c| c.detail.clone()).unwrap_or_default(),
                reused: commit.map(|c| c.detail.contains("reused")).unwrap_or(false),
                shard_health,
                solutions,
            });
        }
        let progress = if obj.stripe_count == 0 {
            100
        } else {
            (committed_count as usize * 100 / obj.stripe_count) as u8
        };
        objects.push(ObjectHealth {
            id: obj.id,
            scheme: obj.scheme,
            version: obj.version,
            k: obj.data_shards,
            n: obj.data_shards + obj.parity_shards,
            stripe_count: obj.stripe_count,
            shard_len: obj.shard_len,
            data_len: obj.data_len,
            manifest_digest: obj.object_digest_hex,
            run_status: obj.run_status,
            run_detail: obj.run_detail,
            export_dir: obj.export_dir,
            progress_pct: progress,
            stripes,
            evidence_count: evid.len(),
        });
    }

    Json(Health { objects, sources })
}

/// Allow downloading an exported object bytes if the caller wants to verify.
pub async fn serve_export_file(path: &std::path::Path) -> Response {
    match tokio::fs::read(path).await {
        Ok(bytes) => (
            [(header::CONTENT_TYPE, "application/octet-stream")],
            bytes,
        )
            .into_response(),
        Err(e) => (StatusCode::NOT_FOUND, e.to_string()).into_response(),
    }
}
