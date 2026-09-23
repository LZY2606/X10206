//! Axum HTTP layer and the embedded operator page.

use crate::demo::import_demo;
use crate::export::export_object;
use crate::runner::{object_out_dir, recompute_after_quarantine, run_recovery};
use crate::store::Store;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, Json},
    routing::{get, post},
    Router,
};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;

pub struct AppState {
    pub store: Store,
    pub data_dir: PathBuf,
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/state", get(api_state))
        .route("/api/demo", post(api_demo))
        .route("/api/objects/{id}/recover", post(api_recover))
        .route("/api/objects/{id}/export", post(api_export))
        .route("/api/sources/{id}/quarantine", post(api_quarantine))
        .with_state(state)
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

fn build_state(state: &AppState) -> Value {
    let store = &state.store;
    let sources: Vec<Value> = store
        .list_sources()
        .into_iter()
        .map(|s| {
            json!({
                "id": s.id,
                "name": s.name,
                "quarantined": s.quarantined,
            })
        })
        .collect();

    let objects: Vec<Value> = store
        .list_objects()
        .into_iter()
        .map(|o| {
            let total = store.stripe_count(&o);
            let commits = store.list_commits(o.id);
            let stripes: Vec<Value> = (0..total)
                .map(|stripe| {
                    let analysis = store.load_analysis(o.id, stripe);
                    let committed = commits.iter().find(|c| c.stripe == stripe);
                    let (combos, excluded, feasible) = match &analysis {
                        Some(a) => (
                            a.combos.len(),
                            a.excluded.len(),
                            a.combos.iter().filter(|c| c.feasible).count(),
                        ),
                        None => (0, 0, 0),
                    };
                    json!({
                        "stripe": stripe,
                        "committed": committed.is_some(),
                        "digest": committed.map(|c| c.digest.clone()),
                        "combos": combos,
                        "feasible": feasible,
                        "excluded": excluded,
                        "analysis": analysis,
                    })
                })
                .collect();
            json!({
                "id": o.id,
                "name": o.name,
                "params": o.params,
                "total_len": o.total_len,
                "object_digest": o.object_digest,
                "stripe_total": total,
                "stripe_committed": commits.len(),
                "stripes": stripes,
            })
        })
        .collect();

    let current_export = std::fs::read_to_string(crate::export::exports_root(&state.data_dir).join("CURRENT"))
        .unwrap_or_default();

    json!({
        "objects": objects,
        "sources": sources,
        "current_export": current_export,
    })
}

async fn api_state(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(build_state(&state))
}

async fn api_demo(State(state): State<Arc<AppState>>) -> Json<Value> {
    let id = import_demo(&state.store);
    Json(json!({ "object_id": id }))
}

async fn api_recover(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, (StatusCode, String)> {
    if state.store.get_object(id).is_none() {
        return Err((StatusCode::NOT_FOUND, "对象不存在".to_string()));
    }
    let report = run_recovery(&state.store, id, &object_out_dir(&state.data_dir, id), None);
    Ok(Json(serde_json::to_value(report).unwrap()))
}

async fn api_export(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, (StatusCode, String)> {
    match export_object(&state.store, id, &state.data_dir) {
        Ok(r) => Ok(Json(serde_json::to_value(r).unwrap())),
        Err(e) => Err((StatusCode::CONFLICT, e)),
    }
}

async fn api_quarantine(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let source = state
        .store
        .list_sources()
        .into_iter()
        .find(|s| s.id == id)
        .ok_or((StatusCode::NOT_FOUND, "来源不存在".to_string()))?;
    let new_state = !source.quarantined;
    state.store.set_quarantine(id, new_state);
    let affected = if new_state {
        recompute_after_quarantine(&state.store, id, &state.data_dir)
    } else {
        Vec::new()
    };
    Ok(Json(json!({
        "source_id": id,
        "quarantined": new_state,
        "recomputed_objects": affected,
    })))
}

const INDEX_HTML: &str = r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>条带复原舱</title>
<style>
  body { font-family: -apple-system, "PingFang SC", sans-serif; margin: 24px; background: #0f1420; color: #dde3f0; }
  h1 { color: #7fd4ff; }
  h2 { color: #9fe8c1; margin-top: 28px; }
  h3 { color: #c9b8ff; }
  button { background: #1f6feb; color: #fff; border: 0; border-radius: 6px; padding: 6px 14px; cursor: pointer; margin: 2px; }
  button.warn { background: #b3541e; }
  button:disabled { background: #444; }
  table { border-collapse: collapse; margin: 8px 0; width: 100%; }
  th, td { border: 1px solid #2a3550; padding: 4px 8px; font-size: 13px; text-align: left; vertical-align: top; }
  th { background: #1a2338; }
  .ok { color: #5fd68a; } .bad { color: #ff7b72; } .dim { color: #8b94a8; }
  .bar { background: #223; border-radius: 4px; height: 12px; width: 220px; display: inline-block; vertical-align: middle; }
  .bar > div { background: #2ea043; height: 12px; border-radius: 4px; }
  code { color: #ffd479; font-size: 12px; }
  .card { background: #151c2e; border: 1px solid #26304a; border-radius: 8px; padding: 12px 16px; margin: 10px 0; }
</style>
</head>
<body>
<h1>条带复原舱</h1>
<p class="dim">离线对象碎片审阅: manifest / data shard / parity shard / 每块摘要导入, 版本化编码参数重建, 按 stripe 提交。</p>
<div>
  <button onclick="loadDemo()">导入演示数据</button>
  <button onclick="refresh()">刷新</button>
  <span id="msg" class="dim"></span>
</div>
<div id="sources"></div>
<div id="objects"></div>
<script>
async function api(path, method) {
  const r = await fetch(path, { method: method || 'GET' });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.error || body.message || JSON.stringify(body) || r.statusText);
  return body;
}
function say(m) { document.getElementById('msg').textContent = m; }
async function loadDemo() {
  try { const r = await api('/api/demo', 'POST'); say('已导入演示对象 #' + r.object_id); refresh(); }
  catch (e) { say('导入失败: ' + e.message); }
}
async function recover(id) {
  try {
    const r = await api('/api/objects/' + id + '/recover', 'POST');
    const done = r.stripes.filter(s => s.status !== 'failed').length;
    say('恢复完成: ' + done + '/' + r.stripes.length + ' 个 stripe 已提交');
    refresh();
  } catch (e) { say('恢复失败: ' + e.message); }
}
async function exportObj(id) {
  try { const r = await api('/api/objects/' + id + '/export', 'POST'); say('导出成功: ' + r.dir + '/' + r.file); refresh(); }
  catch (e) { say('导出失败: ' + e.message); }
}
async function quarantine(id) {
  try {
    const r = await api('/api/sources/' + id + '/quarantine', 'POST');
    say((r.quarantined ? '已隔离来源 #' + id : '已解除隔离 #' + id) +
        (r.recomputed_objects.length ? ', 重算对象: ' + r.recomputed_objects.join(',') : ''));
    refresh();
  } catch (e) { say('操作失败: ' + e.message); }
}
function comboRow(c) {
  const parts = c.participants.map(p => '#' + p.shard_id + '(idx' + p.idx + ',' + p.source + ')').join(' ');
  const rec = (c.recomputed || []).map(r => 'idx' + r[0] + ':' + r[1].slice(0, 10) + '…').join(' ');
  return '<tr><td>#' + c.no + '</td><td>' + c.generation + '</td>' +
    '<td>' + (c.feasible ? '<span class="ok">可行</span>' : '<span class="bad">不可行</span>') + '</td>' +
    '<td>' + parts + '</td><td>' + (c.output_digest ? '<code>' + c.output_digest.slice(0, 16) + '…</code>' : '-') + '</td>' +
    '<td>' + rec + '</td><td>' + c.reason + (c.difference ? '<br><span class="dim">' + c.difference + '</span>' : '') + '</td></tr>';
}
function render(st) {
  let sh = '<h2>来源健康度</h2>';
  if (!st.sources.length) sh += '<p class="dim">尚无来源。</p>';
  else {
    sh += '<table><tr><th>ID</th><th>来源</th><th>状态</th><th>操作</th></tr>';
    for (const s of st.sources) {
      sh += '<tr><td>' + s.id + '</td><td>' + s.name + '</td><td>' +
        (s.quarantined ? '<span class="bad">已隔离</span>' : '<span class="ok">正常</span>') +
        '</td><td><button class="warn" onclick="quarantine(' + s.id + ')">' +
        (s.quarantined ? '解除隔离' : '隔离并重算') + '</button></td></tr>';
    }
    sh += '</table>';
  }
  document.getElementById('sources').innerHTML = sh;

  let oh = '<h2>对象与 stripe</h2>';
  if (st.current_export) oh += '<p class="dim">当前导出: <code>' + st.current_export + '</code></p>';
  if (!st.objects.length) oh += '<p class="dim">尚无对象, 点击“导入演示数据”。</p>';
  for (const o of st.objects) {
    const pct = o.stripe_total ? Math.round(100 * o.stripe_committed / o.stripe_total) : 0;
    oh += '<div class="card"><h3>对象 #' + o.id + ' ' + o.name +
      ' <span class="dim">k=' + o.params.k + ' m=' + o.params.m + ' shard=' + o.params.shard_size +
      'B 编码版本 v' + o.params.version + ' 长度=' + o.total_len + 'B</span></h3>' +
      '<p>恢复进度: <span class="bar"><div style="width:' + pct + '%"></div></span> ' +
      o.stripe_committed + '/' + o.stripe_total +
      ' <button onclick="recover(' + o.id + ')">执行/续跑恢复</button>' +
      ' <button onclick="exportObj(' + o.id + ')">导出</button></p>' +
      '<p class="dim">对象摘要: <code>' + (o.object_digest || '').slice(0, 24) + '…</code></p>';
    for (const s of o.stripes) {
      oh += '<div class="card"><b>stripe ' + s.stripe + '</b> ' +
        (s.committed ? '<span class="ok">已提交</span> <code>' + (s.digest || '').slice(0, 16) + '…</code>'
                     : '<span class="bad">未提交</span>') +
        ' <span class="dim">候选组合 ' + s.combos + ' (可行 ' + s.feasible + '), 排除证据 ' + s.excluded + '</span>';
      if (s.analysis) {
        if (s.analysis.excluded.length) {
          oh += '<table><tr><th colspan="5">被排除的损坏证据</th></tr><tr><th>shard</th><th>idx</th><th>gen</th><th>来源</th><th>原因</th></tr>';
          for (const e of s.analysis.excluded)
            oh += '<tr><td>#' + e.shard_id + '</td><td>' + e.idx + '</td><td>' + e.generation + '</td><td>' + e.source + '</td><td>' + e.reason + '</td></tr>';
          oh += '</table>';
        }
        if (s.analysis.combos.length) {
          oh += '<table><tr><th>组合</th><th>gen</th><th>状态</th><th>参与 shard</th><th>输出摘要</th><th>重算摘要</th><th>说明</th></tr>';
          for (const c of s.analysis.combos) oh += comboRow(c);
          oh += '</table>';
        }
      }
      oh += '</div>';
    }
    oh += '</div>';
  }
  document.getElementById('objects').innerHTML = oh;
}
async function refresh() {
  try { render(await api('/api/state')); }
  catch (e) { say('状态获取失败: ' + e.message); }
}
refresh();
</script>
</body>
</html>"#;
