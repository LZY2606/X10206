//! Axum web UI: objects, stripes, shard health, candidate combos, progress,
//! quarantine + recompute, and export.

use crate::model::*;
use crate::recover::{self, RecoveryConfig};
use crate::store::Store;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, Redirect};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;

pub struct AppState {
    pub store: Store,
    pub export_dir: PathBuf,
    pub config: RecoveryConfig,
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/objects/{id}", get(object_page))
        .route("/objects/{id}/recover", post(recover_now))
        .route("/objects/{id}/export", post(export_now))
        .route("/sources/{name}/quarantine", post(quarantine))
        .route("/sources/{name}/release", post(release))
        .route("/api/import/manifest", post(import_manifest))
        .route("/api/import/shard", post(import_shard))
        .with_state(state)
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn page(title: &str, body: &str) -> Html<String> {
    Html(format!(
        r#"<!doctype html><html lang="zh"><head><meta charset="utf-8">
<title>{t} - 条带复原舱</title>
<style>
body{{font-family:system-ui,sans-serif;margin:2rem;background:#0f1420;color:#dde3ee}}
h1,h2,h3{{color:#7fd4ff}}
table{{border-collapse:collapse;margin:1rem 0;width:100%}}
th,td{{border:1px solid #2a3550;padding:4px 8px;text-align:left;font-size:13px;vertical-align:top}}
th{{background:#1a2338}}
code{{color:#ffd479;font-size:12px;word-break:break-all}}
.ok{{color:#7fe0a3}} .bad{{color:#ff8f8f}} .warn{{color:#ffd479}}
button{{background:#274b73;color:#fff;border:0;padding:4px 12px;border-radius:4px;cursor:pointer}}
form{{display:inline}} .card{{background:#161d2e;border:1px solid #2a3550;border-radius:8px;padding:1rem;margin:1rem 0}}
a{{color:#7fd4ff}}
</style></head><body>
<h1>条带复原舱</h1>
<nav><a href="/">对象总览</a></nav>
{b}
</body></html>"#,
        t = esc(title),
        b = body
    ))
}

fn health_badge(h: &ShardHealth) -> &'static str {
    match h {
        ShardHealth::Ok => "<span class=ok>完好</span>",
        ShardHealth::LengthMismatch => "<span class=bad>长度不符</span>",
        ShardHealth::DigestMismatch => "<span class=bad>摘要不符</span>",
        ShardHealth::Quarantined => "<span class=warn>已隔离</span>",
    }
}

async fn index(State(st): State<Arc<AppState>>) -> Html<String> {
    let mut body = String::new();
    let objects = st.store.list_objects().unwrap_or_default();
    body.push_str("<div class=card><h2>对象</h2><table><tr><th>对象</th><th>编码</th><th>stripe 进度</th><th>分片健康</th><th>可行解</th><th>操作</th></tr>");
    for m in &objects {
        let states = st
            .store
            .stripe_states(&m.object_id, m.stripe_count())
            .unwrap_or_default();
        let committed = states.iter().filter(|s| s.status == "committed").count();
        let shards = st.store.shards_for(&m.object_id).unwrap_or_default();
        let bad = shards.iter().filter(|s| s.health != ShardHealth::Ok).count();
        let (solutions, _) = recover::assemble_solutions(&m, &states, st.config.budget);
        let health = if bad == 0 {
            format!("<span class=ok>{} 全部完好</span>", shards.len())
        } else {
            format!("<span class=warn>{} 完好 / {} 异常</span>", shards.len() - bad, bad)
        };
        body.push_str(&format!(
            "<tr><td><a href=\"/objects/{id}\">{id}</a></td>\
             <td>v{ver} k={k} m={m_} 条带={ss}B</td>\
             <td>{committed}/{total} 已提交</td><td>{health}</td>\
             <td>{nsol}</td>\
             <td><form method=post action=\"/objects/{id}/recover\"><button>恢复/续跑</button></form> \
             <form method=post action=\"/objects/{id}/export\"><button>导出</button></form></td></tr>",
            id = esc(&m.object_id),
            ver = m.encoding.version,
            k = m.encoding.k,
            m_ = m.encoding.m,
            ss = m.encoding.stripe_size,
            committed = committed,
            total = m.stripe_count(),
            health = health,
            nsol = solutions.len(),
        ));
    }
    body.push_str("</table></div>");

    body.push_str("<div class=card><h2>接收来源</h2><table><tr><th>来源</th><th>状态</th><th>操作</th></tr>");
    for (source, quarantined) in st.store.sources().unwrap_or_default() {
        let (badge, action, label) = if quarantined {
            ("<span class=warn>已隔离</span>", "release", "解除隔离")
        } else {
            ("<span class=ok>正常</span>", "quarantine", "隔离并重算")
        };
        body.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td><form method=post action=\"/sources/{}/{}\"><button>{}</button></form></td></tr>",
            esc(&source), badge, esc(&source), action, label
        ));
    }
    body.push_str("</table></div>");
    page("对象总览", &body)
}

async fn object_page(State(st): State<Arc<AppState>>, Path(id): Path<String>) -> Html<String> {
    let m = match st.store.get_manifest(&id) {
        Ok(Some(m)) => m,
        _ => return page("未找到", "<p class=bad>对象不存在</p>"),
    };
    let mut body = String::new();
    body.push_str(&format!(
        "<div class=card><h2>对象 {}</h2><p>编码 v{}: k={} m={} 条带大小={}B 每片={}B 对象长度={}B<br>\
         对象摘要: <code>{}</code></p></div>",
        esc(&m.object_id),
        m.encoding.version, m.encoding.k, m.encoding.m, m.encoding.stripe_size,
        m.shard_bytes, m.object_length,
        esc(m.object_digest.as_deref().unwrap_or("(未提供)")),
    ));

    // Shard health
    body.push_str("<div class=card><h3>分片健康度</h3><table><tr><th>编号</th><th>generation</th><th>来源</th><th>长度</th><th>摘要</th><th>状态</th></tr>");
    for s in st.store.shards_for(&id).unwrap_or_default() {
        body.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td></tr>",
            s.idx, s.generation, esc(&s.source), s.bytes.len(),
            esc(&s.digest[..16.min(s.digest.len())]),
            health_badge(&s.health)
        ));
    }
    body.push_str("</table></div>");

    // Stripes
    let states = st.store.stripe_states(&id, m.stripe_count()).unwrap_or_default();
    body.push_str("<div class=card><h3>Stripe 恢复明细</h3>");
    for st in &states {
        let badge = if st.status == "committed" {
            "<span class=ok>已提交</span>"
        } else {
            "<span class=warn>待恢复</span>"
        };
        body.push_str(&format!("<h4>stripe {} — {} (候选组合 {} 个)</h4>", st.stripe_no, badge, st.alternatives.len()));
        for (i, alt) in st.alternatives.iter().enumerate() {
            let floor = if alt.at_recovery_floor { " <span class=warn>[恰好达到恢复下限]</span>" } else { "" };
            let mixed = if alt.generations.len() > 1 { " <span class=warn>[generation 混杂]</span>" } else { "" };
            body.push_str(&format!(
                "<p>候选 #{}: 行摘要 <code>{}</code>{}{} 等价选择 {} 个<br>参与分片: ",
                i, &alt.row_digest[..16], floor, mixed, alt.equivalent_sets
            ));
            for p in &alt.participants {
                body.push_str(&format!(
                    "<code>#{} g{} {}</code> ", p.idx, p.generation, esc(&p.source)
                ));
            }
            if !alt.excluded.is_empty() {
                body.push_str("<br>排除的损坏证据:<ul>");
                for e in &alt.excluded {
                    body.push_str(&format!(
                        "<li>分片#{} (g{}, {}): {}</li>",
                        e.idx, e.generation, esc(&e.source), esc(&e.reason)
                    ));
                }
                body.push_str("</ul>");
            }
            body.push_str("</p>");
        }
    }
    body.push_str("</div>");

    // Solutions
    let (solutions, exhausted) = recover::assemble_solutions(&m, &states, st.config.budget);
    body.push_str("<div class=card><h3>可行重建</h3>");
    if exhausted {
        body.push_str("<p class=warn>搜索预算已用尽, 结果可能不完整</p>");
    }
    if solutions.is_empty() {
        body.push_str("<p class=warn>暂无可行解</p>");
    }
    for s in &solutions {
        let check = match s.digest_matches_manifest {
            Some(true) => "<span class=ok>对象摘要校验通过</span>",
            Some(false) => "<span class=bad>对象摘要不符</span>",
            None => "<span class=warn>无对象摘要可校验</span>",
        };
        body.push_str(&format!(
            "<p>解 #{}: 重算摘要 <code>{}</code> {}<br>差异: {}</p>",
            s.rank, esc(&s.object_digest), check, esc(&s.diff_summary)
        ));
    }
    body.push_str("</div>");
    page(&format!("对象 {}", id), &body)
}

async fn recover_now(State(st): State<Arc<AppState>>, Path(id): Path<String>) -> Redirect {
    let _ = recover::recover_object(&st.store, &id, &st.config);
    Redirect::to(&format!("/objects/{}", id))
}

async fn export_now(State(st): State<Arc<AppState>>, Path(id): Path<String>) -> Redirect {
    let _ = crate::export::export_object(&st.store, &id, 0, &st.export_dir);
    Redirect::to(&format!("/objects/{}", id))
}

async fn quarantine(State(st): State<Arc<AppState>>, Path(name): Path<String>) -> Redirect {
    let _ = recover::quarantine_and_recompute(&st.store, &name, &st.config);
    Redirect::to("/")
}

async fn release(State(st): State<Arc<AppState>>, Path(name): Path<String>) -> Redirect {
    let _ = st.store.unquarantine_source(&name);
    Redirect::to("/")
}

async fn import_manifest(
    State(st): State<Arc<AppState>>,
    Json(m): Json<Manifest>,
) -> Result<Redirect, (StatusCode, String)> {
    m.validate().map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    st.store
        .put_manifest(&m)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Redirect::to("/"))
}

#[derive(Deserialize)]
struct ShardUpload {
    object_id: String,
    idx: usize,
    generation: u64,
    source: String,
    data_hex: String,
}

async fn import_shard(
    State(st): State<Arc<AppState>>,
    Json(u): Json<ShardUpload>,
) -> Result<Redirect, (StatusCode, String)> {
    let bytes = hex::decode(&u.data_hex).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    st.store
        .add_shard(&u.object_id, u.idx, u.generation, &u.source, &bytes)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Redirect::to("/"))
}

// Silence unused-import warning for Form when forms grow later.
#[allow(dead_code)]
fn _unused(_: Form<()>) {}
