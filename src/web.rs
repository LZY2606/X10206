//! Axum web UI: objects, stripes, shard health, candidate combinations and
//! recovery progress; supports manual source isolation and forced re-run.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, Redirect};
use axum::routing::{get, post};
use axum::{Form, Router};
use rusqlite::params;
use serde::Deserialize;

use crate::db::Db;
use crate::importer;
use crate::model::short;
use crate::query;
use crate::recovery;
use crate::store::{BlobStore, FailInjection};
use crate::exporter;

pub struct AppState {
    pub db: Arc<Db>,
    pub store: Arc<BlobStore>,
    pub data_dir: PathBuf,
    pub failures: Arc<FailInjection>,
}

pub async fn serve(
    addr: SocketAddr,
    db: Arc<Db>,
    store: Arc<BlobStore>,
    data_dir: PathBuf,
    failures: Arc<FailInjection>,
) {
    let state = Arc::new(AppState { db, store, data_dir, failures });
    let app = Router::new()
        .route("/", get(index))
        .route("/objects/:id", get(object_page))
        .route("/objects/:id/recover", post(recover_now))
        .route("/objects/:id/isolate", post(isolate))
        .route("/objects/:id/unisolate", post(unisolate))
        .route("/objects/:id/import", post(import_path))
        .route("/objects/:id/export", post(export_now))
        .route("/import-root", post(import_root))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

fn layout(title: &str, body: String) -> String {
    format!(
        r#"<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root {{ --bg:#0f1420; --panel:#171f30; --ink:#e8edf7; --mut:#9fb0c9; --acc:#5ec8ff;
  --good:#46d39a; --bad:#ff6b6b; --warn:#ffce5a; --neu:#8aa0c0; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; font-family:-apple-system,"PingFang SC","Microsoft Yahei",sans-serif;
  background:var(--bg); color:var(--ink); line-height:1.5; }}
header {{ padding:18px 28px; border-bottom:1px solid #243049; display:flex;
  align-items:baseline; gap:14px; flex-wrap:wrap; }}
header h1 {{ font-size:20px; margin:0; }}
header .sub {{ color:var(--mut); font-size:13px; }}
main {{ padding:24px 28px; max-width:1180px; margin:0 auto; }}
a {{ color:var(--acc); text-decoration:none; }}
a:hover {{ text-decoration:underline; }}
.panel {{ background:var(--panel); border:1px solid #243049; border-radius:12px;
  padding:18px 20px; margin-bottom:18px; }}
.panel h2 {{ font-size:15px; margin:0 0 12px; }}
table {{ border-collapse:collapse; width:100%; font-size:13px; }}
th,td {{ text-align:left; padding:7px 10px; border-bottom:1px solid #233049;
  vertical-align:top; }}
th {{ color:var(--mut); font-weight:600; }}
.pill {{ display:inline-block; padding:2px 9px; border-radius:999px; font-size:12px; }}
.pill.good {{ background:rgba(70,211,154,.16); color:var(--good); }}
.pill.bad {{ background:rgba(255,107,107,.16); color:var(--bad); }}
.pill.warn {{ background:rgba(255,206,90,.16); color:var(--warn); }}
.pill.neu {{ background:rgba(138,160,192,.16); color:var(--neu); }}
.muted {{ color:var(--mut); }}
code,.mono {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; }}
button, .btn {{ background:var(--acc); color:#06222f; border:0; border-radius:8px;
  padding:7px 14px; font-size:13px; cursor:pointer; }}
button.ghost {{ background:#26334d; color:var(--ink); }}
button.danger {{ background:#42273a; color:#ffb4b4; }}
.row {{ display:flex; gap:10px; flex-wrap:wrap; align-items:center; }}
details {{ margin:8px 0; }}
summary {{ cursor:pointer; color:var(--acc); }}
input[type=text] {{ background:#0c1220; border:1px solid #2c3a57; color:var(--ink);
  border-radius:8px; padding:7px 10px; min-width:320px; }}
.progress {{ height:10px; background:#0c1220; border-radius:6px; overflow:hidden;
  border:1px solid #243049; }}
.progress > div {{ height:100%; background:linear-gradient(90deg,var(--good),var(--acc)); }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
  gap:12px; }}
.card {{ background:#121a2a; border:1px solid #243049; border-radius:10px; padding:14px; }}
.card .n {{ font-size:24px; font-weight:700; }}
.flash {{ background:rgba(94,200,255,.12); border:1px solid #2c5d7a; color:#bfe8ff;
  padding:10px 14px; border-radius:8px; margin-bottom:14px; font-size:13px; }}
.tag {{ font-size:11px; color:var(--mut); border:1px solid #2c3a57; padding:1px 6px;
  border-radius:6px; margin-right:4px; }}
</style></head><body>
<header><h1>条带复原舱</h1>
<span class="sub">离线对象碎片审阅 · Cauchy Reed-Solomon / GF(256) · 分条带提交</span></header>
<main>{body}</main></body></html>"#,
        title = title,
        body = body
    )
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn pill(health: &str) -> &'static str {
    match health {
        "good" | "recovered" | "verified" => "good",
        "corrupt" | "below_threshold" | "failed" | "unrecoverable" => "bad",
        "ambiguous" | "budget_exhausted" | "partial" | "unverified" => "warn",
        _ => "neu",
    }
}

async fn index(State(st): State<Arc<AppState>>) -> Html<String> {
    let objs = query::list_objects(&st.db);
    let mut rows = String::new();
    if objs.is_empty() {
        rows.push_str(r#"<tr><td colspan="8" class="muted">尚未导入任何对象。使用下方表单导入离线目录。</td></tr>"#);
    }
    for o in &objs {
        let total = o.total_stripes.max(1);
        let pct = (o.recovered * 100) / total;
        let iso = if o.isolated_sources.is_empty() {
            "<span class='muted'>无</span>".to_string()
        } else {
            o.isolated_sources.iter().map(|s| format!("<span class='tag'>{}</span>", esc(s))).collect()
        };
        rows.push_str(&format!(
            r#"<tr>
<td><a href="/objects/{id}"><code>{id}</code></a></td>
<td class="mono">{gens:?}</td>
<td>{total}</td>
<td><span class="pill good">{rec}</span> <span class="pill warn">{amb}</span> <span class="pill bad">{below}</span> <span class="pill bad">{fail}</span></td>
<td style="min-width:160px"><div class="progress"><div style="width:{pct}%"></div></div>
<div class="muted">{pct}% 已恢复（{rec}/{total}）</div></td>
<td>{iso}</td>
<td>{check}</td>
<td><form method="post" action="/objects/{id}/recover"><button class="ghost">重算全部</button></form></td>
</tr>"#,
            id = esc(&o.object_id),
            gens = o.generations,
            total = o.total_stripes,
            rec = o.recovered,
            amb = o.ambiguous,
            below = o.below_threshold + o.budget_exhausted,
            fail = o.failed + o.not_attempted,
            pct = pct,
            iso = iso,
            check = if o.latest_check_status.is_empty() {
                "<span class='muted'>—</span>".to_string()
            } else {
                format!("<span class='pill {}'>{}</span> <span class='muted'>{}</span>",
                    pill(&o.latest_check_status), esc(&o.latest_check_status), esc(&o.latest_check_note))
            },
        ));
    }

    let body = format!(
        r#"<div class="panel">
<h2>对象总览</h2>
<table><thead><tr><th>对象</th><th>generations</th><th>stripe 数</th><th>健康度</th>
<th>恢复进度</th><th>已隔离来源</th><th>对象校验</th><th></th></tr></thead>
<tbody>{rows}</tbody></table>
</div>
<div class="panel"><h2>导入离线来源目录</h2>
<form method="post" action="/import-root" class="row">
<input type="text" name="path" placeholder="包含 manifest 与 sA-B.bin 的目录绝对路径">
<button>导入原始碎片</button>
</form><p class="muted">原始字节会被内容寻址保存并记录接收来源；原目录保持只读，不做任何改动。</p>
</div>"#,
        rows = rows
    );
    Html(layout("条带复原舱", body))
}

#[derive(Deserialize)]
struct ImportRootForm {
    path: String,
}

async fn import_root(
    State(st): State<Arc<AppState>>,
    Form(form): Form<ImportRootForm>,
) -> Result<Redirect, (StatusCode, String)> {
    let dir = PathBuf::from(&form.path);
    let report = tokio::task::block_in_place(|| {
        importer::import_dir(&st.db, &st.store, &dir)
    })
    .map_err(|e| (StatusCode::BAD_REQUEST, format!("导入失败：{}", e)))?;
    let id = report.object_id.clone();
    let _ = tokio::task::block_in_place(|| {
        recovery::run_recovery(
            &st.db,
            &st.store,
            &id,
            recovery::RecoveryOptions { trigger: "import".into(), force: true },
        )
    });
    Ok(Redirect::to(&format!("/objects/{}?msg=imported", urlencoding_replace(&id))))
}

fn urlencoding_replace(s: &str) -> String {
    s.replace(' ', "%20")
}

async fn import_path(
    State(st): State<Arc<AppState>>,
    Path(id): Path<String>,
    Form(form): Form<ImportRootForm>,
) -> Result<Redirect, (StatusCode, String)> {
    let dir = PathBuf::from(&form.path);
    let report = tokio::task::block_in_place(|| {
        importer::import_dir(&st.db, &st.store, &dir)
    })
    .map_err(|e| (StatusCode::BAD_REQUEST, format!("导入失败：{}", e)))?;
    if report.object_id != id {
        return Err((StatusCode::CONFLICT, format!("该目录属于另一个对象：{}", report.object_id)));
    }
    let _ = tokio::task::block_in_place(|| {
        recovery::run_recovery(
            &st.db,
            &st.store,
            &id,
            recovery::RecoveryOptions { trigger: "reimport".into(), force: true },
        )
    });
    Ok(Redirect::to(&format!("/objects/{}?msg=imported", urlencoding_replace(&id))))
}

#[derive(Deserialize)]
struct RecoverForm {
    force: Option<String>,
}

async fn recover_now(
    State(st): State<Arc<AppState>>,
    Path(id): Path<String>,
    Form(form): Form<RecoverForm>,
) -> Redirect {
    let force = form.force.as_deref() == Some("1");
    let id2 = id.clone();
    tokio::task::block_in_place(|| {
        recovery::run_recovery(
            &st.db,
            &st.store,
            &id2,
            recovery::RecoveryOptions {
                trigger: if force { "manual_force" } else { "manual" }.into(),
                force,
            },
        )
    });
    Redirect::to(&format!("/objects/{}?msg=recovered", urlencoding_replace(&id)))
}

#[derive(Deserialize)]
struct SourceForm {
    source: String,
}

async fn isolate(
    State(st): State<Arc<AppState>>,
    Path(id): Path<String>,
    Form(form): Form<SourceForm>,
) -> Redirect {
    {
        let conn = st.db.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO isolated_sources(object_id, source, isolated_at)
             VALUES (?1,?2,?3)",
            params![id, form.source, crate::db::now_ms()],
        )
        .unwrap();
    }
    let id2 = id.clone();
    tokio::task::block_in_place(|| {
        recovery::run_recovery(
            &st.db,
            &st.store,
            &id2,
            recovery::RecoveryOptions { trigger: "isolate".into(), force: true },
        )
    });
    Redirect::to(&format!("/objects/{}?msg=isolated", urlencoding_replace(&id)))
}

async fn unisolate(
    State(st): State<Arc<AppState>>,
    Path(id): Path<String>,
    Form(form): Form<SourceForm>,
) -> Redirect {
    {
        let conn = st.db.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM isolated_sources WHERE object_id=?1 AND source=?2",
            params![id, form.source],
        )
        .unwrap();
    }
    let id2 = id.clone();
    tokio::task::block_in_place(|| {
        recovery::run_recovery(
            &st.db,
            &st.store,
            &id2,
            recovery::RecoveryOptions { trigger: "unisolate".into(), force: true },
        )
    });
    Redirect::to(&format!("/objects/{}?msg=unisolated", urlencoding_replace(&id)))
}

async fn export_now(
    State(st): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Redirect, (StatusCode, String)> {
    let export_root = st.data_dir.join("exports");
    let res = tokio::task::block_in_place(|| {
        exporter::export_object(&st.db, &st.store, &export_root, &id)
    })
    .map_err(|e| (StatusCode::BAD_REQUEST, format!("导出失败：{}", e)))?;
    Ok(Redirect::to(&format!(
        "/objects/{}?msg=exported&dir={}",
        urlencoding_replace(&id),
        urlencoding_replace(&res.target_dir.to_string_lossy())
    )))
}

#[derive(Deserialize)]
struct MsgQuery {
    msg: Option<String>,
    dir: Option<String>,
}

async fn object_page(
    State(st): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(q): Query<MsgQuery>,
) -> Result<Html<String>, StatusCode> {
    let objs = query::list_objects(&st.db);
    let obj = objs.into_iter().find(|o| o.object_id == id).ok_or(StatusCode::NOT_FOUND)?;
    let stripes = query::list_stripes(&st.db, &id);
    let health = query::shard_health(&st.db, &id);
    let gens = query::list_generations(&st.db, &id);
    let sources = query::all_sources(&st.db, &id);
    let checks = query::latest_object_checks(&st.db, &id);

    let flash = match q.msg.as_deref() {
        Some("imported") => "<div class='flash'>导入完成，已自动重算受影响 stripe。</div>".to_string(),
        Some("recovered") => "<div class='flash'>恢复轮次已提交；仅完整验证的 stripe 被复用。</div>".to_string(),
        Some("isolated") => "<div class='flash'>来源已隔离，受影响 stripe 已强制重算。</div>".to_string(),
        Some("unisolated") => "<div class='flash'>已解除隔离并重新枚举候选。</div>".to_string(),
        Some("exported") => format!("<div class='flash'>导出完成（原子切换）：<code>{}</code></div>",
            esc(q.dir.as_deref().unwrap_or(""))),
        _ => String::new(),
    };

    let mut gen_cards = String::new();
    for (gen, k, m, size, count) in gens {
        gen_cards.push_str(&format!(
            "<div class='card'><div class='muted'>generation</div><div class='n'>G{}</div>
             <div class='muted'>k={} m={} shard_size={}</div><div>{} 个 stripe</div></div>",
            gen, k, m, size, count
        ));
    }

    let total = obj.total_stripes.max(1);
    let pct = obj.recovered * 100 / total;
    let stats = format!(
        r#"<div class="grid">
<div class="card"><div class="muted">已恢复</div><div class="n">{}</div></div>
<div class="card"><div class="muted">多个可行解</div><div class="n">{}</div></div>
<div class="card"><div class="muted">低于下限/预算</div><div class="n">{}</div></div>
<div class="card"><div class="muted">失败</div><div class="n">{}</div></div>
<div class="card"><div class="muted">进度</div><div class="n">{}%</div>
<div class="progress" style="margin-top:8px"><div style="width:{}%"></div></div></div>
</div>"#,
        obj.recovered, obj.ambiguous,
        obj.below_threshold + obj.budget_exhausted,
        obj.failed + obj.not_attempted, pct, pct
    );

    let mut check_rows = String::new();
    for c in &checks {
        check_rows.push_str(&format!(
            r#"<tr><td>G{}</td><td><span class="pill {p}">{}</span></td>
<td>{}/{}</td><td class="mono">{}</td><td class="mono">{}</td><td>{}</td></tr>"#,
            c.generation, c.status, c.matching_stripes, c.stripe_count,
            short(&c.object_digest_expected), short(&c.object_digest_actual), esc(&c.note),
            p = pill(&c.status)
        ));
    }

    let mut stripe_rows = String::new();
    for srow in &stripes {
        let amb = if srow.ambiguous { " <span class='pill warn'>差异已保留</span>" } else { "" };
        let gen = srow.generation.map(|g| format!("G{}", g)).unwrap_or_else(|| "—".into());
        stripe_rows.push_str(&format!(
            r#"<tr><td><a href="{anchor}">{hashidx}</a></td><td>{gen}</td>
<td><span class="pill {p}">{label}</span>{amb}</td>
<td>{oc} 个可行解</td><td class="muted">{note}</td></tr>"#,
            gen = gen,
            p = pill(&srow.status),
            label = esc(&srow.status_label),
            amb = amb,
            oc = srow.outcome_count,
            note = esc(&srow.note),
            anchor = format!("#stripe-{}", srow.stripe_index),
            hashidx = format!("#{}", srow.stripe_index)
        ));
    }

    // Shard health grouped by generation/stripe.
    let mut health_rows = String::new();
    for h in &health {
        let iso = if h.isolated { " <span class='pill neu'>已隔离</span>" } else { "" };
        let src = h.sources.iter().map(|s| format!("<span class='tag'>{}</span>", esc(s))).collect::<String>();
        health_rows.push_str(&format!(
            r#"<tr><td>G{} s{}-{}</td><td><span class="pill {p}">{}</span>{iso}</td>
<td>{}</td><td class="mono">{}</td><td class="mono">{}</td>
<td>{src}</td></tr>"#,
            h.generation, h.stripe_index, h.shard_index,
            esc(&h.health_label), h.byte_length, short(&h.blob_hash),
            short(&h.expected_digest),
            p = pill(&h.health), iso = iso, src = src
        ));
    }

    // Candidate combinations per stripe.
    let mut combo_panels = String::new();
    for srow in &stripes {
        let outcomes = query::outcomes_for_stripe(&st.db, &id, srow.stripe_index);
        let mut oc_html = String::new();
        for o in &outcomes {
            let active = if o.active { " <span class='pill good'>当前采用</span>" } else { "" };
            let trust = if !o.feasible {
                "<span class='pill bad'>不可行</span>"
            } else if o.all_digests_match {
                "<span class='pill good'>摘要全部吻合</span>"
            } else {
                "<span class='pill warn'>摘要冲突</span>"
            };
            let mut diff = String::new();
            if !o.differences.is_empty() {
                diff.push_str("<ul>");
                for d in &o.differences {
                    diff.push_str(&format!("<li>{}</li>", esc(d)));
                }
                diff.push_str("</ul>");
            }
            let mut block_rows = String::new();
            for b in &o.blocks {
                let role = if b.rebuilt {
                    "<span class='pill neu'>重建</span>"
                } else {
                    "<span class='pill good'>参与计算</span>"
                };
                let m = if b.matches_expected {
                    "<span class='pill good'>吻合</span>"
                } else {
                    "<span class='pill bad'>不一致</span>"
                };
                block_rows.push_str(&format!(
                    r#"<tr><td>{shard}</td><td>{role}</td><td class="mono">{frag}</td>
<td class="mono">{dig}</td><td>{m}</td></tr>"#,
                    shard = b.shard_index,
                    frag = b.fragment_id.map(|f| format!("#{}", f)).unwrap_or_else(|| "—".into()),
                    dig = short(&b.recomputed_digest),
                    role = role,
                    m = m
                ));
            }
            let mut ev_rows = String::new();
            for e in &o.evidence {
                let (label, cls) = match e.role.as_str() {
                    "participant" => ("参与计算", "good"),
                    "rebuilt" => ("重建缺口", "neu"),
                    "excluded_corrupt" => ("排除：损坏证据", "bad"),
                    _ => ("排除：本组合未选用", "warn"),
                };
                let reason = if e.reason_label.is_empty() {
                    String::new()
                } else {
                    format!(" — {}", esc(&e.reason_label))
                };
                ev_rows.push_str(&format!(
                    r#"<tr><td>{}</td><td><span class="pill {cls}">{label}</span></td>
<td>{}</td><td class="muted">{src}{reason}</td></tr>"#,
                    e.shard_index,
                    e.fragment_id.map(|f| format!("#{}", f)).unwrap_or_else(|| "—".into()),
                    cls = cls, label = label,
                    src = esc(&e.receipt_source), reason = reason
                ));
            }
            oc_html.push_str(&format!(
                r#"<div class="card" style="margin-bottom:10px">
<div class="row"><strong>G{gen} 候选组合 rank {rank}</strong>{active}{trust}</div>
<div class="muted">stripe 摘要 <code>{digest}</code></div>
{diff}
<details><summary>参与/重建块与重新计算的摘要（{nb}）</summary>
<table><thead><tr><th>shard</th><th>角色</th><th>块摘要</th><th>重算摘要</th><th>校验</th></tr></thead>
<tbody>{blocks}</tbody></table></details>
<details><summary>排除与参与证据（{ne}）</summary>
<table><thead><tr><th>shard</th><th>角色</th><th>fragment</th><th>来源/原因</th></tr></thead>
<tbody>{ev}</tbody></table></details>
</div>"#,
                gen = o.generation, rank = o.rank, active = active, trust = trust,
                digest = short(&o.stripe_digest), diff = diff,
                nb = o.blocks.len(), blocks = block_rows,
                ne = o.evidence.len(), ev = ev_rows
            ));
        }
        if oc_html.is_empty() {
            oc_html = "<span class='muted'>尚无尝试记录。</span>".to_string();
        }
        combo_panels.push_str(&format!(
            r#"<div class="panel" id="stripe-{i}"><h2>stripe {hashmark}</h2>{oc}</div>"#,
            i = srow.stripe_index,
            hashmark = format!("#{}", srow.stripe_index),
            oc = oc_html
        ));
    }

    // Source isolation panel.
    let isolated: std::collections::BTreeSet<String> =
        obj.isolated_sources.iter().cloned().collect();
    let mut source_html = String::new();
    for src in &sources {
        let on = isolated.contains(src);
        source_html.push_str(&format!(
            r#"<div class="row" style="justify-content:space-between;margin:6px 0">
<span><span class="tag">{src}</span>{state}</span>
<span>{form}</span></div>"#,
            src = esc(src),
            state = if on { "<span class='pill warn'>隔离中</span>" } else { "<span class='pill good'>参与中</span>" },
            form = if on {
                format!(r#"<form method="post" action="/objects/{}/unisolate">
<input type="hidden" name="source" value="{}"><button class="ghost">解除隔离并重算</button></form>"#,
                    esc(&id), esc(src))
            } else {
                format!(r#"<form method="post" action="/objects/{}/isolate">
<input type="hidden" name="source" value="{}"><button class="danger">隔离来源并重算</button></form>"#,
                    esc(&id), esc(src))
            }
        ));
    }
    if sources.is_empty() {
        source_html = "<span class='muted'>无已记录来源。</span>".to_string();
    }

    let body = format!(
        r#"{flash}
<div class="row" style="justify-content:space-between">
<h2 style="margin:0"><code>{id}</code></h2>
<div class="row">
<form method="post" action="/objects/{id}/recover">
<button>按当前隔离状态重算</button></form>
<form method="post" action="/objects/{id}/recover">
<input type="hidden" name="force" value="1">
<button class="ghost">强制重算（忽略复用）</button></form>
<form method="post" action="/objects/{id}/export">
<button class="ghost">原子导出到新目录</button></form>
<a class="btn" href="/" style="background:#26334d;color:var(--ink)">返回</a>
</div></div>
<div class="panel" style="margin-top:14px">{stats}</div>
<div class="panel"><h2>编码参数（按 generation）</h2><div class="grid">{gen_cards}</div></div>
<div class="panel"><h2>对象校验（不只是“成功”状态）</h2>
<table><thead><tr><th>generation</th><th>结论</th><th>stripe 吻合</th>
<th>期望对象摘要</th><th>重算对象摘要</th><th>说明</th></tr></thead>
<tbody>{check_rows}</tbody></table></div>
<div class="panel"><h2>stripe 健康度与恢复进度</h2>
<table><thead><tr><th>stripe</th><th>采用 generation</th><th>状态</th>
<th>候选组合</th><th>说明</th></tr></thead><tbody>{stripe_rows}</tbody></table></div>
<div class="panel"><h2>shard 健康度（重复编号 / 损坏 / generation 混杂全部可见）</h2>
<table><thead><tr><th>位置</th><th>健康</th><th>长度</th><th>内容摘要</th>
<th>manifest 摘要</th><th>接收来源</th></tr></thead>
<tbody>{health_rows}</tbody></table></div>
<div class="panel"><h2>人工隔离来源后重算受影响 stripe</h2>{source_html}
<form method="post" action="/objects/{id}/import" style="margin-top:12px">
<div class="row"><input type="text" name="path" placeholder="追加导入新的离线目录（绝对路径）">
<button>导入并重算</button></div></form></div>
{combos}"#,
        flash = flash, id = esc(&id), stats = stats, gen_cards = gen_cards,
        check_rows = if check_rows.is_empty() {
            "<tr><td colspan='6' class='muted'>尚无恢复轮次。</td></tr>".into()
        } else { check_rows },
        stripe_rows = stripe_rows, health_rows = if health_rows.is_empty() {
            "<tr><td colspan='6' class='muted'>无 fragment。</td></tr>".into()
        } else { health_rows },
        source_html = source_html, combos = combo_panels
    );

    Ok(Html(layout("条带复原舱 · 对象", body)))
}
