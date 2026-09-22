//! Axum Web 层：对象 / stripe / shard 健康度 / 候选组合 / 恢复进度页面，
//! 支持人工隔离来源后重算受影响 stripe。

use crate::db::Db;
use crate::exporter;
use crate::gf256::Field;
use crate::model::ObjectManifest;
use crate::recovery::{self, FailGate};
use axum::{
    extract::{Path as AxumPath, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Router,
};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Db>,
    pub field: Arc<Field>,
    pub data_dir: std::path::PathBuf,
    pub inbox_dir: std::path::PathBuf,
    pub staging_dir: std::path::PathBuf,
    pub exports_dir: std::path::PathBuf,
    pub budget: usize,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/objects/{id}", get(object_page))
        .route("/objects/{id}/recover", post(recover_object_route))
        .route("/objects/{id}/stripes/{stripe}", get(stripe_page))
        .route("/objects/{id}/isolate", post(isolate_source))
        .route("/objects/{id}/export", post(export_route))
        .route("/objects/{id}/reimport", post(reimport_route))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state)
}

fn manifest_for(db: &Db, id: &str) -> Result<ObjectManifest, Response> {
    let json = db
        .get_manifest_json(id)
        .map_err(|e| server_error(e.to_string()))?
        .ok_or_else(|| not_found(&format!("对象 {id} 不存在")))?;
    serde_json::from_str(&json).map_err(|e| server_error(e.to_string()))
}

async fn index(State(st): State<AppState>) -> Response {
    let objects = st.db.list_objects().unwrap_or_default();
    let warnings = warning_count(&st.db).unwrap_or(0);
    let mut cards = String::new();
    for o in &objects {
        let reports = recovery::list_stripe_reports(&st.db, &o.object_id).unwrap_or_default();
        let committed = reports.iter().filter(|r| r.committed).count();
        let unrecov = reports.iter().filter(|r| r.status == "unrecoverable").count();
        let raw = recovery::list_raw_blocks(&st.db, &o.object_id).unwrap_or_default();
        let status_class = if committed == o.stripe_count {
            "ok"
        } else if unrecov > 0 {
            "bad"
        } else {
            "warn"
        };
        cards.push_str(&format!(
            r#"<a class="card {cls}" href="/objects/{id}">
  <div class="card-title">{id}</div>
  <div class="meta">codec v{cv} · k={k} m={m} · block={bl} · stripes={sc}</div>
  <div class="meta">已提交 stripe {cm}/{sc} · 不可恢复 {ur} · 原始碎片 {rb}</div>
</a>"#,
            cls = status_class,
            id = escape(&o.object_id),
            cv = o.codec_version,
            k = o.k,
            m = o.m,
            bl = o.block_len,
            sc = o.stripe_count,
            cm = committed,
            ur = unrecov,
            rb = raw.len()
        ));
    }
    let body = page(
        "条带复原舱",
        &format!(
            r#"
<h1>条带复原舱</h1>
<p class="sub">离线对象碎片版本化纠删码重建审阅 · 导入警告 {w} 条 · 搜索预算 {budget}</p>
<div class="cards">{cards}</div>
<p class="hint">打开对象查看 stripe / shard 健康度、候选组合与恢复进度，可隔离某个接收来源后重算。</p>
"#,
            w = warnings,
            budget = st.budget,
            cards = cards
        ),
    );
    Html(body).into_response()
}

async fn object_page(State(st): State<AppState>, AxumPath(id): AxumPath<String>) -> Response {
    let manifest = match manifest_for(&st.db, &id) {
        Ok(m) => m,
        Err(r) => return r,
    };
    let reports = recovery::list_stripe_reports(&st.db, &id).unwrap_or_default();
    let raw = recovery::list_raw_blocks(&st.db, &id).unwrap_or_default();
    let sources = st.db.list_sources(&id).unwrap_or_default();
    let isolated: BTreeSet<String> =
        st.db.isolated_sources(&id).unwrap_or_default().into_iter().collect();

    let committed = reports.iter().filter(|r| r.committed).count();
    let total = manifest.stripe_count;
    let pct = if total == 0 { 0 } else { committed * 100 / total };

    // shard 健康度矩阵
    let mut matrix = String::new();
    for stripe in 0..manifest.stripe_count {
        matrix.push_str("<tr><td class='num'>");
        matrix.push_str(&stripe.to_string());
        matrix.push_str("</td>");
        for shard in 0..manifest.n() {
            let cands: Vec<_> = raw
                .iter()
                .filter(|r| r.stripe == stripe && r.shard == shard)
                .collect();
            let cls = if cands.is_empty() {
                "cell missing"
            } else if cands.len() == 1 {
                "cell one"
            } else {
                let sigs: std::collections::HashSet<&str> =
                    cands.iter().map(|c| c.recalculated.as_str()).collect();
                if sigs.len() == 1 {
                    "cell dup"
                } else {
                    "cell conflict"
                }
            };
            matrix.push_str(&format!(r#"<td class="{cls}" title="stripe {stripe} shard {shard}: {n} 个候选"></td>"#, n = cands.len()));
        }
        let rep = reports.iter().find(|r| r.stripe == stripe);
        let (status, badge) = match rep {
            Some(r) => {
                let b = if r.committed {
                    "badge ok"
                } else if r.status == "unrecoverable" {
                    "badge bad"
                } else if r.content_diverge {
                    "badge warn"
                } else {
                    "badge"
                };
                (r.status.clone(), b)
            }
            None => ("未分析".into(), "badge"),
        };
        matrix.push_str(&format!(
            r#"<td><span class="{badge}">{status}</span></td>
<td class="num"><a href="/objects/{oid}/stripes/{stripe}">审阅 →</a></td></tr>"#,
            badge = badge,
            status = status,
            oid = id,
            stripe = stripe
        ));
    }

    let mut src_rows = String::new();
    for src in &sources {
        let iso = isolated.contains(src);
        src_rows.push_str(&format!(
            r#"<tr><td>{src}</td><td>{iso}</td><td>
<form method="post" action="/objects/{id}/isolate" class="inline">
<input type="hidden" name="source" value="{src}">
<input type="hidden" name="isolate" value="{next}">
<button type="submit">{label}</button>
</form></td></tr>"#,
            iso = if iso { "已隔离" } else { "参与中" },
            next = if iso { 0 } else { 1 },
            label = if iso { "解除隔离并重算" } else { "隔离并重算" }
        ));
    }

    let body = page(
        &format!("对象 {}", escape(&id)),
        &format!(
            r#"
<h1>对象 {id}</h1>
<p class="sub">codec v{cv} · k={k}（恢复下限）· m={m} · 固定块长 {bl} · {sc} stripe · 对象长度 {ol}</p>
<p class="sub">对象摘要：{od}</p>
<div class="progress"><div class="bar" style="width:{pct}%"></div></div>
<p class="sub">恢复进度 {cm}/{total} stripe（{pct}%）</p>
<form method="post" action="/objects/{id}/recover" class="inline"><button type="submit">分析 / 重算全部 stripe</button></form>
<form method="post" action="/objects/{id}/reimport" class="inline"><button type="submit" class="ghost">重新扫描 inbox</button></form>
<form method="post" action="/objects/{id}/export" class="inline"><button type="submit" class="ghost">导出（新目录 + 原子清单）</button></form>

<h2>Stripe × Shard 健康度</h2>
<table class="grid">
<tr><th>stripe</th>{heads}<th>状态</th><th>操作</th></tr>
{matrix}
</table>
<div class="legend">
<span class="cell one"></span> 单候选
<span class="cell dup"></span> 重复编号（同内容）
<span class="cell conflict"></span> 同编号多内容候选
<span class="cell missing"></span> 缺失
</div>

<h2>接收来源隔离</h2>
<table><tr><th>来源</th><th>状态</th><th>操作</th></tr>{src_rows}</table>

<h2>原始碎片（{nraw}）</h2>
{rawtable}
"#,
            cv = manifest.codec_version,
            k = manifest.k,
            m = manifest.m,
            bl = manifest.block_len,
            sc = manifest.stripe_count,
            ol = manifest.object_len,
            od = manifest.object_digest.clone().unwrap_or_else(|| "未提供".into()),
            cm = committed,
            heads = (0..manifest.n())
                .map(|i| {
                    let kind = if i < manifest.k { "D" } else { "P" };
                    format!("<th>{i}{kind}</th>")
                })
                .collect::<String>(),
            nraw = raw.len(),
            rawtable = raw_table(&raw, manifest.block_len)
        ),
    );
    Html(body).into_response()
}

async fn stripe_page(
    State(st): State<AppState>,
    AxumPath((id, stripe)): AxumPath<(String, usize)>,
) -> Response {
    let manifest = match manifest_for(&st.db, &id) {
        Ok(m) => m,
        Err(r) => return r,
    };
    let reports = recovery::list_stripe_reports(&st.db, &id).unwrap_or_default();
    let report = reports.into_iter().find(|r| r.stripe == stripe);
    let plans = recovery::list_plans(&st.db, &id, stripe).unwrap_or_default();
    let pre = recovery::list_pre_exclusions(&st.db, &id, stripe).unwrap_or_default();
    let raw = recovery::list_raw_blocks(&st.db, &id)
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.stripe == stripe)
        .collect::<Vec<_>>();

    let mut plan_html = String::new();
    if plans.is_empty() {
        plan_html.push_str("<p class='sub'>尚未分析或无可行方案。</p>");
    }
    for p in &plans {
        let badge = if p.trust_ok { "badge ok" } else { "badge warn" };
        let trust = if p.trust_ok { "摘要校验通过" } else { "无完整摘要或校验未通过" };
        let mut parts = String::from("<ul class='parts'>");
        for pt in &p.participants {
            parts.push_str(&format!(
                "<li>shard {sh}（{kind}）← raw#{id} src={src} gen={g}</li>",
                sh = pt.shard,
                kind = if pt.shard < manifest.k { "data" } else { "parity" },
                id = pt.raw_block_id,
                src = escape(&pt.source),
                g = pt.generation
            ));
        }
        parts.push_str("</ul>");

        let mut outs = String::from(
            "<table><tr><th>shard</th><th>来源</th><th>重算摘要</th><th>期望摘要</th><th>校验</th></tr>",
        );
        for o in &p.outputs {
            let check = match o.digest_ok {
                Some(true) => "<span class='badge ok'>一致</span>",
                Some(false) => "<span class='badge bad'>不符</span>",
                None => "<span class='muted'>无摘要可核对</span>",
            };
            outs.push_str(&format!(
                "<tr><td>{sh}</td><td>{src}</td><td class='hash'>{rec}</td><td class='hash'>{exp}</td><td>{chk}</td></tr>",
                sh = o.shard,
                src = o.source,
                rec = short(&o.recomputed),
                exp = o.expected.as_deref().map(short).unwrap_or_else(|| "—".into()),
                chk = check
            ));
        }
        outs.push_str("</table>");

        let mut excl = String::new();
        if p.exclusions.is_empty() {
            excl.push_str("<p class='muted'>无排除项。</p>");
        } else {
            excl.push_str("<ul class='ev'>");
            for (reason, detail) in &p.exclusions {
                excl.push_str(&format!("<li><code>{}</code> {}</li>", escape(reason), escape(detail)));
            }
            excl.push_str("</ul>");
        }

        plan_html.push_str(&format!(
            r#"<section class="plan">
<h3>方案 #{rank} · gen {g} · {uni} · <span class="{badge}">{trust}</span></h3>
<p class="sub">参与计算的 shard：</p>{parts}
<p class="sub">输出（含接收与重建）及重新计算的摘要：</p>{outs}
<p class="sub">被排除的损坏证据：</p>{excl}
<p class="hash muted">内容签名 {sig}</p>
</section>"#,
            rank = p.rank,
            g = p.generation,
            uni = if p.uniform_gen { "generation 一致" } else { "generation 混杂" },
            sig = p.content_sig,
        ));
    }

    let mut pre_html = String::new();
    if !pre.is_empty() {
        pre_html.push_str("<ul class='ev'>");
        for e in &pre {
            pre_html.push_str(&format!(
                "<li>shard {} <code>{}</code> {}</li>",
                e.shard.map(|v| v.to_string()).unwrap_or_else(|| "?".into()),
                escape(&e.reason),
                escape(&e.detail)
            ));
        }
        pre_html.push_str("</ul>");
    }

    let status_line = match &report {
        Some(r) => format!(
            "{} · 可行方案 {} · 检查组合 {}（预算截断 {}）· 内容分歧 {} · 已提交 {}",
            r.status,
            r.feasible_count,
            r.inspected_combos,
            if r.truncated { "是" } else { "否" },
            if r.content_diverge { "是（保留全部答案）" } else { "否" },
            if r.committed {
                format!("是（gen {}）", r.committed_gen.map(|g| g.to_string()).unwrap_or_else(|| "?".into()))
            } else {
                "否".into()
            }
        ),
        None => "尚未分析".to_string(),
    };

    let body = page(
        &format!("对象 {} · stripe {}", escape(&id), stripe),
        &format!(
            r#"
<h1>对象 {id} · stripe {stripe}</h1>
<p><a href="/objects/{id}">← 返回对象</a></p>
<p class="sub">{status_line}</p>
<form method="post" action="/objects/{id}/recover"><button type="submit">重算该对象（复用已提交 stripe）</button></form>
<h2>条带级预排除</h2>{pre}
<h2>候选组合与重建（{n}）</h2>{plans}
<h2>该 stripe 接收到的原始碎片</h2>{rawtable}
"#,
            n = plans.len(),
            plans = plan_html,
            pre = if pre_html.is_empty() { "<p class='muted'>无。</p>".to_string() } else { pre_html },
            rawtable = raw_table(&raw, manifest.block_len)
        ),
    );
    Html(body).into_response()
}

#[derive(Deserialize)]
struct RecoverQuery {
    stripe: Option<usize>,
    msg: Option<String>,
}

#[derive(Deserialize)]
struct IsolateForm {
    source: String,
    isolate: i64,
}

async fn recover_object_route(
    State(st): State<AppState>,
    AxumPath(id): AxumPath<String>,
    Query(q): Query<RecoverQuery>,
) -> Response {
    let manifest = match manifest_for(&st.db, &id) {
        Ok(m) => m,
        Err(r) => return r,
    };
    recovery::sweep_staging(&st.staging_dir);
    let opts = recovery::RecoverOptions { budget: st.budget };
    let gate: &dyn FailGate = &recovery::NoFail;
    match recovery::recover_object(&st.db, &st.field, &manifest, &st.staging_dir, &opts, gate) {
        Ok(summary) => {
            let msg = format!(
                "已提交 {}/{} stripe（复用 {}，重建 {}，不可恢复 {}），对象可信：{}，重算摘要 {}",
                summary.stripes_committed,
                summary.stripes_total,
                summary.stripes_reused,
                summary.stripes_rebuilt,
                summary.stripes_unrecoverable,
                summary.object_trusted,
                summary.object_digest_recomputed.as_deref().unwrap_or("—")
            );
            let _ = q;
            Redirect::to(&format!("/objects/{id}?msg={}", urlencode(&msg))).into_response()
        }
        Err(e) => server_error(format!("恢复失败: {e}")),
    }
}

async fn isolate_source(
    State(st): State<AppState>,
    AxumPath(id): AxumPath<String>,
    Form(form): Form<IsolateForm>,
) -> Response {
    if let Err(e) = st.db.set_source_isolated(&id, &form.source, form.isolate != 0) {
        return server_error(e.to_string());
    }
    // 隔离/解除隔离影响所有相关 stripe：清除该对象的提交以强制重算（只保留可复用且未涉及该来源的 stripe 由 verify 处理）。
    // 简化语义：隔离一个来源后，全部 stripe 重新分析；已提交 stripe 若不涉及该来源仍会通过 verify 复用。
    let manifest = match manifest_for(&st.db, &id) {
        Ok(m) => m,
        Err(r) => return r,
    };
    // 若涉及被隔离来源的已提交 stripe，移除其提交，确保结果反映人工操作。
    let raw = recovery::list_raw_blocks(&st.db, &id).unwrap_or_default();
    let affected: BTreeSet<usize> = raw
        .iter()
        .filter(|r| r.source == form.source)
        .map(|r| r.stripe)
        .collect();
    {
        if let Ok(mut conn) = st.db.conn.lock() {
            if let Ok(tx) = conn.transaction() {
                for stripe in &affected {
                    let _ = tx.execute(
                        "DELETE FROM committed_blocks WHERE object_id=?1 AND stripe=?2",
                        rusqlite::params![id, *stripe as i64],
                    );
                    let _ = tx.execute(
                        "DELETE FROM commits WHERE object_id=?1 AND stripe=?2",
                        rusqlite::params![id, *stripe as i64],
                    );
                    let _ = tx.execute(
                        "UPDATE stripe_reports SET committed=0, committed_gen=NULL
                         WHERE object_id=?1 AND stripe=?2",
                        rusqlite::params![id, *stripe as i64],
                    );
                }
                let _ = tx.commit();
            }
        }
    }
    let _ = manifest;
    let msg = if form.isolate != 0 {
        format!("已隔离来源 {}，受影响 {} 个 stripe 将重算", form.source, affected.len())
    } else {
        format!("已解除隔离来源 {}，受影响 {} 个 stripe 将重算", form.source, affected.len())
    };
    Redirect::to(&format!("/objects/{id}?msg={}", urlencode(&msg))).into_response()
}

async fn export_route(State(st): State<AppState>, AxumPath(id): AxumPath<String>) -> Response {
    let manifest = match manifest_for(&st.db, &id) {
        Ok(m) => m,
        Err(r) => return r,
    };
    match exporter::export_object(&st.db, &manifest, &st.exports_dir) {
        Ok(outcome) => {
            let verify = exporter::verify_export(&outcome);
            let msg = match verify {
                Ok(()) => format!(
                    "已导出到 {}（清单原子切换，复核通过，可信={}）",
                    outcome.dir.display(),
                    outcome.object_trusted
                ),
                Err(e) => format!("导出完成但复核失败: {e}"),
            };
            Redirect::to(&format!("/objects/{id}?msg={}", urlencode(&msg))).into_response()
        }
        Err(e) => server_error(format!("导出失败: {e}")),
    }
}

async fn reimport_route(State(st): State<AppState>, AxumPath(id): AxumPath<String>) -> Response {
    match crate::importer::import_dir(&st.db, &st.inbox_dir) {
        Ok(o) => {
            let msg = format!("重新扫描完成：清单 {}，碎片 {}，警告 {}", o.manifests, o.blocks, o.warnings);
            Redirect::to(&format!("/objects/{id}?msg={}", urlencode(&msg))).into_response()
        }
        Err(e) => server_error(format!("重新扫描失败: {e}")),
    }
}

// ----------------------------- 渲染辅助 -----------------------------

fn raw_table(rows: &[recovery::RawBlockRow], block_len: usize) -> String {
    if rows.is_empty() {
        return "<p class='muted'>无原始碎片。</p>".to_string();
    }
    let mut t = String::from(
        "<table><tr><th>id</th><th>stripe</th><th>shard</th><th>类型</th><th>gen</th><th>来源</th><th>长度</th><th>重算摘要</th><th>随附摘要</th><th>来源路径</th></tr>",
    );
    for r in rows {
        let len_class = if r.length != block_len { "bad" } else { "muted" };
        let att = match &r.attached_digest {
            Some(a) => {
                if a.eq_ignore_ascii_case(&r.recalculated) {
                    format!("<span class='muted'>{}</span>", short(a))
                } else {
                    format!("<span class='badge bad'>{}</span>", short(a))
                }
            }
            None => "<span class='muted'>—</span>".to_string(),
        };
        t.push_str(&format!(
            "<tr><td>{id}</td><td>{s}</td><td>{i}</td><td>{kind}</td><td>{g}</td><td>{src}</td>
<td class='{lc}'>{len}</td><td class='hash'>{rec}</td><td>{att}</td><td class='path'>{path}</td></tr>",
            id = r.id,
            s = r.stripe,
            i = r.shard,
            kind = r.kind,
            g = r.generation,
            src = escape(&r.source),
            lc = len_class,
            len = r.length,
            rec = short(&r.recalculated),
            path = escape(&r.origin_path)
        ));
    }
    t.push_str("</table>");
    t
}

fn warning_count(db: &Db) -> rusqlite::Result<i64> {
    db.conn.lock().unwrap().query_row(
        "SELECT COUNT(*) FROM import_warnings",
        [],
        |r| r.get(0),
    )
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn short(hash: &str) -> String {
    if hash.len() <= 16 {
        hash.to_string()
    } else {
        format!("{}…", &hash[..16])
    }
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn not_found(msg: &str) -> Response {
    (StatusCode::NOT_FOUND, Html(page("未找到", &format!("<h1>未找到</h1><p>{}</p>", escape(msg)))))
        .into_response()
}

fn server_error(msg: String) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, Html(page("错误", &format!("<h1>错误</h1><p>{}</p>", escape(&msg))))).into_response()
}

fn page(title: &str, content: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} - 条带复原舱</title>
<style>{css}</style></head>
<body><main>{content}</main></body></html>"#,
        css = CSS
    )
}

const CSS: &str = r#"
:root {{ --bg:#0f1420; --panel:#171e2e; --line:#26314a; --fg:#e7ecf5; --muted:#8b97ad;
        --ok:#2fbf71; --warn:#e0a431; --bad:#e35d6a; --accent:#5b8cff; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--fg);
  font:14px/1.6 -apple-system,"PingFang SC","Microsoft YaHei",sans-serif; }}
main {{ max-width:1100px; margin:0 auto; padding:28px 22px 60px; }}
h1 {{ font-size:22px; margin:0 0 6px; }}
h2 {{ font-size:16px; margin:26px 0 10px; border-left:3px solid var(--accent); padding-left:8px; }}
h3 {{ font-size:14px; margin:14px 0 8px; }}
a {{ color:var(--accent); text-decoration:none; }}
.sub,.muted {{ color:var(--muted); }}
.cards {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(280px,1fr)); gap:12px; margin:16px 0; }}
.card {{ display:block; background:var(--panel); border:1px solid var(--line); border-radius:10px;
  padding:14px 16px; color:var(--fg); }}
.card:hover {{ border-color:var(--accent); }}
.card.ok {{ border-left:4px solid var(--ok); }}
.card.warn {{ border-left:4px solid var(--warn); }}
.card.bad {{ border-left:4px solid var(--bad); }}
.card-title {{ font-weight:600; margin-bottom:4px; }}
.meta {{ color:var(--muted); font-size:12px; }}
table {{ border-collapse:collapse; width:100%; background:var(--panel); border-radius:8px; overflow:hidden; }}
th,td {{ border-bottom:1px solid var(--line); padding:6px 9px; text-align:left; font-size:12.5px; }}
th {{ color:var(--muted); font-weight:500; background:#131a29; }}
td.num {{ text-align:center; font-variant-numeric:tabular-nums; }}
.hash {{ font-family:ui-monospace,Menlo,monospace; font-size:11px; color:var(--muted); }}
.path {{ font-family:ui-monospace,Menlo,monospace; font-size:11px; color:var(--muted); max-width:260px;
  overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
.grid td {{ text-align:center; }}
.cell {{ display:inline-block; width:15px; height:15px; border-radius:3px; }}
td.cell {{ padding:4px; }}
.cell.one {{ background:#24402d; border:1px solid #2f6b43; }}
.cell.dup {{ background:#3a3520; border:1px solid #6b5f2f; }}
.cell.conflict {{ background:#452530; border:1px solid #8a3a49; }}
.cell.missing {{ background:#1b2230; border:1px dashed #39435c; }}
.legend {{ margin:8px 0; color:var(--muted); font-size:12px; display:flex; gap:14px; align-items:center; }}
.legend .cell {{ margin-right:4px; vertical-align:middle; }}
.badge {{ display:inline-block; padding:1px 8px; border-radius:10px; background:#2a3550;
  color:var(--fg); font-size:11.5px; }}
.badge.ok {{ background:#1d4530; color:#8be0ab; }}
.badge.warn {{ background:#46381c; color:#f0c56e; }}
.badge.bad {{ background:#4d232a; color:#f39aa2; }}
button {{ background:var(--accent); color:#fff; border:0; border-radius:7px; padding:7px 14px;
  font-size:13px; cursor:pointer; margin:6px 8px 6px 0; }}
button.ghost {{ background:#25304a; }}
.inline {{ display:inline-block; margin:0; }}
.progress {{ background:#1a2233; border-radius:8px; height:10px; margin:12px 0 4px; overflow:hidden; }}
.bar {{ background:linear-gradient(90deg,#2fbf71,#5b8cff); height:100%; }}
.plan {{ background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:12px 16px; margin:12px 0; }}
.parts,.ev {{ margin:6px 0; padding-left:18px; }}
.ev code {{ color:#f39aa2; }}
"#;
