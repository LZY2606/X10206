//! Axum Web UI：对象、stripe、shard 健康度、候选组合、恢复进度、
//! 人工来源隔离、受影响 stripe 重算、按 stripe 提交、原子导出。

use crate::db::Store;
use crate::import::import_path;
use crate::model::StripeState;
use crate::service::{
    analyze_stripe, commit_solution, export_obj, get_object, list_objects, list_shards,
    reanalyze_object, set_source_isolated, stripe_summaries, all_sources, SEARCH_BUDGET,
};
use axum::{
    extract::{Path as AxPath, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Router,
};
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
}

pub fn router(store: Arc<Store>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/objects/{id}", get(object_page))
        .route("/objects/{id}/analyze", post(analyze_all))
        .route("/objects/{id}/stripes/{idx}", get(stripe_page))
        .route("/objects/{id}/stripes/{idx}/analyze", post(analyze_one))
        .route("/objects/{id}/stripes/{idx}/commit", post(commit_one))
        .route("/objects/{id}/export", post(do_export))
        .route("/import", post(do_import))
        .route("/sources", get(sources_page))
        .route("/sources/toggle", post(toggle_source))
        .with_state(AppState { store })
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn page(title: &str, body: String) -> Html<String> {
    Html(format!(
        r#"<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} - 条带复原舱</title>
<style>
:root{{--bg:#0f1420;--panel:#171e2e;--line:#28324a;--fg:#e6ebf5;--mut:#93a0b8;--ok:#35c48a;--warn:#e8b33e;--bad:#ef6a6a;--acc:#5b9cff;}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--fg);font:14px/1.55 -apple-system,"PingFang SC","Microsoft YaHei",sans-serif}}
header{{padding:18px 26px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:16px}}
header h1{{font-size:19px;margin:0;letter-spacing:2px}}
header nav a{{color:var(--mut);text-decoration:none;margin-right:14px}}
header nav a:hover{{color:var(--acc)}}
main{{padding:22px 26px;max-width:1180px;margin:0 auto}}
h2{{font-size:16px;margin:26px 0 10px}}
.card{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:12px 0}}
table{{border-collapse:collapse;width:100%;font-size:13px}}
th,td{{border-bottom:1px solid var(--line);padding:7px 9px;text-align:left;vertical-align:top}}
th{{color:var(--mut);font-weight:600}}
a{{color:var(--acc);text-decoration:none}} a:hover{{text-decoration:underline}}
.badge{{display:inline-block;padding:1px 9px;border-radius:999px;font-size:12px;border:1px solid var(--line)}}
.ok{{color:var(--ok);border-color:var(--ok)}} .warn{{color:var(--warn);border-color:var(--warn)}} .bad{{color:var(--bad);border-color:var(--bad)}}
.mut{{color:var(--mut)}} code,pre{{font-family:ui-monospace,Menlo,Consolas,monospace}}
pre{{background:#0b0f18;border:1px solid var(--line);border-radius:8px;padding:10px;overflow:auto;font-size:12px;max-height:340px}}
button,.btn{{background:var(--acc);color:#fff;border:0;border-radius:7px;padding:6px 14px;font-size:13px;cursor:pointer}}
button.ghost{{background:transparent;color:var(--acc);border:1px solid var(--acc)}}
button.danger{{background:transparent;color:var(--bad);border:1px solid var(--bad)}}
.row{{display:flex;gap:10px;align-items:center;flex-wrap:wrap}}
.small{{font-size:12px;color:var(--mut)}}
.bar{{height:8px;background:#0b0f18;border-radius:5px;overflow:hidden;margin:6px 0}}
.bar>i{{display:block;height:100%;background:var(--ok)}}
.tag{{font-size:11px;color:var(--mut)}}
.diff{{color:var(--warn)}}
</style></head><body>
<header>
<h1>条带复原舱</h1>
<nav><a href="/">对象</a><a href="/sources">来源隔离</a></nav>
</header>
<main>{body}</main>
</body></html>"#,
        title = esc(title),
    ))
}

struct Err500(String);
impl From<std::io::Error> for Err500 {
    fn from(e: std::io::Error) -> Self {
        Err500(e.to_string())
    }
}

impl IntoResponse for Err500 {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            page("错误", format!("<div class='card'>操作失败：<pre>{}</pre></div>", esc(&self.0))),
        )
            .into_response()
    }
}

fn err<E: std::fmt::Display>(e: E) -> Err500 {
    Err500(e.to_string())
}

#[derive(Deserialize)]
struct ImportForm {
    path: String,
}

async fn do_import(
    State(st): State<AppState>,
    Form(f): Form<ImportForm>,
) -> Result<Redirect, Err500> {
    let p = std::path::PathBuf::from(&f.path);
    let report = import_path(&st.store, &p).map_err(err)?;
    let oid = report.objects.first().cloned().unwrap_or_default();
    Ok(Redirect::to(&format!("/objects/{}", oid)))
}

async fn index(State(st): State<AppState>) -> Html<String> {
    let objects = list_objects(&st.store);
    let mut body = String::new();
    body.push_str("<h2>导入离线碎片目录</h2>");
    body.push_str(
        "<div class='card'><form method='post' action='/import' class='row'>\
         <input name='path' placeholder='包含 manifest.json 的目录绝对路径' style='flex:1;background:#0b0f18;color:var(--fg);border:1px solid var(--line);border-radius:7px;padding:8px'>\
         <button type='submit'>导入并保存原始字节</button></form>\
         <div class='small'>导入读取 manifest、data/parity shard 与 *.sidecar.json 每块摘要；原始字节原样存入 vault，源文件不改动。</div></div>",
    );
    body.push_str("<h2>对象</h2><div class='card'><table><thead><tr>\
        <th>对象</th><th>编码参数</th><th>stripe 数</th><th>长度</th><th>恢复进度</th></tr></thead><tbody>");
    if objects.is_empty() {
        body.push_str("<tr><td colspan=5 class='mut'>暂无对象。可用 data/input 下的演示目录导入，或直接使用已内置的演示数据。</td></tr>");
    }
    for o in &objects {
        let sums = stripe_summaries(&st.store, o);
        let total = sums.len();
        let committed = sums.iter().filter(|s| s.state == StripeState::Committed).count();
        let solved = sums.iter().filter(|s| s.state == StripeState::Solved).count();
        let broken = sums.iter().filter(|s| s.state == StripeState::Broken).count();
        let pct = if total == 0 { 0 } else { committed * 100 / total };
        let p = &o.params;
        body.push_str(&format!(
            "<tr><td><a href='/objects/{oid}'><code>{oid}</code></a></td>\
             <td class='small'>{v}<br>k={k}, m={m}, GF(2^{b})</td>\
             <td>{total}</td><td>{len} 符号/stripe</td>\
             <td style='min-width:230px'><div class='row small'>\
             <span>已提交 {committed}/{total}</span><span class='mut'>可恢复 {solved}</span>{broken_chip}\
             </div><div class='bar'><i style='width:{pct}%'></i></div></td></tr>",
            oid = esc(&o.object_id),
            v = esc(&p.version),
            k = p.k,
            m = p.m,
            b = p.field_bits,
            len = o.stripe_len,
            broken_chip = if broken > 0 {
                format!("<span class='badge bad'>损坏 {broken}</span>")
            } else {
                String::new()
            },
        ));
    }
    body.push_str("</tbody></table></div>");
    page("对象", body)
}

fn state_badge(s: StripeState) -> String {
    let cls = match s {
        StripeState::Committed => "ok",
        StripeState::Solved => "warn",
        StripeState::Unrecoverable => "bad",
        StripeState::Broken => "bad",
    };
    format!("<span class='badge {cls}'>{}</span>", s.label())
}

async fn object_page(
    State(st): State<AppState>,
    AxPath(id): AxPath<String>,
) -> Result<Html<String>, Err500> {
    let o = get_object(&st.store, &id).ok_or_else(|| Err500("对象不存在".into()))?;
    let sums = stripe_summaries(&st.store, &o);
    let shards = list_shards(&st.store, &o.object_id);
    let isolated: HashSet<String> = crate::service::isolated_sources(&st.store).into_iter().collect();
    let sources: HashSet<String> = shards.iter().map(|s| s.source.clone()).collect();
    let affected_by_isolation = sources.iter().any(|s| isolated.contains(s));

    let mut body = String::new();
    body.push_str(&format!(
        "<h2>对象 <code>{}</code></h2><div class='card'>\
         <div class='row small'>\
         <span>{}</span><span>k={}, m={}, GF(2^{})</span>\
         <span>{} stripe × {} 符号</span>{obj_digest}</div>\
         <div class='row' style='margin-top:12px'>\
         <form method='post' action='/objects/{id}/analyze'><button type='submit'>重算全部 stripe</button></form>\
         <form method='post' action='/objects/{id}/export'><button class='ghost' type='submit'>原子导出已提交 stripe</button></form>\
         </div>{iso_note}<div class='small'>搜索预算：每 stripe 至多 {budget} 个 ≥k 候选组合，超限标记 truncated。</div></div>",
        esc(&o.object_id),
        esc(&o.params.version),
        o.params.k,
        o.params.m,
        o.params.field_bits,
        o.stripe_count,
        o.stripe_len,
        id = esc(&o.object_id),
        obj_digest = match &o.object_digest {
            Some(d) => format!("<span>对象摘要 <code>{}</code></span>", &d[..16.min(d.len())]),
            None => String::new(),
        },
        iso_note = if affected_by_isolation {
            "<div class='small' style='color:var(--warn);margin-top:8px'>存在被隔离来源；重算将自动排除该来源的候选。</div>"
        } else {
            ""
        },
        budget = SEARCH_BUDGET,
    ));

    body.push_str("<h2>Stripe</h2><div class='card'><table><thead><tr>\
        <th>#</th><th>状态</th><th>可行解</th><th>候选位置</th><th>shard 健康度</th>\
        <th>枚举/预算</th><th></th></tr></thead><tbody>");
    for s in &sums {
        let trunc = if s.truncated {
            " <span class='badge bad'>truncated</span>"
        } else {
            ""
        };
        body.push_str(&format!(
            "<tr><td>{idx}</td><td>{state}</td><td>{feas}</td>\
             <td>{cand} / {n}</td>\
             <td><span class='ok'>{good}</span> 健康 · <span class='bad'>{badv}</span> 损坏 · 共 {tot}</td>\
             <td class='small'>{visited}{trunc}</td>\
             <td><a href='/objects/{oid}/stripes/{idx}'>候选组合 / 提交</a></td></tr>",
            idx = s.stripe_idx,
            state = state_badge(s.state),
            feas = s.feasible_count,
            cand = s.candidate_positions,
            n = o.params.n(),
            good = s.shard_verified,
            badv = s.shard_bad,
            tot = s.shard_total,
            visited = s.visited,
            oid = esc(&o.object_id),
        ));
    }
    body.push_str("</tbody></table></div>");

    body.push_str("<h2>Shard 健康度</h2><div class='card'><table><thead><tr>\
        <th>stripe</th><th>位置</th><th>角色</th><th>generation</th><th>来源</th>\
        <th>声称长度</th><th>实际长度</th><th>声称摘要</th><th>重算摘要</th><th>健康</th></tr></thead><tbody>");
    for r in &shards {
        let role = if r.shard_idx < o.params.k { "data" } else { "parity" };
        let (hcls, hlabel) = (r.health.cls(), r.health.label());
        let iso = if isolated.contains(&r.source) {
            " <span class='badge bad'>来源隔离</span>"
        } else {
            ""
        };
        body.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}{iso}</td>\
             <td>{}</td><td>{}</td><td><code>{}</code></td><td><code>{}</code></td>\
             <td><span class='badge {hcls}'>{hlabel}</span></td></tr>",
            r.stripe_idx,
            r.shard_idx,
            role,
            r.generation,
            esc(&r.source),
            r.claimed_len,
            r.actual_len,
            r.claimed_digest.as_deref().unwrap_or("—").chars().take(16).collect::<String>(),
            &r.actual_digest[..16],
        ));
    }
    body.push_str("</tbody></table></div>");
    Ok(page(&o.object_id, body))
}

#[derive(Deserialize)]
struct RankForm {
    rank: usize,
}

async fn stripe_page(
    State(st): State<AppState>,
    AxPath((id, idx_str)): AxPath<(String, String)>,
) -> Result<Html<String>, Err500> {
    let o = get_object(&st.store, &id).ok_or_else(|| Err500("对象不存在".into()))?;
    let idx: usize = idx_str.parse().map_err(err)?;
    let outcome = analyze_stripe(&st.store, &o, idx, false)?;
    let isolated: HashSet<String> = crate::service::isolated_sources(&st.store).into_iter().collect();
    let rows: Vec<_> = list_shards(&st.store, &o.object_id)
        .into_iter()
        .filter(|r| r.stripe_idx == idx)
        .collect();

    let mut body = String::new();
    body.push_str(&format!(
        "<p><a href='/objects/{oid}'>← 返回对象</a></p><h2>Stripe {idx} {state}</h2>\
         <div class='card small row'>\
         <span>枚举组合数（≥k）：<b>{visited}</b> / 预算 {budget}</span>\
         <span>可行重建：<b>{feas}</b></span>{trunc}\
         <form method='post' action='/objects/{oid}/stripes/{idx}/analyze'>\
         <button class='ghost' type='submit'>隔离后重算此 stripe</button></form></div>",
        oid = esc(&o.object_id),
        idx = idx,
        state = state_badge(outcome.state),
        visited = outcome.visited,
        budget = SEARCH_BUDGET,
        feas = outcome.feasible_count,
        trunc = if outcome.truncated {
            "<span class='badge bad'>搜索被预算截断，可能还有答案</span>"
        } else {
            ""
        },
    ));

    body.push_str("<h2>接收候选（按 generation 降、来源升序）</h2><div class='card'><table><thead><tr>\
        <th>位置</th><th>角色</th><th>generation</th><th>来源</th><th>健康</th><th>摘要</th><th>是否进入枚举</th>\
        </tr></thead><tbody>");
    for r in &rows {
        let role = if r.shard_idx < o.params.k { "data" } else { "parity" };
        let eligible = r.actual_len == o.stripe_len
            && !matches!(
                r.health,
                crate::model::ShardHealth::DigestMismatch | crate::model::ShardHealth::LengthMismatch
            )
            && !isolated.contains(&r.source);
        let enter = if eligible {
            "<span class='badge ok'>候选</span>"
        } else {
            "<span class='badge bad'>排除：仅作证据</span>"
        };
        let iso = if isolated.contains(&r.source) {
            " <span class='badge bad'>隔离</span>"
        } else {
            ""
        };
        body.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}{iso}</td>\
             <td><span class='badge {}'>{}</span></td><td><code>{}</code></td><td>{}</td></tr>",
            r.shard_idx,
            role,
            r.generation,
            esc(&r.source),
            r.health.cls(),
            r.health.label(),
            &r.actual_digest[..16],
            enter,
        ));
    }
    body.push_str("</tbody></table></div>");

    body.push_str("<h2>可行重建（全部保留，按确定性顺序排序）</h2>");
    if outcome.solutions.is_empty() {
        body.push_str("<div class='card'>无可行集合：健康候选少于恢复下限或互相矛盾，不可恢复。</div>");
    }
    for (rank, sol) in outcome.solutions.iter().enumerate() {
        let head = if rank == 0 {
            "推荐（榜首）"
        } else {
            "备选可行解"
        };
        let match_chip = if sol.matches_stripe_digest {
            "<span class='badge ok'>与 manifest stripe 摘要一致</span>"
        } else {
            "<span class='badge warn'>无 manifest 摘要或不一致</span>"
        };
        let mix = if sol.mix_level == 0 {
            format!("<span class='small'>generation 纯净（min gen {}）</span>", sol.min_generation)
        } else {
            format!("<span class='badge warn'>generation 混杂 程度 {}（min gen {}）</span>", sol.mix_level, sol.min_generation)
        };
        let diff = if sol.diff_positions.is_empty() {
            "<span class='small'>与榜首字节一致</span>".to_string()
        } else {
            format!(
                "<span class='diff'>与榜首差异位置：{:?}</span>",
                sol.diff_positions
            )
        };
        body.push_str(&format!(
            "<div class='card'><div class='row'>\
             <span class='badge {}'>#{rank} {head}</span>{match_chip}{mix}\
             <span class='small'>排除损坏证据 {exc}</span>{diff}</div>\
             <div class='small' style='margin:8px 0'>data 摘要 <code>{dd}</code><br>\
             stripe 摘要 <code>{sd}</code></div>",
            if rank == 0 { "ok" } else { "warn" },
            exc = sol.excluded_count,
            dd = &sol.data_digest[..24],
            sd = &sol.stripe_digest[..24],
        ));

        body.push_str("<table><thead><tr><th>参与计算 shard</th><th>位置</th><th>角色</th><th>generation</th><th>来源</th><th>健康</th><th>输出块重算摘要</th></tr></thead><tbody>");
        for p in &sol.participants {
            body.push_str(&format!(
                "<tr><td><code>#{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>",
                p.shard_id, p.position, p.role, p.generation, esc(&p.source), p.health, &p.recomputed_sha256[..16]
            ));
        }
        body.push_str("</tbody></table>");

        body.push_str("<table style='margin-top:8px'><thead><tr><th>被排除的损坏证据</th><th>位置</th><th>generation</th><th>来源</th><th>原因</th><th>声称摘要</th><th>重算摘要</th></tr></thead><tbody>");
        if sol.excluded.is_empty() {
            body.push_str("<tr><td colspan=7 class='mut'>无（所有接收到的块均与本解一致或冗余）</td></tr>");
        }
        for e in &sol.excluded {
            body.push_str(&format!(
                "<tr><td><code>#{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td><td><code>{}</code></td></tr>",
                e.shard_id, e.position, e.generation, esc(&e.source), esc(&e.reason),
                e.claimed_sha256.as_deref().unwrap_or("—").chars().take(16).collect::<String>(),
                &e.recomputed_sha256[..16]
            ));
        }
        body.push_str("</tbody></table>");

        body.push_str(&format!(
            "<div style='margin-top:10px'><form method='post' action='/objects/{oid}/stripes/{idx}/commit'>\
             <input type='hidden' name='rank' value='{rank}'>\
             <button type='submit'>按 stripe 原子提交此解（重算 + 读回 + 切换）</button>\
             </form></div></div>",
            oid = esc(&o.object_id),
            idx = idx,
        ));
    }
    Ok(page(&format!("stripe-{idx}"), body))
}

async fn analyze_one(
    State(st): State<AppState>,
    AxPath((id, idx)): AxPath<(String, usize)>,
) -> Result<Redirect, Err500> {
    let o = get_object(&st.store, &id).ok_or_else(|| Err500("对象不存在".into()))?;
    analyze_stripe(&st.store, &o, idx, true).map_err(err)?;
    Ok(Redirect::to(&format!("/objects/{id}/stripes/{idx}")))
}

async fn analyze_all(State(st): State<AppState>, AxPath(id): AxPath<String>) -> Result<Redirect, Err500> {
    let o = get_object(&st.store, &id).ok_or_else(|| Err500("对象不存在".into()))?;
    reanalyze_object(&st.store, &o).map_err(err)?;
    Ok(Redirect::to(&format!("/objects/{id}")))
}

async fn commit_one(
    State(st): State<AppState>,
    AxPath((id, idx)): AxPath<(String, usize)>,
    Form(form): Form<RankForm>,
) -> Result<Redirect, Err500> {
    let o = get_object(&st.store, &id).ok_or_else(|| Err500("对象不存在".into()))?;
    commit_solution(&st.store, &o, idx, form.rank).map_err(err)?;
    Ok(Redirect::to(&format!("/objects/{id}")))
}

async fn do_export(State(st): State<AppState>, AxPath(id): AxPath<String>) -> Result<Html<String>, Err500> {
    let o = get_object(&st.store, &id).ok_or_else(|| Err500("对象不存在".into()))?;
    let result = export_obj(&st.store, &o).map_err(err)?;
    Ok(page(
        "导出完成",
        format!(
            "<div class='card'><b>导出完成（原子清单切换）</b><p class='small'>\
             目录：<code>{dir}</code><br>清单摘要：<code>{digest}</code><br>\
             导出 ID：{eid}</p><p><a href='/objects/{id}'>返回对象</a></p></div>",
            dir = esc(&result.dir.to_string_lossy().as_ref()),
            digest = &result.manifest_digest[..24],
            eid = esc(&result.export_id),
            id = esc(&id),
        ),
    ))
}

async fn sources_page(State(st): State<AppState>) -> Html<String> {
    let sources = all_sources(&st.store);
    let mut body = String::from(
        "<h2>来源隔离</h2><div class='card'>隔离一个来源后，重算受影响 stripe 时将不再使用该来源的任何候选；\
         被排除的块仍作为证据列在解法报告中。<table style='margin-top:10px'><thead><tr>\
         <th>来源</th><th>状态</th><th></th></tr></thead><tbody>",
    );
    if sources.is_empty() {
        body.push_str("<tr><td colspan=3 class='mut'>暂无来源。</td></tr>");
    }
    for (source, isolated) in sources {
        let (label, btn) = if isolated {
            ("已隔离", "解除隔离")
        } else {
            ("正常", "人工隔离")
        };
        let cls = if isolated { "bad" } else { "ok" };
        body.push_str(&format!(
            "<tr><td>{}</td><td><span class='badge {cls}'>{label}</span></td>\
             <td><form method='post' action='/sources/toggle'>\
             <input type='hidden' name='source' value='{}'>\
             <input type='hidden' name='isolated' value='{}'>\
             <button class='ghost' type='submit'>{btn}</button></form></td></tr>",
            esc(&source),
            esc(&source),
            !isolated,
        ));
    }
    body.push_str("</tbody></table></div>");
    page("来源隔离", body)
}

#[derive(Deserialize)]
struct ToggleForm {
    source: String,
    isolated: bool,
}

async fn toggle_source(
    State(st): State<AppState>,
    Form(form): Form<ToggleForm>,
) -> Redirect {
    set_source_isolated(&st.store, &form.source, form.isolated);
    Redirect::to("/sources")
}
