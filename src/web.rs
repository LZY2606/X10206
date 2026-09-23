//! Axum 页面与操作接口。页面为服务端渲染 HTML（标题“条带复原舱”）。

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Router,
};
use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};

use crate::export;
use crate::recover::Engine;
use crate::store::{ObjectRow, Store};

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Mutex<Store>>,
    pub engine: Arc<Engine>,
}

pub fn router(store: Store, engine: Engine) -> Router {
    let state = AppState { store: Arc::new(Mutex::new(store)), engine: Arc::new(engine) };
    Router::new()
        .route("/", get(index))
        .route("/objects/:oid", get(object_page))
        .route("/objects/:oid/recover", post(recover_obj))
        .route("/objects/:oid/quarantine/:source", post(quarantine))
        .route("/objects/:oid/unquarantine/:source", post(unquarantine))
        .route("/objects/:oid/export", post(do_export))
        .with_state(state)
}

async fn index(State(st): State<AppState>) -> Html<String> {
    let store = st.store.lock().unwrap();
    let objects = store.list_objects().unwrap_or_default();
    let rows: Vec<String> = objects
        .iter()
        .map(|o| {
            format!(
                "<li><a href='/objects/{}'>{}</a> <span class='dim'>GF(2^{}) k={} m={} stripes={}</span></li>",
                esc(&o.object_id),
                esc(&o.object_id),
                o.field_bits,
                o.k,
                o.m,
                o.stripes
            )
        })
        .collect();
    Html(page(
        "条带复原舱",
        &format!(
            "<h1>条带复原舱</h1>
             <p class='dim'>离线对象碎片审阅与 Reed-Solomon 条带重建。按 stripe 提交，多重可行答案全部保留。</p>
             <h2>对象</h2>
             <ul class='objects'>{}</ul>
             <p class='dim'>对象为空时，使用 <code>--seed</code> 生成演示 fixture。</p>",
            if rows.is_empty() { "<li class='dim'>（暂无导入对象）</li>".into() } else { rows.join("") }
        ),
    ))
}

#[derive(serde::Deserialize)]
struct ObjParams {
    msg: Option<String>,
}

async fn object_page(
    State(st): State<AppState>,
    Path(oid): Path<String>,
    Query(q): Query<ObjParams>,
) -> Result<Html<String>, AppError> {
    let store = st.store.lock().unwrap();
    let obj = store
        .get_object(&oid)?
        .ok_or_else(|| AppError(StatusCode::NOT_FOUND, "对象不存在".into()))?;
    Ok(Html(render_object(&store, &obj, q.msg.as_deref())?))
}

async fn recover_obj(
    State(st): State<AppState>,
    Path(oid): Path<String>,
) -> Result<Redirect, AppError> {
    {
        let store = st.store.lock().unwrap();
        st.engine.cancel.store(false, std::sync::atomic::Ordering::SeqCst);
        let r = st.engine.run(&store, &oid)?;
        let mut parts = Vec::new();
        parts.push(format!("新提交 {} 条，复用 {} 条", r.stripes_committed_new, r.stripes_reused));
        if let Some(m) = r.object_digest_matched {
            parts.push(format!("对象摘要{}", if m { "一致" } else { "不一致" }));
        }
        if !r.stripes_blocked.is_empty() {
            parts.push(format!("阻塞 {} 条", r.stripes_blocked.len()));
        }
        if r.write_failure {
            parts.push("发生磁盘写失败".into());
        }
        if r.aborted {
            parts.push("运行中断（已提交 stripe 可复用）".into());
        }
        return Ok(Redirect::to(&format!(
            "/objects/{}?msg={}",
            oid,
            urlencode(&parts.join("；"))
        )));
    }
}

async fn quarantine(
    State(st): State<AppState>,
    Path((oid, source)): Path<(String, String)>,
) -> Result<Redirect, AppError> {
    let store = st.store.lock().unwrap();
    let obj = store.get_object(&oid)?.ok_or(AppError(StatusCode::NOT_FOUND, "对象不存在".into()))?;
    let source = url_decode(&source);
    let added = store.quarantine_source(obj.id, &source)?;
    if added {
        // 隔离来源后，使用该来源参与的已提交 stripe 全部失效，需要重算。
        for stripe in 0..obj.stripes {
            if let Ok(prov) = store.load_committed(&obj, stripe as usize) {
                if prov.participating.iter().any(|p| p.source == source) {
                    store.drop_commit(obj.id, stripe as usize)?;
                }
            }
        }
    }
    Ok(Redirect::to(&format!("/objects/{}?msg={}", oid, urlencode("来源已隔离，相关 stripe 将重算"))))
}

async fn unquarantine(
    State(st): State<AppState>,
    Path((oid, source)): Path<(String, String)>,
) -> Result<Redirect, AppError> {
    let store = st.store.lock().unwrap();
    let obj = store.get_object(&oid)?.ok_or(AppError(StatusCode::NOT_FOUND, "对象不存在".into()))?;
    store.unquarantine_source(obj.id, &url_decode(&source))?;
    Ok(Redirect::to(&format!("/objects/{}?msg={}", oid, urlencode("来源已解除隔离"))))
}

async fn do_export(
    State(st): State<AppState>,
    Path(oid): Path<String>,
) -> Result<Redirect, AppError> {
    let store = st.store.lock().unwrap();
    let r = export::export_object(&store, &oid)?;
    Ok(Redirect::to(&format!(
        "/objects/{}?msg={}",
        oid,
        urlencode(&format!("已导出 {}（摘要 {}）", r.export_id, &r.object_digest[..12]))
    )))
}

struct AppError(StatusCode, String);

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        (self.0, format!("条带复原舱错误: {}", self.1)).into_response()
    }
}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    }
}

fn render_object(
    store: &Store,
    obj: &ObjectRow,
    msg: Option<&str>,
) -> std::io::Result<String> {
    let k = obj.k as usize;
    let n = k + obj.m as usize;
    let replicas = store.list_replicas(obj.id)?;
    let evidence = store.list_evidence(obj.id)?;
    let quarantined: HashSet<String> = store.quarantined(obj.id)?.into_iter().collect();
    let sources = store.distinct_sources(obj.id)?;
    let last_run = store.last_run(obj.id)?;

    let mut by_stripe: BTreeMap<usize, Vec<&crate::store::ReplicaRow>> = BTreeMap::new();
    for r in &replicas {
        by_stripe.entry(r.stripe_idx as usize).or_default().push(r);
    }

    let mut stripes_html = String::new();
    let mut committed_count = 0usize;
    for stripe in 0..obj.stripes as usize {
        let rows = by_stripe.get(&stripe).cloned().unwrap_or_default();
        let mut by_slot: BTreeMap<usize, Vec<&crate::store::ReplicaRow>> = BTreeMap::new();
        for r in &rows {
            by_slot.entry(r.slot as usize).or_default().push(r);
        }
        let distinct_contents: HashSet<String> =
            rows.iter().map(|r| r.digest_actual.clone()).collect();
        let usable_slots: HashSet<usize> = by_slot
            .iter()
            .filter(|(_, rs)| {
                rs.iter().any(|r| {
                    r.byte_len == obj.shard_size
                        && !quarantined.contains(&r.source)
                        && r.digest_expected
                            .as_ref()
                            .map_or(true, |d| d.eq_ignore_ascii_case(&r.digest_actual))
                })
            })
            .map(|(s, _)| *s)
            .collect();
        let solutions = store.list_solutions(obj.id, stripe)?;
        let commit = store.committed_solution(obj.id, stripe)?;
        let committed = commit.is_some();
        if committed {
            committed_count += 1;
        }
        let health = if committed {
            "ok"
        } else if usable_slots.len() >= k {
            "warn"
        } else {
            "bad"
        };
        let health_label = if committed {
            "已提交"
        } else if usable_slots.len() >= k {
            "可重建/待确认"
        } else {
            "不足恢复下限"
        };

        let mut slot_html = String::new();
        for slot in 0..n {
            let rs = by_slot.get(&slot).cloned().unwrap_or_default();
            let classes: Vec<&str> = rs
                .iter()
                .map(|r| {
                    if quarantined.contains(&r.source) {
                        "rep quarantined"
                    } else if r.byte_len != obj.shard_size {
                        "rep bad"
                    } else if r
                        .digest_expected
                        .as_ref()
                        .map_or(false, |d| !d.eq_ignore_ascii_case(&r.digest_actual))
                    {
                        "rep bad"
                    } else {
                        "rep ok"
                    }
                })
                .collect();
            let label = if rs.is_empty() {
                "<span class='dim'>缺失</span>".to_string()
            } else {
                rs.iter()
                    .zip(classes.iter())
                    .map(|(r, cls)| {
                        format!(
                            "<span class='{cls}'>#{} gen{} {} len{} <code>{}</code></span>",
                            r.id,
                            r.generation,
                            if r.source.is_empty() { "(无来源)" } else { &r.source },
                            r.byte_len,
                            &r.digest_actual[..8]
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(" ")
            };
            slot_html.push_str(&format!(
                "<div class='slot'><b>slot {slot}{}</b><div>{label}</div></div>",
                if slot < k { " (数据)" } else { " (校验)" }
            ));
        }

        let sol_html = if solutions.is_empty() {
            "<span class='dim'>尚无可行重建</span>".to_string()
        } else {
            let committed_id = commit.as_ref().map(|(id, _, _)| *id);
            solutions
                .iter()
                .map(|s| {
                    let mut badges = Vec::new();
                    if s.tainted {
                        badges.push("<span class='tag tainted'>含摘要损坏候选</span>");
                    }
                    match s.matches_object_digest {
                        Some(true) => badges.push("<span class='tag ok'>对象摘要一致</span>"),
                        Some(false) => badges.push("<span class='tag bad'>对象摘要不一致</span>"),
                        None => {}
                    }
                    if committed_id == Some(s.id) {
                        badges.push("<span class='tag commit'>已提交</span>");
                    }
                    format!(
                        "<details><summary>方案 #{} rank={} gen{} <code>{}</code> {}</summary>\
                         <div class='dim'>参与 replica: {}</div>\
                         <div class='dim'>数据块摘要: {}</div></details>",
                        s.id,
                        s.rank,
                        s.generation,
                        &s.output_digest[..12],
                        badges.join(" "),
                        s.replica_ids
                            .iter()
                            .map(|i| format!("#{i}"))
                            .collect::<Vec<_>>()
                            .join(", "),
                        s.data_digests
                            .iter()
                            .map(|d| d[..8].to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                })
                .collect::<Vec<_>>()
                .join("")
        };

        let ev: Vec<_> = evidence.iter().filter(|e| e.stripe_idx as usize == stripe).collect();
        let ev_html = if ev.is_empty() {
            String::new()
        } else {
            let items: Vec<String> = ev
                .iter()
                .map(|e| {
                    format!(
                        "<li class='ev {}'>[{}] {}{} — {}</li>",
                        e.kind,
                        e.kind,
                        e.slot.map(|s| format!(" slot{s}")).unwrap_or_default(),
                        e.replica_id.map(|r| format!(" replica#{r}")).unwrap_or_default(),
                        esc(&e.detail)
                    )
                })
                .collect();
            format!("<ul class='evidence'>{}</ul>", items.join(""))
        };

        stripes_html.push_str(&format!(
            "<section class='stripe {health}'>
               <h3>stripe {stripe} <span class='pill {health}'>{health_label}</span>
                 <span class='dim'>不同候选内容 {} 个 · 可用 slot {}/{}</span></h3>
               <div class='slots'>{slot_html}</div>
               <div class='sols'><b>候选组合（确定性枚举，全部保留）：</b>{sol_html}</div>
               {ev_html}
             </section>",
            distinct_contents.len(),
            usable_slots.len(),
            k
        ));
    }

    // 来源管理。
    let src_html = sources
        .iter()
        .map(|s| {
            let label = if s.is_empty() { "(无来源)" } else { s };
            if quarantined.contains(s) {
                format!(
                    "<span class='src quarantined'>{} <form method='post' action='/objects/{}/unquarantine/{}'><button>解除隔离</button></form></span>",
                    esc(label),
                    esc(&obj.object_id),
                    urlencode(s)
                )
            } else {
                format!(
                    "<span class='src'>{} <form method='post' action='/objects/{}/quarantine/{}'><button>隔离并重算</button></form></span>",
                    esc(label),
                    esc(&obj.object_id),
                    urlencode(s)
                )
            }
        })
        .collect::<Vec<_>>()
        .join(" ");

    let export_ready = committed_count == obj.stripes as usize;
    let run_info = last_run
        .map(|(id, budget, checked, done)| {
            format!(
                "<p class='dim'>上次运行 {id}：预算 {budget}，枚举 {checked} 个组合，{}",
                if done { "已完成" } else { "中断（已提交 stripe 可复用）" }
            )
        })
        .unwrap_or_default();

    let body = format!(
        "<p><a href='/'>&larr; 对象列表</a></p>
         <h1>对象 {oid}</h1>
         <p class='dim'>GF(2^{fb}) · k={k} · m={m} · shard_size={ss} · stripes={st}
            · 对象摘要：{od}</p>
         <div class='msg'>{msg}</div>
         {run_info}
         <div class='progress'><b>恢复进度</b>：{committed_count}/{total} stripe 已提交
           <form method='post' action='/objects/{oid}/recover'><button>运行恢复（确定性枚举）</button></form>
           <form method='post' action='/objects/{oid}/export'>
             <button {disabled}>导出新目录（原子清单切换）</button></form>
         </div>
         <h2>来源</h2><div class='sources'>{src_html}</div>
         <h2>Stripe</h2>
         {stripes_html}",
        oid = esc(&obj.object_id),
        fb = obj.field_bits,
        m = obj.m,
        ss = obj.shard_size,
        st = obj.stripes,
        od = obj
            .object_digest
            .as_ref()
            .map(|d| format!("<code>{}</code>", &d[..16]))
            .unwrap_or_else(|| "<i>未提供（多解全部保留）</i>".into()),
        msg = msg.map(|m| format!("{}", esc(m))).unwrap_or_default(),
        total = obj.stripes,
        disabled = if export_ready { "" } else { "disabled title='需要全部 stripe 已提交'" },
    );
    Ok(page(&format!("条带复原舱 · {}", obj.object_id), &body))
}

pub(crate) fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
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

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn page(title: &str, body: &str) -> String {
    format!(
        r#"<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<title>{title}</title><style>
:root {{ --ok:#1a7f37; --warn:#9a6700; --bad:#cf222e; --bg:#f6f8fa; }}
body {{ font-family: -apple-system, "PingFang SC", sans-serif; margin: 24px; background:var(--bg); color:#1f2328; }}
h1 {{ margin-bottom:4px; }}
.dim {{ color:#656d76; font-size: 13px; }}
code {{ background:#eaeef2; padding:1px 4px; border-radius:4px; font-size:12px; }}
.stripe {{ background:#fff; border:1px solid #d0d7de; border-left-width:6px; border-radius:8px; padding:12px 16px; margin:12px 0; }}
.stripe.ok {{ border-left-color:var(--ok); }}
.stripe.warn {{ border-left-color:var(--warn); }}
.stripe.bad {{ border-left-color:var(--bad); }}
.pill {{ padding:2px 8px; border-radius:10px; color:#fff; font-size:12px; }}
.pill.ok {{ background:var(--ok); }} .pill.warn {{ background:var(--warn); }} .pill.bad {{ background:var(--bad); }}
.slots {{ display:grid; grid-template-columns: repeat(auto-fill,minmax(220px,1fr)); gap:6px; margin:8px 0; }}
.slot {{ background:#f6f8fa; border-radius:6px; padding:6px 8px; font-size:12px; }}
.rep {{ display:inline-block; margin:1px 0; padding:0 6px; border-radius:4px; }}
.rep.ok {{ background:#dafbe1; }} .rep.bad {{ background:#ffebe9; }} .rep.quarantined {{ background:#fff8c5; text-decoration:line-through; }}
.tag {{ font-size:11px; padding:1px 6px; border-radius:8px; }}
.tag.ok {{ background:#dafbe1; color:var(--ok); }} .tag.bad {{ background:#ffebe9; color:var(--bad); }}
.tag.tainted {{ background:#fff1e5; color:#bc4c00; }} .tag.commit {{ background:#ddf4ff; color:#0969da; }}
.evidence {{ list-style:none; padding-left:0; }} .evidence li {{ font-size:12px; margin:2px 0; }}
.ev.length_mismatch,.ev.out_of_field,.ev.digest_mismatch,.ev.contradiction,.ev.write_failure {{ color:var(--bad); }}
.ev.generation_mix,.ev.duplicate_slot,.ev.rank_deficient,.ev.budget_exhausted,.ev.stale_temp_block {{ color:var(--warn); }}
form {{ display:inline; margin-left:8px; }}
button {{ cursor:pointer; }}
.progress {{ background:#fff; border:1px solid #d0d7de; border-radius:8px; padding:10px 14px; }}
.sources .src {{ display:inline-block; background:#fff; border:1px solid #d0d7de; border-radius:6px; padding:4px 8px; margin:3px; }}
.quarantined {{ opacity:.75; }}
.msg {{ color:#0969da; font-size:13px; }}
</style></head><body>{body}</body></html>"#,
        title = esc(title)
    )
}
