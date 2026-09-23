pub const INDEX: &str = r##"<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>条带复原舱</title>
<style>
  body { font-family: -apple-system, "PingFang SC", "Microsoft YaHei", sans-serif; margin: 24px; background:#0f141b; color:#dde4ec; }
  h1 { color:#7fd4ff; }
  h2 { color:#9fd8ff; border-bottom:1px solid #2a3646; padding-bottom:4px; }
  .card { background:#18202c; border:1px solid #2a3646; border-radius:8px; padding:16px; margin-bottom:16px; }
  table { border-collapse: collapse; width:100%; margin:8px 0; }
  th, td { border:1px solid #2a3646; padding:6px 10px; text-align:left; font-size:14px; }
  th { background:#202b3a; }
  button { background:#2b6cb0; color:#fff; border:none; border-radius:5px; padding:6px 14px; cursor:pointer; margin:2px; }
  button:hover { background:#3182ce; }
  button.warn { background:#b04a2b; }
  input, textarea { background:#0f141b; color:#dde4ec; border:1px solid #2a3646; border-radius:4px; padding:6px; }
  textarea { width:100%; height:120px; font-family:monospace; }
  .ok { color:#68d391; } .bad { color:#fc8181; } .mid { color:#f6e05e; }
  pre { background:#0b0f14; padding:12px; border-radius:6px; overflow:auto; max-height:420px; font-size:12px; }
  .tag { display:inline-block; background:#2a3646; border-radius:4px; padding:1px 8px; margin:1px; font-size:12px; }
</style>
</head>
<body>
<h1>条带复原舱</h1>
<p>离线对象碎片审阅：导入 manifest 与碎片，按 stripe 枚举可行重建，提交后可原子导出。</p>

<div class="card">
  <h2>操作</h2>
  <button onclick="loadDemo()">载入演示数据</button>
  <button onclick="refresh()">刷新</button>
  <div style="margin-top:10px">
    <h3>导入 manifest（JSON）</h3>
    <textarea id="manifestText" placeholder='{"name":"obj","k":3,"m":2,"shard_len":16,"stripes":1,"ec_version":1,"shards":[{"stripe":0,"index":0,"kind":"data","sha256":"..."}]}'></textarea>
    <button onclick="importManifest()">导入</button>
  </div>
  <div style="margin-top:10px">
    <h3>上传碎片</h3>
    对象ID <input id="upObj" size="3"> stripe <input id="upStripe" size="3">
    编号 <input id="upIndex" size="3"> generation <input id="upGen" size="3" value="1">
    来源 <input id="upSource" size="8" value="alpha">
    文件 <input type="file" id="upFile">
    <button onclick="uploadShard()">上传</button>
  </div>
</div>

<div class="card"><h2>对象与 stripe 健康度</h2><div id="objects">加载中…</div></div>
<div class="card"><h2>来源隔离</h2><div id="sources">—</div></div>
<div class="card"><h2>恢复报告</h2><pre id="report">（选择对象执行“恢复”后在此显示候选组合、排除证据与重算摘要）</pre></div>

<script>
async function api(path, opts) {
  const r = await fetch(path, opts);
  const t = await r.text();
  if (!r.ok) { alert('错误: ' + t); throw new Error(t); }
  return t ? JSON.parse(t) : {};
}
async function refresh() {
  const st = await api('/api/state');
  renderObjects(st);
  renderSources(st);
}
function renderObjects(st) {
  if (!st.objects.length) { document.getElementById('objects').innerHTML = '暂无对象'; return; }
  let h = '';
  for (const o of st.objects) {
    h += `<h3>#${o.id} ${o.name} <span class="tag">k=${o.k} m=${o.m}</span><span class="tag">shard=${o.shard_len}B</span><span class="tag">ec v${o.ec_version}</span></h3>`;
    h += `<button onclick="recover(${o.id})">恢复</button><button onclick="exportObj(${o.id})">导出</button><button onclick="showReport(${o.id})">查看报告</button>`;
    h += '<table><tr><th>stripe</th><th>健康度</th><th>有效块</th><th>收到碎片</th><th>冲突编号</th><th>已提交</th></tr>';
    for (const s of o.stripes_detail) {
      const cls = s.health==='健康'?'ok':(s.health==='可恢复'?'mid':'bad');
      h += `<tr><td>${s.stripe}</td><td class="${cls}">${s.health}</td><td>${s.valid}/${s.total}</td><td>${s.received}</td><td>${s.conflicts.join(', ')||'—'}</td><td>${s.committed?'✔':'—'}</td></tr>`;
    }
    h += '</table>';
  }
  document.getElementById('objects').innerHTML = h;
}
function renderSources(st) {
  const set = new Set();
  for (const o of st.objects) for (const s of o.sources) set.add(s);
  if (!set.size) { document.getElementById('sources').innerHTML = '暂无来源'; return; }
  let h = '';
  for (const s of [...set].sort()) {
    const q = st.quarantined.includes(s);
    h += `<span class="tag">${s}${q?'（已隔离）':''}</span>`;
    h += q ? `<button onclick="quarantine('${s}',false)">解除隔离</button>`
           : `<button class="warn" onclick="quarantine('${s}',true)">隔离</button>`;
  }
  document.getElementById('sources').innerHTML = h;
}
async function loadDemo() { await api('/api/demo', {method:'POST'}); refresh(); }
async function importManifest() {
  const m = document.getElementById('manifestText').value;
  await api('/api/objects', {method:'POST', headers:{'Content-Type':'application/json'}, body:m});
  refresh();
}
async function uploadShard() {
  const f = document.getElementById('upFile').files[0];
  if (!f) { alert('请选择文件'); return; }
  const q = `stripe=${upStripe.value}&index=${upIndex.value}&generation=${upGen.value}&source=${encodeURIComponent(upSource.value)}`;
  await api(`/api/objects/${upObj.value}/shards?${q}`, {method:'POST', body: await f.arrayBuffer()});
  refresh();
}
async function recover(id) {
  const r = await api(`/api/objects/${id}/recover`, {method:'POST'});
  document.getElementById('report').textContent = JSON.stringify(r, null, 2);
  refresh();
}
async function showReport(id) {
  try {
    const r = await api(`/api/objects/${id}/report`);
    document.getElementById('report').textContent = JSON.stringify(r, null, 2);
  } catch(e) {}
}
async function exportObj(id) {
  const r = await api(`/api/objects/${id}/export`, {method:'POST'});
  alert('已导出到: ' + r.exported);
}
async function quarantine(src, on) {
  const r = await api('/api/quarantine', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({source:src, quarantined:on})});
  if (on && r.affected_stripes.length) alert('受影响 stripe 已重置，请对相关对象重新执行恢复');
  refresh();
}
refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>"##;
