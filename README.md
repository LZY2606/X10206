# 条带复原舱（Stripe Recovery Cabin）

离线环境下审阅对象碎片、判定哪些 stripe 可恢复、并证明重建结果可信的 Rust 服务。
使用 **Rust + Axum + SQLite**，数据全部保存在项目目录下的 `data/`。

## 运行

```bash
cargo build --all-targets
cargo test --all-targets
cargo run -- --addr 127.0.0.1:5266
```

打开 <http://127.0.0.1:5266>，页面标题为「条带复原舱」。空库时会自动导入并恢复一个
内置演示对象 `demo-object`（gf16，k=2，m=2，3 个 stripe），覆盖：

- **stripe 0**：只剩 parity 2/3，恰好达到恢复下限 k；
- **stripe 1**：shard1 位翻转（摘要不符）+ 同编号无摘要损坏候选，冗余核对后排除；
- **stripe 2**：部分写造成 generation g1/g2 混杂，枚举两个可行 stripe 解，由对象摘要唯一裁定。

页面显示对象 / stripe / shard 健康度、候选组合、被排除的损坏证据、恢复进度，
支持点击来源进行人工隔离并重算受影响 stripe，以及导出首选（或指定）结果。

## Bundle 导入格式

```
manifest.json
shards/
  s<stripe>_sh<shard>_g<generation>[-后缀].bin      原始碎片（永不改动）
  s<stripe>_sh<shard>_g<generation>[-后缀].digest   可选，单行 hex SHA-256
  s<stripe>_sh<shard>_g<generation>[-后缀].meta.json 可选，{"source":"node-A"}
```

`manifest.json`（v1 版本化编码参数）：

```json
{
  "object_id": "demo-object",
  "codec_version": 1,
  "field": "gf16",
  "k": 2, "m": 2,
  "stripe_length": 4,
  "stripe_count": 3,
  "object_length": 24,
  "object_digest": "可选：整个对象的 SHA-256，用于在多解间裁定"
}
```

生产参数用 `gf256`，测试 fixture 用 `gf16`（Cauchy 矩阵要求 2k+m ≤ 域大小）。
文件名允许 `-后缀` 以表达同一 `(stripe, shard)` 的多个内容候选。

## 设计要点

- **候选选择不先到先得**：按 stripe 收集碎片，剔除越界、长度不符、摘要不符、被隔离来源后，
  在 generation 约束下枚举所有 k 元 shard 编号子集，并对同编号的多个内容候选做笛卡尔展开。
- **版本化编码**：v1 为 Cauchy 系统化 Reed-Solomon，`codec_version` 存于 manifest 并在重建时校验。
- **确定性 + 搜索预算**：枚举顺序（generation 新者优先、编号字典序）与解排序全部确定；
  stripe 预算 256、对象笛卡尔积预算 1024（`src/engine.rs`），触预算会留下证据。
- **冗余核对与多答案**：每个组合重建后与组合外候选比对——
  无摘要/摘要损坏候选作为损坏证据排除；同编号同代两个已验证内容不同时保留为歧义分支；
  跨 stripe 组装时若有对象摘要只保留匹配结果，无摘要则保留全部不同结果并指出差异 stripe。
- **按 stripe 提交**：重建块先写 `tmp/` 再内容寻址提升到 `blocks/`，所有块就位后写
  `stripe_commits` 行；中断后续跑只复用「摘要完整」的已提交 stripe，`tmp/` 临时块绝不进入最终读取。
- **导出**：每次写入全新目录，含 `object.bin`、逐 shard 块和 `provenance.json`
  （参与计算的 shard、被排除证据、重算摘要），最后原子 rename 切换 `manifest.json`；原始碎片不改。

## API

- `GET /api/objects`，`GET /api/objects/:id`
- `POST /api/objects/:id/isolate` `{"sources":["node-A"]}`
- `POST /api/objects/:id/recover` `{"reuse":true}`
- `POST /api/objects/:id/export` `{"outcome_id":null}`
- `POST /api/import` `{"dir":"bundle 绝对路径"}`，`POST /api/demo`

## 测试覆盖

`cargo test --all-targets`（21 个测试）：

- 单块 / 多块缺失、位翻转被摘要+冗余排除、重复 shard 编号确定性选候选；
- generation 混杂由对象摘要裁定、恰好 k 边界恢复、低于下限、长度不符；
- manifest 无摘要时保留多个可行答案且组合排序确定；
- 磁盘写失败不能报成功、提交中断后续跑只复用完整 stripe、删块后强制重建；
- 临时块不被最终读取、未恢复禁止导出、来源隔离导致重算失败 / 解除后恢复；
- Axum 路由：页面标题、恢复、导出、隔离返回 400。

## 目录

```
src/gf.rs        GF(2^8)/GF(2^4) 有限域
src/coding.rs    Cauchy 系统化 RS 编解码
src/engine.rs    候选枚举、冗余核对、跨 stripe 对象组装
src/model.rs     manifest / 碎片 / 证据 / 解 领域模型
src/importer.rs  bundle 导入（原始字节 + 来源 + 摘要）
src/recovery.rs  按 stripe 提交、续跑复用
src/exporter.rs  新目录 + 原子清单切换
src/store.rs     SQLite 元数据 + 文件块 + 故障注入钩子
src/web.rs       Axum API；src/static/index.html 为内嵌单页
tests/           gf16 小有限域 fixture
```
