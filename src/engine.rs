//! 条带复原舱引擎：导入、可行性枚举、逐 stripe 提交、人工隔离与导出。

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rusqlite::params;
use serde_json::{json, Value};

use crate::gf256;
use crate::model::{
    sha256_hex, CodingParams, FragmentStatus, ManifestFile, CODING_VERSION,
};
use crate::store::{now_ts, Store, StoreError};

pub const RUN_ID: &str = "run-1";
pub const DEFAULT_BUDGET: i64 = 256;

pub struct Engine {
    pub store: Arc<Store>,
    pub data_dir: PathBuf,
    pub budget: i64,
}

#[derive(Debug)]
pub enum EngineError {
    Store(StoreError),
    Invalid(String),
}
impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineError::Store(e) => write!(f, "{e}"),
            EngineError::Invalid(s) => write!(f, "{s}"),
        }
    }
}
impl std::error::Error for EngineError {}
impl From<StoreError> for EngineError {
    fn from(e: StoreError) -> Self {
        EngineError::Store(e)
    }
}

#[derive(Clone, Debug)]
struct FragRow {
    id: i64,
    generation: u64,
    stripe_index: usize,
    shard_index: usize,
    frag_generation: u64,
    source: String,
    expected_digest: Option<String>,
    actual_digest: Option<String>,
    length: Option<i64>,
    expected_length: i64,
    status: String,
    raw_rel_path: Option<String>,
    reasons: Vec<String>,
}

#[derive(Clone)]
struct ComboOutcome {
    frag_generation: u64,
    fragment_ids: Vec<i64>,
    shard_indexes: Vec<usize>,
    mixed: bool,
    invert_ok: bool,
    parity_ok: Option<bool>,
    data_digest_match: Option<bool>,
    output_digest: Option<String>,
    all_blocks: Option<Vec<Vec<u8>>>,
    reason: Option<String>,
}

impl Engine {
    pub fn new(store: Arc<Store>, data_dir: PathBuf, budget: i64) -> Self {
        Engine {
            store,
            data_dir,
            budget,
        }
    }

    /// 初始化运行记录（中断续跑：同一 run 复用已提交 stripe）。
    pub fn ensure_run(&self) -> Result<(), EngineError> {
        let c = self.store.lock();
        let exists: i64 =
            c.query_row("SELECT COUNT(*) FROM run WHERE id=?1", params![RUN_ID], |r| r.get(0))?;
        if exists == 0 {
            c.execute(
                "INSERT INTO run(id, created_at, search_budget, note) VALUES(?1,?2,?3,?4)",
                params![RUN_ID, now_ts(), self.budget, "版本化纠删码恢复"],
            )?;
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // 导入
    // ------------------------------------------------------------------

    /// 扫描数据目录下的 manifest（顶层 *.json），逐个导入。
    /// 重复内容的 manifest 具有确定性 import_id，重复导入会被跳过。
    pub fn scan_imports(&self) -> Result<Vec<String>, EngineError> {
        let mut imported = Vec::new();
        if !self.data_dir.exists() {
            return Ok(imported);
        }
        let mut paths: Vec<PathBuf> = Vec::new();
        for entry in std::fs::read_dir(&self.data_dir)? {
            let entry = entry?;
            let p = entry.path();
            if p.is_file() {
                if let Some(ext) = p.extension() {
                    if ext == "json" {
                        paths.push(p);
                    }
                }
            }
        }
        paths.sort();
        for p in paths {
            let bytes = std::fs::read(&p)?;
            let digest = sha256_hex(&bytes);
            let import_id = format!("imp-{}", &digest[0..16]);
            let already: i64 = self.store.lock().query_row(
                "SELECT COUNT(*) FROM object_manifest WHERE import_id=?1",
                params![import_id],
                |r| r.get(0),
            )?;
            if already > 0 {
                continue;
            }
            let mf: ManifestFile = match serde_json::from_slice(&bytes) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("跳过无法解析的 manifest {}: {e}", p.display());
                    continue;
                }
            };
            self.import_manifest(&import_id, &p, &mf, &bytes)?;
            imported.push(import_id);
        }
        if !imported.is_empty() {
            self.recover_all()?;
        }
        Ok(imported)
    }

    fn import_manifest(
        &self,
        import_id: &str,
        manifest_path: &Path,
        mf: &ManifestFile,
        raw_bytes: &[u8],
    ) -> Result<(), EngineError> {
        validate_manifest(mf)?;
        let rel = self.store.save_manifest_bytes(import_id, raw_bytes)?;
        let coding = &mf.coding;
        let ts = now_ts();

        {
            let c = self.store.lock();
            c.execute(
                "INSERT INTO object(object_id, latest_generation, created_at)
                 VALUES(?1, ?2, ?3)
                 ON CONFLICT(object_id) DO UPDATE SET
                    latest_generation=MAX(latest_generation, excluded.latest_generation)",
                params![mf.object_id, mf.generation, ts],
            )?;
            c.execute(
                "INSERT INTO object_manifest
                 (import_id, object_id, generation, object_len, object_digest,
                  coding_version, data_shards, parity_shards, shard_size,
                  manifest_rel_path, imported_at)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                params![
                    import_id,
                    mf.object_id,
                    mf.generation,
                    mf.object_len,
                    mf.object_digest,
                    coding.version,
                    coding.data_shards,
                    coding.parity_shards,
                    coding.shard_size,
                    rel,
                    ts
                ],
            )?;
            for stripe in &mf.stripes {
                c.execute(
                    "INSERT OR REPLACE INTO stripe
                     (object_id, generation, stripe_index, data_len, data_digest)
                     VALUES(?1,?2,?3,?4,?5)",
                    params![
                        mf.object_id,
                        mf.generation,
                        stripe.stripe_index,
                        stripe.data_len,
                        stripe.data_digest
                    ],
                )?;
                for frag in &stripe.fragments {
                    let source = frag
                        .source
                        .clone()
                        .or_else(|| first_path_segment(&frag.path))
                        .unwrap_or_else(|| "default".to_string());
                    let frag_generation = frag.generation.unwrap_or(mf.generation);
                    let file_path = self.data_dir.join(&frag.path);
                    let (status, actual_digest, length, raw_rel, mut reasons) =
                        self.inspect_fragment(&file_path, coding.shard_size, &frag.digest);
                    let isolated = self.is_source_isolated(&source);
                    if isolated {
                        status_promote_isolated(&mut status, &mut reasons);
                    }
                    c.execute(
                        "INSERT INTO fragment
                         (import_id, object_id, generation, stripe_index, shard_index,
                          frag_generation, source, expected_digest, actual_digest, length,
                          expected_length, status, raw_rel_path, original_path, reasons)
                         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
                        params![
                            import_id,
                            mf.object_id,
                            mf.generation,
                            stripe.stripe_index,
                            frag.shard_index,
                            frag_generation,
                            source,
                            frag.digest,
                            actual_digest,
                            length,
                            coding.shard_size as i64,
                            status.as_str(),
                            raw_rel,
                            frag.path,
                            serde_json::to_string(&reasons).unwrap_or_else(|_| "[]".into())
                        ],
                    )?;
                }
            }
        }
        let _ = manifest_path;
        Ok(())
    }

    fn inspect_fragment(
        &self,
        file_path: &Path,
        shard_size: usize,
        expected_digest: &str,
    ) -> (
        FragmentStatus,
        Option<String>,
        Option<i64>,
        Option<String>,
        Vec<String>,
    ) {
        let mut reasons = Vec::new();
        match std::fs::read(file_path) {
            Err(_) => {
                reasons.push(format!("文件缺失: {}", file_path.display()));
                (FragmentStatus::Missing, None, None, None, reasons)
            }
            Ok(bytes) => {
                let length = bytes.len() as i64;
                let (raw_rel, actual) = self
                    .store
                    .save_raw(&bytes)
                    .map(|(r, d)| (Some(r), Some(d)))
                    .unwrap_or((None, None));
                if bytes.len() != shard_size {
                    reasons.push(format!(
                        "长度不符: 实际 {} 期望 {}",
                        bytes.len(),
                        shard_size
                    ));
                }
                let digest_ok = actual.as_deref() == Some(expected_digest);
                if !digest_ok {
                    reasons.push(format!(
                        "摘要不符: 实际 {} 期望 {}",
                        actual.clone().unwrap_or_default(),
                        expected_digest
                    ));
                }
                let status = if bytes.len() != shard_size {
                    FragmentStatus::LengthMismatch
                } else if !digest_ok {
                    FragmentStatus::DigestMismatch
                } else {
                    FragmentStatus::Valid
                };
                (status, actual, Some(length), raw_rel, reasons)
            }
        }
    }
}

fn status_promote_isolated(status: &mut FragmentStatus, reasons: &mut Vec<String>) {
    if *status == FragmentStatus::Valid {
        *status = FragmentStatus::Isolated;
    }
    reasons.push("来源已被人工隔离".to_string());
}

fn first_path_segment(path: &str) -> Option<String> {
    let p = Path::new(path);
    p.components().next().and_then(|c| match c {
        std::path::Component::Normal(s) => Some(s.to_string_lossy().to_string()),
        _ => None,
    })
}

fn validate_manifest(mf: &ManifestFile) -> Result<(), EngineError> {
    if mf.object_id.trim().is_empty() {
        return Err(EngineError::Invalid("object_id 为空".into()));
    }
    let c = &mf.coding;
    if c.version != CODING_VERSION {
        return Err(EngineError::Invalid(format!(
            "不支持的编码版本 {}（支持 {}）",
            c.version, CODING_VERSION
        )));
    }
    if c.data_shards == 0 || c.parity_shards == 0 {
        return Err(EngineError::Invalid("data_shards/parity_shards 必须为正".into()));
    }
    if c.n() > 256 {
        return Err(EngineError::Invalid("GF(256) 下 shard 总数不能超过 256".into()));
    }
    if c.shard_size == 0 {
        return Err(EngineError::Invalid("shard_size 必须为正".into()));
    }
    let mut seen = BTreeSet::new();
    for stripe in &mf.stripes {
        if (stripe.data_len as usize) > c.shard_size {
            return Err(EngineError::Invalid(format!(
                "stripe {} 的 data_len 超过 shard_size",
                stripe.stripe_index
            )));
        }
        let mut shard_ids = BTreeSet::new();
        for frag in &stripe.fragments {
            if frag.shard_index >= c.n() {
                return Err(EngineError::Invalid(format!(
                    "shard_index {} 超出范围",
                    frag.shard_index
                )));
            }
            shard_ids.insert(frag.shard_index);
        }
        seen.insert(stripe.stripe_index);
        let _ = shard_ids;
    }
    let expected: BTreeSet<usize> = (0..mf.stripes.len()).collect();
    if seen != expected {
        return Err(EngineError::Invalid("stripe_index 必须从 0 连续编号".into()));
    }
    Ok(())
}

    // ------------------------------------------------------------------
    // 可行性分析（枚举，绝不先到先得）
    // ------------------------------------------------------------------

    pub fn recover_all(&self) -> Result<(), EngineError> {
        let keys: Vec<(String, u64, usize, String, i64, i64, i64)> = {
            let c = self.store.lock();
            let mut stmt = c.prepare(
                "SELECT s.object_id, s.generation, s.stripe_index, s.data_digest,
                        m.data_shards, m.parity_shards, m.shard_size
                 FROM stripe s JOIN object_manifest m
                   ON s.object_id=m.object_id AND s.generation=m.generation
                 ORDER BY s.object_id, s.generation, s.stripe_index",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)? as u64,
                    r.get::<_, usize>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, i64>(4)? as usize,
                    r.get::<_, i64>(5)? as usize,
                    r.get::<_, i64>(6)? as usize,
                ))
            })?;
            rows.filter_map(|x| x.ok()).collect()
        };
        for (object_id, generation, stripe_index, data_digest, k, parity, shard_size) in keys {
            let coding = CodingParams {
                version: CODING_VERSION.into(),
                data_shards: k,
                parity_shards: parity,
                shard_size,
            };
            self.analyze_stripe(&object_id, generation, stripe_index, &coding, &data_digest)?;
            self.commit_chosen(&object_id, generation, stripe_index, &coding)?;
        }
        Ok(())
    }

    fn load_fragments(&self, object_id: &str, generation: u64, stripe_index: usize) -> Vec<FragRow> {
        let c = self.store.lock();
        let mut stmt = c
            .prepare(
                "SELECT id, generation, stripe_index, shard_index, frag_generation, source,
                        expected_digest, actual_digest, length, expected_length,
                        status, raw_rel_path, reasons
                 FROM fragment
                 WHERE object_id=?1 AND generation=?2 AND stripe_index=?3
                 ORDER BY shard_index, frag_generation, source, id",
            )
            .expect("prepare");
        let rows = stmt
            .query_map(params![object_id, generation, stripe_index], |r| {
                let reasons_s: String = r.get(12)?;
                Ok(FragRow {
                    id: r.get(0)?,
                    generation: r.get::<_, i64>(1)? as u64,
                    stripe_index: r.get(2)?,
                    shard_index: r.get(3)?,
                    frag_generation: r.get::<_, i64>(4)? as u64,
                    source: r.get(5)?,
                    expected_digest: r.get(6)?,
                    actual_digest: r.get::<_, Option<String>>(7)?,
                    length: r.get(8)?,
                    expected_length: r.get(9)?,
                    status: r.get(10)?,
                    raw_rel_path: r.get(11)?,
                    reasons: serde_json::from_str(&reasons_s).unwrap_or_default(),
                })
            })
            .expect("query");
        rows.filter_map(|x| x.ok()).collect()
    }

    /// 删除某 stripe 旧的分析/尝试/方案记录（隔离或新导入后重算）。
    fn reset_analysis(&self, object_id: &str, generation: u64, stripe_index: usize) {
        let c = self.store.lock();
        c.execute(
            "DELETE FROM attempt WHERE object_id=?1 AND generation=?2 AND stripe_index=?3",
            params![object_id, generation, stripe_index],
        )
        .ok();
        c.execute(
            "DELETE FROM solution WHERE object_id=?1 AND generation=?2 AND stripe_index=?3",
            params![object_id, generation, stripe_index],
        )
        .ok();
        c.execute(
            "DELETE FROM stripe_analysis WHERE object_id=?1 AND generation=?2 AND stripe_index=?3",
            params![object_id, generation, stripe_index],
        )
        .ok();
    }

    #[allow(clippy::too_many_arguments)]
    fn analyze_stripe(
        &self,
        object_id: &str,
        generation: u64,
        stripe_index: usize,
        coding: &CodingParams,
        data_digest: &str,
    ) -> Result<(), EngineError> {
        self.reset_analysis(object_id, generation, stripe_index);
        let all = self.load_fragments(object_id, generation, stripe_index);
        let k = coding.k();
        let n = coding.n();
        let shard_size = coding.shard_size;
        let data_len: usize = {
            let c = self.store.lock();
            c.query_row(
                "SELECT data_len FROM stripe WHERE object_id=?1 AND generation=?2 AND stripe_index=?3",
                params![object_id, generation, stripe_index],
                |r| r.get::<_, i64>(0),
            )? as usize
        };

        // 按 shard 编号收集候选（同编号多内容候选），仅 valid 参与组合。
        let mut by_index: BTreeMap<usize, Vec<FragRow>> = BTreeMap::new();
        let mut excluded: Vec<Value> = Vec::new();
        for f in &all {
            if f.status == "valid" {
                by_index.entry(f.shard_index).or_default().push(f.clone());
            } else {
                excluded.push(json!({
                    "fragment_id": f.id,
                    "shard_index": f.shard_index,
                    "source": f.source,
                    "frag_generation": f.frag_generation,
                    "status": f.status,
                    "evidence": f.reasons,
                }));
            }
        }
        let shard_ids: Vec<usize> = by_index.keys().copied().collect();

        // 计数所有候选组合（确定性枚举空间大小）。
        let total_assignments = count_assignments(&by_index, k);
        let truncated = total_assignments > self.budget as u128;

        // 枚举：纯 generation 组合优先；无可行解时再枚举 generation 混杂组合作为证据。
        let mut tested = 0i64;
        let mut seen = 0i64;
        let mut outcomes: Vec<ComboOutcome> = Vec::new();
        let mut stop = false;

        // 第一遍：纯 generation 组合
        for (idxs, choice) in enumerate_assignments(&by_index, k) {
            seen += 1;
            let gens: BTreeSet<u64> = choice.iter().map(|f| f.frag_generation).collect();
            let mixed = gens.len() > 1;
            if mixed {
                continue;
            }
            if tested >= self.budget {
                stop = true;
                break;
            }
            let o = self.evaluate_combo(&choice, coding, data_len, data_digest, tested + 1, false, generation)?;
            tested += 1;
            self.record_attempt(object_id, generation, stripe_index, &o, &idxs)?;
            if o.is_feasible() {
                outcomes.push(o);
            }
        }
        // 第二遍：generation 混杂组合（仅当纯组合无可行解且预算有余）
        if outcomes.is_empty() && !stop {
            for (idxs, choice) in enumerate_assignments(&by_index, k) {
                let gens: BTreeSet<u64> = choice.iter().map(|f| f.frag_generation).collect();
                if gens.len() <= 1 {
                    continue;
                }
                if tested >= self.budget {
                    stop = true;
                    break;
                }
                let o = self.evaluate_combo(&choice, coding, data_len, data_digest, tested + 1, true, generation)?;
                tested += 1;
                self.record_attempt(object_id, generation, stripe_index, &o, &idxs)?;
                if o.is_feasible() {
                    outcomes.push(o);
                }
            }
        }
        let _ = n;

        // 按重算输出摘要分组：同输出的组合互为等价；不同输出保留为多个可行答案。
        let mut groups: BTreeMap<String, Vec<ComboOutcome>> = BTreeMap::new();
        for o in outcomes {
            if let Some(d) = o.output_digest.clone() {
                groups.entry(d).or_default().push(o);
            }
        }
        let distinct_outputs: Vec<String> = groups.keys().cloned().collect();
        let feasible = !groups.is_empty();
        let chosen_digest = distinct_outputs.first().cloned();

        let mut solution_ids: Vec<i64> = Vec::new();
        for (out_digest, group) in &groups {
            // 代表：参与 fragment id 元组字典序最小
            let representative = group
                .iter()
                .min_by(|a, b| a.fragment_ids.cmp(&b.fragment_ids))
                .unwrap();
            let differences = if distinct_outputs.len() > 1 {
                let mut diffs = Vec::new();
                for other in &distinct_outputs {
                    if other == out_digest {
                        continue;
                    }
                    let rep_other = groups.get(other).unwrap().first().unwrap();
                    let offsets = diff_offsets(
                        representative.all_blocks.as_ref().unwrap(),
                        rep_other.all_blocks.as_ref().unwrap(),
                        8,
                    );
                    diffs.push(json!({
                        "other_output_digest": other,
                        "different_offsets_sample": offsets,
                    }));
                }
                diffs
            } else {
                Vec::new()
            };
            let c = self.store.lock();
            c.execute(
                "INSERT INTO solution
                 (object_id, generation, stripe_index, frag_generation, output_digest,
                  fragment_ids, shard_indexes, equivalent_combos, chosen, differences, created_at)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                params![
                    object_id,
                    generation,
                    stripe_index,
                    representative.frag_generation as i64,
                    out_digest,
                    serde_json::to_string(&representative.fragment_ids).unwrap(),
                    serde_json::to_string(&representative.shard_indexes).unwrap(),
                    group.len() as i64,
                    chosen_digest.as_deref() == Some(out_digest.as_str()),
                    serde_json::to_string(&differences).unwrap(),
                    now_ts()
                ],
            )?;
            solution_ids.push(c.last_insert_rowid());
        }

        let failure_reason = if feasible {
            None
        } else {
            Some(self.build_failure_reason(
                &shard_ids,
                k,
                tested,
                stop,
                &excluded,
                object_id,
                generation,
                stripe_index,
            )?)
        };

        {
            let c = self.store.lock();
            c.execute(
                "INSERT INTO stripe_analysis
                 (object_id, generation, stripe_index, feasible, chosen, committed,
                  strategy, combos_seen, combos_tested, truncated, output_digest,
                  failure_reason, updated_at)
                 VALUES(?1,?2,?3,?4,?5,0,?6,?7,?8,?9,?10,?11,?12)",
                params![
                    object_id,
                    generation,
                    stripe_index,
                    feasible,
                    feasible,
                    if feasible { "generation-then-mixed" } else { "exhausted" },
                    total_assignments.min(i64::MAX as u128) as i64,
                    tested,
                    truncated || stop,
                    chosen_digest,
                    failure_reason,
                    now_ts()
                ],
            )?;
        }
        let _ = solution_ids;
        let _ = excluded;
        Ok(())
    }

