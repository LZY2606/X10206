//! 候选集合枚举与可行性判定（不接触数据库，便于确定性测试）。
//!
//! 规则：
//! * 候选选择绝不先到先得——按 (generation 降, source 升, shard_id 升) 排序后枚举；
//! * 每个位置可选任一候选或“缺席”，仅参与数 >= k 的组合才尝试重建；
//! * 组合顺序、可行解排序全部确定；
//! * 枚举设搜索预算，超限置 truncated。

use crate::gf::{GfError, GfField};

#[derive(Debug, Clone)]
pub struct Candidate {
    pub shard_id: i64,
    pub position: usize,
    pub generation: u64,
    pub source: String,
    pub bytes: Vec<u8>,
    /// 0=摘要完整 1=无摘要
    pub health: u8,
}

#[derive(Debug, Clone)]
pub struct FeasibleOutcome {
    /// 重建后的全部 n 块（参与位置为原始字节，缺位置为重算字节）
    pub full: Vec<Vec<u8>>,
    /// 参与计算的候选（按位置升序）
    pub participating_ids: Vec<i64>,
    pub picked_positions: Vec<usize>,
    pub generations: Vec<u64>,
}

pub struct Enumeration {
    pub outcomes: Vec<FeasibleOutcome>,
    pub visited: usize,
    pub truncated: bool,
}

/// 每个位置的候选先确定性排序。
pub fn sort_candidates(cands: &mut Vec<Candidate>) {
    cands.sort_by(|a, b| {
        b.generation
            .cmp(&a.generation)
            .then_with(|| a.source.cmp(&b.source))
            .then_with(|| a.shard_id.cmp(&b.shard_id))
    });
}

struct Dfs<'a> {
    field: &'a GfField,
    k: usize,
    by_pos: &'a [Vec<Candidate>],
    chosen: Vec<Option<usize>>,
    budget: usize,
    visited: usize,
    truncated: bool,
    outcomes: Vec<FeasibleOutcome>,
}

impl<'a> Dfs<'a> {
    fn run(&mut self, pos: usize) {
        if pos == self.by_pos.len() {
            let mut known: Vec<(usize, Vec<u8>)> = Vec::new();
            let mut ids = Vec::new();
            let mut gens = Vec::new();
            let mut positions = Vec::new();
            for (p, choice) in self.chosen.iter().enumerate() {
                if let Some(ci) = choice {
                    let c = &self.by_pos[p][*ci];
                    known.push((p, c.bytes.clone()));
                    ids.push(c.shard_id);
                    gens.push(c.generation);
                    positions.push(p);
                }
            }
            if known.len() >= self.k {
                self.visited += 1;
                if self.visited <= self.budget {
                    match self.field.reconstruct(self.k, self.by_pos.len() - self.k, &known) {
                        Ok(full) => {
                            gens.sort_unstable();
                            gens.dedup();
                            self.outcomes.push(FeasibleOutcome {
                                full,
                                participating_ids: ids,
                                picked_positions: positions,
                                generations: gens,
                            });
                        }
                        // 矛盾（Inconsistent/LengthMismatch 等）= 不可行组合，跳过。
                        Err(_) => {}
                    }
                } else {
                    self.truncated = true;
                }
            }
            return;
        }
        // 候选（已排序）在前，“缺席”在最后：新 generation 组合优先被看到。
        for ci in 0..self.by_pos[pos].len() {
            self.chosen[pos] = Some(ci);
            self.run(pos + 1);
            if self.truncated {
                return;
            }
        }
        self.chosen[pos] = None;
        self.run(pos + 1);
    }
}

pub fn enumerate(
    field: &GfField,
    k: usize,
    n: usize,
    mut by_pos: Vec<Vec<Candidate>>,
    budget: usize,
) -> Result<Enumeration, GfError> {
    if by_pos.len() != n {
        by_pos.resize(n, Vec::new());
    }
    for c in by_pos.iter_mut() {
        sort_candidates(c);
    }
    let mut dfs = Dfs {
        field,
        k,
        by_pos: &by_pos,
        chosen: vec![None; n],
        budget,
        visited: 0,
        truncated: false,
        outcomes: Vec::new(),
    };
    dfs.run(0);
    Ok(Enumeration {
        outcomes: dfs.outcomes,
        visited: dfs.visited,
        truncated: dfs.truncated,
    })
}
