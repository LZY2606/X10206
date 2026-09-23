//! 共享领域类型：摘要、证据、故障注入。

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

pub const DIGEST_ALG: &str = "sha256";

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// 对象摘要：按 stripe 升序、slot 升序拼接所有 shard 原始字节后取 SHA-256。
/// 摘要的具体排列规则属于版本化 manifest 的一部分（alg=sha256,layout=stripe-grid）。
pub fn object_digest_hex(grid: &[Vec<Vec<u8>>]) -> String {
    let mut h = Sha256::new();
    for stripe in grid {
        for shard in stripe {
            h.update(shard);
        }
    }
    hex::encode(h.finalize())
}

/// 证据种类：每一条被排除的候选或不可行组合都必须落库，不能只报“失败”。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// manifest 声明长度与实际字节数不符。
    LengthMismatch,
    /// 字节落在编码域之外（GF16 出现 >15 的符号）。
    OutOfField,
    /// 随碎片提供的 shard 摘要与重算摘要不符。
    DigestMismatch,
    /// 同一 (stripe,slot) 收到多个不同内容候选。
    DuplicateSlot,
    /// 同一组合内候选的 generation 不一致（部分写）。
    GenerationMix,
    /// 参与 shard 不足 k 个，线性方程组秩不足。
    RankDeficient,
    /// 超定校验时冗余行与解矛盾（典型位翻转）。
    Contradiction,
    /// 搜索预算耗尽，未枚举完全。
    BudgetExhausted,
    /// 组合本身可行但使用了摘要损坏的候选，仅作备选。
    TaintedAlternative,
    /// 临时块 / 中断残留，恢复时不得读取。
    StaleTempBlock,
    /// 写盘失败（注入或真实 I/O 错误）。
    WriteFailure,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EvidenceKind::LengthMismatch => "length_mismatch",
            EvidenceKind::OutOfField => "out_of_field",
            EvidenceKind::DigestMismatch => "digest_mismatch",
            EvidenceKind::DuplicateSlot => "duplicate_slot",
            EvidenceKind::GenerationMix => "generation_mix",
            EvidenceKind::RankDeficient => "rank_deficient",
            EvidenceKind::Contradiction => "contradiction",
            EvidenceKind::BudgetExhausted => "budget_exhausted",
            EvidenceKind::TaintedAlternative => "tainted_alternative",
            EvidenceKind::StaleTempBlock => "stale_temp_block",
            EvidenceKind::WriteFailure => "write_failure",
        }
    }

    pub fn parse(s: &str) -> EvidenceKind {
        match s {
            "length_mismatch" => Self::LengthMismatch,
            "out_of_field" => Self::OutOfField,
            "digest_mismatch" => Self::DigestMismatch,
            "duplicate_slot" => Self::DuplicateSlot,
            "generation_mix" => Self::GenerationMix,
            "rank_deficient" => Self::RankDeficient,
            "contradiction" => Self::Contradiction,
            "budget_exhausted" => Self::BudgetExhausted,
            "tainted_alternative" => Self::TaintedAlternative,
            "stale_temp_block" => Self::StaleTempBlock,
            "write_failure" => Self::WriteFailure,
            other => panic!("未知证据种类 {other}"),
        }
    }
}

/// 磁盘写故障注入门：默认放行；测试可令下一次或全部写入失败。
#[derive(Default)]
pub struct FaultGate {
    fail_all: AtomicBool,
    fail_after: Mutex<Option<u64>>,
    counter: AtomicU64,
    pub failed_count: AtomicU64,
}

impl FaultGate {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn fail_all(&self, on: bool) {
        self.fail_all.store(on, Ordering::SeqCst);
    }

    /// 再发生 `n` 次写后，让紧随其后的那一次写失败。
    pub fn fail_once_after(self: &Arc<Self>, n: u64) {
        *self.fail_after.lock().unwrap() = Some(n);
    }

    pub fn reset(self: &Arc<Self>) {
        self.fail_all.store(false, Ordering::SeqCst);
        *self.fail_after.lock().unwrap() = None;
        self.counter.store(0, Ordering::SeqCst);
        self.failed_count.store(0, Ordering::SeqCst);
    }

    pub fn writes_seen(&self) -> u64 {
        self.counter.load(Ordering::SeqCst)
    }

    /// 每次写文件前调用；返回 Err 时调用方必须模拟写失败。
    pub fn ticket(&self) -> Result<(), String> {
        let n = self.counter.fetch_add(1, Ordering::SeqCst) + 1;
        let mut fail = self.fail_all.load(Ordering::SeqCst);
        let mut after = self.fail_after.lock().unwrap();
        if let Some(target) = *after {
            if n > target {
                fail = true;
                *after = None;
            }
        }
        if fail {
            self.failed_count.fetch_add(1, Ordering::SeqCst);
            Err("injected disk write failure".to_string())
        } else {
            Ok(())
        }
    }
}
