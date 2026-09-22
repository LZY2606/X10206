//! Stripe-scoped recovery: deterministic candidate enumeration, evidence
//! accounting, per-stripe atomic commits and crash-safe reuse.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use rusqlite::{params, Connection};
use serde_json::json;

use crate::coding::{recover, CodingParams};
use crate::gf256::Field;
use crate::model::{sha256_hex, FragmentFlag, StripeStatus};
use crate::store::{Store, FAULT_COMMIT_WRITE};

/// Deterministic cap on candidate combinations evaluated per stripe.
pub const DEFAULT_STRIPE_BUDGET: u64 = 1024;
/// Deterministic cap on stripe-set combinations when object digest breaks ties.
pub const DEFAULT_OBJECT_BUDGET: u64 = 256;

#[derive(Debug, Clone)]
pub struct Candidate {
    pub uid: i64,
    pub source_id: String,
    pub generation: u64,
    pub bytes: Vec<u8>,
    pub computed_digest: String,
    pub declared_digest: Option<String>,
    pub hard_flagged: bool,
    pub wrong_generation: bool,
    pub flags: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RejectedSet {
    pub chosen_uids: Vec<i64>,
    pub generation_mix: bool,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct FeasibleSet {
    pub ordinal: usize,
    pub chosen_uids: Vec<i64>,
    pub chosen_indices: Vec<usize>,
    pub generation: u64,
    pub output_digests: BTreeMap<usize, String>,
    pub output_bytes: BTreeMap<usize, Vec<u8>>,
    pub excluded: Vec<ExcludedEvidence>,
    pub matches_declared: bool,
}

#[derive(Debug, Clone)]
pub struct ExcludedEvidence {
    pub uid: Option<i64>,
    pub shard_index: usize,
    pub source_id: String,
    pub reason: String,
    pub computed_digest: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StripeAnalysis {
    pub stripe_index: usize,
    pub params: CodingParams,
    pub candidates: BTreeMap<usize, Vec<Candidate>>,
    pub feasible: Vec<FeasibleSet>,
    pub rejected: Vec<RejectedSet>,
    pub budget_hit: bool,
    pub inspected: u64,
    pub difference_summary: String,
}
