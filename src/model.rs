//! Domain types shared by import, analysis, storage and web layers.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub object_id: String,
    pub coding_version: String,
    pub data_shards: usize,
    pub parity_shards: usize,
    pub shard_size: usize,
    pub stripe_count: usize,
    pub object_digest: String,
    #[serde(default)]
    pub note: String,
}

impl Manifest {
    pub fn total_shards(&self) -> usize {
        self.data_shards + self.parity_shards
    }
}

/// One received shard copy, together with provenance and evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FragmentRecord {
    pub object_id: String,
    pub stripe: usize,
    pub position: usize,
    pub generation: u64,
    pub source: String,
    pub received_digest: Option<String>,
    pub actual_digest: String,
    pub size: usize,
    pub raw_path: String,
    pub digest_matches: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExcludedEvidence {
    pub kind: String,
    pub detail: String,
    pub stripe: usize,
    pub position: Option<usize>,
    pub source: String,
    pub generation: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ParticipatingShard {
    pub stripe: usize,
    pub position: usize,
    pub generation: u64,
    pub source: String,
    pub shard_digest: String,
    pub present_before: bool,
}

/// One viable reconstruction for a single stripe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StripeFeasibleSet {
    pub stripe: usize,
    pub generation_profile: String,
    pub score: i64,
    pub used: Vec<ParticipatingShard>,
    pub excluded: Vec<ExcludedEvidence>,
    pub data_digest: String,
    pub shard_digests: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ObjectSolution {
    pub object_id: String,
    pub sets: Vec<StripeFeasibleSet>,
    pub object_digest: String,
    pub digest_match: bool,
}
