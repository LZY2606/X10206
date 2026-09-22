use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParamsV1 {
    pub k: usize,
    pub n: usize,
    pub stripe_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scheme", rename_all = "snake_case")]
pub enum EncodingSpec {
    CauchyGf256V1(ParamsV1),
}

impl EncodingSpec {
    pub fn k(&self) -> usize {
        match self {
            Self::CauchyGf256V1(params) => params.k,
        }
    }

    pub fn n(&self) -> usize {
        match self {
            Self::CauchyGf256V1(params) => params.n,
        }
    }

    pub fn stripe_size(&self) -> usize {
        match self {
            Self::CauchyGf256V1(params) => params.stripe_size,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedShard {
    pub index: usize,
    #[serde(default)]
    pub length: Option<usize>,
    #[serde(default)]
    pub digest_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StripeSpec {
    pub index: usize,
    #[serde(default)]
    pub data_digest_sha256: Option<String>,
    #[serde(default)]
    pub shards: Vec<ExpectedShard>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub manifest_version: String,
    pub encoding: EncodingSpec,
    #[serde(default)]
    pub object_digest_sha256: Option<String>,
    pub stripe_count: usize,
    #[serde(default)]
    pub stripes: Vec<StripeSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceivedFragmentInput {
    pub fragment_id: String,
    pub source_id: String,
    pub stripe_index: usize,
    pub shard_index: usize,
    #[serde(default)]
    pub generation: i64,
    #[serde(with = "hex_bytes")]
    pub bytes: Vec<u8>,
    #[serde(default)]
    pub received_at: i64,
    #[serde(default)]
    pub claimed_digest_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportBundle {
    pub manifest: Manifest,
    #[serde(default)]
    pub fragments: Vec<ReceivedFragmentInput>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate<'a> {
    pub fragment: &'a ReceivedFragmentInput,
    pub actual_digest: String,
    pub generation_consistent: bool,
    pub length_ok: bool,
    pub digest_ok: bool,
}

impl<'a> Candidate<'a> {
    pub fn eligible(&self) -> bool {
        self.generation_consistent && self.length_ok && self.digest_ok
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExcludedEvidence {
    pub fragment_id: String,
    pub source_id: String,
    pub shard_index: usize,
    pub generation: i64,
    pub actual_digest_sha256: String,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ParticipatingShard {
    pub shard_index: usize,
    pub fragment_id: String,
    pub source_id: String,
    pub generation: i64,
    pub length: usize,
    pub digest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecomputedShardDigest {
    pub index: usize,
    pub length: usize,
    pub digest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SolutionReport {
    pub solution_id: String,
    pub generation: i64,
    pub participating: Vec<ParticipatingShard>,
    pub excluded: Vec<ExcludedEvidence>,
    pub reconstructed_indices: Vec<usize>,
    pub recomputed_shard_digests: Vec<RecomputedShardDigest>,
    pub recomputed_data_digest_sha256: String,
    pub object_reconstruction_digest_sha256: String,
    pub matches_object_digest: Option<bool>,
    pub object_digest_inputs: usize,
    pub trust: String,
    pub differences_from_primary: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ShardHealth {
    pub shard_index: usize,
    pub eligible_candidate_count: usize,
    pub rejected_candidate_count: usize,
    pub selected_generation: Option<i64>,
    pub best_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StripeAnalysis {
    pub stripe_index: usize,
    pub available_indices: usize,
    pub threshold: usize,
    pub recoverable: bool,
    pub search_budget: usize,
    pub combinations_considered: usize,
    pub budget_exhausted: bool,
    pub solutions: Vec<SolutionReport>,
    pub rejected: Vec<ExcludedEvidence>,
    pub shard_health: Vec<ShardHealth>,
}

pub mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let value = String::deserialize(deserializer)?;
        hex::decode(value.trim_start_matches("0x")).map_err(serde::de::Error::custom)
    }
}
