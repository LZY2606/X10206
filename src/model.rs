//! On-disk import format: a versioned manifest plus received fragments.
//!
//! A bundle directory contains:
//! - `manifest.json`        versioned object description
//! - `fragments.jsonl`      one received-fragment record per line
//! - the fragment files referenced by the records (any filenames)
//!
//! The manifest is the authority on coding parameters and expected per-block
//! digests; `fragments.jsonl` preserves the *claimed* digest and the source a
//! fragment arrived from. Duplicate shard numbers are intentionally allowed.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};

pub const IMPORT_FORMAT: &str = "srp-import-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestFile {
    pub format_version: String,
    #[serde(rename = "object")]
    pub object: ManifestObject,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestObject {
    pub object_id: String,
    pub coding_version: String,
    pub data_shards: usize,
    pub parity_shards: usize,
    pub shard_length: usize,
    pub stripe_count: usize,
    pub current_generation: u64,
    pub object_digests: BTreeMap<String, String>,
    pub stripes: Vec<StripeManifest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeManifest {
    pub stripe: u32,
    pub generation: u64,
    #[serde(default)]
    pub generations: BTreeMap<String, GenView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenView {
    pub digest: String,
    pub shard_digests: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceivedRecord {
    pub file: String,
    pub stripe: u32,
    pub index: u32,
    pub source: String,
    pub generation: u64,
    pub digest: String,
    pub received_at: String,
}

#[derive(Debug, Clone)]
pub struct ReceivedFragment {
    pub record: ReceivedRecord,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct LoadedBundle {
    pub manifest_raw: Vec<u8>,
    pub manifest: ManifestFile,
    pub fragments: Vec<ReceivedFragment>,
}

impl ManifestFile {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.format_version != IMPORT_FORMAT {
            bail!("unsupported import format version: {}", self.format_version);
        }
        let o = &self.object;
        if o.coding_version != crate::coding::CODE_VERSION {
            bail!("unsupported coding version: {}", o.coding_version);
        }
        crate::coding::CodingParams::new(o.data_shards, o.parity_shards)?;
        if o.shard_length == 0 {
            bail!("shard_length must be positive");
        }
        if o.stripe_count == 0 {
            bail!("stripe_count must be positive");
        }
        if o.stripes.len() != o.stripe_count {
            bail!(
                "manifest declares {} stripes but lists {}",
                o.stripe_count,
                o.stripes.len()
            );
        }
        let n = (o.data_shards + o.parity_shards) as u32;
        for (pos, s) in o.stripes.iter().enumerate() {
            if s.stripe as usize != pos {
                bail!("stripe list not in order at position {pos}");
            }
            let key = s.generation.to_string();
            let view = s
                .generations
                .get(&key)
                .with_context(|| format!("stripe {} missing view for generation {}", s.stripe, s.generation))?;
            if view.shard_digests.len() != o.data_shards + o.parity_shards {
                bail!("stripe {} generation {} should list exactly {n} shard digests", s.stripe, s.generation);
            }
            for i in 0..n {
                if !view.shard_digests.contains_key(&i.to_string()) {
                    bail!("stripe {} generation {} missing digest for shard {i}", s.stripe, s.generation);
                }
            }
        }
        if !o.object_digests.contains_key(&o.current_generation.to_string()) {
            bail!("object digests missing current generation {}", o.current_generation);
        }
        Ok(())
    }
}

pub fn load_bundle(dir: &Path) -> anyhow::Result<LoadedBundle> {
    let manifest_path = dir.join("manifest.json");
    let manifest_raw = std::fs::read(&manifest_path)
        .with_context(|| format!("reading {}", manifest_path.display()))?;
    let manifest: ManifestFile = serde_json::from_slice(&manifest_raw).context("parsing manifest")?;
    manifest.validate()?;

    let frag_path = dir.join("fragments.jsonl");
    let lines = std::fs::read_to_string(&frag_path)
        .with_context(|| format!("reading {}", frag_path.display()))?;
    let mut fragments = Vec::new();
    for (lineno, line) in lines.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let record: ReceivedRecord =
            serde_json::from_str(line).with_context(|| format!("fragments.jsonl line {}", lineno + 1))?;
        let bytes = std::fs::read(dir.join(&record.file))
            .with_context(|| format!("reading fragment {}", record.file))?;
        fragments.push(ReceivedFragment { record, bytes });
    }
    if fragments.is_empty() {
        bail!("bundle contains no received fragments");
    }
    Ok(LoadedBundle { manifest_raw, manifest, fragments })
}
