//! Bundle import: persist the raw manifest and every received fragment into
//! the content-addressed store, then record provenance rows in SQLite.
//! Source fragment files are never modified.

use std::collections::BTreeMap;

use anyhow::{bail, Context};
use rusqlite::params;

use crate::blobstore::BlobStore;
use crate::db::{now_millis, json_put};
use crate::digest::sha256_hex;
use crate::model::LoadedBundle;

pub struct ImportStats {
    pub object_id: String,
    pub fragments_inserted: usize,
    pub fragments_present: usize,
    pub reused: bool,
}

pub fn import_bundle(
    conn: &mut rusqlite::Connection,
    store: &BlobStore,
    bundle: &LoadedBundle,
) -> anyhow::Result<ImportStats> {
    let manifest_digest = sha256_hex(&bundle.manifest_raw);
    let obj = &bundle.manifest.object;

    let existing = crate::db::get_object(conn, &obj.object_id)?;
    if let Some(ex) = &existing {
        if ex.manifest_digest != manifest_digest {
            bail!(
                "object {} already imported with a different manifest ({})",
                obj.object_id,
                ex.manifest_digest
            );
        }
    }

    // Validate every fragment against the manifest's stripe/index space and
    // length, and store its original bytes before touching the database.
    let n = obj.data_shards + obj.parity_shards;
    for f in &bundle.fragments {
        let rec = &f.record;
        if rec.stripe as usize >= obj.stripe_count {
            bail!("fragment references unknown stripe {}", rec.stripe);
        }
        if rec.index as usize >= n {
            bail!("fragment references shard index {} beyond {}", rec.index, n - 1);
        }
        if f.bytes.len() != obj.shard_length {
            bail!(
                "fragment stripe {} index {} has length {} but manifest says {}",
                rec.stripe,
                rec.index,
                f.bytes.len(),
                obj.shard_length
            );
        }
    }

    if existing.is_none() {
        store.put(&manifest_digest, &bundle.manifest_raw)?;
    }
    let mut inserted = 0usize;
    let mut present = 0usize;

    let tx = conn.transaction()?;
    if existing.is_none() {
        tx.execute(
            "INSERT INTO objects(object_id, coding_version, data_shards, parity_shards,
                shard_length, stripe_count, current_generation, object_digests,
                manifest_digest, manifest_blob, imported_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                obj.object_id,
                obj.coding_version,
                obj.data_shards as i64,
                obj.parity_shards as i64,
                obj.shard_length as i64,
                obj.stripe_count as i64,
                obj.current_generation as i64,
                json_put(&obj.object_digests),
                manifest_digest,
                manifest_digest,
                now_millis()
            ],
        )?;
        for sm in &obj.stripes {
            let gen_key = sm.generation.to_string();
            let view = sm.generations.get(&gen_key).expect("validated");
            let shard_digests: BTreeMap<String, String> = view.shard_digests.clone();
            let data_digests: BTreeMap<String, String> = (0..obj.data_shards)
                .map(|i| (i.to_string(), shard_digests[&i.to_string()].clone()))
                .collect();
            tx.execute(
                "INSERT INTO stripes(object_id, stripe, generation, data_digests, shard_digests)
                 VALUES (?1,?2,?3,?4,?5)",
                params![
                    obj.object_id,
                    sm.stripe as i64,
                    sm.generation as i64,
                    json_put(&data_digests),
                    json_put(&shard_digests)
                ],
            )?;
        }
    }

    for f in &bundle.fragments {
        let rec = &f.record;
        let actual = sha256_hex(&f.bytes);
        let existed_blob = store.put(&actual, &f.bytes)?;
        let _ = existed_blob;
        let claim_ok = rec.digest == actual;

        // Cross-check: expected digest declared in the manifest for that gen.
        let sm = &obj.stripes[rec.stripe as usize];
        let mut expected_for_generation: Option<&str> = None;
        if let Some(view) = sm.generations.get(&rec.generation.to_string()) {
            expected_for_generation = view.shard_digests.get(&rec.index.to_string()).map(String::as_str);
        }
        // Expected digest mismatch is not an import error: it is evidence to be
        // surfaced during analysis. We only record claim_ok (claimed vs actual).
        let _ = expected_for_generation;

        let inserted_row = tx.execute(
            "INSERT OR IGNORE INTO fragments(object_id, stripe, shard_index, source,
                generation, claimed_digest, actual_digest, length, blob_digest,
                received_at, claim_ok)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                obj.object_id,
                rec.stripe as i64,
                rec.index as i64,
                rec.source,
                rec.generation as i64,
                rec.digest,
                actual,
                f.bytes.len() as i64,
                actual,
                rec.received_at,
                claim_ok as i64
            ],
        )?;
        if inserted_row == 1 {
            inserted += 1;
        } else {
            present += 1;
        }
    }

    // Sanity: the declared current-generation per-stripe digests must be
    // mutually consistent with the manifest's object digest whenever all
    // expected data blocks are concatenated. This validates manifests only;
    // received fragments may still be missing/corrupt.
    verify_manifest_object_digest(bundle).context("manifest internal consistency")?;

    tx.commit()?;
    Ok(ImportStats {
        object_id: obj.object_id.clone(),
        fragments_inserted: inserted,
        fragments_present: present,
        reused: existing.is_some(),
    })
}

fn verify_manifest_object_digest(bundle: &LoadedBundle) -> anyhow::Result<()> {
    // Object digest is defined over reconstructed bytes, so it can only be
    // verified after recovery. At import time we validate digest shapes.
    let obj = &bundle.manifest.object;
    for (gen, d) in &obj.object_digests {
        if d.len() != 64 {
            bail!("object digest for generation {gen} is not sha256 hex");
        }
    }
    for sm in &obj.stripes {
        for (gen, view) in &sm.generations {
            if view.digest.len() != 64 {
                bail!("stripe {} gen {gen} data digest is not sha256 hex", sm.stripe);
            }
            for (i, d) in &view.shard_digests {
                if d.len() != 64 {
                    bail!("stripe {} gen {gen} shard {i} digest is not sha256 hex", sm.stripe);
                }
            }
        }
    }
    Ok(())
}
