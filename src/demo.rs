use crate::coding::encode;
use crate::ingest;
use crate::model::{ManifestFile, ManifestShard, ManifestStripe};
use crate::store::{sha256_hex, Store};
use std::fs;
use std::path::Path;

pub fn bootstrap_demo_if_empty(data_dir: &Path) -> std::io::Result<()> {
    let inbox = data_dir.join("inbox");
    fs::create_dir_all(&inbox)?;
    let nonempty = fs::read_dir(&inbox)?.any(|entry| entry.map(|e| e.path().exists()).unwrap_or(false));
    if nonempty {
        return Ok(());
    }
    let scenarios = vec![
        ("demo_alpha", 1, 2, 1, 8, vec!["alpha-a", "alpha-b"], vec![(0, vec![2]), (1, vec![0])]),
        ("demo_boundary", 2, 2, 1, 6, vec!["boundary-a", "boundary-b"], vec![(0, vec![2]), (1, vec![2])]),
        ("demo_duplicate", 3, 2, 1, 8, vec!["duplicate-a", "duplicate-b"], vec![(0, vec![2]), (1, vec![2])]),
        ("demo_generation_mix", 4, 2, 1, 8, vec!["genmix-old", "genmix-new"], vec![(0, vec![2]), (1, vec![])]),
        ("demo_bitflip", 5, 2, 1, 8, vec!["bitflip-a", "bitflip-b"], vec![(0, vec![]), (1, vec![2])]),
        ("demo_bad_length", 6, 2, 1, 8, vec!["badlen-a"], vec![(0, vec![2]), (1, vec![0, 1, 2])]),
        ("demo_below", 7, 3, 2, 8, vec!["below-a"], vec![(0, vec![0, 2, 3, 4]), (1, vec![1, 2, 3, 4])]),
    ];
    for scenario in scenarios {
        write_scenario(data_dir, scenario)?;
    }
    let store = Store::open(data_dir).map_err(|e| std::io::Error::other(e.to_string()))?;
    ingest::ingest_inbox(&store)?;
    Ok(())
}

#[allow(clippy::type_complexity)]
fn write_scenario(
    data_dir: &Path,
    scenario: (&str, i64, usize, usize, usize, Vec<&str>, Vec<(usize, Vec<usize>)>),
) -> std::io::Result<()> {
    let (object_id, generation, k, m, stripe_size, sources, missing) = scenario;
    let mut payload = Vec::new();
    for byte in 0..(stripe_size * 2 - 3) {
        payload.push((byte as u8).wrapping_mul(7).wrapping_add(generation as u8));
    }
    let mut stripes = Vec::new();
    let mut all_shards: Vec<Vec<Vec<u8>>> = Vec::new();
    for stripe_index in 0..2 {
        let start = stripe_index * k * stripe_size;
        let mut logical = vec![0u8; k * stripe_size];
        let end = (start + logical.len()).min(payload.len());
        if start < payload.len() {
            logical[..end - start].copy_from_slice(&payload[start..end]);
        }
        let data: Vec<Vec<u8>> = (0..k).map(|i| logical[i * stripe_size..(i + 1) * stripe_size].to_vec()).collect();
        let parity = encode(&data, m, stripe_size);
        let mut shards = data;
        shards.extend(parity);
        let mut shard_specs = Vec::new();
        for (index, bytes) in shards.iter().enumerate() {
            shard_specs.push(ManifestShard { index, generation, length: bytes.len(), sha256: sha256_hex(bytes) });
        }
        stripes.push(ManifestStripe {
            index: stripe_index,
            data_len: logical.len().min(payload.len().saturating_sub(start)),
            sha256: sha256_hex(&logical[..logical.len().min(payload.len().saturating_sub(start))]),
            shards: shard_specs,
        });
        all_shards.push(shards);
    }
    let object_digest = sha256_hex(&payload);
    let manifest = ManifestFile {
        schema: "stripes-recovery-pod/v1".to_string(),
        object_id: object_id.to_string(),
        object_size: payload.len(),
        generation,
        data_shards: k,
        parity_shards: m,
        stripe_size,
        object_sha256: object_digest,
        stripes,
    };
    for (source_index, source) in sources.iter().enumerate() {
        let dir = data_dir.join("inbox").join(source);
        fs::create_dir_all(&dir)?;
        if source_index == 0 {
            let manifest_path = dir.join(format!("{object_id}.manifest.json"));
            fs::write(manifest_path, serde_json::to_vec_pretty(&manifest).unwrap())?;
        }
        for (stripe_index, shards) in all_shards.iter().enumerate() {
            let missing_list = &missing[stripe_index].1;
            for (shard_index, bytes) in shards.iter().enumerate() {
                if missing_list.contains(&shard_index) {
                    continue;
                }
                let source_rank = source_index as u8;
                let mut output = bytes.clone();
                let mut file_generation = generation;
                if object_id == "demo_duplicate" && source_index == 1 && shard_index == 0 {
                    // Same content and same shard number from a second source.
                }
                if object_id == "demo_bitflip" && source_index == 1 && shard_index == 1 && stripe_index == 0 {
                    output[3] ^= 0x01;
                }
                if object_id == "demo_generation_mix" && source_index == 0 && shard_index == 0 {
                    file_generation = generation - 1;
                }
                if object_id == "demo_bad_length" && source_index == 0 && shard_index == 1 && stripe_index == 0 {
                    output.truncate(output.len() - 2);
                }
                if object_id == "demo_duplicate" && source_index == 1 && shard_index != 0 {
                    continue;
                }
                if object_id == "demo_bitflip" && source_index == 1 && shard_index != 1 {
                    continue;
                }
                if object_id == "demo_boundary" && source_index == 1 && shard_index == 2 {
                    // Parity is absent; the healthy sources together provide exactly k.
                    continue;
                }
                let name = format!("shard-{object_id}-{file_generation}-{stripe_index}-{shard_index}.bin");
                let path = dir.join(&name);
                fs::write(&path, &output)?;
                fs::write(format!("{}.sha256", path.display()), format!("{}  {name}\n", sha256_hex(&output)))?;
                let _ = source_rank;
            }
        }
    }
    Ok(())
}
