use std::path::Path;

use crate::coding::{CODE_VERSION, CodeParams, encode};
use crate::import::import_directory;
use crate::model::{Manifest, ManifestShard, StoredShardKind};
use crate::store::{Storage, digest_hex};

fn write_fixture(
    root: &Path,
    manifest: &Manifest,
    stripe: usize,
    kind: StoredShardKind,
    index: usize,
    generation: u64,
    source: &str,
    bytes: &[u8],
    expected_digest: Option<&str>,
    include_file: bool,
    tamper: bool,
) {
    if !include_file {
        return;
    }
    let dir = root.join(format!("stripe-{stripe}"));
    std::fs::create_dir_all(&dir).unwrap();
    let kind_name = if kind == StoredShardKind::Data { "data" } else { "parity" };
    let filename = format!("{kind_name}_i{index:04}_g{generation:020}_{source}.bin");
    let path = dir.join(&filename);
    let mut actual = bytes.to_vec();
    if tamper {
        actual[0] ^= 0x01;
    }
    std::fs::write(&path, &actual).unwrap();
    std::fs::write(path.with_extension("bin.digest"), format!("{}\n", digest_hex(&actual))).unwrap();
    let _ = expected_digest;
}

fn manifest_shard(stripe: usize, kind: StoredShardKind, index: usize, generation: u64, length: usize, digest: Option<String>) -> ManifestShard {
    ManifestShard {
        stripe,
        kind,
        index,
        generation: Some(generation),
        length: Some(length),
        digest,
    }
}

fn make_manifest(
    object_id: &str,
    params: CodeParams,
    shard_size: usize,
    generation: u64,
    object_digest: Option<String>,
    shards: Vec<ManifestShard>,
) -> Manifest {
    Manifest {
        schema_version: "manifest.v1".to_string(),
        code_version: CODE_VERSION.to_string(),
        object_id: object_id.to_string(),
        object_size: (params.data_shards * shard_size) as u64,
        object_digest,
        generation,
        data_shards: params.data_shards,
        parity_shards: params.parity_shards,
        shard_size,
        stripe_count: 1,
        shards,
    }
}

pub fn seed_demo(storage: &Storage) -> std::io::Result<usize> {
    if storage.object_count()? > 0 {
        return Ok(0);
    }
    let fixture_root = storage.root().join("fixtures");
    std::fs::create_dir_all(&fixture_root)?;
    let mut count = 0;

    {
        let params = CodeParams { data_shards: 2, parity_shards: 1 };
        let data = vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8]];
        let encoded = encode(&data, params);
        let digest = digest_hex(&[1u8, 2, 3, 4, 5, 6, 7, 8]);
        let mut shards = Vec::new();
        for index in 0..params.data_shards {
            shards.push(manifest_shard(0, StoredShardKind::Data, index, 1, 4, Some(digest_hex(&encoded.data[index]))));
        }
        shards.push(manifest_shard(0, StoredShardKind::Parity, 0, 1, 4, Some(digest_hex(&encoded.parity[0]))));
        let manifest = make_manifest("alpha-healthy", params, 4, 1, Some(digest), shards);
        let root = fixture_root.join("alpha");
        std::fs::create_dir_all(&root)?;
        std::fs::write(root.join("manifest.json"), serde_json::to_vec_pretty(&manifest)?).unwrap();
        for index in 0..params.data_shards {
            write_fixture(&root, &manifest, 0, StoredShardKind::Data, index, 1, "nodeA", &encoded.data[index], None, true, false);
        }
        import_directory(storage, &root, "fixture/alpha")?;
        count += 1;
    }

    {
        let params = CodeParams { data_shards: 2, parity_shards: 1 };
        let data = vec![vec![10, 20, 30, 40], vec![50, 60, 70, 80]];
        let encoded = encode(&data, params);
        let digest = digest_hex(&[10u8, 20, 30, 40, 50, 60, 70, 80]);
        let mut shards = vec![
            manifest_shard(0, StoredShardKind::Data, 0, 1, 4, Some(digest_hex(&encoded.data[0]))),
            manifest_shard(0, StoredShardKind::Data, 1, 1, 4, Some(digest_hex(&encoded.data[1]))),
            manifest_shard(0, StoredShardKind::Parity, 0, 1, 4, Some(digest_hex(&encoded.parity[0]))),
        ];
        shards[1].length = Some(3);
        let manifest = make_manifest("beta-boundary", params, 4, 1, Some(digest), shards);
        let root = fixture_root.join("beta");
        std::fs::create_dir_all(&root)?;
        std::fs::write(root.join("manifest.json"), serde_json::to_vec_pretty(&manifest)?).unwrap();
        write_fixture(&root, &manifest, 0, StoredShardKind::Data, 0, 1, "nodeA", &encoded.data[0], None, true, false);
        write_fixture(&root, &manifest, 0, StoredShardKind::Data, 1, 1, "nodeB", &encoded.data[1], None, false, false);
        write_fixture(&root, &manifest, 0, StoredShardKind::Parity, 0, 1, "nodeC", &encoded.parity[0], None, true, false);
        import_directory(storage, &root, "fixture/beta")?;
        count += 1;
    }

    {
        let params = CodeParams { data_shards: 3, parity_shards: 2 };
        let data = vec![vec![9, 8, 7, 6], vec![5, 4, 3, 2], vec![11, 12, 13, 14]];
        let encoded = encode(&data, params);
        let mut flat = Vec::new();
        data.iter().for_each(|shard| flat.extend(shard));
        let digest = digest_hex(&flat);
        let mut shards = Vec::new();
        for index in 0..params.data_shards {
            shards.push(manifest_shard(0, StoredShardKind::Data, index, 1, 4, Some(digest_hex(&encoded.data[index]))));
        }
        for index in 0..params.parity_shards {
            shards.push(manifest_shard(0, StoredShardKind::Parity, index, 1, 4, Some(digest_hex(&encoded.parity[index]))));
        }
        let manifest = make_manifest("gamma-corruption", params, 4, 1, Some(digest), shards);
        let root = fixture_root.join("gamma");
        std::fs::create_dir_all(&root)?;
        std::fs::write(root.join("manifest.json"), serde_json::to_vec_pretty(&manifest)?).unwrap();
        write_fixture(&root, &manifest, 0, StoredShardKind::Data, 0, 1, "nodeA", &encoded.data[0], None, true, false);
        write_fixture(&root, &manifest, 0, StoredShardKind::Data, 0, 1, "nodeB", &encoded.data[0], None, true, false);
        write_fixture(&root, &manifest, 0, StoredShardKind::Data, 1, 1, "nodeC", &encoded.data[1], None, true, false);
        write_fixture(&root, &manifest, 0, StoredShardKind::Data, 2, 1, "nodeD", &encoded.data[2], None, false, false);
        write_fixture(&root, &manifest, 0, StoredShardKind::Parity, 0, 1, "nodeE", &encoded.parity[0], None, true, true);
        write_fixture(&root, &manifest, 0, StoredShardKind::Parity, 1, 1, "nodeF", &encoded.parity[1], None, true, false);
        import_directory(storage, &root, "fixture/gamma")?;
        count += 1;
    }

    {
        let params = CodeParams { data_shards: 2, parity_shards: 1 };
        let new_data = vec![vec![31, 32, 33, 34], vec![35, 36, 37, 38]];
        let new_encoded = encode(&new_data, params);
        let old_data = vec![vec![131, 132, 133, 134], vec![135, 136, 137, 138]];
        let old_encoded = encode(&old_data, params);
        let digest = digest_hex(&[31u8, 32, 33, 34, 35, 36, 37, 38]);
        let mut shards = Vec::new();
        for index in 0..params.data_shards {
            shards.push(manifest_shard(0, StoredShardKind::Data, index, 2, 4, Some(digest_hex(&new_encoded.data[index]))));
            shards.push(manifest_shard(0, StoredShardKind::Data, index, 1, 4, Some(digest_hex(&new_encoded.data[index]))));
        }
        shards.push(manifest_shard(0, StoredShardKind::Parity, 0, 2, 4, Some(digest_hex(&new_encoded.parity[0]))));
        shards.push(manifest_shard(0, StoredShardKind::Parity, 0, 1, 4, Some(digest_hex(&new_encoded.parity[0]))));
        let manifest = make_manifest("delta-generations", params, 4, 2, Some(digest), shards);
        let root = fixture_root.join("delta");
        std::fs::create_dir_all(&root)?;
        std::fs::write(root.join("manifest.json"), serde_json::to_vec_pretty(&manifest)?).unwrap();
        write_fixture(&root, &manifest, 0, StoredShardKind::Data, 0, 2, "newA", &new_encoded.data[0], None, true, false);
        write_fixture(&root, &manifest, 0, StoredShardKind::Data, 1, 2, "newB", &new_encoded.data[1], None, true, false);
        write_fixture(&root, &manifest, 0, StoredShardKind::Data, 0, 1, "oldA", &old_encoded.data[0], None, true, false);
        write_fixture(&root, &manifest, 0, StoredShardKind::Parity, 0, 1, "oldP", &old_encoded.parity[0], None, true, false);
        import_directory(storage, &root, "fixture/delta")?;
        count += 1;
    }

    {
        let params = CodeParams { data_shards: 2, parity_shards: 1 };
        let data = vec![vec![91, 92, 93, 94], vec![95, 96, 97, 98]];
        let encoded = encode(&data, params);
        let alternate_data = vec![encoded.data[0].clone(), vec![1, 1, 1, 1]];
        let alternate = encode(&alternate_data, params);
        let shards = vec![
            manifest_shard(0, StoredShardKind::Data, 0, 1, 4, None),
            manifest_shard(0, StoredShardKind::Data, 1, 1, 4, None),
            manifest_shard(0, StoredShardKind::Parity, 0, 1, 4, None),
        ];
        let manifest = make_manifest("zeta-ambiguous", params, 4, 1, None, shards);
        let root = fixture_root.join("zeta");
        std::fs::create_dir_all(&root)?;
        std::fs::write(root.join("manifest.json"), serde_json::to_vec_pretty(&manifest)?).unwrap();
        write_fixture(&root, &manifest, 0, StoredShardKind::Data, 0, 1, "nodeA", &encoded.data[0], None, true, false);
        write_fixture(&root, &manifest, 0, StoredShardKind::Data, 1, 1, "nodeB", &encoded.data[1], None, false, false);
        write_fixture(&root, &manifest, 0, StoredShardKind::Parity, 0, 1, "nodeC", &encoded.parity[0], None, true, false);
        write_fixture(&root, &manifest, 0, StoredShardKind::Parity, 0, 1, "nodeD", &alternate.parity[0], None, true, false);
        import_directory(storage, &root, "fixture/zeta")?;
        count += 1;
    }

    Ok(count)
}
