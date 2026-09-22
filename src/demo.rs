//! 演示数据：一个两 stripe 对象，覆盖缺块、位翻转、重复编号与 generation 混杂。

use crate::model::*;
use crate::rs::ReedSolomon;
use crate::store::Store;
use crate::util::sha256_hex;

pub fn seed(store: &Store) -> rusqlite::Result<()> {
    let k = 3;
    let m = 2;
    let shard_size = 8;
    let stripe_count = 2;
    let rs = ReedSolomon::new(k, m);

    let mut stripes: Vec<Vec<Vec<u8>>> = Vec::new();
    for s in 0..stripe_count {
        let data: Vec<Vec<u8>> = (0..k)
            .map(|i| {
                (0..shard_size)
                    .map(|j| ((s * 37 + i * 11 + j * 7 + 13) % 251) as u8)
                    .collect()
            })
            .collect();
        let mut all = data.clone();
        all.extend(rs.encode_parity(&data));
        stripes.push(all);
    }

    let manifest = Manifest {
        stripes: stripes
            .iter()
            .map(|shards| StripeManifest {
                shard_digests: shards.iter().map(|s| Some(sha256_hex(s))).collect(),
            })
            .collect(),
    };

    let create = CreateObject {
        id: "demo-001".into(),
        name: "演示对象-极地观测切片".into(),
        params: EncodingParams {
            version: 1,
            k,
            m,
            shard_size,
        },
        object_len: (k * shard_size * stripe_count) as u64,
        manifest,
    };
    store.create_object(&create)?;
    let id = &create.id;

    // stripe 0：完整，全部来自 node-a。
    for (i, shard) in stripes[0].iter().enumerate() {
        store.add_fragment(id, 0, i as u32, 1, "node-a", &sha256_hex(shard), shard)?;
    }
    // stripe 1：缺 2、4 号；node-b 的 0 号副本发生位翻转；node-c 的 1 号属于旧 generation。
    for &i in &[0usize, 1, 3] {
        let shard = &stripes[1][i];
        store.add_fragment(id, 1, i as u32, 1, "node-a", &sha256_hex(shard), shard)?;
    }
    let mut flipped = stripes[1][0].clone();
    flipped[3] ^= 0x5a;
    store.add_fragment(id, 1, 0, 1, "node-b", &sha256_hex(&stripes[1][0]), &flipped)?;
    store.add_fragment(id, 1, 1, 2, "node-c", &sha256_hex(&stripes[1][1]), &stripes[1][1])?;
    Ok(())
}
