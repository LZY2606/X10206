//! Built-in offline fixtures seeded on first launch. Uses GF(256) Reed-
//! Solomon so every anomaly is easy to inspect byte by byte.

use std::io;

use crate::digest::{object_data_digest, sha256_hex};
use crate::gf256::Gf256;
use crate::model::{ImportBundle, Manifest, ReceiptInput};
use crate::rs::{encode, CodecVersion};
use crate::store::Store;

fn receipt(
    stripe: usize,
    shard: usize,
    generation: i64,
    source: &str,
    bytes: Vec<u8>,
) -> ReceiptInput {
    let digest = sha256_hex(&bytes);
    ReceiptInput {
        stripe,
        shard,
        generation,
        source: source.to_string(),
        digest,
        bytes,
    }
}

fn claimed_corrupt(
    stripe: usize,
    shard: usize,
    generation: i64,
    source: &str,
    mut bytes: Vec<u8>,
) -> ReceiptInput {
    // Bit flip in bytes, but the *claimed* digest is still for the original.
    let original_digest = sha256_hex(&bytes);
    bytes[0] ^= 0x01;
    ReceiptInput {
        stripe,
        shard,
        generation,
        source: source.to_string(),
        digest: original_digest,
        bytes,
    }
}

fn bundle(
    object_id: &str,
    version: CodecVersion,
    k: usize,
    m: usize,
    stripe_count: usize,
    shard_len: usize,
    object_digest: Option<String>,
    receipts: Vec<ReceiptInput>,
) -> ImportBundle {
    ImportBundle {
        manifest: Manifest {
            object_id: object_id.to_string(),
            codec_version: version.as_i64(),
            k,
            m,
            stripe_count,
            shard_len,
            object_digest,
            generation: 1,
        },
        receipts,
    }
}

/// Object alpha: k=3,m=2, two stripes; rich corruption, digest resolves it.
fn build_alpha() -> ImportBundle {
    let gf = Gf256::new();
    let (k, m, shard_len) = (3, 2, 4);
    let data0 = vec![
        vec![1u8, 2, 3, 4],
        vec![5, 6, 7, 8],
        vec![9, 10, 11, 12],
    ];
    let data1 = vec![
        vec![20u8, 21, 22, 23],
        vec![24, 25, 26, 27],
        vec![28, 29, 30, 31],
    ];
    let c0 = encode(&gf, CodecVersion::V1, k, m, &data0);
    let c1 = encode(&gf, CodecVersion::V1, k, m, &data1);
    let stripes = vec![c0, c1];
    let digest = object_data_digest(&stripes, k);

    let mut receipts = Vec::new();
    // Stripe 0: shard0 from node-a healthy; shard1 from node-b bit-flipped
    // (its claimed digest exposes the flip); shard2 from node-c healthy;
    // parity shard3 healthy from node-d; parity shard4 missing. Plus a
    // duplicate-numbered stale gen0 copy of shard2 from node-e.
    receipts.push(receipt(0, 0, 1, "node-a", stripes[0][0].clone()));
    receipts.push(claimed_corrupt(0, 1, 1, "node-b", stripes[0][1].clone()));
    receipts.push(receipt(0, 2, 1, "node-c", stripes[0][2].clone()));
    receipts.push(receipt(0, 3, 1, "node-d", stripes[0][3].clone()));
    // Stale generation candidate for shard2 (different bytes, digest-healthy).
    let stale2 = vec![90u8, 91, 92, 93];
    receipts.push(receipt(0, 2, 0, "node-e", stale2));
    // A receipt whose length disagrees with the manifest.
    receipts.push(receipt(0, 4, 1, "node-f", vec![1, 2, 3]));

    // Stripe 1: exactly k=3 healthy receipts (threshold case): 0,2,4.
    receipts.push(receipt(1, 0, 1, "node-a", stripes[1][0].clone()));
    receipts.push(receipt(1, 2, 1, "node-c", stripes[1][2].clone()));
    receipts.push(receipt(1, 4, 1, "node-d", stripes[1][4].clone()));
    // Out of range shard index.
    receipts.push(receipt(1, 9, 1, "node-z", vec![0; shard_len]));

    bundle("alpha", CodecVersion::V1, k, m, 2, shard_len, Some(digest), receipts)
}

/// Object beta: k=2,m=1, one stripe, exactly k=2 candidates at shard0 with
/// two digest-healthy contents and no object digest -> two feasible answers
/// that differ in every missing shard. Isolating one source makes it unique.
fn build_beta() -> ImportBundle {
    let gf = Gf256::new();
    let (k, m, shard_len) = (2, 1, 2);
    let data = vec![vec![7u8, 8], vec![9, 10]];
    let coded = encode(&gf, CodecVersion::V2, k, m, &data);

    let mut receipts = Vec::new();
    // shard1 present (healthy) from node-a.
    receipts.push(receipt(0, 1, 1, "node-a", coded[1].clone()));
    // shard0 has two digest-healthy content candidates from two sources.
    receipts.push(receipt(0, 0, 1, "node-b", coded[0].clone()));
    // An alternative consistent shard0: data shard0' = coded0 xor delta with
    // a matching parity candidate omitted, so reconstruction with each yields
    // different missing parity/data — but it must still satisfy the single
    // witness. With k=2 and only one other shard, any shard0 + shard1 solves,
    // and there are no extra witnesses, so both answers survive.
    let alt0 = coded[0].iter().map(|b| b ^ 0x5A).collect::<Vec<u8>>();
    receipts.push(receipt(0, 0, 1, "node-c", alt0));

    bundle("beta", CodecVersion::V2, k, m, 1, shard_len, None, receipts)
}

pub fn seed_demo_data(store: &Store) -> io::Result<()> {
    for b in [build_alpha(), build_beta()] {
        crate::importer::import_bundle(store, b)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    }
    Ok(())
}
