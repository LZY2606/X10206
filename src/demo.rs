//! Deterministic demo fixture: one object whose stripes exercise single
//! missing shard, bit-flip evidence, duplicate numbering, length mismatch,
//! generation mixing and boundary (exactly-k) recovery.

use crate::recover::{sha256_hex, ManifestEntry};
use crate::rs::{Coder, CodingParams};
use crate::store::Store;

pub fn import_demo(store: &Store) -> i64 {
    let params = CodingParams {
        version: 1,
        k: 3,
        m: 2,
        shard_size: 8,
    };
    let coder = Coder::new(params);
    let n = coder.n();
    let stripes = 3usize;
    let total_len = 60u64; // last stripe is partial (12 of 24 bytes used)

    let object_bytes: Vec<u8> = (0..total_len).map(|i| ((i * 7 + 3) % 256) as u8).collect();
    let object_digest = sha256_hex(&object_bytes);

    let object_id = store.create_object("demo-object", &params, total_len, &object_digest);

    // Manifest: declared length for every (stripe, idx).
    for stripe in 0..stripes {
        for idx in 0..n {
            store.add_manifest_entry(
                object_id,
                stripe,
                &ManifestEntry {
                    idx,
                    len: params.shard_size,
                },
            );
        }
    }

    // Encode all stripes.
    let mut encoded: Vec<Vec<Vec<u8>>> = Vec::new();
    for stripe in 0..stripes {
        let base = stripe * params.k * params.shard_size;
        let mut data = Vec::new();
        for j in 0..params.k {
            let mut shard = vec![0u8; params.shard_size];
            for b in 0..params.shard_size {
                let pos = base + j * params.shard_size + b;
                if pos < object_bytes.len() {
                    shard[b] = object_bytes[pos];
                }
            }
            data.push(shard);
        }
        encoded.push(coder.encode(&data));
    }

    let relay_a = store.ensure_source("relay-a");
    let relay_b = store.ensure_source("relay-b");
    let relay_c = store.ensure_source("relay-c");

    let put = |stripe: usize, idx: usize, gen: u64, src: i64, bytes: Vec<u8>| {
        store.add_shard(object_id, stripe, idx, gen, src, &bytes);
    };

    // Stripe 0: idx 3 missing entirely -> single missing shard recovery.
    put(0, 0, 1, relay_a, encoded[0][0].clone());
    put(0, 1, 1, relay_b, encoded[0][1].clone());
    put(0, 2, 1, relay_a, encoded[0][2].clone());
    put(0, 4, 1, relay_c, encoded[0][4].clone());

    // Stripe 1: idx 1 bit-flipped in transit (declared digest is the original
    // one, so the recomputed digest exposes the corruption); idx 4 arrives
    // truncated -> manifest length mismatch evidence.
    put(1, 0, 1, relay_a, encoded[1][0].clone());
    let mut flipped = encoded[1][1].clone();
    flipped[3] ^= 0x5A;
    let flipped_id = {
        // Store with the *original* declared digest to model a block whose
        // accompanying digest no longer matches its corrupted bytes.
        let conn = store.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO shards(object_id, stripe, idx, generation, source_id, bytes, digest)
             VALUES(?1,?2,?3,?4,?5,?6,?7)",
            rusqlite::params![
                object_id,
                1i64,
                1i64,
                1i64,
                relay_b,
                flipped,
                sha256_hex(&encoded[1][1])
            ],
        )
        .unwrap();
        conn.last_insert_rowid()
    };
    let _ = flipped_id;
    put(1, 2, 1, relay_a, encoded[1][2].clone());
    put(1, 3, 1, relay_c, encoded[1][3].clone());
    put(1, 4, 1, relay_c, encoded[1][4][..7].to_vec()); // partial write: 7 of 8 bytes

    // Stripe 2: generation mixing. gen 1 holds exactly k=3 shards (boundary
    // recovery). A partial gen-2 rewrite of a *different* object version
    // delivers idx 0/1 only; relay-b also ships a duplicate idx 0 whose
    // digest does not match its bytes.
    put(2, 0, 1, relay_a, encoded[2][0].clone());
    put(2, 1, 1, relay_b, encoded[2][1].clone());
    put(2, 2, 1, relay_a, encoded[2][2].clone());
    let alt: Vec<u8> = (0..8).map(|b| (200 + b) as u8).collect();
    put(2, 0, 2, relay_c, alt.clone());
    put(2, 1, 2, relay_c, alt.clone());
    // Duplicate idx 0, digest self-inconsistent -> excluded as evidence.
    {
        let conn = store.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO shards(object_id, stripe, idx, generation, source_id, bytes, digest)
             VALUES(?1,?2,?3,?4,?5,?6,?7)",
            rusqlite::params![
                object_id,
                2i64,
                0i64,
                1i64,
                relay_b,
                encoded[2][0].clone(),
                sha256_hex(b"not-the-right-bytes").as_str(),
            ],
        )
        .unwrap();
    }

    object_id
}
