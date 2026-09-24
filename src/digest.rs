//! Content digests. Every stored block carries a SHA-256 digest; a committed
//! stripe is only reused after re-verifying its recovered blocks on disk.

use sha2::{Digest, Sha256};

pub const PREFIX: &str = "sha256:";

pub fn of_bytes(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let mut out = String::with_capacity(7 + 64);
    out.push_str(PREFIX);
    for b in h.finalize() {
        out.push_str(&hex::encode_upper([b]));
    }
    out
}

/// Object digest: hash the concatenation of stripes in order, each stripe
/// being its `n` shards in index order. Input is `stripes[stripe][shard]`.
pub fn of_object(
    stripes: &[Vec<Vec<u8>>],
    shard_len: usize,
    n: usize,
    data_len: usize,
) -> String {
    let mut h = Sha256::new();
    h.update(b"STRIPE-RECOVERY-POD/OBJECT/v1\n");
    h.update((data_len as u64).to_be_bytes());
    h.update((n as u64).to_be_bytes());
    h.update((shard_len as u64).to_be_bytes());
    for stripe in stripes {
        for shard in stripe {
            h.update(shard);
        }
    }
    let mut out = String::with_capacity(7 + 64);
    out.push_str(PREFIX);
    for b in h.finalize() {
        out.push_str(&hex::encode_upper([b]));
    }
    out
}

/// Compare a digest in the manifest with a computed digest. A missing
/// manifest digest (`None`) is "no anchor" rather than a mismatch.
pub fn matches(expected: Option<&str>, actual: &str) -> bool {
    match expected {
        None => true,
        Some(e) => e.eq_ignore_ascii_case(actual),
    }
}
