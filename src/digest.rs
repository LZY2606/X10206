use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Object digest: concatenate each stripe's k*shard_size data window,
/// truncated to that stripe's real `data_len`, in stripe order.
pub fn object_digest(stripe_windows: &[(usize, &[Vec<u8>])], shard_size: usize) -> String {
    let mut h = Sha256::new();
    for (data_len, data_shards) in stripe_windows {
        let mut taken = 0usize;
        for shard in data_shards.iter() {
            let remain = data_len.saturating_sub(taken);
            if remain == 0 {
                break;
            }
            let n = remain.min(shard.len().min(shard_size));
            h.update(&shard[..n]);
            taken += n;
        }
    }
    hex::encode(h.finalize())
}
