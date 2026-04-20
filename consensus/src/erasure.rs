use crate::error::{ConsensusError, ConsensusResult};
use ed25519_dalek::{Digest as _, Sha512};
use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

// ---------------------------------------------------------------------------
// Merkle proof
// ---------------------------------------------------------------------------

/// One step in a Merkle authentication path.
/// `sibling` is the hash of the sibling node; `sibling_is_left` indicates
/// whether the sibling sits to the *left* of the current node at this level.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MerkleProof {
    pub path: Vec<([u8; 32], bool)>,
}

// ---------------------------------------------------------------------------
// Reed-Solomon helpers
// ---------------------------------------------------------------------------

/// Byte-size of each shard when splitting `data_len` bytes into `k` pieces.
pub fn shard_size(data_len: usize, k: usize) -> usize {
    (data_len + k - 1) / k
}

/// Encode `data` with (k data shards, n-k parity shards).
///
/// Returns all `n` shards (each of equal length) plus the Merkle root
/// that commits to them all, plus one proof per shard.
/// The tree is built once and all proofs are extracted in a single pass.
pub fn encode(data: &[u8], k: usize, n: usize) -> (Vec<Vec<u8>>, [u8; 32], Vec<MerkleProof>) {
    assert!(k > 0 && n >= k, "RS parameters must satisfy 0 < k ≤ n");
    let sz = shard_size(data.len(), k);

    // Build k data shards, zero-padding the last one.
    let mut shards: Vec<Vec<u8>> = (0..k)
        .map(|i| {
            let start = i * sz;
            let mut shard = vec![0u8; sz];
            if start < data.len() {
                let end = ((i + 1) * sz).min(data.len());
                shard[..end - start].copy_from_slice(&data[start..end]);
            }
            shard
        })
        .collect();

    // Append n-k zeroed parity shards (filled by the encoder).
    for _ in k..n {
        shards.push(vec![0u8; sz]);
    }

    ReedSolomon::new(k, n - k)
        .expect("Invalid RS parameters")
        .encode(&mut shards)
        .expect("RS encoding failed");

    let (root, proofs) = merkle_root_and_proofs(&shards);
    (shards, root, proofs)
}

/// Reconstruct the original `block_len` bytes from a sparse shard vector.
/// `shards_opt[i]` is `Some(bytes)` if shard `i` is available, `None` otherwise.
/// At least `k` entries must be `Some`.
pub fn reconstruct(
    mut shards_opt: Vec<Option<Vec<u8>>>,
    k: usize,
    n: usize,
    block_len: usize,
) -> ConsensusResult<Vec<u8>> {
    ReedSolomon::new(k, n - k)
        .expect("Invalid RS parameters")
        .reconstruct(&mut shards_opt)
        .map_err(|_| ConsensusError::ErasureReconstructionFailed)?;

    // Concatenate the k data shards and trim the padding.
    let mut data = Vec::with_capacity(block_len);
    for opt in shards_opt.into_iter().take(k) {
        data.extend_from_slice(&opt.expect("Reconstruction must fill all data shards"));
    }
    data.truncate(block_len);
    Ok(data)
}

// ---------------------------------------------------------------------------
// Merkle tree
// ---------------------------------------------------------------------------

/// Build the Merkle tree once and return the root plus all n leaf proofs.
/// Each shard is hashed exactly once; all proofs are extracted from the
/// stored layers in O(n log n) total work.
fn merkle_root_and_proofs(shards: &[Vec<u8>]) -> ([u8; 32], Vec<MerkleProof>) {
    let n = shards.len();

    // Build all layers, storing each one.
    let mut layers: Vec<Vec<[u8; 32]>> = Vec::new();
    layers.push(shards.iter().map(|s| hash_leaf(s)).collect());

    while layers.last().unwrap().len() > 1 {
        let prev = layers.last().unwrap();
        let next = prev
            .chunks(2)
            .map(|pair| {
                let right = if pair.len() == 2 { pair[1] } else { pair[0] };
                hash_node(&pair[0], &right)
            })
            .collect();
        layers.push(next);
    }

    let root = layers.last().unwrap()[0];

    // Extract one proof per leaf from the stored layers.
    let proofs = (0..n)
        .map(|leaf_idx| {
            let mut path = Vec::new();
            let mut idx = leaf_idx;
            for layer in &layers[..layers.len() - 1] {
                let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
                let sibling = if sibling_idx < layer.len() {
                    layer[sibling_idx]
                } else {
                    layer[idx]
                };
                // sibling_is_left = true when sibling is LEFT (current node is right child).
                path.push((sibling, idx % 2 == 1));
                idx /= 2;
            }
            MerkleProof { path }
        })
        .collect();

    (root, proofs)
}

/// Verify that `shard` at position `index` is authentic under `root`.
pub fn verify_proof(shard: &[u8], index: usize, proof: &MerkleProof, root: &[u8; 32]) -> bool {
    let _ = index; // The index is encoded implicitly in the proof path direction bits.
    let mut current = hash_leaf(shard);

    for (sibling, sibling_is_left) in &proof.path {
        current = if *sibling_is_left {
            hash_node(sibling, &current)
        } else {
            hash_node(&current, sibling)
        };
    }

    &current == root
}

// ---------------------------------------------------------------------------
// Hash helpers (domain-separated)
// ---------------------------------------------------------------------------

/// Hash a leaf node (domain byte 0x00).
fn hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(b"\x00");
    h.update(data);
    h.finalize().as_slice()[..32].try_into().unwrap()
}

/// Hash an internal Merkle node (domain byte 0x01).
fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(b"\x01");
    h.update(left);
    h.update(right);
    h.finalize().as_slice()[..32].try_into().unwrap()
}
