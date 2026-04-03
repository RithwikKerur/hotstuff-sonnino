/// Benchmark: per-shard individual verify() vs. one verify_batch() vs. custom range verifier.
///
/// Simulates the scenario in HotStuff mempool:
///   - N=10 nodes, f=3 faults → data_shards = 2f+1 = 7, total = N*(2f+1) = 70 leaves
///   - Each node owns k=7 contiguous leaves at positions node_idx*7 .. (node_idx+1)*7
///
/// Three approaches benchmarked:
///   Option A  – k individual verify() calls, each with a separate single-leaf proof
///   Batch     – 1 verify_batch() call using a single multi-leaf proof (current code)
///   Option B  – custom bottom-up range verifier using the multi-leaf proof's siblings
///               but WITHOUT rebuilding SparseMerkleTree<Nil> internally
/// // ./target/release/merkle_bench
use std::time::{Duration, Instant};

use smtree::{
    index::TreeIndex,
    node_template::MTreeNodeSmt,
    pad_secret::ALL_ZEROS_SECRET,
    proof::MerkleProof,
    traits::{InclusionProvable as _, Mergeable, Serializable as _},
    tree::SparseMerkleTree,
};

type Node = MTreeNodeSmt<blake3::Hasher>;
type Tree = SparseMerkleTree<Node>;
type Proof = MerkleProof<Node>;

// ── Parameters ──────────────────────────────────────────────────────────────
const N: usize = 10; // committee size
const F: usize = 3; // max faults
const DATA_SHARDS: usize = 2 * F + 1; // 7
const TOTAL_SHARDS: usize = N * DATA_SHARDS; // 70
const SHARD_SIZE: usize = 1_024; // bytes per shard (1 KB representative)
const ITERS: u32 = 10_000; // repetitions per measurement

// ── Helpers ──────────────────────────────────────────────────────────────────

fn build_shards() -> Vec<Vec<u8>> {
    (0..TOTAL_SHARDS)
        .map(|i| {
            let mut s = vec![0u8; SHARD_SIZE];
            s[0] = (i & 0xff) as u8;
            s[1] = ((i >> 8) & 0xff) as u8;
            s
        })
        .collect()
}

fn hash_shard(shard: &[u8], index: usize) -> Node {
    // Matches CodedBatch::commit() leaf hashing in coded_batch.rs
    let mut hasher = blake3::Hasher::new();
    hasher.update(shard);
    hasher.update(&index.to_le_bytes());
    let hash = hasher.finalize();
    Node::new(hash.as_bytes().to_vec())
}

fn build_tree(shards: &[Vec<u8>]) -> Tree {
    let n = shards.len();
    // smtree height = ceil(log2(n)), min 1
    let height = (0usize..)
        .find(|&h| (1usize << h) >= n)
        .unwrap()
        .max(1);
    let mut tree: Tree = SparseMerkleTree::new(height);
    let list: Vec<(TreeIndex, Node)> = shards
        .iter()
        .enumerate()
        .map(|(i, s)| (TreeIndex::from_u64(height, i as u64), hash_shard(s, i)))
        .collect();
    tree.construct_smt_nodes(&list, &ALL_ZEROS_SECRET);
    tree
}

fn root_node(tree: &Tree) -> Node {
    let raw = tree.get_root().serialize();
    Node::new(raw)
}

// ── Proof builders ────────────────────────────────────────────────────────────

/// Build k individual single-leaf proofs (Option A).
fn build_individual_proofs(
    tree: &Tree,
    node_idx: usize,
) -> Vec<Vec<u8>> {
    let height = tree.get_height();
    (0..DATA_SHARDS)
        .map(|j| {
            let abs = node_idx * DATA_SHARDS + j;
            let idx = TreeIndex::from_u64(height, abs as u64);
            let proof = Proof::generate_inclusion_proof(tree, &[idx])
                .expect("single-leaf proof failed");
            proof.serialize()
        })
        .collect()
}

/// Build one multi-leaf batch proof (Batch / Option B).
fn build_batch_proof(tree: &Tree, node_idx: usize) -> Vec<u8> {
    let height = tree.get_height();
    let indices: Vec<TreeIndex> = (0..DATA_SHARDS)
        .map(|j| {
            let abs = node_idx * DATA_SHARDS + j;
            TreeIndex::from_u64(height, abs as u64)
        })
        .collect();
    let proof = Proof::generate_inclusion_proof(tree, &indices)
        .expect("batch proof failed");
    proof.serialize()
}

// ── Verification routines ─────────────────────────────────────────────────────

/// Option A: k individual verify() calls.
#[inline(never)]
fn verify_option_a(
    shards: &[Vec<u8>],   // k shards for this node
    start: usize,          // first absolute index
    proofs: &[Vec<u8>],   // k serialized single-leaf proofs
    root: &Node,
) -> bool {
    for (j, (shard, proof_bytes)) in shards.iter().zip(proofs.iter()).enumerate() {
        let leaf = hash_shard(shard, start + j);
        let proof = Proof::deserialize(proof_bytes).expect("deserialize proof");
        if !proof.verify(&leaf, root) {
            return false;
        }
    }
    true
}

/// Batch: 1 verify_batch() call (current code path).
#[inline(never)]
fn verify_batch_current(
    shards: &[Vec<u8>],
    start: usize,
    batch_proof_bytes: &[u8],
    root: &Node,
) -> bool {
    let leaves: Vec<Node> = shards
        .iter()
        .enumerate()
        .map(|(j, s)| hash_shard(s, start + j))
        .collect();
    let proof = Proof::deserialize(batch_proof_bytes).expect("deserialize proof");
    proof.verify_batch(&leaves, root)
}

/// Option B: custom bottom-up range verifier.
///
/// Uses the multi-leaf proof's sibling list directly.  Walks from the leaf
/// level up to the root, pairing adjacent nodes; when one side of a pair is
/// absent from our range, it consumes the next sibling from the *end* of the
/// siblings array.  This matches the reverse-BFS order used by verify_batch
/// internally, but avoids reconstructing SparseMerkleTree<Nil>.
///
/// Correctness relies on the leaves being *contiguous* (so at most one
/// incomplete pair per level).
#[inline(never)]
fn verify_option_b(
    shards: &[Vec<u8>],
    start: usize,
    height: usize,
    batch_proof_bytes: &[u8],
    root: &Node,
) -> bool {
    let k = shards.len();
    let proof = Proof::deserialize(batch_proof_bytes).expect("deserialize proof");
    let siblings = proof.get_path_siblings();
    let mut sib_end = siblings.len();

    // Allocate a level buffer – at most 2^height slots, but we only populate start..start+k.
    let level_size = 1usize << height;
    let mut nodes: Vec<Option<Node>> = vec![None; level_size];
    for (j, shard) in shards.iter().enumerate() {
        nodes[start + j] = Some(hash_shard(shard, start + j));
    }

    for _ in (1..=height).rev() {
        let next_size = nodes.len() / 2;
        let mut next: Vec<Option<Node>> = vec![None; next_size];

        // Process pairs left to right.  At any given level, incomplete pairs
        // (one side in our range, one outside) consume one sibling each.
        // We iterate left to right, so we consume siblings right-to-left
        // within the level – matching reverse-BFS order for the padding nodes
        // that smtree lists in left-to-right BFS order.
        //
        // To consume in right-to-left order within a level, we first collect
        // positions of incomplete pairs, then process them right to left.
        let mut full_pairs: Vec<usize> = Vec::new();
        let mut incomplete: Vec<usize> = Vec::new(); // parent indices

        for p in 0..next_size {
            let l = nodes[2 * p].is_some();
            let r = nodes[2 * p + 1].is_some();
            if l && r {
                full_pairs.push(p);
            } else if l || r {
                incomplete.push(p);
            }
        }

        // Full pairs: no sibling needed.
        for &p in &full_pairs {
            let lv = nodes[2 * p].take().unwrap();
            let rv = nodes[2 * p + 1].take().unwrap();
            next[p] = Some(Node::merge(&lv, &rv));
        }

        // Incomplete pairs: consume siblings RIGHT to LEFT (largest p first).
        for &p in incomplete.iter().rev() {
            if sib_end == 0 {
                return false;
            }
            sib_end -= 1;
            let sib = &siblings[sib_end];
            next[p] = if nodes[2 * p].is_some() {
                let lv = nodes[2 * p].take().unwrap();
                Some(Node::merge(&lv, sib))
            } else {
                let rv = nodes[2 * p + 1].take().unwrap();
                Some(Node::merge(sib, &rv))
            };
        }

        nodes = next;
    }

    nodes[0].as_ref() == Some(root)
}

// ── Timing helper ─────────────────────────────────────────────────────────────

fn bench<F: Fn() -> bool>(label: &str, iters: u32, f: F) -> Duration {
    // Warm-up
    for _ in 0..100 {
        assert!(f(), "{label}: verification returned false");
    }
    let t0 = Instant::now();
    for _ in 0..iters {
        std::hint::black_box(f());
    }
    let elapsed = t0.elapsed();
    let ns_per = elapsed.as_nanos() / iters as u128;
    println!("  {label:<35} {:>8} ns/iter   ({} iters)", ns_per, iters);
    elapsed
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    println!("=== Merkle Proof Benchmark ===");
    println!(
        "N={N}, F={F}, data_shards={DATA_SHARDS}, total_shards={TOTAL_SHARDS}, \
         shard_size={SHARD_SIZE} B, iters={ITERS}\n"
    );

    let shards = build_shards();
    let tree = build_tree(&shards);
    let height = tree.get_height();
    let root = root_node(&tree);

    println!("Tree height: {height}");

    // Pre-generate proofs for all nodes.
    let individual_proofs: Vec<Vec<Vec<u8>>> = (0..N)
        .map(|ni| build_individual_proofs(&tree, ni))
        .collect();
    let batch_proofs: Vec<Vec<u8>> = (0..N)
        .map(|ni| build_batch_proof(&tree, ni))
        .collect();

    // ── Proof sizes ────────────────────────────────────────────────────────
    let a_total_bytes: usize = individual_proofs[0].iter().map(|p| p.len()).sum();
    let b_bytes = batch_proofs[0].len();
    println!("\nProof sizes (node 0):");
    println!(
        "  Option A  ({DATA_SHARDS} × single-leaf proofs):  {} bytes total ({} bytes each)",
        a_total_bytes,
        a_total_bytes / DATA_SHARDS
    );
    println!("  Batch/B   (1 × multi-leaf proof):      {} bytes", b_bytes);
    println!(
        "  Size ratio A/B: {:.2}x\n",
        a_total_bytes as f64 / b_bytes as f64
    );

    // ── Correctness check for Option B ─────────────────────────────────────
    print!("Correctness check for Option B across all nodes ... ");
    for ni in 0..N {
        let start = ni * DATA_SHARDS;
        let node_shards = &shards[start..start + DATA_SHARDS];
        assert!(
            verify_option_b(node_shards, start, height, &batch_proofs[ni], &root),
            "Option B failed for node {ni}"
        );
    }
    println!("OK\n");

    // ── Per-node timing ─────────────────────────────────────────────────────
    println!("Per-node timing (averaged over all {N} nodes × {ITERS} iters each):");
    let mut total_a = Duration::ZERO;
    let mut total_batch = Duration::ZERO;
    let mut total_b = Duration::ZERO;

    for ni in 0..N {
        let start = ni * DATA_SHARDS;
        let node_shards = &shards[start..start + DATA_SHARDS];
        let ind_proofs = &individual_proofs[ni];
        let bat_proof = &batch_proofs[ni];

        println!("  Node {ni} (shards {start}..{}):", start + DATA_SHARDS);
        total_a += bench("Option A (k×verify())", ITERS, || {
            verify_option_a(node_shards, start, ind_proofs, &root)
        });
        total_batch += bench("Batch   (verify_batch())", ITERS, || {
            verify_batch_current(node_shards, start, bat_proof, &root)
        });
        total_b += bench("Option B (custom range)", ITERS, || {
            verify_option_b(node_shards, start, height, bat_proof, &root)
        });
        println!();
    }

    // ── Summary ─────────────────────────────────────────────────────────────
    let total_iters = (N as u32) * ITERS;
    let avg_a = total_a.as_nanos() / total_iters as u128;
    let avg_batch = total_batch.as_nanos() / total_iters as u128;
    let avg_b = total_b.as_nanos() / total_iters as u128;

    println!("=== Summary (average across all nodes) ===");
    println!("  Option A  (k×verify()):       {avg_a:>8} ns/iter");
    println!("  Batch     (verify_batch()):   {avg_batch:>8} ns/iter");
    println!("  Option B  (custom range):     {avg_b:>8} ns/iter");
    println!();
    println!("  Batch / Option A speedup:   {:.2}x", avg_batch as f64 / avg_a as f64);
    println!("  Option B / Option A speedup: {:.2}x", avg_b as f64 / avg_a as f64);
    println!("  Option B / Batch speedup:   {:.2}x", avg_batch as f64 / avg_b as f64);
}
