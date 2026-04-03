use crate::{
    batch_maker::Batch,
    config::Committee,
    ensure,
    error::{MempoolError, MempoolResult},
};
use crypto::{Digest, PublicKey, Signature, SignatureService};
use itertools::Itertools as _;
use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};
use smtree::{
    index::TreeIndex,
    node_template::MTreeNodeSmt,
    proof::MerkleProof,
    traits::{InclusionProvable as _, Mergeable, Serializable as _},
    tree::SparseMerkleTree,
};
use std::convert::TryInto as _;

#[cfg(test)]
#[path = "tests/coded_batch_tests.rs"]
pub mod coded_batch_tests;

/// Represents an erasure-coded shard, generated from a batch of transactions.
pub type Shard = Vec<u8>;

/// Convenient shortcut representing a Merkle tree.
type Tree = SparseMerkleTree<MTreeNodeSmt<blake3::Hasher>>;

/// An erasure-corrected transaction batch.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct CodedBatch {
    /// All the data shards (not the parity shards) of the erasure-coded
    /// transactions batch.
    pub shards: Vec<Shard>,
}

impl CodedBatch {
    /// Encodes (erasure-corrected) a transactions batch.
    pub fn new(batch: Batch, batch_size: usize, committee: &Committee) -> Self {
        let (data_shards, parity_shards) = committee.shards();
        let remainder = batch_size % data_shards;
        let symbols_length = match remainder {
            0 => batch_size / data_shards,
            _ => batch_size / data_shards + 1,
        };

        // Fill with zeros: it is important that the batch size is divisible by data_shards'.
        let filler = vec![0u8; data_shards * symbols_length - batch_size];

        // make the parity shards.
        let parity = vec![0u8; symbols_length * parity_shards];

        // Assemble all shards and encode them.
        let mut shards: Vec<Shard> = batch
            .into_iter()
            .flatten()
            .chain(filler.into_iter())
            .chain(parity.into_iter())
            .chunks(symbols_length)
            .into_iter()
            .map(|x| x.collect::<Vec<_>>())
            .collect();

        ReedSolomon::new(data_shards, parity_shards)
            .expect("Failed to initialize RS encoder")
            .encode(&mut shards)
            .expect("Failed to encode data");

        Self { shards }
    }

    /// Reconstruct the coded transaction batch from enough shards.
    pub fn reconstruct(
        mut coded_shards: Vec<Option<Shard>>,
        committee: &Committee,
    ) -> MempoolResult<Self> {
        let (data_shards, parity_shards) = committee.shards();

        // Reconstruct the coded batch.
        let decoder = ReedSolomon::new(data_shards, parity_shards)
            .expect("Failed to initialize RS decoder from committee");
        decoder.reconstruct(&mut coded_shards)?;

        // Ensure the reconstruction succeeded.
        let result: Vec<_> = coded_shards.into_iter().flatten().collect();
        ensure!(decoder.verify(&result)?, MempoolError::MalformedCodedBatch);
        Ok(Self { shards: result })
    }

    /// Compute a Merkle tree using the coded shards as leaves.
    pub fn commit(&self) -> Tree {
        let leaves: Vec<_> = self
            .shards
            .iter()
            .enumerate()
            .map(|(i, shard)| {
                let mut hasher = blake3::Hasher::new();
                hasher.update(shard);
                hasher.update(&i.to_le_bytes());
                let hash = hasher.finalize();
                MTreeNodeSmt::new(hash.as_bytes().to_vec())
            })
            .collect();

        Tree::new_merkle_tree(&leaves)
    }

    /// Compress the coded batch by only keeping the data shards.
    pub fn compress(&mut self, committee: &Committee) {
        let (data_shards, _) = committee.shards();
        self.shards.truncate(data_shards);
    }

    /// Expand the coded batch by re-creating the parity shards.
    pub fn expand(&mut self, committee: &Committee) -> MempoolResult<()> {
        let (_, parity_shards) = committee.shards();
        let mut coded_shards: Vec<_> = self.shards.iter().cloned().map(Some).collect();
        coded_shards.extend(vec![None; parity_shards]);
        self.shards = Self::reconstruct(coded_shards, committee)?.shards;
        Ok(())
    }
}

/// Represents a serialized Merkle proof.
type SerializedProof = Vec<u8>;

/// Convenient shortcut representing a Merkle proof.
type Proof = MerkleProof<MTreeNodeSmt<blake3::Hasher>>;

/// A self-authenticated bundle of the `data_shards` erasure-coded shards
/// assigned to one node (absolute indices `node_idx*k .. (node_idx+1)*k`).
/// A single batch Merkle proof covers all shards in the bundle.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthenticatedShard {
    /// The `data_shards` shards assigned to this node.
    pub shards: Vec<Shard>,
    /// Index of the destination node in the committee.
    pub node_idx: usize,
    /// One batch Merkle proof covering all shards in this bundle.
    pub proof: SerializedProof,
    pub root: Digest,
    pub author: PublicKey,
    pub signature: Signature,
}

#[cfg(test)]
impl PartialEq for AuthenticatedShard {
    fn eq(&self, other: &Self) -> bool {
        self.shards == other.shards
            && self.node_idx == other.node_idx
            && self.proof == other.proof
            && self.root == other.root
            && self.author == other.author
    }
}

#[cfg(test)]
impl Eq for AuthenticatedShard {}

impl AuthenticatedShard {
    fn build_batch_proof(node_idx: usize, data_shards: usize, tree: &Tree) -> Proof {
        let height = tree.get_height();
        let indices: Vec<TreeIndex> = (0..data_shards)
            .map(|j| TreeIndex::from_u64(height, (node_idx * data_shards + j) as u64))
            .collect();
        Proof::generate_inclusion_proof(tree, &indices)
            .expect("Failed to generate batch Merkle proof")
    }

    /// Create a new authenticated shard bundle for one node.
    pub async fn new(
        shards: Vec<Shard>,
        node_idx: usize,
        data_shards: usize,
        tree: &Tree,
        author: PublicKey,
        signature_service: &mut SignatureService,
    ) -> Self {
        let serialized_root = tree.get_root().serialize();
        let root = Digest(serialized_root[0..32].try_into().unwrap());
        let signature = signature_service.request_signature(root.clone()).await;
        let proof = Self::build_batch_proof(node_idx, data_shards, tree);
        Self { shards, node_idx, proof: proof.serialize(), root, author, signature }
    }

    /// Build a bundle using an existing signature (used by Reconstructor after sync recovery).
    pub fn make_with_signature(
        shards: Vec<Shard>,
        node_idx: usize,
        data_shards: usize,
        tree: &Tree,
        root: Digest,
        author: PublicKey,
        signature: Signature,
    ) -> Self {
        let proof = Self::build_batch_proof(node_idx, data_shards, tree);
        Self { shards, node_idx, proof: proof.serialize(), root, author, signature }
    }

    /// After a batch is committed, reduce this bundle to its first shard by
    /// deriving a new single-leaf Merkle proof.
    ///
    /// The proof is built by running the same bottom-up walk as `verify()` but
    /// recording the sibling of shard[0]'s path at every level.  No additional
    /// data is needed beyond the shards and the existing batch proof.
    pub fn prune_to_anchor_shard(&self, data_shards: usize) -> Self {
        assert_eq!(self.shards.len(), data_shards, "bundle already pruned");

        let proof = Proof::deserialize(&self.proof).expect("valid proof");
        let height = proof.get_indexes()[0].get_height();
        let start = self.node_idx * data_shards;
        let batch_sibs = proof.get_path_siblings();
        let mut sib_end = batch_sibs.len();

        // Place leaf hashes at their absolute positions.
        let level_size = 1usize << height;
        let mut nodes: Vec<Option<MTreeNodeSmt<blake3::Hasher>>> = vec![None; level_size];
        for (j, shard) in self.shards.iter().enumerate() {
            let mut h = blake3::Hasher::new();
            h.update(shard);
            h.update(&(start + j).to_le_bytes());
            let hash = h.finalize();
            nodes[start + j] = Some(MTreeNodeSmt::new(hash.as_bytes().to_vec()));
        }

        // Collect single-leaf proof siblings bottom-up (leaf→root order), then reverse.
        let mut new_sibs: Vec<MTreeNodeSmt<blake3::Hasher>> = Vec::new();

        for level_from_leaf in 1..=height {
            let next_size = nodes.len() / 2;
            let mut next: Vec<Option<MTreeNodeSmt<blake3::Hasher>>> = vec![None; next_size];

            // Position of shard[0]'s node in the *current* (pre-merge) nodes array.
            let path_node = start >> (level_from_leaf - 1);
            let sibling_node = path_node ^ 1;

            // Case 1: sibling is in nodes (computed from our shards) → capture now.
            if let Some(sib) = nodes[sibling_node].as_ref() {
                new_sibs.push(sib.clone());
            }

            // Standard Option-B bottom-up merge.
            let mut full: Vec<usize> = Vec::new();
            let mut incomplete: Vec<usize> = Vec::new();
            for p in 0..next_size {
                match (nodes[2 * p].is_some(), nodes[2 * p + 1].is_some()) {
                    (true, true) => full.push(p),
                    (true, false) | (false, true) => incomplete.push(p),
                    (false, false) => {}
                }
            }
            for &p in &full {
                let lv = nodes[2 * p].take().unwrap();
                let rv = nodes[2 * p + 1].take().unwrap();
                next[p] = Some(Mergeable::merge(&lv, &rv));
            }
            for &p in incomplete.iter().rev() {
                let left_exists = nodes[2 * p].is_some();
                let missing = if left_exists { 2 * p + 1 } else { 2 * p };
                sib_end -= 1;
                let sib = &batch_sibs[sib_end];
                // Case 2: the missing side IS the sibling we need → capture it.
                if missing == sibling_node {
                    new_sibs.push(sib.clone());
                }
                next[p] = Some(if left_exists {
                    Mergeable::merge(&nodes[2 * p].take().unwrap(), sib)
                } else {
                    Mergeable::merge(sib, &nodes[2 * p + 1].take().unwrap())
                });
            }
            nodes = next;
        }

        // Reverse to standard root→leaf ordering.
        new_sibs.reverse();
        let mut single_proof = Proof::new(TreeIndex::from_u64(height, start as u64));
        single_proof.set_siblings(new_sibs);

        Self {
            shards: vec![self.shards[0].clone()],
            node_idx: self.node_idx,
            proof: single_proof.serialize(),
            root: self.root.clone(),
            author: self.author,
            signature: self.signature.clone(),
        }
    }

    /// Verify the bundle: signature, shard count, and Merkle inclusion (Option B range verifier).
    ///
    /// Accepts both full bundles (`shards.len() == data_shards`, batch proof) and pruned
    /// bundles (`shards.len() == 1`, single-leaf proof).
    pub fn verify(&self, committee: &Committee) -> MempoolResult<()> {
        ensure!(
            committee.stake(&self.author) > 0,
            MempoolError::UnknownAuthority(self.author)
        );
        self.signature.verify(&self.root, &self.author)?;

        let (data_shards, _) = committee.shards();
        ensure!(
            self.shards.len() == data_shards || self.shards.len() == 1,
            MempoolError::BadInclusionProof
        );

        let proof =
            Proof::deserialize(&self.proof).map_err(|_| MempoolError::BadInclusionProof)?;
        let root_node = MTreeNodeSmt::deserialize(&self.root.to_vec())
            .map_err(|_| MempoolError::BadInclusionProof)?;

        let height = proof
            .get_indexes()
            .first()
            .ok_or(MempoolError::BadInclusionProof)?
            .get_height();

        let start = self.node_idx * data_shards;
        let siblings = proof.get_path_siblings();
        let mut sib_end = siblings.len();

        // Place leaf hashes at their absolute positions.
        let level_size = 1usize << height;
        let mut nodes: Vec<Option<MTreeNodeSmt<blake3::Hasher>>> = vec![None; level_size];
        for (j, shard) in self.shards.iter().enumerate() {
            let mut hasher = blake3::Hasher::new();
            hasher.update(shard);
            hasher.update(&(start + j).to_le_bytes());
            let hash = hasher.finalize();
            nodes[start + j] = Some(MTreeNodeSmt::new(hash.as_bytes().to_vec()));
        }

        // Walk bottom-up, pairing adjacent nodes.  Incomplete pairs (one side
        // outside our range) consume a sibling from the proof in reverse-BFS
        // order, which means RIGHT-to-LEFT within each level.
        for _ in (1..=height).rev() {
            let next_size = nodes.len() / 2;
            let mut next: Vec<Option<MTreeNodeSmt<blake3::Hasher>>> = vec![None; next_size];

            let mut full: Vec<usize> = Vec::new();
            let mut incomplete: Vec<usize> = Vec::new();
            for p in 0..next_size {
                match (nodes[2 * p].is_some(), nodes[2 * p + 1].is_some()) {
                    (true, true) => full.push(p),
                    (true, false) | (false, true) => incomplete.push(p),
                    (false, false) => {}
                }
            }

            for &p in &full {
                let lv = nodes[2 * p].take().unwrap();
                let rv = nodes[2 * p + 1].take().unwrap();
                next[p] = Some(Mergeable::merge(&lv, &rv));
            }
            for &p in incomplete.iter().rev() {
                ensure!(sib_end > 0, MempoolError::BadInclusionProof);
                sib_end -= 1;
                let sib = &siblings[sib_end];
                next[p] = Some(if nodes[2 * p].is_some() {
                    Mergeable::merge(&nodes[2 * p].take().unwrap(), sib)
                } else {
                    Mergeable::merge(sib, &nodes[2 * p + 1].take().unwrap())
                });
            }

            nodes = next;
        }

        ensure!(
            nodes[0].as_ref() == Some(&root_node),
            MempoolError::BadInclusionProof
        );
        Ok(())
    }
}
