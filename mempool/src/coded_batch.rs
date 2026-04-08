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
    traits::{InclusionProvable as _, Serializable as _},
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

/// A self-authenticated encoded batch shard.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthenticatedShard {
    pub shard: Shard,
    pub destination: usize,
    pub proof: SerializedProof,
    pub root: Digest,
    pub author: PublicKey,
    pub signature: Signature,
}

#[cfg(test)]
impl PartialEq for AuthenticatedShard {
    fn eq(&self, other: &Self) -> bool {
        self.shard == other.shard
            && self.destination == other.destination
            && self.proof == other.proof
            && self.root == other.root
            && self.author == other.author
    }
}

#[cfg(test)]
impl Eq for AuthenticatedShard {}

impl AuthenticatedShard {
    /// Make a new authenticated batch shard from an encoded shard.
    pub async fn new(
        shard: Shard,
        destination: usize,
        tree: &Tree,
        author: PublicKey,
        signature_service: &mut SignatureService,
    ) -> Self {
        // Sign the Merkle root.
        let serialized_root = tree.get_root().serialize();
        let root = Digest(serialized_root[0..32].try_into().unwrap());
        let signature = signature_service.request_signature(root.clone()).await;

        // Construct the Merkle proof.
        let index_list = vec![TreeIndex::from_u64(tree.get_height(), destination as u64)];
        let proof = Proof::generate_inclusion_proof(tree, &index_list)
            .expect("Failed to generate merkle proof");

        Self {
            shard,
            destination,
            proof: proof.serialize(),
            root,
            author,
            signature,
        }
    }

    /// Verify the authenticated shard.
    /// Uses `self.destination` as the leaf index in the Merkle tree.
    pub fn verify(&self, committee: &Committee) -> MempoolResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            MempoolError::UnknownAuthority(self.author)
        );

        // Deserialize the proof and the tree's root.
        let deserialized_proof =
            Proof::deserialize(&self.proof).map_err(|_| MempoolError::BadInclusionProof)?;
        let deserialized_root = MTreeNodeSmt::deserialize(&self.root.to_vec())
            .map_err(|_| MempoolError::BadInclusionProof)?;

        // Verify the signature on the Merkle root.
        self.signature.verify(&self.root, &self.author)?;

        // Build the leaf using the absolute shard index (self.destination).
        let leaf = make_leaf(&self.shard, self.destination);

        // Check the Merkle proof.
        let ok = deserialized_proof.verify(&leaf, &deserialized_root);
        ensure!(ok, MempoolError::BadInclusionProof);
        Ok(())
    }
}

/// Hash a shard together with its absolute index to form a Merkle leaf.
fn make_leaf(shard: &[u8], destination: usize) -> MTreeNodeSmt<blake3::Hasher> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(shard);
    hasher.update(&destination.to_le_bytes());
    let hash = hasher.finalize();
    MTreeNodeSmt::new(hash.as_bytes().to_vec())
}

/// A bundle of two authenticated shards destined for the same node, sharing one signature.
/// The two shards are at consecutive indices `2i` and `2i+1` for some node index `i`.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthenticatedBundle {
    pub shard_a: Shard,
    pub dest_a: usize,
    pub proof_a: SerializedProof,
    pub shard_b: Shard,
    pub dest_b: usize,
    pub proof_b: SerializedProof,
    pub root: Digest,
    pub author: PublicKey,
    pub signature: Signature,
}

impl AuthenticatedBundle {
    /// Build a bundle for one node from two (shard, absolute-index) pairs.
    /// The signature over the Merkle root is provided externally (signed once per batch).
    pub fn new(
        shard_a: Shard,
        dest_a: usize,
        shard_b: Shard,
        dest_b: usize,
        tree: &Tree,
        author: PublicKey,
        signature: Signature,
    ) -> Self {
        let serialized_root = tree.get_root().serialize();
        let root = Digest(serialized_root[0..32].try_into().unwrap());
        let height = tree.get_height();

        let proof_a = Proof::generate_inclusion_proof(
            tree,
            &[TreeIndex::from_u64(height, dest_a as u64)],
        )
        .expect("Failed to generate proof for shard_a")
        .serialize();

        let proof_b = Proof::generate_inclusion_proof(
            tree,
            &[TreeIndex::from_u64(height, dest_b as u64)],
        )
        .expect("Failed to generate proof for shard_b")
        .serialize();

        Self { shard_a, dest_a, proof_a, shard_b, dest_b, proof_b, root, author, signature }
    }

    /// Verify the bundle (one signature check + two Merkle proof checks).
    /// Returns the two constituent `AuthenticatedShard`s on success.
    pub fn verify(
        &self,
        committee: &Committee,
    ) -> MempoolResult<(AuthenticatedShard, AuthenticatedShard)> {
        ensure!(
            committee.stake(&self.author) > 0,
            MempoolError::UnknownAuthority(self.author)
        );

        // One signature check for both shards.
        self.signature.verify(&self.root, &self.author)?;

        let deserialized_root = MTreeNodeSmt::deserialize(&self.root.to_vec())
            .map_err(|_| MempoolError::BadInclusionProof)?;

        // Verify shard_a proof.
        let proof_a = Proof::deserialize(&self.proof_a)
            .map_err(|_| MempoolError::BadInclusionProof)?;
        ensure!(
            proof_a.verify(&make_leaf(&self.shard_a, self.dest_a), &deserialized_root),
            MempoolError::BadInclusionProof
        );

        // Verify shard_b proof.
        let proof_b = Proof::deserialize(&self.proof_b)
            .map_err(|_| MempoolError::BadInclusionProof)?;
        ensure!(
            proof_b.verify(&make_leaf(&self.shard_b, self.dest_b), &deserialized_root),
            MempoolError::BadInclusionProof
        );

        let a = AuthenticatedShard {
            shard: self.shard_a.clone(),
            destination: self.dest_a,
            proof: self.proof_a.clone(),
            root: self.root.clone(),
            author: self.author,
            signature: self.signature.clone(),
        };
        let b = AuthenticatedShard {
            shard: self.shard_b.clone(),
            destination: self.dest_b,
            proof: self.proof_b.clone(),
            root: self.root.clone(),
            author: self.author,
            signature: self.signature.clone(),
        };
        Ok((a, b))
    }
}
