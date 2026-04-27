use crate::config::Committee;
use crate::consensus::Round;
use crate::erasure::MerkleProof;
use crate::error::{ConsensusError, ConsensusResult};
use crypto::{Digest, Hash, PublicKey, Signature, SignatureService};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::convert::TryInto;
use std::fmt;

#[cfg(test)]
#[path = "tests/messages_tests.rs"]
pub mod messages_tests;

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Block {
    pub qc: QC,
    pub tc: Option<TC>,
    pub author: PublicKey,
    pub round: Round,
    /// Each entry is a serialized batch of transactions from the leader's mempool.
    pub payload: Vec<Vec<u8>>,
    pub signature: Signature,
}

impl Block {
    pub async fn new(
        qc: QC,
        tc: Option<TC>,
        author: PublicKey,
        round: Round,
        payload: Vec<Vec<u8>>,
        mut signature_service: SignatureService,
    ) -> Self {
        let block = Self {
            qc,
            tc,
            author,
            round,
            payload,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(block.digest()).await;
        Self { signature, ..block }
    }

    pub fn genesis() -> Self {
        Block::default()
    }

    pub fn parent(&self) -> &Digest {
        &self.qc.hash
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(
            voting_rights > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        // Check the signature.
        self.signature.verify(&self.digest(), &self.author)?;

        // Check the embedded QC.
        if self.qc != QC::genesis() {
            self.qc.verify(committee)?;
        }

        // Check the TC embedded in the block (if any).
        if let Some(ref tc) = self.tc {
            tc.verify(committee)?;
        }
        Ok(())
    }
}

impl Hash for Block {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.author.0);
        hasher.update(self.round.to_le_bytes());
        for x in &self.payload {
            hasher.update(x);
        }
        hasher.update(&self.qc.hash);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: B({}, {}, {:?}, {})",
            self.digest(),
            self.author,
            self.round,
            self.qc,
            self.payload.iter().map(|x| x.len()).sum::<usize>(),
        )
    }
}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "B{}", self.round)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Vote {
    pub hash: Digest,
    pub round: Round,
    pub author: PublicKey,
    pub signature: Signature,
}

impl Vote {
    pub async fn new(
        block: &Block,
        author: PublicKey,
        mut signature_service: SignatureService,
    ) -> Self {
        let vote = Self {
            hash: block.digest(),
            round: block.round,
            author,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(vote.digest()).await;
        Self { signature, ..vote }
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        // Check the signature.
        self.signature.verify(&self.digest(), &self.author)?;
        Ok(())
    }
}

impl Hash for Vote {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.hash);
        hasher.update(self.round.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Vote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "V({}, {}, {})", self.author, self.round, self.hash)
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct QC {
    pub hash: Digest,
    pub round: Round,
    pub votes: Vec<(PublicKey, Signature)>,
}

impl QC {
    pub fn genesis() -> Self {
        QC::default()
    }

    pub fn timeout(&self) -> bool {
        self.hash == Digest::default() && self.round != 0
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the QC has a quorum.
        let mut weight = 0;
        let mut used = HashSet::new();
        for (name, _) in self.votes.iter() {
            ensure!(!used.contains(name), ConsensusError::AuthorityReuse(*name));
            let voting_rights = committee.stake(name);
            ensure!(voting_rights > 0, ConsensusError::UnknownAuthority(*name));
            used.insert(*name);
            weight += voting_rights;
        }
        ensure!(
            weight >= committee.quorum_threshold(),
            ConsensusError::QCRequiresQuorum
        );

        // Check the signatures.
        Signature::verify_batch(&self.digest(), &self.votes).map_err(ConsensusError::from)
    }
}

impl Hash for QC {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.hash);
        hasher.update(self.round.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for QC {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "QC({}, {})", self.hash, self.round)
    }
}

impl PartialEq for QC {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash && self.round == other.round
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Timeout {
    pub high_qc: QC,
    pub round: Round,
    pub author: PublicKey,
    pub signature: Signature,
}

impl Timeout {
    pub async fn new(
        high_qc: QC,
        round: Round,
        author: PublicKey,
        mut signature_service: SignatureService,
    ) -> Self {
        let timeout = Self {
            high_qc,
            round,
            author,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(timeout.digest()).await;
        Self {
            signature,
            ..timeout
        }
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        // Check the signature.
        self.signature.verify(&self.digest(), &self.author)?;

        // Check the embedded QC.
        if self.high_qc != QC::genesis() {
            self.high_qc.verify(committee)?;
        }
        Ok(())
    }
}

impl Hash for Timeout {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.round.to_le_bytes());
        hasher.update(self.high_qc.round.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Timeout {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "TV({}, {}, {:?})", self.author, self.round, self.high_qc)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TC {
    pub round: Round,
    pub votes: Vec<(PublicKey, Signature, Round)>,
}

impl TC {
    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the QC has a quorum.
        let mut weight = 0;
        let mut used = HashSet::new();
        for (name, _, _) in self.votes.iter() {
            ensure!(!used.contains(name), ConsensusError::AuthorityReuse(*name));
            let voting_rights = committee.stake(name);
            ensure!(voting_rights > 0, ConsensusError::UnknownAuthority(*name));
            used.insert(*name);
            weight += voting_rights;
        }
        ensure!(
            weight >= committee.quorum_threshold(),
            ConsensusError::TCRequiresQuorum
        );

        // Check the signatures.
        for (author, signature, high_qc_round) in &self.votes {
            let mut hasher = Sha512::new();
            hasher.update(self.round.to_le_bytes());
            hasher.update(high_qc_round.to_le_bytes());
            let digest = Digest(hasher.finalize().as_slice()[..32].try_into().unwrap());
            signature.verify(&digest, author)?;
        }
        Ok(())
    }

    pub fn high_qc_rounds(&self) -> Vec<Round> {
        self.votes.iter().map(|(_, _, r)| r).cloned().collect()
    }
}

impl fmt::Debug for TC {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "TC({}, {:?})", self.round, self.high_qc_rounds())
    }
}

// ---------------------------------------------------------------------------
// StoredFragments / SyncFragments
// ---------------------------------------------------------------------------

/// What every node stores at `digest` key in RocksDB: its own designated RS
/// shard set for that block.  The synchronizer and helper call `into_block` to
/// reconstruct the full block on demand.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredFragments {
    pub data_shards: usize,
    pub total_shards: usize,
    pub block_len: usize,
    pub shard_indices: Vec<usize>,
    pub shards: Vec<Vec<u8>>,
    pub proofs: Vec<MerkleProof>,
    pub merkle_root: [u8; 32],
}

impl StoredFragments {
    pub fn into_block(self) -> ConsensusResult<Block> {
        let mut shards_opt = vec![None; self.total_shards];
        for (idx, shard) in self.shard_indices.into_iter().zip(self.shards.into_iter()) {
            shards_opt[idx] = Some(shard);
        }
        let bytes = crate::erasure::reconstruct(
            shards_opt,
            self.data_shards,
            self.total_shards,
            self.block_len,
        )?;
        bincode::deserialize(&bytes).map_err(ConsensusError::SerializationError)
    }
}

/// Sent by the Helper in response to a `SyncRequest`.  The receiver reconstructs
/// the block, re-encodes it, and stores its own designated shard set.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SyncFragments {
    pub digest: Digest,
    pub data_shards: usize,
    pub total_shards: usize,
    pub block_len: usize,
    pub shard_indices: Vec<usize>,
    pub shards: Vec<Vec<u8>>,
    pub proofs: Vec<MerkleProof>,
    pub merkle_root: [u8; 32],
}

// ---------------------------------------------------------------------------
// ErasureProposal
// ---------------------------------------------------------------------------

/// Sent by the leader to each node during block dissemination.
///
/// Each node receives `data_shards` (= 2F+1) consecutive RS fragments of the
/// serialised block, together with their Merkle proofs against `merkle_root`.
/// The node can reconstruct the full block independently from its fragment set
/// (since k = 2F+1 = the number of fragments it receives).
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ErasureProposal {
    // Block header fields sent in the clear for early leader validation.
    pub author: PublicKey,
    pub round: Round,
    pub qc: QC,
    pub tc: Option<TC>,
    pub signature: Signature,

    // Erasure coding parameters.
    /// Merkle root committing to all `total_shards` RS shards.
    pub merkle_root: [u8; 32],
    /// k = 2F+1: minimum shards needed for reconstruction (= shards per node).
    pub data_shards: usize,
    /// n = (2F+1)*N: total shards across all nodes.
    pub total_shards: usize,
    /// Original serialised-block length (used to trim zero-padding after reconstruction).
    pub block_len: usize,

    // This node's fragment set.
    /// Global shard indices assigned to this node.
    pub shard_indices: Vec<usize>,
    /// Shard bytes for each index above (each shard has the same length).
    pub shards: Vec<Vec<u8>>,
    /// Merkle proof for each shard above.
    pub proofs: Vec<MerkleProof>,
}
