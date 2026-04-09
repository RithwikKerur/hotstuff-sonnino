use crate::{
    coded_batch::{AuthenticatedBundle, AuthenticatedShard},
    config::Committee,
    ensure,
    error::{MempoolError, MempoolResult},
    mempool::MempoolMessage,
};
use bytes::Bytes;
use crypto::{Digest, PublicKey, Signature, SignatureService};
use log::warn;
use network::{CancelHandler, ReliableSender};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use store::Store;
use tokio::sync::mpsc::{Receiver, Sender};

/// A vote on a coded batch.
#[derive(Serialize, Deserialize, Debug)]
pub struct BatchVote {
    /// The Merkle root of the coded batch.
    pub root: Digest,
    /// The signer's identity.
    pub author: PublicKey,
    /// The signature over of the Merkle root.
    pub signature: Signature,
}

impl BatchVote {
    pub async fn new(
        root: Digest,
        author: PublicKey,
        signature_service: &mut SignatureService,
    ) -> Self {
        Self {
            root: root.clone(),
            author,
            signature: signature_service.request_signature(root).await,
        }
    }

    pub fn verify(&self, committee: &Committee) -> MempoolResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            MempoolError::UnknownAuthority(self.author)
        );

        // Check the signature.
        // TODO: Make signature on root||author.
        self.signature.verify(&self.root, &self.author)?;
        Ok(())
    }
}

/// Maximum number of votes for which we are waiting for a certificate.
const MAX_PENDING_VOTES: usize = 100;

/// Vote for our own batch shards.
pub struct SelfVoter {
    /// The public key of this authority.
    name: PublicKey,
    /// The committee information.
    committee: Committee,
    /// The persistent storage.
    store: Store,
    /// The service to sign digests.
    signature_service: SignatureService,
    /// Receives the two-shard bundle for our own node.
    rx_authenticated_shard: Receiver<AuthenticatedBundle>,
    /// Outputs the votes for our own shards.
    tx_vote: Sender<BatchVote>,
}

impl SelfVoter {
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        store: Store,
        signature_service: SignatureService,
        rx_authenticated_shard: Receiver<AuthenticatedBundle>,
        tx_vote: Sender<BatchVote>,
    ) {
        tokio::spawn(async move {
            Self {
                name,
                committee,
                store,
                signature_service,
                rx_authenticated_shard,
                tx_vote,
            }
            .run()
            .await
        });
    }

    async fn run(&mut self) {
        while let Some(bundle) = self.rx_authenticated_shard.recv().await {
            // Verify signature + both Merkle proofs in one call.
            let (shard_a, shard_b) = match bundle.verify(&self.committee) {
                Ok(pair) => pair,
                Err(e) => { warn!("{}", e); continue; }
            };

            // Commit both shards + sentinel atomically in one RocksDB write.
            let mut batch: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(3);
            for shard in [&shard_a, &shard_b] {
                let serialized = bincode::serialize(shard)
                    .expect("Failed to serialize authenticated shard");
                let mut key = shard.root.to_vec();
                key.extend_from_slice(&(shard.destination as u64).to_le_bytes());
                batch.push((key, serialized));
            }
            batch.push((bundle.root.to_vec(), vec![1u8]));
            self.store.write_batch(batch).await;

            // Vote.
            let vote = BatchVote::new(bundle.root.clone(), self.name, &mut self.signature_service).await;
            self.tx_vote.send(vote).await.expect("Failed to send vote");
        }
    }
}

/// Vote for our other nodes' batch shards.
pub struct NodesVoter {
    /// The public key of this authority.
    name: PublicKey,
    /// The committee information.
    committee: Committee,
    /// The persistent storage.
    store: Store,
    /// The service to sign digests.
    signature_service: SignatureService,
    /// Receives the two-shard bundle for this node from the batch leader.
    rx_authenticated_shard: Receiver<AuthenticatedBundle>,
    /// Receives Merkle roots from consensus allowing to clean up internal state.
    rx_cleanup: Receiver<(PublicKey, Digest)>,
    /// The network sender.
    network: ReliableSender,
    /// Keeps the cancel handle of all the votes we sent.
    pending: HashMap<PublicKey, HashMap<Digest, CancelHandler>>,
}

impl NodesVoter {
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        store: Store,
        signature_service: SignatureService,
        rx_authenticated_shard: Receiver<AuthenticatedBundle>,
        rx_cleanup: Receiver<(PublicKey, Digest)>,
    ) {
        tokio::spawn(async move {
            Self {
                name,
                committee,
                store,
                signature_service,
                rx_authenticated_shard,
                rx_cleanup,
                network: ReliableSender::new(),
                pending: HashMap::new(),
            }
            .run()
            .await
        });
    }

    async fn run(&mut self) {
        loop {
            tokio::select! {
                // Process incoming two-shard bundle.
                Some(bundle) = self.rx_authenticated_shard.recv() => {
                    // Verify signature + both Merkle proofs.
                    let (shard_a, shard_b) = match bundle.verify(&self.committee) {
                        Ok(pair) => pair,
                        Err(e) => { warn!("{}", e); continue; }
                    };

                    let root = bundle.root.clone();
                    let author = bundle.author;

                    // Commit both shards + sentinel atomically in one RocksDB write.
                    let mut batch: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(3);
                    for shard in [&shard_a, &shard_b] {
                        let serialized = bincode::serialize(shard)
                            .expect("Failed to serialize authenticated shard");
                        let mut key = shard.root.to_vec();
                        key.extend_from_slice(&(shard.destination as u64).to_le_bytes());
                        batch.push((key, serialized));
                    }
                    batch.push((root.to_vec(), vec![1u8]));
                    self.store.write_batch(batch).await;

                    // Vote and reply.
                    let vote = BatchVote::new(root.clone(), self.name, &mut self.signature_service).await;
                    let address = self
                        .committee
                        .mempool_address(&author)
                        .expect("Author of valid bundle is not in the committee");
                    let message = MempoolMessage::BatchVote(vote);
                    let serialized = bincode::serialize(&message).expect("Failed to serialize vote");
                    let handle = self.network.send(address, Bytes::from(serialized)).await;
                    let map = self.pending.entry(author).or_insert_with(HashMap::new);
                    if map.len() >= MAX_PENDING_VOTES {
                        let key = map.keys().next().unwrap().clone();
                        map.retain(|x, _| x != &key);
                    }
                    map.insert(root.clone(), handle);
                },
                // Clean up internal state.
                Some((author, root)) = self.rx_cleanup.recv() => {
                    if let Some(map) = self.pending.get_mut(&author) {
                        let _ = map.remove(&root);
                    }
                }
            }
        }
    }
}
