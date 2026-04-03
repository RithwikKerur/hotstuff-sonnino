use crate::{
    aggregator::FullAvailabilityProof,
    config::Committee,
    mempool::MempoolMessage,
};
use bincode;
use crypto::{Digest, PublicKey};
use log::{debug, info, warn};
use std::collections::HashSet;
use store::Store;
use tokio::sync::mpsc::Receiver;

/// Drops extra shards (keeping exactly 1) for a batch once BOTH conditions are met:
///   1. A FullAvailabilityProof has been received (all nodes acknowledged the batch).
///   2. The block containing this batch has been committed and executed.
///
/// At least 1 shard is always retained.
pub struct ShardCleaner {
    name: PublicKey,
    committee: Committee,
    store: Store,
    /// Batch roots for which a FullAvailabilityProof has arrived.
    rx_proof: Receiver<FullAvailabilityProof>,
    /// Batch roots that have been committed/executed by the application layer.
    rx_committed: Receiver<Vec<Digest>>,
    /// Roots where we have a proof but not yet a commit.
    pending_proof: HashSet<Digest>,
    /// Roots where we have a commit but not yet a proof.
    pending_commit: HashSet<Digest>,
}

impl ShardCleaner {
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        store: Store,
        rx_proof: Receiver<FullAvailabilityProof>,
        rx_committed: Receiver<Vec<Digest>>,
    ) {
        tokio::spawn(async move {
            Self {
                name,
                committee,
                store,
                rx_proof,
                rx_committed,
                pending_proof: HashSet::new(),
                pending_commit: HashSet::new(),
            }
            .run()
            .await;
        });
    }

    /// Reduce the bundle for this node from k shards to 1 (the anchor shard),
    /// deriving an updated single-leaf Merkle proof from the existing batch proof.
    async fn prune(&mut self, root: &Digest) {
        let (data_shards, _) = self.committee.shards();
        let node_idx = match self.committee.index(&self.name) {
            Some(i) => i,
            None => return,
        };

        let mut key = root.to_vec();
        key.extend_from_slice(&(node_idx as u64).to_le_bytes());

        let serialized = match self.store.read(key.clone()).await {
            Ok(Some(b)) => b,
            Ok(None) => {
                debug!("Prune: no bundle stored for root {} node {}", root, node_idx);
                return;
            }
            Err(e) => {
                warn!("Prune: store read error for root {}: {}", root, e);
                return;
            }
        };

        let bundle = match bincode::deserialize::<MempoolMessage>(&serialized) {
            Ok(MempoolMessage::AuthenticatedShard(s)) => s,
            _ => {
                warn!("Prune: unexpected format for root {} node {}", root, node_idx);
                return;
            }
        };

        if bundle.shards.len() == 1 {
            debug!("Prune: bundle for root {} node {} already pruned", root, node_idx);
            return;
        }

        let pruned = bundle.prune_to_anchor_shard(data_shards);
        let msg = MempoolMessage::AuthenticatedShard(pruned);
        match bincode::serialize(&msg) {
            Ok(bytes) => {
                self.store.write(key, bytes).await;
                info!(
                    "Pruned batch {}: node {} reduced to anchor shard, dropped {} shards",
                    root,
                    node_idx,
                    data_shards - 1
                );
            }
            Err(e) => warn!("Prune: serialize error for root {}: {}", root, e),
        }
    }

    async fn run(&mut self) {
        loop {
            tokio::select! {
                Some(proof) = self.rx_proof.recv() => {
                    if let Err(e) = proof.verify(&self.committee) {
                        warn!("Invalid full availability proof for batch {}: {}", proof.root, e);
                        continue;
                    }
                    let root = proof.root.clone();
                    if self.pending_commit.remove(&root) {
                        // Both conditions met — prune now.
                        self.prune(&root).await;
                    } else {
                        self.pending_proof.insert(root);
                    }
                }
                Some(roots) = self.rx_committed.recv() => {
                    for root in roots {
                        if self.pending_proof.remove(&root) {
                            // Both conditions met — prune now.
                            self.prune(&root).await;
                        } else {
                            self.pending_commit.insert(root);
                        }
                    }
                }
            }
        }
    }
}
