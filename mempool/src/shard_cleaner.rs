use crate::{aggregator::FullAvailabilityProof, config::Committee};
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

    /// Drop shards 1..data_shards for this node, keeping only shard 0.
    async fn prune(&mut self, root: &Digest) {
        let (data_shards, _) = self.committee.shards();
        let node_idx = match self.committee.index(&self.name) {
            Some(i) => i,
            None => return,
        };

        let kept = node_idx * data_shards;
        for offset in 1..data_shards {
            let shard_idx = node_idx * data_shards + offset;
            let mut key = root.to_vec();
            key.extend_from_slice(&(shard_idx as u64).to_le_bytes());
            debug!("Dropping shard {} of batch {}", shard_idx, root);
            self.store.delete(key).await;
        }
        info!(
            "Pruned batch {}: kept shard {}, dropped {} shards",
            root,
            kept,
            data_shards - 1
        );
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
