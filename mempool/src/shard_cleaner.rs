use crate::{aggregator::FullAvailabilityProof, config::Committee};
use crypto::PublicKey;
use log::{debug, info, warn};
use store::Store;
use tokio::sync::mpsc::Receiver;

/// Listens for FullAvailabilityProofs and deletes all but the first stored shard
/// for each certified batch, reducing storage from `data_shards` to 1 shard per node.
pub struct ShardCleaner {
    name: PublicKey,
    committee: Committee,
    store: Store,
    rx_proof: Receiver<FullAvailabilityProof>,
}

impl ShardCleaner {
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        store: Store,
        rx_proof: Receiver<FullAvailabilityProof>,
    ) {
        tokio::spawn(async move {
            Self {
                name,
                committee,
                store,
                rx_proof,
            }
            .run()
            .await;
        });
    }

    async fn run(&mut self) {
        while let Some(proof) = self.rx_proof.recv().await {
            debug!("Received full availability proof for batch {}", proof.root);

            if let Err(e) = proof.verify(&self.committee) {
                warn!("Invalid full availability proof for batch {}: {}", proof.root, e);
                continue;
            }

            let (data_shards, _) = self.committee.shards();
            let node_idx = match self.committee.index(&self.name) {
                Some(i) => i,
                None => continue,
            };

            // Keep the first shard (offset 0) and delete offsets 1..data_shards-1.
            let kept = node_idx * data_shards;
            let deleted_count = data_shards - 1;
            for offset in 1..data_shards {
                let shard_idx = node_idx * data_shards + offset;
                let mut key = proof.root.to_vec();
                key.extend_from_slice(&shard_idx.to_le_bytes());
                debug!("Dropping shard {} of batch {}", shard_idx, proof.root);
                self.store.delete(key).await;
            }
            info!(
                "Pruned batch {}: kept shard {}, dropped {} shards",
                proof.root, kept, deleted_count
            );
        }
    }
}
