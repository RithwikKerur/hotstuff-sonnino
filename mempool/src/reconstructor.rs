use crate::{
    coded_batch::{AuthenticatedShard, CodedBatch, Shard},
    config::Committee,
};
use crypto::{Digest, PublicKey};
use log::{debug, warn};
use std::{
    collections::{HashMap, HashSet},
};
use store::Store;
use tokio::sync::mpsc::Receiver;

#[cfg(test)]
#[path = "tests/reconstructor_tests.rs"]
pub mod reconstructor_tests;

pub struct Reconstructor {
    /// The public key of this authority.
    name: PublicKey,
    /// The committee information.
    committee: Committee,
    /// The persistent storage.
    store: Store,
    /// Receive the root of the missing batches.
    rx_missing: Receiver<Digest>,
    /// Receives authenticated shards for the roots we requested.
    rx_shard: Receiver<AuthenticatedShard>,
    /// Keeps a set of missing batches.
    missing: HashSet<Digest>,
    /// Aggregator helping to reconstruct a batch from its shards.
    collected_shards: HashMap<Digest, Vec<Option<Shard>>>,
}

impl Reconstructor {
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        store: Store,
        rx_missing: Receiver<Digest>,
        rx_shard: Receiver<AuthenticatedShard>,
    ) {
        tokio::spawn(async move {
            Self {
                name,
                committee,
                store,
                rx_missing,
                rx_shard,
                missing: HashSet::new(),
                collected_shards: HashMap::new(),
            }
            .run()
            .await;
        });
    }

    async fn run(&mut self) {
        loop {
            tokio::select! {
                Some(root) = self.rx_missing.recv() => {
                    self.missing.insert(root);
                }
                Some(shard) = self.rx_shard.recv() => {
                    // Verify the shard (uses shard.destination directly).
                    let (data_shards, parity_shards) = self.committee.shards();
                    let total_shards = data_shards + parity_shards; // = 2N
                    if shard.destination >= total_shards {
                        warn!("Invalid shard: destination {} out of range", shard.destination);
                        continue;
                    }
                    if let Err(e) = shard.verify(&self.committee) {
                        warn!("{}", e);
                        continue;
                    }

                    // Ensure we requested this batch.
                    if !self.missing.contains(&shard.root) {
                        continue;
                    }

                    // Add the shard to the aggregator.
                    let index = shard.destination;
                    let root = shard.root.clone();
                    self.collected_shards
                        .entry(root.clone())
                        .or_insert_with(|| vec![None; total_shards])[index] = Some(shard.shard);

                    // Check if we have enough shards to reconstruct the batch.
                    if self
                        .collected_shards
                        .get(&root)
                        .unwrap()
                        .iter()
                        .filter(|x| x.is_some())
                        .count() >= data_shards
                    {
                        debug!("Reconstructing {}", root);

                        let shards = self.collected_shards.remove(&root).unwrap();
                        match CodedBatch::reconstruct(shards, &self.committee) {
                            Ok(_) => {
                                // Write sentinels so both the synchronizer and the
                                // consensus payload-waiter fire.
                                let node_idx = self.committee.index(&self.name).unwrap_or(0);
                                let first_shard = (2 * node_idx) as u64;
                                let mut shard_key = root.to_vec();
                                shard_key.extend_from_slice(&first_shard.to_le_bytes());
                                self.store.write(shard_key, vec![1u8]).await;
                                self.store.write(root.to_vec(), vec![1u8]).await;
                            }
                            Err(e) => warn!("Failed to reconstruct batch {}: {}", root, e),
                        }

                        self.missing.remove(&root);
                    }
                },
            }
        }
    }
}
