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
                    // Verify the shard.
                    let destination = match self.committee.name(shard.destination) {
                        Some(x) => x,
                        None => {
                            warn!("Invalid shard: Unknown destination node");
                            continue;
                        }
                    };
                    if let Err(e) = shard.verify(&destination, &self.committee) {
                        warn!("{}", e);
                        continue;
                    }

                    // Ensure we requested this batch.
                    if !self.missing.contains(&shard.root) {
                        continue;
                    }

                    // Add the shard to the aggregator.
                    let size = self.committee.size();
                    let index = shard.destination;
                    let root = shard.root.clone();
                    self.collected_shards
                        .entry(root.clone())
                        .or_insert_with(|| vec![None; size])[index] = Some(shard.shard);

                    // Check if we have enough shards to reconstruct the batch.
                    let (data_shards, _) = self.committee.shards();
                    if self
                        .collected_shards
                        .get(&root)
                        .unwrap()
                        .iter()
                        .filter(|x| x.is_some())
                        .count() >= data_shards
                    {
                        debug!("Reconstructing {}", root);

                        // Reconstruct the batch.
                        let shards = self.collected_shards.remove(&root).unwrap();
                        match CodedBatch::reconstruct(shards, &self.committee) {
                            Ok(_) => {
                                // Store a sentinel at root||name to signal availability
                                // to the synchronizer. The full batch is not stored since
                                // each node only retains its own shard.
                                let mut key = root.to_vec();
                                key.extend(self.name.to_vec());
                                self.store.write(key, vec![1u8]).await;
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
