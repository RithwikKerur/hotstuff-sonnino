use crate::{
    coded_batch::{AuthenticatedShard, CodedBatch, Shard},
    config::Committee,
    mempool::MempoolMessage,
};
use crypto::{Digest, PublicKey, Signature};
use log::{debug, warn};
use smtree::traits::Serializable as _;
use std::{
    collections::{HashMap, HashSet},
    convert::TryInto as _,
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
    /// One (author, signature) per root, sourced from a verified received shard.
    /// Reused to build a valid AuthenticatedShard after reconstruction.
    sample_authors: HashMap<Digest, (PublicKey, Signature)>,
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
                sample_authors: HashMap::new(),
            }
            .run()
            .await;
        });
    }
    async fn run(&mut self) {
        loop {
            tokio::select! {
                Some(root) = self.rx_missing.recv() => {
                    //debug!("Registering missing batch {}", root);
                    self.missing.insert(root);
                }
                Some(shard) = self.rx_shard.recv() => {
                    //debug!("Received shard of {}", shard.root);

                    // Verify the bundle.
                    let (data_shards, parity_shards) = self.committee.shards();
                    let total_shards = data_shards + parity_shards;
                    if let Err(e) = shard.verify(&self.committee) {
                        warn!("{}", e);
                        continue;
                    }

                    // Ensure we requested this batch.
                    if !self.missing.contains(&shard.root) {
                        continue;
                    }

                    // Save one (author, signature) so we can rebuild a valid
                    // AuthenticatedShard bundle after reconstruction.
                    let root = shard.root.clone();
                    self.sample_authors
                        .entry(root.clone())
                        .or_insert_with(|| (shard.author, shard.signature.clone()));

                    // Add each individual shard from the bundle to the aggregator.
                    let start = shard.node_idx * data_shards;
                    let entry = self
                        .collected_shards
                        .entry(root.clone())
                        .or_insert_with(|| vec![None; total_shards]);
                    for (j, s) in shard.shards.into_iter().enumerate() {
                        entry[start + j] = Some(s);
                    }

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
                        let batch = CodedBatch::reconstruct(shards, &self.committee)
                            .expect("Failed to reconstruct batch from verified shards");

                        // Store our assigned bundle, serialized as
                        // MempoolMessage::AuthenticatedShard so the Helper can
                        // serve it correctly on sync requests.
                        let node_idx = self.committee.index(&self.name).unwrap_or(0);
                        let (data_shards, _) = self.committee.shards();
                        if let Some((author, signature)) = self.sample_authors.remove(&root) {
                            let tree = batch.commit();
                            let bundle_shards = batch.shards
                                [node_idx * data_shards..(node_idx + 1) * data_shards]
                                .to_vec();
                            let authenticated = AuthenticatedShard::make_with_signature(
                                bundle_shards,
                                node_idx,
                                data_shards,
                                &tree,
                                root.clone(),
                                author,
                                signature,
                            );
                            let message = MempoolMessage::AuthenticatedShard(authenticated);
                            let serialized = bincode::serialize(&message)
                                .expect("Failed to serialize reconstructed shard bundle");
                            let mut key = root.to_vec();
                            key.extend_from_slice(&(node_idx as u64).to_le_bytes());
                            self.store.write(key, serialized).await;
                        }

                        // Write a sentinel at the 32-byte root key so the consensus layer
                        // (Committer / MempoolDriver) can detect payload availability.
                        self.store.write(root.to_vec(), vec![1u8]).await;

                        // Update the missing batch set.
                        self.missing.remove(&root);
                    }

                },
            }
        }
    }
}
