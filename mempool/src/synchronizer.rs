use crate::{config::Committee, mempool::MempoolMessage};
use bytes::Bytes;
use crypto::{Digest, PublicKey};
use futures::stream::{futures_unordered::FuturesUnordered, StreamExt as _};
use log::debug;
use network::SimpleSender;
use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};
use store::Store;
use tokio::{
    sync::mpsc::{Receiver, Sender},
    time::{sleep, Duration, Instant},
};

/// Resolution of the timer managing retrials of sync requests (in ms).
const TIMER_RESOLUTION: u64 = 1_000;

// The `Synchronizer` is responsible to keep the mempool in sync with the others.
pub struct Synchronizer {
    /// The public key of this authority.
    name: PublicKey,
    /// The committee information.
    committee: Committee,
    // The persistent storage.
    store: Store,
    /// The delay to wait before re-trying to send sync requests.
    sync_retry_delay: u64,
    /// Input channel to receive the digests of certificates from the consensus.
    rx_digest: Receiver<Vec<(Digest, PublicKey)>>,
    /// Inform the `Reconstructor` of the missing batches.
    tx_missing: Sender<Digest>,
    /// A network sender to send requests to the other mempools.
    network: SimpleSender,
    /// Keeps the root (of batches) that are waiting to be processed by the consensus.
    pending: HashMap<Digest, u128>,
}

impl Synchronizer {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        store: Store,
        sync_retry_delay: u64,
        rx_digest: Receiver<Vec<(Digest, PublicKey)>>,
        tx_missing: Sender<Digest>,
    ) {
        tokio::spawn(async move {
            Self {
                name,
                committee,
                store,
                sync_retry_delay,
                rx_digest,
                tx_missing,
                network: SimpleSender::new(),
                pending: HashMap::new(),
            }
            .run()
            .await;
        });
    }

    /// Returns the store key for this node's first shard of a batch (index 2*node_idx).
    fn shard_key(digest: &Digest, committee: &Committee, name: &PublicKey) -> Vec<u8> {
        let node_idx = committee.index(name).unwrap_or(0);
        let first_shard = (2 * node_idx) as u64;
        let mut key = digest.to_vec();
        key.extend_from_slice(&first_shard.to_le_bytes());
        key
    }

    /// Helper function. Waits for a specific store key to become available.
    async fn waiter(missing: Digest, key: Vec<u8>, mut store: Store) -> Digest {
        store
            .notify_read(key)
            .await
            .expect("Failed to read store");
        missing
    }

    async fn sync(&mut self, missing: Digest) {
        // Always request individual shards from all nodes; we no longer serve full batches.
        let message = MempoolMessage::ShardRequest(missing, self.name);
        let addresses = self
            .committee
            .broadcast_addresses(&self.name)
            .iter()
            .map(|(_, address)| *address)
            .collect();
        let serialized = bincode::serialize(&message).expect("Failed to serialize our own message");
        self.network
            .lucky_broadcast(addresses, Bytes::from(serialized), self.committee.size())
            .await;
    }

    /// Main loop listening to the consensus' messages.
    async fn run(&mut self) {
        let mut waiting = FuturesUnordered::new();

        let timer = sleep(Duration::from_millis(TIMER_RESOLUTION));
        tokio::pin!(timer);

        loop {
            tokio::select! {
                Some(digests) = self.rx_digest.recv() => {
                    for (digest, _author) in digests {
                        if self.pending.contains_key(&digest) {
                            continue;
                        }

                        // Check if we already have our first shard for this batch.
                        let key = Self::shard_key(&digest, &self.committee, &self.name);
                        if self
                            .store
                            .read(key.clone())
                            .await
                            .expect("Failed to read store")
                            .is_some()
                        {
                            continue;
                        }

                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .expect("Failed to measure time")
                            .as_millis();
                        let fut = Self::waiter(digest.clone(), key, self.store.clone());
                        waiting.push(fut);
                        self.pending.insert(digest.clone(), now);

                        self.tx_missing.send(digest.clone()).await.expect("Failed to send root");
                        self.sync(digest).await;
                    }
                },

                Some(digest) = waiting.next() => {
                    debug!("Finished to sync batch {}", digest);
                    self.pending.remove(&digest);
                },

                () = &mut timer => {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("Failed to measure time")
                        .as_millis();

                    let mut retry = Vec::new();
                    for (digest, timestamp) in &mut self.pending {
                        if *timestamp + (self.sync_retry_delay as u128) < now {
                            debug!("Requesting sync for batch {} (retry)", digest);
                            retry.push(digest.clone());
                            *timestamp = now;
                        }
                    }
                    for digest in retry {
                        self.sync(digest).await;
                    }

                    timer.as_mut().reset(Instant::now() + Duration::from_millis(TIMER_RESOLUTION));
                },
            }
        }
    }
}
