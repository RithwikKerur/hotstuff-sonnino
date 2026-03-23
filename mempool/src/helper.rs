use crate::{config::Committee, mempool::MempoolMessage};
use bytes::Bytes;
use crypto::{Digest, PublicKey};
use log::warn;
use network::SimpleSender;
use store::Store;
use tokio::sync::mpsc::Receiver;

#[cfg(test)]
#[path = "tests/helper_tests.rs"]
pub mod helper_tests;

/// A task dedicated to help other authorities by replying to their shard requests.
pub struct Helper {
    // The public key of this authority.
    name: PublicKey,
    /// The committee information.
    committee: Committee,
    /// The persistent storage.
    store: Store,
    /// Input channel to receive shard requests.
    rx_request: Receiver<(Digest, PublicKey)>,
    /// A network sender to send the shards to the other mempools.
    network: SimpleSender,
}

impl Helper {
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        store: Store,
        rx_request: Receiver<(Digest, PublicKey)>,
    ) {
        tokio::spawn(async move {
            Self {
                name,
                committee,
                store,
                rx_request,
                network: SimpleSender::new(),
            }
            .run()
            .await;
        });
    }

    async fn run(&mut self) {
        while let Some((root, origin)) = self.rx_request.recv().await {
            let address = match self.committee.mempool_address(&origin) {
                Some(x) => x,
                None => {
                    warn!("Received shard request from unknown authority: {}", origin);
                    continue;
                }
            };

            // Read our own shard for this batch (stored at root || name).
            let mut key = root.to_vec();
            key.extend(self.name.to_vec());
            let data = self
                .store
                .read(key)
                .await
                .expect("Failed to read store")
                .and_then(|serialized| {
                    match bincode::deserialize::<MempoolMessage>(&serialized) {
                        Ok(MempoolMessage::AuthenticatedShard(shard)) => {
                            let reply = MempoolMessage::ShardReply(shard);
                            Some(bincode::serialize(&reply).expect("Failed to serialize shard reply"))
                        }
                        Ok(_) | Err(_) => {
                            // Stored value is a sentinel (reconstructed batch) or
                            // unrecognised format — we cannot serve a proper ShardReply.
                            None
                        }
                    }
                });

            if let Some(data) = data {
                self.network.send(address, Bytes::from(data)).await;
            }
        }
    }
}
