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

/// A task dedicated to help other authorities by replying to their batch
/// requests.
pub struct Helper {
    // The public key of this authority.
    name: PublicKey,
    /// The committee information.
    committee: Committee,
    /// The persistent storage.
    store: Store,
    /// Input channel to receive shard and batch requests.
    rx_request: Receiver<(Digest, PublicKey, bool)>,
    /// A network sender to send the batches to the other mempools.
    network: SimpleSender,
}

impl Helper {
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        store: Store,
        rx_request: Receiver<(Digest, PublicKey, bool)>,
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
        while let Some((root, origin, want_shard)) = self.rx_request.recv().await {
            // TODO: Do some accounting to prevent bad nodes from monopolizing
            // our resources.

            // get the requestors address.
            let address = match self.committee.mempool_address(&origin) {
                Some(x) => x,
                None => {
                    warn!("Received batch request from unknown authority: {}", origin);
                    continue;
                }
            };

            if want_shard {
                // Send our bundle (all data_shards for our node_idx) to the requestor.
                let node_idx = self.committee.index(&self.name).unwrap_or(0);
                let mut key = root.to_vec();
                key.extend_from_slice(&(node_idx as u64).to_le_bytes());
                if let Ok(Some(serialized)) = self.store.read(key).await {
                    match bincode::deserialize(&serialized) {
                        Ok(MempoolMessage::AuthenticatedShard(shard)) => {
                            let message = MempoolMessage::ShardReply(shard);
                            let reply = bincode::serialize(&message)
                                .expect("Failed to serialize shard reply");
                            self.network.send(address, Bytes::from(reply)).await;
                        }
                        _ => warn!("Shard bundle stored in unexpected format"),
                    }
                }
            } else {
                // Batch request: look up the full batch by root.
                let data = self
                    .store
                    .read(root.to_vec())
                    .await
                    .expect("Failed to read store");
                if let Some(data) = data {
                    self.network.send(address, Bytes::from(data)).await;
                }
            }
        }
    }
}
