use crate::{coded_batch::AuthenticatedShard, config::Committee, mempool::MempoolMessage};
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

            // Send both of our assigned shards (indices 2*node_idx and 2*node_idx+1).
            let node_idx = self.committee.index(&self.name).unwrap_or(0);
            for dest in [2 * node_idx, 2 * node_idx + 1] {
                let mut key = root.to_vec();
                key.extend_from_slice(&(dest as u64).to_le_bytes());
                if let Ok(Some(serialized)) = self.store.read(key).await {
                    match bincode::deserialize::<AuthenticatedShard>(&serialized) {
                        Ok(shard) => {
                            let reply = MempoolMessage::ShardReply(shard);
                            let data = bincode::serialize(&reply)
                                .expect("Failed to serialize shard reply");
                            self.network.send(address, Bytes::from(data)).await;
                        }
                        Err(_) => warn!("Shard at dest {} stored in unexpected format", dest),
                    }
                }
            }
        }
    }
}
