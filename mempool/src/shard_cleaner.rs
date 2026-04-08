use crate::{aggregator::FullAvailabilityProof, config::Committee};
use crypto::PublicKey;
use log::{debug, warn};
use store::Store;
use tokio::sync::mpsc::Receiver;

/// Listens for FullAvailabilityProofs (from the network and from the local aggregator)
/// and drops the second shard (dest = 2*node_idx+1) for each certified batch,
/// halving per-node storage after full network acknowledgement.
pub struct ShardCleaner {
    name: PublicKey,
    committee: Committee,
    store: Store,
    rx_network_proof: Receiver<FullAvailabilityProof>,
    rx_self_proof: Receiver<FullAvailabilityProof>,
}

impl ShardCleaner {
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        store: Store,
        rx_network_proof: Receiver<FullAvailabilityProof>,
        rx_self_proof: Receiver<FullAvailabilityProof>,
    ) {
        tokio::spawn(async move {
            Self { name, committee, store, rx_network_proof, rx_self_proof }.run().await;
        });
    }

    async fn prune(&mut self, proof: FullAvailabilityProof) {
        if let Err(e) = proof.verify(&self.committee) {
            warn!("Invalid FullAvailabilityProof for batch {}: {}", proof.root, e);
            return;
        }

        let node_idx = match self.committee.index(&self.name) {
            Some(i) => i,
            None => return,
        };

        // Drop the second shard (dest = 2*node_idx+1); keep the first for reconstruction.
        let dest_b = (2 * node_idx + 1) as u64;
        let mut key = proof.root.to_vec();
        key.extend_from_slice(&dest_b.to_le_bytes());
        self.store.delete(key).await;
        debug!("Dropped second shard (dest={}) for batch {}", dest_b, proof.root);
    }

    async fn run(&mut self) {
        loop {
            tokio::select! {
                Some(proof) = self.rx_network_proof.recv() => self.prune(proof).await,
                Some(proof) = self.rx_self_proof.recv()    => self.prune(proof).await,
            }
        }
    }
}
