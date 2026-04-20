use crate::config::{Committee, Stake};
use crate::consensus::{ConsensusMessage, Round};
use crate::erasure;
use crate::messages::{Block, ErasureProposal, QC, TC};
use bytes::Bytes;
use crypto::{Digest, PublicKey, SignatureService};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use futures::stream::futures_unordered::FuturesUnordered;
use futures::stream::StreamExt as _;
use log::{debug, info};
use network::{CancelHandler, ReliableSender};
use std::collections::HashMap;
use std::convert::TryInto;
use tokio::sync::mpsc::{Receiver, Sender};

#[derive(Debug)]
pub enum ProposerMessage {
    Make(Round, QC, Option<TC>),
    Cleanup(Vec<Digest>),
}

pub struct Proposer {
    name: PublicKey,
    committee: Committee,
    signature_service: SignatureService,
    /// Receives serialised batches from the local mempool.
    rx_mempool: Receiver<Vec<u8>>,
    rx_message: Receiver<ProposerMessage>,
    tx_loopback: Sender<Block>,
    /// Maps batch digest → batch bytes for efficient cleanup.
    buffer: HashMap<Digest, Vec<u8>>,
    network: ReliableSender,
}

impl Proposer {
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        signature_service: SignatureService,
        rx_mempool: Receiver<Vec<u8>>,
        rx_message: Receiver<ProposerMessage>,
        tx_loopback: Sender<Block>,
    ) {
        tokio::spawn(async move {
            Self {
                name,
                committee,
                signature_service,
                rx_mempool,
                rx_message,
                tx_loopback,
                buffer: HashMap::new(),
                network: ReliableSender::new(),
            }
            .run()
            .await;
        });
    }

    /// SHA-512/256 digest of a serialised batch; matches what BatchMaker logs.
    fn batch_digest(batch: &[u8]) -> Digest {
        Digest(
            Sha512::digest(batch).as_slice()[..32]
                .try_into()
                .expect("SHA-512 output is always ≥ 32 bytes"),
        )
    }

    /// Await a cancel-handler and yield the associated stake value.
    async fn waiter(wait_for: CancelHandler, deliver: Stake) -> Stake {
        let _ = wait_for.await;
        deliver
    }

    async fn make_block(&mut self, round: Round, qc: QC, tc: Option<TC>) {
        // ---------------------------------------------------------------
        // 1. Build and sign the block.
        // ---------------------------------------------------------------
        let payload: Vec<Vec<u8>> = self.buffer.drain().map(|(_, v)| v).collect();
        let block = Block::new(
            qc.clone(),
            tc.clone(),
            self.name,
            round,
            payload,
            self.signature_service.clone(),
        )
        .await;

        if !block.payload.is_empty() {
            info!("Created {}", block);
            #[cfg(feature = "benchmark")]
            for x in &block.payload {
                let digest = Self::batch_digest(x);
                info!("Created {} -> {:?}", block, digest);
            }
        }
        debug!("Created {:?}", block);

        // ---------------------------------------------------------------
        // 2. Erasure-code the serialised block.
        //    Scheme: k = 2F+1 data shards, n = k * N total shards.
        //    Each of the N nodes receives k consecutive shards (enough to
        //    independently reconstruct the full block).
        // ---------------------------------------------------------------
        let block_bytes = bincode::serialize(&block).expect("Failed to serialise block");
        let block_len = block_bytes.len();

        let k = self.committee.quorum_threshold() as usize; // 2F+1
        let n_nodes = self.committee.size();                 // N
        let n = k * n_nodes;                                 // (2F+1)*N total shards

        debug!(
            "Erasure-coding block {} ({}B): k={} n={}",
            block, block_len, k, n
        );

        let (shards, merkle_root, proofs) = erasure::encode(&block_bytes, k, n);

        // ---------------------------------------------------------------
        // 3. Send per-node ErasureProposal messages to every OTHER node.
        // ---------------------------------------------------------------
        let ordered = self.committee.ordered_authorities();
        let mut handles: FuturesUnordered<_> = FuturesUnordered::new();

        for (node_idx, (name, address)) in ordered.iter().enumerate() {
            if name == &self.name {
                continue; // Leader handles itself via the loopback.
            }

            // Shards assigned to this node: [node_idx*k, (node_idx+1)*k).
            let shard_indices: Vec<usize> = (node_idx * k..(node_idx + 1) * k).collect();
            let node_shards: Vec<Vec<u8>> =
                shard_indices.iter().map(|&i| shards[i].clone()).collect();
            let node_proofs: Vec<_> =
                shard_indices.iter().map(|&i| proofs[i].clone()).collect();

            let proposal = ErasureProposal {
                author: self.name,
                round,
                qc: qc.clone(),
                tc: tc.clone(),
                signature: block.signature.clone(),
                merkle_root,
                data_shards: k,
                total_shards: n,
                block_len,
                shard_indices,
                shards: node_shards,
                proofs: node_proofs,
            };

            let message =
                bincode::serialize(&ConsensusMessage::ErasureProposal(proposal))
                    .expect("Failed to serialise ErasureProposal");

            let handler = self
                .network
                .send(*address, Bytes::from(message))
                .await;

            let stake = self.committee.stake(name);
            handles.push(Self::waiter(handler, stake));
        }

        // ---------------------------------------------------------------
        // 4. Feed the full block into the local core for immediate processing.
        //    The leader already has everything it needs; no reconstruction required.
        // ---------------------------------------------------------------
        self.tx_loopback
            .send(block)
            .await
            .expect("Failed to send block to loopback");

        // ---------------------------------------------------------------
        // 5. Wait until 2F+1 nodes (counting ourselves) have ACKed receipt.
        // ---------------------------------------------------------------
        let mut total_stake = self.committee.stake(&self.name);
        while let Some(stake) = handles.next().await {
            total_stake += stake;
            if total_stake >= self.committee.quorum_threshold() {
                break;
            }
        }
    }

    async fn run(&mut self) {
        loop {
            tokio::select! {
                Some(batch) = self.rx_mempool.recv() => {
                    let digest = Self::batch_digest(&batch);
                    self.buffer.insert(digest, batch);
                },
                Some(message) = self.rx_message.recv() => match message {
                    ProposerMessage::Make(round, qc, tc) => self.make_block(round, qc, tc).await,
                    ProposerMessage::Cleanup(digests) => {
                        for x in &digests {
                            self.buffer.remove(x);
                        }
                    }
                }
            }
        }
    }
}
