use crate::{
    aggregator::{AggregatorService, BatchCertificate, FullAvailabilityProof},
    batch_maker::{BatchMaker, Transaction},
    certificate_verifier::CertificateVerifier,
    coded_batch::{AuthenticatedShard, CodedBatch},
    config::{Committee, Parameters},
    helper::Helper,
    reconstructor::Reconstructor,
    shard_cleaner::ShardCleaner,
    synchronizer::Synchronizer,
    voter::{BatchVote, NodesVoter, SelfVoter, SerializedShard},
};
use async_trait::async_trait;
use bytes::Bytes;
use crypto::{Digest, PublicKey, SignatureService};
use futures::sink::SinkExt as _;
use log::{info, warn};
use network::{MessageHandler, Receiver as NetworkReceiver, Writer};
use serde::{Deserialize, Serialize};
use std::error::Error;
use store::Store;
use tokio::sync::mpsc::{channel, Receiver, Sender};

#[cfg(test)]
#[path = "tests/mempool_tests.rs"]
pub mod mempool_tests;

/// The default channel capacity for each channel of the mempool.
pub const CHANNEL_CAPACITY: usize = 1_000;

/// The message exchanged between the nodes' mempool.
#[derive(Debug, Serialize, Deserialize)]
pub enum MempoolMessage {
    AuthenticatedShard(AuthenticatedShard),
    BatchVote(BatchVote),
    BatchCertificate(BatchCertificate),
    ShardRequest(Digest, PublicKey),
    ShardReply(AuthenticatedShard),
    BatchRequest(Digest, PublicKey),
    CodedBatch(CodedBatch),
    FullAvailabilityProof(FullAvailabilityProof),
}

pub struct Mempool;

impl Mempool {
    pub fn spawn(
        // The public key of this authority.
        name: PublicKey,
        // The committee information.
        committee: Committee,
        // The configuration parameters.
        parameters: Parameters,
        // The service signing digests.
        signature_service: SignatureService,
        // The persistent storage.
        store: Store,
        // Receives sync requests from consensus.
        rx_consensus: Receiver<Vec<(Digest, PublicKey)>>,
        // Sends messages to consensus.
        tx_consensus: Sender<BatchCertificate>,
        // Receives committed batch roots from the application layer for shard cleanup.
        rx_committed_payloads: Receiver<Vec<Digest>>,
    ) {
        // NOTE: This log entry is used to compute performance.
        parameters.log();

        let (tx_aggregator, rx_aggregator) = channel(CHANNEL_CAPACITY);
        let (tx_missing, rx_missing) = channel(CHANNEL_CAPACITY);
        // Shared proof channel: fed by AggregatorService (self) and network (other leaders).
        let (tx_proof, rx_proof) = channel(CHANNEL_CAPACITY);

        // Spawn all mempool tasks.
        Self::handle_consensus_messages(
            name,
            committee.clone(),
            store.clone(),
            &parameters,
            rx_consensus,
            tx_missing,
        );
        Self::handle_clients_transactions(
            name,
            committee.clone(),
            signature_service.clone(),
            store.clone(),
            &parameters,
            tx_consensus.clone(),
            tx_aggregator.clone(),
            rx_aggregator,
            tx_proof.clone(),
        );
        Self::handle_mempool_messages(
            name,
            committee.clone(),
            signature_service,
            store,
            tx_consensus,
            tx_aggregator,
            rx_missing,
            tx_proof,
            rx_proof,
            rx_committed_payloads,
        );

        info!(
            "Mempool successfully booted on {}",
            committee
                .mempool_address(&name)
                .expect("Our public key is not in the committee")
                .ip()
        );
    }

    /// Spawn all tasks responsible to handle messages from the consensus.
    fn handle_consensus_messages(
        name: PublicKey,
        committee: Committee,
        store: Store,
        parameters: &Parameters,
        rx_consensus: Receiver<Vec<(Digest, PublicKey)>>,
        tx_missing: Sender<Digest>,
    ) {
        Synchronizer::spawn(
            name,
            committee,
            store,
            parameters.sync_retry_delay,
            parameters.sync_nodes,
            parameters.sync_bias,
            /* rx_certificate */ rx_consensus,
            tx_missing,
        );
    }

    /// Spawn all tasks responsible to handle clients transactions.
    #[allow(clippy::too_many_arguments)]
    fn handle_clients_transactions(
        name: PublicKey,
        committee: Committee,
        signature_service: SignatureService,
        store: Store,
        parameters: &Parameters,
        tx_consensus: Sender<BatchCertificate>,
        tx_aggregator: Sender<BatchVote>,
        rx_aggregator: Receiver<BatchVote>,
        tx_proof: Sender<FullAvailabilityProof>,
    ) {
        let (tx_batch_maker, rx_batch_maker) = channel(CHANNEL_CAPACITY);
        let (tx_voter, rx_voter) = channel(CHANNEL_CAPACITY);
        let (tx_root, rx_root) = channel(CHANNEL_CAPACITY);

        let mut address = committee
            .transactions_address(&name)
            .expect("Our public key is not in the committee");
        address.set_ip("0.0.0.0".parse().unwrap());
        NetworkReceiver::spawn(
            address,
            /* handler */ TxReceiverHandler { tx_batch_maker },
        );

        BatchMaker::spawn(
            name,
            committee.clone(),
            signature_service.clone(),
            parameters.batch_size,
            parameters.max_batch_delay,
            /* rx_transaction */ rx_batch_maker,
            /* tx_authenticated_shard */ tx_voter,
            tx_root,
        );

        SelfVoter::spawn(
            name,
            committee.clone(),
            store,
            signature_service,
            /* rx_authenticated_shard */ rx_voter,
            tx_aggregator,
        );

        AggregatorService::spawn(
            name,
            committee,
            rx_root,
            /* rx_vote */ rx_aggregator,
            /* tx_output */ tx_consensus,
            /* tx_self_proof */ tx_proof,
        );

        info!("Mempool listening to client transactions on {}", address);
    }

    /// Spawn all tasks responsible to handle messages from other mempools.
    #[allow(clippy::too_many_arguments)]
    fn handle_mempool_messages(
        name: PublicKey,
        committee: Committee,
        signature_service: SignatureService,
        store: Store,
        tx_consensus: Sender<BatchCertificate>,
        tx_aggregator: Sender<BatchVote>,
        rx_missing: Receiver<Digest>,
        tx_proof: Sender<FullAvailabilityProof>,
        rx_proof: Receiver<FullAvailabilityProof>,
        rx_committed: Receiver<Vec<Digest>>,
    ) {
        let (tx_voter, rx_voter) = channel(CHANNEL_CAPACITY);
        let (tx_certificate_verifier, rx_certificate_verifier) = channel(CHANNEL_CAPACITY);
        let (tx_cleanup, rx_cleanup) = channel(CHANNEL_CAPACITY);
        let (tx_helper, rx_helper) = channel(CHANNEL_CAPACITY);
        let (tx_shard, rx_shard) = channel(CHANNEL_CAPACITY);

        let mut address = committee
            .mempool_address(&name)
            .expect("Our public key is not in the committee");
        address.set_ip("0.0.0.0".parse().unwrap());
        NetworkReceiver::spawn(
            address,
            /* handler */
            MempoolReceiverHandler {
                tx_voter,
                tx_aggregator,
                tx_certificate_verifier,
                tx_helper,
                tx_shard,
                tx_proof,
            },
        );

        NodesVoter::spawn(
            name,
            committee.clone(),
            store.clone(),
            signature_service,
            /* rx_authenticated_shard */ rx_voter,
            rx_cleanup,
        );

        CertificateVerifier::spawn(
            committee.clone(),
            /* rx_input */ rx_certificate_verifier,
            /* tx_output */ tx_consensus,
            tx_cleanup,
        );

        Helper::spawn(
            name,
            committee.clone(),
            store.clone(),
            /* rx_request */ rx_helper,
        );

        Reconstructor::spawn(name, committee.clone(), store.clone(), rx_missing, rx_shard);

        ShardCleaner::spawn(name, committee, store, rx_proof, rx_committed);

        info!("Mempool listening to mempool messages on {}", address);
    }
}

/// Defines how the network receiver handles incoming transactions.
#[derive(Clone)]
struct TxReceiverHandler {
    tx_batch_maker: Sender<Transaction>,
}

#[async_trait]
impl MessageHandler for TxReceiverHandler {
    async fn dispatch(&self, _writer: &mut Writer, message: Bytes) -> Result<(), Box<dyn Error>> {
        // Send the transaction to the batch maker.
        self.tx_batch_maker
            .send(message.to_vec())
            .await
            .expect("Failed to send transaction");

        // Give the change to schedule other tasks.
        tokio::task::yield_now().await;
        Ok(())
    }
}

/// Defines how the network receiver handles incoming mempool messages.
#[derive(Clone)]
struct MempoolReceiverHandler {
    tx_voter: Sender<(AuthenticatedShard, SerializedShard)>,
    tx_aggregator: Sender<BatchVote>,
    tx_certificate_verifier: Sender<BatchCertificate>,
    tx_helper: Sender<(Digest, PublicKey, bool)>,
    tx_shard: Sender<AuthenticatedShard>,
    tx_proof: Sender<FullAvailabilityProof>,
}

#[async_trait]
impl MessageHandler for MempoolReceiverHandler {
    async fn dispatch(&self, writer: &mut Writer, serialized: Bytes) -> Result<(), Box<dyn Error>> {
        // Reply with an ACK.
        let _ = writer.send(Bytes::from("Ack")).await;

        // Deserialize and parse the message.
        match bincode::deserialize(&serialized) {
            Ok(MempoolMessage::AuthenticatedShard(shard)) => self
                .tx_voter
                .send((shard, serialized.to_vec()))
                .await
                .expect("Failed to send shard"),
            Ok(MempoolMessage::BatchVote(vote)) => self
                .tx_aggregator
                .send(vote)
                .await
                .expect("Failed to send vote"),
            Ok(MempoolMessage::BatchCertificate(certificate)) => self
                .tx_certificate_verifier
                .send(certificate)
                .await
                .expect("Failed to send certificate"),
            Ok(MempoolMessage::ShardRequest(missing, sender)) => self
                .tx_helper
                .send((missing, sender, true))
                .await
                .expect("Failed to send shard request"),
            Ok(MempoolMessage::BatchRequest(missing, sender)) => self
                .tx_helper
                .send((missing, sender, false))
                .await
                .expect("Failed to send batch request"),
            Ok(MempoolMessage::ShardReply(shard)) => {
                // TODO: Ensure that `shard.destination` is the sender of this message. Otherwise
                // a bad batch creator may send us junk shards impersonating other nodes, and
                // we won't be able to reconstruct the batch.
                self.tx_shard
                    .send(shard)
                    .await
                    .expect("Failed to send shard");
            }
            Ok(MempoolMessage::CodedBatch(_)) => {
                // Nodes no longer store or serve full coded batches; discard.
            }
            Ok(MempoolMessage::FullAvailabilityProof(proof)) => self
                .tx_proof
                .send(proof)
                .await
                .expect("Failed to send full availability proof"),
            Err(e) => warn!("Serialization error: {}", e),
        }
        Ok(())
    }
}
