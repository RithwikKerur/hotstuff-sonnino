use crate::batch_maker::{BatchMaker, Transaction};
use crate::config::{Committee, Parameters};
use async_trait::async_trait;
use bytes::Bytes;
use crypto::PublicKey;
use futures::sink::SinkExt as _;
use log::info;
use network::{MessageHandler, Receiver as NetworkReceiver, Writer};
use serde::{Deserialize, Serialize};
use std::error::Error;
use tokio::sync::mpsc::{channel, Sender};

#[cfg(test)]
#[path = "tests/mempool_tests.rs"]
pub mod mempool_tests;

/// The default channel capacity for each channel of the mempool.
pub const CHANNEL_CAPACITY: usize = 1_000;

/// The message exchanged between the nodes' mempool (kept for batch serialization compatibility).
#[derive(Debug, Serialize, Deserialize)]
pub enum MempoolMessage {
    Batch(Vec<Vec<u8>>),
}

pub struct Mempool;

impl Mempool {
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        parameters: Parameters,
        // Output channel: delivers serialized batches to the consensus proposer.
        tx_consensus: Sender<Vec<u8>>,
    ) {
        // NOTE: This log entry is used to compute performance.
        parameters.log();

        // Spawn the client-facing transaction pipeline.
        Self::handle_clients_transactions(name, committee, parameters, tx_consensus);
    }

    /// Spawn all tasks responsible to handle client transactions.
    fn handle_clients_transactions(
        name: PublicKey,
        committee: Committee,
        parameters: Parameters,
        tx_consensus: Sender<Vec<u8>>,
    ) {
        let (tx_batch_maker, rx_batch_maker) = channel(CHANNEL_CAPACITY);

        // We first receive clients' transactions from the network.
        let mut address = committee
            .transactions_address(&name)
            .expect("Our public key is not in the committee");
        address.set_ip("0.0.0.0".parse().unwrap());
        NetworkReceiver::spawn(
            address,
            /* handler */ TxReceiverHandler { tx_batch_maker },
        );

        // The `BatchMaker` assembles transactions into batches and forwards them directly
        // to the consensus proposer — no separate batch broadcast phase.
        BatchMaker::spawn(
            parameters.batch_size,
            parameters.max_batch_delay,
            /* rx_transaction */ rx_batch_maker,
            /* tx_batch */ tx_consensus,
        );

        info!("Mempool listening to client transactions on {}", address);
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

        // Give the chance to schedule other tasks.
        tokio::task::yield_now().await;
        Ok(())
    }
}
