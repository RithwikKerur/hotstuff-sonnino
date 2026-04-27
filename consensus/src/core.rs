use crate::aggregator::Aggregator;
use crate::config::Committee;
use crate::consensus::{ConsensusMessage, Round};
use crate::erasure;
use crate::error::{ConsensusError, ConsensusResult};
use crate::leader::LeaderElector;
use crate::messages::{Block, ErasureProposal, StoredFragments, SyncFragments, Timeout, Vote, QC, TC};
use crate::proposer::ProposerMessage;
use crate::synchronizer::Synchronizer;
use crate::timer::Timer;
use async_recursion::async_recursion;
use bytes::Bytes;
use crypto::Hash as _;
use crypto::{Digest, PublicKey, SignatureService};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use log::{debug, error, info, warn};
use network::SimpleSender;
use std::cmp::max;
use std::collections::{HashMap, VecDeque};
use std::convert::TryInto;
use std::time::Instant;
use store::Store;
use tokio::sync::mpsc::{Receiver, Sender};

#[cfg(test)]
#[path = "tests/core_tests.rs"]
pub mod core_tests;

pub struct Core {
    name: PublicKey,
    committee: Committee,
    store: Store,
    signature_service: SignatureService,
    leader_elector: LeaderElector,
    synchronizer: Synchronizer,
    rx_message: Receiver<ConsensusMessage>,
    rx_loopback: Receiver<Block>,
    rx_proposer_loopback: Receiver<ErasureProposal>,
    tx_proposer: Sender<ProposerMessage>,
    tx_commit: Sender<Block>,
    round: Round,
    last_voted_round: Round,
    last_committed_round: Round,
    high_qc: QC,
    timer: Timer,
    aggregator: Aggregator,
    network: SimpleSender,
    // Fragment sets awaiting ancestor confirmation before being written to disk.
    pending_fragments: HashMap<Digest, StoredFragments>,
    // Phase timing: keyed by round number.
    phase1_start: HashMap<Round, Instant>, // when process_block first sees the block
    phase1_end: HashMap<Round, Instant>,   // when the node casts its vote (phase 1 done)
}

impl Core {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        signature_service: SignatureService,
        store: Store,
        leader_elector: LeaderElector,
        synchronizer: Synchronizer,
        timeout_delay: u64,
        rx_message: Receiver<ConsensusMessage>,
        rx_loopback: Receiver<Block>,
        rx_proposer_loopback: Receiver<ErasureProposal>,
        tx_proposer: Sender<ProposerMessage>,
        tx_commit: Sender<Block>,
    ) {
        tokio::spawn(async move {
            Self {
                name,
                committee: committee.clone(),
                signature_service,
                store,
                leader_elector,
                synchronizer,
                rx_message,
                rx_loopback,
                rx_proposer_loopback,
                tx_proposer,
                tx_commit,
                round: 1,
                last_voted_round: 0,
                last_committed_round: 0,
                high_qc: QC::genesis(),
                timer: Timer::new(timeout_delay),
                aggregator: Aggregator::new(committee),
                network: SimpleSender::new(),
                pending_fragments: HashMap::new(),
                phase1_start: HashMap::new(),
                phase1_end: HashMap::new(),
            }
            .run()
            .await
        });
    }

    async fn store_fragments(&mut self, block_digest: Digest, frags: StoredFragments) {
        let key = block_digest.to_vec();
        let value = bincode::serialize(&frags).expect("Failed to serialize fragment store entry");
        self.store.write(key, value).await;
    }

    fn proposal_to_stored_fragments(proposal: &ErasureProposal) -> StoredFragments {
        StoredFragments {
            data_shards: proposal.data_shards,
            total_shards: proposal.total_shards,
            block_len: proposal.block_len,
            shard_indices: proposal.shard_indices.clone(),
            shards: proposal.shards.clone(),
            proofs: proposal.proofs.clone(),
            merkle_root: proposal.merkle_root,
        }
    }



    fn increase_last_voted_round(&mut self, target: Round) {
        self.last_voted_round = max(self.last_voted_round, target);
    }

    async fn make_vote(&mut self, block: &Block) -> Option<Vote> {
        // Check if we can vote for this block.
        let safety_rule_1 = block.round > self.last_voted_round;
        let mut safety_rule_2 = block.qc.round + 1 == block.round;
        if let Some(ref tc) = block.tc {
            let mut can_extend = tc.round + 1 == block.round;
            can_extend &= block.qc.round >= *tc.high_qc_rounds().iter().max().expect("Empty TC");
            safety_rule_2 |= can_extend;
        }
        if !(safety_rule_1 && safety_rule_2) {
            return None;
        }

        // Ensure we won't vote for contradicting blocks.
        self.increase_last_voted_round(block.round);
        // TODO [issue #15]: Write to storage preferred_round and last_voted_round.
        Some(Vote::new(block, self.name, self.signature_service.clone()).await)
    }

    async fn commit(&mut self, block: Block) -> ConsensusResult<()> {
        if self.last_committed_round >= block.round {
            return Ok(());
        }

        // Ensure we commit the entire chain. This is needed after view-change.
        let mut to_commit = VecDeque::new();
        let mut parent = block.clone();
        while self.last_committed_round + 1 < parent.round {
            let ancestor = self
                .synchronizer
                .get_parent_block(&parent)
                .await?
                .expect("We should have all the ancestors by now");
            to_commit.push_front(ancestor.clone());
            parent = ancestor;
        }
        to_commit.push_front(block.clone());

        // Save the last committed block.
        self.last_committed_round = block.round;

        // Snapshot the commit time once; all blocks in the batch are committed together.
        let commit_time = Instant::now();

        // Send all the newly committed blocks to the node's application layer.
        while let Some(block) = to_commit.pop_back() {
            // Log phase timing for this block if we recorded both phase boundaries.
            if let (Some(&p1_start), Some(&p1_end)) = (
                self.phase1_start.get(&block.round),
                self.phase1_end.get(&block.round),
            ) {
                let phase1_ms = (p1_end - p1_start).as_secs_f64() * 1000.0;
                let phase2_ms = (commit_time - p1_end).as_secs_f64() * 1000.0;
                info!(
                    "PHASE_TIMING round={} phase1_ms={:.3} phase2_ms={:.3}",
                    block.round, phase1_ms, phase2_ms
                );
            }
            self.phase1_start.remove(&block.round);
            self.phase1_end.remove(&block.round);

            if !block.payload.is_empty() {
                info!("Committed {}", block);

                #[cfg(feature = "benchmark")]
                for x in &block.payload {
                    // Recompute the digest so it matches what the BatchMaker logged.
                    let digest = Digest(
                        Sha512::digest(x.as_slice()).as_slice()[..32]
                            .try_into()
                            .expect("SHA-512 digest is always ≥ 32 bytes"),
                    );
                    // NOTE: This log entry is used to compute performance.
                    info!("Committed {} -> {:?}", block, digest);
                }
            }
            debug!("Committed {:?}", block);
            if let Err(e) = self.tx_commit.send(block).await {
                warn!("Failed to send block through the commit channel: {}", e);
            }
        }
        Ok(())
    }

    fn update_high_qc(&mut self, qc: &QC) {
        if qc.round > self.high_qc.round {
            self.high_qc = qc.clone();
        }
    }

    async fn local_timeout_round(&mut self) -> ConsensusResult<()> {
        warn!("Timeout reached for round {}", self.round);

        // Increase the last voted round.
        self.increase_last_voted_round(self.round);

        // Make a timeout message.
        let timeout = Timeout::new(
            self.high_qc.clone(),
            self.round,
            self.name,
            self.signature_service.clone(),
        )
        .await;
        debug!("Created {:?}", timeout);

        // Reset the timer.
        self.timer.reset();

        // Broadcast the timeout message.
        debug!("Broadcasting {:?}", timeout);
        let addresses = self
            .committee
            .broadcast_addresses(&self.name)
            .into_iter()
            .map(|(_, x)| x)
            .collect();
        let message = bincode::serialize(&ConsensusMessage::Timeout(timeout.clone()))
            .expect("Failed to serialize timeout message");
        self.network
            .broadcast(addresses, Bytes::from(message))
            .await;

        // Process our message.
        self.handle_timeout(&timeout).await
    }

    #[async_recursion]
    async fn handle_vote(&mut self, vote: &Vote) -> ConsensusResult<()> {
        debug!("Processing {:?}", vote);
        if vote.round < self.round {
            return Ok(());
        }

        // Ensure the vote is well formed.
        vote.verify(&self.committee)?;

        // Add the new vote to our aggregator and see if we have a quorum.
        if let Some(qc) = self.aggregator.add_vote(vote.clone())? {
            debug!("Assembled {:?}", qc);

            // Phase 1 ends here: this node has collected a quorum of votes and
            // formed a QC. Only the vote-collecting leader reaches this point.
            self.phase1_end.insert(qc.round, Instant::now());

            // Process the QC.
            self.process_qc(&qc).await;

            // Make a new block if we are the next leader.
            if self.name == self.leader_elector.get_leader(self.round) {
                self.generate_proposal(None).await;
            }
        }
        Ok(())
    }

    async fn handle_timeout(&mut self, timeout: &Timeout) -> ConsensusResult<()> {
        debug!("Processing {:?}", timeout);
        if timeout.round < self.round {
            return Ok(());
        }

        // Ensure the timeout is well formed.
        timeout.verify(&self.committee)?;

        // Process the QC embedded in the timeout.
        self.process_qc(&timeout.high_qc).await;

        // Add the new vote to our aggregator and see if we have a quorum.
        if let Some(tc) = self.aggregator.add_timeout(timeout.clone())? {
            debug!("Assembled {:?}", tc);

            // Try to advance the round.
            self.advance_round(tc.round).await;

            // Broadcast the TC.
            debug!("Broadcasting {:?}", tc);
            let addresses = self
                .committee
                .broadcast_addresses(&self.name)
                .into_iter()
                .map(|(_, x)| x)
                .collect();
            let message = bincode::serialize(&ConsensusMessage::TC(tc.clone()))
                .expect("Failed to serialize timeout certificate");
            self.network
                .broadcast(addresses, Bytes::from(message))
                .await;

            // Make a new block if we are the next leader.
            if self.name == self.leader_elector.get_leader(self.round) {
                self.generate_proposal(Some(tc)).await;
            }
        }
        Ok(())
    }

    #[async_recursion]
    async fn advance_round(&mut self, round: Round) {
        if round < self.round {
            return;
        }
        // Reset the timer and advance round.
        self.timer.reset();
        self.round = round + 1;
        debug!("Moved to round {}", self.round);

        // Cleanup the vote aggregator.
        self.aggregator.cleanup(&self.round);
    }

    #[async_recursion]
    async fn generate_proposal(&mut self, tc: Option<TC>) {
        self.tx_proposer
            .send(ProposerMessage::Make(self.round, self.high_qc.clone(), tc))
            .await
            .expect("Failed to send message to proposer");
    }

    /// Tell the proposer to drop any buffered batches that were already committed
    /// in blocks b0, b1, or block.
    async fn cleanup_proposer(&mut self, b0: &Block, b1: &Block, block: &Block) {
        let digests: Vec<Digest> = b0
            .payload
            .iter()
            .chain(b1.payload.iter())
            .chain(block.payload.iter())
            .map(|batch| {
                Digest(
                    Sha512::digest(batch.as_slice()).as_slice()[..32]
                        .try_into()
                        .expect("SHA-512 digest is always ≥ 32 bytes"),
                )
            })
            .collect();
        self.tx_proposer
            .send(ProposerMessage::Cleanup(digests))
            .await
            .expect("Failed to send message to proposer");
    }

    async fn process_qc(&mut self, qc: &QC) {
        self.advance_round(qc.round).await;
        self.update_high_qc(qc);
    }

    #[async_recursion]
    async fn process_block(&mut self, block: &Block) -> ConsensusResult<()> {
        debug!("Processing {:?}", block);

        // Record Phase 1 start: the first time this node sees the block.
        self.phase1_start
            .entry(block.round)
            .or_insert_with(Instant::now);

        // Let's see if we have the last three ancestors of the block, that is:
        //      b0 <- |qc0; b1| <- |qc1; block|
        // If we don't, the synchronizer asks for them from other nodes. It will
        // then ensure we process both ancestors in the correct order, and
        // finally make us resume processing this block.
        let (b0, b1) = match self.synchronizer.get_ancestors(block).await? {
            Some(ancestors) => ancestors,
            None => {
                debug!("Processing of {} suspended: missing parent", block.digest());
                return Ok(());
            }
        };

        // Ancestors confirmed — flush this block's fragment set to disk.
        // This fires notify_read for any block suspended waiting on this digest.
        if let Some(frags) = self.pending_fragments.remove(&block.digest()) {
            self.store_fragments(block.digest(), frags).await;
        }

        self.cleanup_proposer(&b0, &b1, block).await;

        // Check if we can commit the head of the 2-chain.
        // Note that we commit blocks only if we have all their ancestors.
        if b0.round + 1 == b1.round {
            self.commit(b0).await?;
        }

        // Ensure the block's round is as expected.
        // This check is important: it prevents bad leaders from producing blocks
        // far in the future that may cause overflow on the round number.
        if block.round != self.round {
            return Ok(());
        }

        // See if we can vote for this block.
        if let Some(vote) = self.make_vote(block).await {
            debug!("Created {:?}", vote);
            let next_leader = self.leader_elector.get_leader(self.round + 1);
            if next_leader == self.name {
                self.handle_vote(&vote).await?;
            } else {
                debug!("Sending {:?} to {}", vote, next_leader);
                let address = self
                    .committee
                    .address(&next_leader)
                    .expect("The next leader is not in the committee");
                let message = bincode::serialize(&ConsensusMessage::Vote(vote))
                    .expect("Failed to serialize vote");
                self.network.send(address, Bytes::from(message)).await;
            }
        }
        Ok(())
    }

    async fn handle_sync_fragments(&mut self, frags: SyncFragments) -> ConsensusResult<()> {
        // Reconstruct the full block from the responder's shard set.
        let mut shards_opt = vec![None; frags.total_shards];
        for (idx, shard) in frags.shard_indices.iter().zip(frags.shards.iter()) {
            shards_opt[*idx] = Some(shard.clone());
        }
        let block_bytes =
            erasure::reconstruct(shards_opt, frags.data_shards, frags.total_shards, frags.block_len)?;

        // Verify the reconstructed block is well-formed and its digest matches.
        let block: Block =
            bincode::deserialize(&block_bytes).map_err(ConsensusError::SerializationError)?;
        ensure!(
            block.digest() == frags.digest,
            ConsensusError::MalformedBlock(frags.digest)
        );
        block.verify(&self.committee)?;

        // Re-encode and store this node's designated shard set.
        let k = frags.data_shards;
        let n = frags.total_shards;
        let (shards, merkle_root, proofs) = erasure::encode(&block_bytes, k, n);
        let ordered = self.committee.ordered_authorities();
        let node_idx = ordered
            .iter()
            .position(|(name, _)| name == &self.name)
            .expect("Our public key is not in the committee");
        let shard_indices: Vec<usize> = (node_idx * k..(node_idx + 1) * k).collect();
        let my_shards: Vec<Vec<u8>> = shard_indices.iter().map(|&i| shards[i].clone()).collect();
        let my_proofs: Vec<_> = shard_indices.iter().map(|&i| proofs[i].clone()).collect();

        self.pending_fragments.insert(
            frags.digest,
            StoredFragments {
                data_shards: k,
                total_shards: n,
                block_len: frags.block_len,
                shard_indices,
                shards: my_shards,
                proofs: my_proofs,
                merkle_root,
            },
        );

        // Advance round based on embedded QC/TC, then run the normal pipeline
        // so that process_block can flush our fragments and cascade any
        // further sync that's needed for missing ancestors.
        self.process_qc(&block.qc).await;
        if let Some(ref tc) = block.tc {
            self.advance_round(tc.round).await;
        }
        self.process_block(&block).await
    }

    async fn handle_erasure_proposal(
        &mut self,
        proposal: ErasureProposal,
    ) -> ConsensusResult<()> {
        // ------------------------------------------------------------------
        // 1. Early leader check (before doing any expensive work).
        // ------------------------------------------------------------------
        ensure!(
            proposal.author == self.leader_elector.get_leader(proposal.round),
            ConsensusError::WrongLeader {
                digest: Digest::default(),
                leader: proposal.author,
                round: proposal.round,
            }
        );

        // ------------------------------------------------------------------
        // 2. Verify each shard's Merkle proof before reconstruction.
        //    Rejects corrupt or mismatched shards from a Byzantine leader
        //    without paying the cost of RS reconstruction first.
        // ------------------------------------------------------------------
        for ((shard, idx), proof) in proposal
            .shards
            .iter()
            .zip(proposal.shard_indices.iter())
            .zip(proposal.proofs.iter())
        {
            ensure!(
                erasure::verify_proof(shard, *idx, proof, &proposal.merkle_root),
                ConsensusError::InvalidMerkleProof
            );
        }

        // ------------------------------------------------------------------
        // 3. Reconstruct the full block from the fragment set.
        //    Each node receives k = 2F+1 shards, which is exactly the
        //    reconstruction threshold, so no inter-node help is needed.
        // ------------------------------------------------------------------
        let k = proposal.data_shards;
        let n = proposal.total_shards;
        let mut shards_opt: Vec<Option<Vec<u8>>> = vec![None; n];
        for (idx, shard) in proposal
            .shard_indices
            .iter()
            .zip(proposal.shards.iter())
        {
            shards_opt[*idx] = Some(shard.clone());
        }
        let block_bytes = erasure::reconstruct(shards_opt, k, n, proposal.block_len)?;

        // ------------------------------------------------------------------
        // 4. Deserialise and run normal block verification.
        // ------------------------------------------------------------------
        let block: Block =
            bincode::deserialize(&block_bytes).map_err(ConsensusError::SerializationError)?;

        ensure!(
            block.author == proposal.author,
            ConsensusError::MalformedBlock(block.digest())
        );
        ensure!(
            block.round == proposal.round,
            ConsensusError::MalformedBlock(block.digest())
        );

        block.verify(&self.committee)?;

        // ------------------------------------------------------------------
        // 5. Advance round based on embedded QC / TC.
        // ------------------------------------------------------------------
        self.process_qc(&block.qc).await;
        if let Some(ref tc) = block.tc {
            self.advance_round(tc.round).await;
        }

        // ------------------------------------------------------------------
        // 6. Park fragment set in memory; the disk write happens inside
        //    process_block after get_ancestors confirms ancestors are present.
        //    This preserves the invariant: a block is on disk only once all
        //    its ancestors are on disk (so notify_read never fires prematurely).
        // ------------------------------------------------------------------
        self.pending_fragments
            .insert(block.digest(), Self::proposal_to_stored_fragments(&proposal));

        debug!(
            "Queued {} fragment(s) for {:?}",
            proposal.shards.len(),
            block
        );

        // ------------------------------------------------------------------
        // 7. Hand off to the normal block-processing pipeline (vote, commit).
        // ------------------------------------------------------------------
        self.process_block(&block).await
    }

    async fn handle_tc(&mut self, tc: TC) -> ConsensusResult<()> {
        tc.verify(&self.committee)?;
        if tc.round < self.round {
            return Ok(());
        }
        self.advance_round(tc.round).await;
        if self.name == self.leader_elector.get_leader(self.round) {
            self.generate_proposal(Some(tc)).await;
        }
        Ok(())
    }

    pub async fn run(&mut self) {
        // Upon booting, generate the very first block (if we are the leader).
        // Also, schedule a timer in case we don't hear from the leader.
        self.timer.reset();
        if self.name == self.leader_elector.get_leader(self.round) {
            self.generate_proposal(None).await;
        }

        // This is the main loop: it processes incoming blocks and votes,
        // and receives timeout notifications from our Timeout Manager.
        loop {
            let result = tokio::select! {
                Some(message) = self.rx_message.recv() => match message {
                    ConsensusMessage::ErasureProposal(p) => self.handle_erasure_proposal(p).await,
                    ConsensusMessage::SyncFragments(f) => self.handle_sync_fragments(f).await,
                    ConsensusMessage::Vote(vote) => self.handle_vote(&vote).await,
                    ConsensusMessage::Timeout(timeout) => self.handle_timeout(&timeout).await,
                    ConsensusMessage::TC(tc) => self.handle_tc(tc).await,
                    _ => panic!("Unexpected protocol message")
                },
                // Synchronizer resume: parent became available, re-run process_block.
                Some(block) = self.rx_loopback.recv() => self.process_block(&block).await,
                // Leader's own proposal comes as an ErasureProposal via this channel.
                Some(proposal) = self.rx_proposer_loopback.recv() => self.handle_erasure_proposal(proposal).await,
                () = &mut self.timer => self.local_timeout_round().await,
            };
            match result {
                Ok(()) => (),
                Err(ConsensusError::StoreError(e)) => error!("{}", e),
                Err(ConsensusError::SerializationError(e)) => error!("Store corrupted. {}", e),
                Err(e) => warn!("{}", e),
            }
        }
    }
}
