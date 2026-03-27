use crate::{
    config::{Committee, Stake},
    ensure,
    error::{MempoolError, MempoolResult},
    mempool::MempoolMessage,
    voter::BatchVote,
};
use bytes::Bytes;
use crypto::{Digest, PublicKey, Signature};
use log::{debug, info, warn};
use network::SimpleSender;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    hash::{Hash, Hasher},
};
use tokio::sync::mpsc::{Receiver, Sender};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BatchCertificate {
    pub root: Digest,
    pub author: PublicKey,
    pub votes: Vec<(PublicKey, Signature)>,
}

impl PartialEq for BatchCertificate {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root
    }
}
impl Eq for BatchCertificate {}

impl Hash for BatchCertificate {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.root.hash(state);
    }
}

impl BatchCertificate {
    pub fn verify(&self, committee: &Committee) -> MempoolResult<()> {
        // Ensure the Certificate has a quorum.
        let mut weight = 0;
        let mut used = HashSet::new();
        for (name, _) in self.votes.iter() {
            ensure!(!used.contains(name), MempoolError::AuthorityReuse(*name));
            let voting_rights = committee.stake(name);
            ensure!(voting_rights > 0, MempoolError::UnknownAuthority(*name));
            used.insert(*name);
            weight += voting_rights;
        }
        ensure!(
            weight >= committee.quorum_threshold(),
            MempoolError::CertificateRequiresQuorum
        );

        // Check the signatures.
        // TODO: verify signature on root||author.
        Signature::verify_batch(&self.root, &self.votes).map_err(MempoolError::from)
    }
}

/// A proof that all N nodes have acknowledged a batch, allowing shards to be pruned.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FullAvailabilityProof {
    pub root: Digest,
    pub author: PublicKey,
    pub votes: Vec<(PublicKey, Signature)>,
}

impl FullAvailabilityProof {
    pub fn verify(&self, committee: &Committee) -> MempoolResult<()> {
        // Ensure all N nodes have signed.
        let mut used = HashSet::new();
        for (name, _) in self.votes.iter() {
            ensure!(!used.contains(name), MempoolError::AuthorityReuse(*name));
            ensure!(committee.stake(name) > 0, MempoolError::UnknownAuthority(*name));
            used.insert(*name);
        }
        ensure!(
            used.len() == committee.size(),
            MempoolError::CertificateRequiresQuorum
        );
        Signature::verify_batch(&self.root, &self.votes).map_err(MempoolError::from)
    }
}

struct Aggregator {
    author: PublicKey,
    weight: Stake,
    votes: Vec<(PublicKey, Signature)>,
    used: HashSet<PublicKey>,
    certificate_emitted: bool,
}

impl Aggregator {
    pub fn new(author: PublicKey) -> Self {
        Self {
            author,
            weight: 0,
            votes: Vec::new(),
            used: HashSet::new(),
            certificate_emitted: false,
        }
    }

    /// Try to append a vote. Returns a certificate once quorum is reached (once),
    /// and a FullAvailabilityProof once all N nodes have voted.
    pub fn append(
        &mut self,
        root: Digest,
        signature: Signature,
        author: PublicKey,
        committee: &Committee,
    ) -> MempoolResult<(Option<BatchCertificate>, Option<FullAvailabilityProof>)> {
        // Ensure it is the first time this authority votes.
        ensure!(
            self.used.insert(author),
            MempoolError::AuthorityReuse(author)
        );

        self.votes.push((author, signature));
        self.weight += committee.stake(&author);

        let certificate = if !self.certificate_emitted && self.weight >= committee.quorum_threshold() {
            self.certificate_emitted = true;
            Some(BatchCertificate {
                author: self.author,
                root: root.clone(),
                votes: self.votes.clone(),
            })
        } else {
            None
        };

        let proof = if self.used.len() == committee.size() {
            Some(FullAvailabilityProof {
                root,
                author: self.author,
                votes: self.votes.clone(),
            })
        } else {
            None
        };

        Ok((certificate, proof))
    }
}

pub struct AggregatorService;

impl AggregatorService {
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        mut rx_root: Receiver<Digest>,
        mut rx_vote: Receiver<BatchVote>,
        tx_output: Sender<BatchCertificate>,
        tx_self_proof: Sender<FullAvailabilityProof>,
    ) {
        tokio::spawn(async move {
            let mut aggregators = HashMap::new();
            let mut network = SimpleSender::new();

            loop {
                tokio::select! {
                    Some(root) = rx_root.recv() => {
                        debug!("Tracking votes for new batch {}", root);
                        aggregators.insert(root, Aggregator::new(name));
                    },
                    Some(vote) = rx_vote.recv() => {
                        if let Err(e) = vote.verify(&committee) {
                            warn!("{}", e);
                            continue;
                        }
                        debug!("Received vote for batch {} from {}", vote.root, vote.author);
                        let aggregator = match aggregators.get_mut(&vote.root) {
                            Some(x) => x,
                            None => {
                                debug!("Ignoring vote for unknown/completed batch {}", vote.root);
                                continue;
                            }
                        };

                        match aggregator.append(vote.root, vote.signature, vote.author, &committee) {
                            Ok((cert_opt, proof_opt)) => {
                                if let Some(certificate) = cert_opt {
                                    let root = certificate.root.clone();
                                    info!("Assembled BatchCertificate for batch {} ({} votes)", root, certificate.votes.len());

                                    tx_output
                                        .send(certificate.clone())
                                        .await
                                        .expect("Failed to output certificate");

                                    let addresses = committee
                                        .broadcast_addresses(&name)
                                        .into_iter()
                                        .map(|(_, x)| x)
                                        .collect();
                                    let message = MempoolMessage::BatchCertificate(certificate);
                                    let serialized = bincode::serialize(&message)
                                        .expect("Failed to serialize certificate");
                                    network.broadcast(addresses, Bytes::from(serialized)).await;
                                }

                                if let Some(proof) = proof_opt {
                                    let root = proof.root.clone();
                                    let _ = aggregators.remove(&root);
                                    info!("Assembled FullAvailabilityProof for batch {} (all {} nodes responded)", root, committee.size());

                                    // Broadcast to all other nodes.
                                    let addresses = committee
                                        .broadcast_addresses(&name)
                                        .into_iter()
                                        .map(|(_, x)| x)
                                        .collect();
                                    let message = MempoolMessage::FullAvailabilityProof(proof.clone());
                                    let serialized = bincode::serialize(&message)
                                        .expect("Failed to serialize full availability proof");
                                    network.broadcast(addresses, Bytes::from(serialized)).await;

                                    // Also trigger cleanup on the leader itself directly,
                                    // since broadcast_addresses excludes self.
                                    tx_self_proof
                                        .send(proof)
                                        .await
                                        .expect("Failed to send proof to self cleaner");
                                }
                            },
                            Err(e) => warn!("{}", e)
                        }
                    }
                }
            }
        });
    }
}
