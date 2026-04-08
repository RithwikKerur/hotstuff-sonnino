/// N-shard RS benchmark: N/3 data shards + 2N/3 parity shards = N total.
///
/// Each node receives exactly one shard. Reconstruction requires only N/3
/// shards (any N/3 nodes suffice), giving tolerance to 2N/3 failures.
/// Compare with bench_dissemination where data_shards=quorum(N) and each
/// node receives quorum(N) shards.
///
///   bench_dissemination   →  quorum(N)*N total shards, quorum(N) shards/node
///   bench_simple_sharding →  N total shards, 1 shard/node, N/3 data shards
///
/// Run with:
///   cargo run --bin bench_simple_sharding
use crypto::{generate_production_keypair, Digest, PublicKey, SecretKey, SignatureService};
use mempool::{
    coded_batch::{AuthenticatedShard, Shard},
    config::Committee,
};
use rand::RngCore;
use reed_solomon_erasure::galois_8::ReedSolomon;
use smtree::{
    index::TreeIndex,
    node_template::MTreeNodeSmt,
    proof::MerkleProof,
    traits::{InclusionProvable as _, Serializable as _},
    tree::SparseMerkleTree,
};
use std::{convert::TryInto, net::SocketAddr, time::Instant};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const N_NODES: usize = 10;
const BATCH_SIZE_BYTES: usize = 100_000;
const TX_SIZE: usize = 512;
const RUNS: usize = 20;
// Use a different port range from bench_dissemination to allow parallel runs.
const BASE_PORT: u16 = 20200;

type Tree = SparseMerkleTree<MTreeNodeSmt<blake3::Hasher>>;
type Proof = MerkleProof<MTreeNodeSmt<blake3::Hasher>>;

fn make_committee(keys: &[(PublicKey, SecretKey)]) -> Committee {
    let info: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(i, (pk, _))| {
            let tx_addr: SocketAddr =
                format!("127.0.0.1:{}", BASE_PORT + i as u16).parse().unwrap();
            let mem_addr: SocketAddr =
                format!("127.0.0.1:{}", BASE_PORT + 1000 + i as u16).parse().unwrap();
            (*pk, 1u32, tx_addr, mem_addr)
        })
        .collect();
    Committee::new(info, 0)
}

/// RS-encode `data` into `data_shards + parity_shards` shards of equal size.
/// data_shards  = N / 3
/// parity_shards = N - data_shards  (≈ 2N/3)
/// Total shards = N, one per node.
fn rs_encode(data: &[u8], data_shards: usize, parity_shards: usize) -> Vec<Shard> {
    let total = data_shards + parity_shards;
    let shard_size = (data.len() + data_shards - 1) / data_shards;
    // Pad so that data fits evenly into data_shards pieces.
    let mut padded = data.to_vec();
    padded.resize(shard_size * data_shards, 0u8);
    // Append zeroed parity space.
    padded.extend(vec![0u8; shard_size * parity_shards]);

    let mut shards: Vec<Shard> = padded.chunks(shard_size).map(|c| c.to_vec()).collect();
    assert_eq!(shards.len(), total);

    ReedSolomon::new(data_shards, parity_shards)
        .expect("Failed to initialize RS encoder")
        .encode(&mut shards)
        .expect("Failed to RS encode");

    shards
}

/// Build a Merkle tree over shards using the same leaf hash as CodedBatch::commit().
fn commit(shards: &[Shard]) -> Tree {
    let leaves: Vec<_> = shards
        .iter()
        .enumerate()
        .map(|(i, shard)| {
            let mut hasher = blake3::Hasher::new();
            hasher.update(shard);
            hasher.update(&i.to_le_bytes());
            MTreeNodeSmt::new(hasher.finalize().as_bytes().to_vec())
        })
        .collect();
    Tree::new_merkle_tree(&leaves)
}

fn stats(mut data: Vec<f64>) -> (f64, f64, f64, f64) {
    data.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = data.len();
    let mean = data.iter().sum::<f64>() / n as f64;
    let p50 = data[n / 2];
    let p99 = data[n.saturating_sub(1).min((n as f64 * 0.99) as usize)];
    let max = *data.last().unwrap();
    (mean, p50, p99, max)
}

fn print_phase(label: &str, data: Vec<f64>) {
    let (mean, p50, p99, max) = stats(data);
    println!(
        "  {:<30} mean={:>7.2}ms  p50={:>7.2}ms  p99={:>7.2}ms  max={:>7.2}ms",
        label, mean, p50, p99, max
    );
}

#[tokio::main]
async fn main() {
    let data_shards = N_NODES / 3;
    let parity_shards = N_NODES - data_shards;

    println!("\n=== Simple N-shard RS benchmark (N/3 data + 2N/3 parity) ===");
    println!("  N={N_NODES}  batch={BATCH_SIZE_BYTES}B  tx_size={TX_SIZE}B  runs={RUNS}");
    println!("  data_shards={data_shards}  parity_shards={parity_shards}  total_shards={N_NODES}  (1 shard/node)\n");

    let keys: Vec<_> = (0..N_NODES).map(|_| generate_production_keypair()).collect();
    let committee = make_committee(&keys);

    // The leader is the node at committee index 0 (keys are sorted inside Committee).
    let leader_pk: PublicKey = committee.name(0).unwrap();
    let leader_idx = keys.iter().position(|(pk, _)| pk == &leader_pk).unwrap();
    let (_, leader_sk) = keys.into_iter().nth(leader_idx).unwrap();

    let shard_size = (BATCH_SIZE_BYTES + data_shards - 1) / data_shards;
    println!("  shard_size≈{shard_size}B  proofs_per_batch={N_NODES}\n");

    let mut sig_service = SignatureService::new(leader_sk);

    let mut split_times: Vec<f64> = vec![];
    let mut tree_times: Vec<f64> = vec![];
    let mut proof_times: Vec<f64> = vec![];
    let mut serialize_times: Vec<f64> = vec![];
    let mut tcp_times: Vec<f64> = vec![];
    let mut verify_times: Vec<f64> = vec![];
    let mut wire_bytes_runs: Vec<f64> = vec![];

    for run in 0..RUNS {
        // ── 1. Random batch ───────────────────────────────────────────────────
        let mut raw = vec![0u8; BATCH_SIZE_BYTES];
        rand::thread_rng().fill_bytes(&mut raw);

        // ── 2. RS encode: N/3 data shards + 2N/3 parity shards ───────────────
        let t = Instant::now();
        let shards = rs_encode(&raw, data_shards, parity_shards);
        split_times.push(t.elapsed().as_secs_f64() * 1000.0);

        // ── 3. Merkle tree ────────────────────────────────────────────────────
        let t = Instant::now();
        let tree = commit(&shards);
        tree_times.push(t.elapsed().as_secs_f64() * 1000.0);

        // Sign once — all shards share the same root.
        let serialized_root = tree.get_root().serialize();
        let root = Digest(serialized_root[0..32].try_into().unwrap());
        let signature = sig_service.request_signature(root.clone()).await;

        // ── 4. Proof generation (one AuthenticatedShard per node) ─────────────
        // Node at committee index i receives shard i. We construct AuthenticatedShard
        // directly to reuse the single signature across all N proofs.
        let t = Instant::now();
        let auth_shards: Vec<AuthenticatedShard> = shards
            .iter()
            .enumerate()
            .map(|(i, shard)| {
                let index_list =
                    vec![TreeIndex::from_u64(tree.get_height(), i as u64)];
                let proof = Proof::generate_inclusion_proof(&tree, &index_list)
                    .expect("Failed to generate Merkle proof");
                AuthenticatedShard {
                    shard: shard.clone(),
                    destination: i,
                    proof: proof.serialize(),
                    root: root.clone(),
                    author: leader_pk,
                    signature: signature.clone(),
                }
            })
            .collect();
        proof_times.push(t.elapsed().as_secs_f64() * 1000.0);

        // ── 5. Serialization ──────────────────────────────────────────────────
        let t = Instant::now();
        let serialized: Vec<Vec<u8>> = auth_shards
            .iter()
            .map(|s| bincode::serialize(s).unwrap())
            .collect();
        serialize_times.push(t.elapsed().as_secs_f64() * 1000.0);

        let total_wire: usize = serialized.iter().map(|b: &Vec<u8>| b.len()).sum();
        wire_bytes_runs.push(total_wire as f64);

        if run == 0 {
            let per_shard = total_wire / N_NODES;
            println!(
                "  Wire bytes: total={total_wire}B  per_shard≈{per_shard}B  \
                 raw_batch={BATCH_SIZE_BYTES}B  overhead={:.2}x\n",
                total_wire as f64 / BATCH_SIZE_BYTES as f64
            );
        }

        // ── 6. TCP send + receive (loopback, N-1 remote nodes) ────────────────
        // Skip index 0 (the leader itself); send shards 1..N to N-1 peers.
        let t = Instant::now();
        let mut handles = vec![];
        for (i, payload) in serialized.iter().enumerate().skip(1) {
            let port = BASE_PORT + 2000 + run as u16 * N_NODES as u16 + i as u16;
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let payload: Vec<u8> = payload.clone();

            let listener = TcpListener::bind(addr).await.unwrap();
            let recv = tokio::spawn(async move {
                let (mut s, _) = listener.accept().await.unwrap();
                let len = s.read_u32().await.unwrap() as usize;
                let mut buf = vec![0u8; len];
                s.read_exact(&mut buf).await.unwrap();
                buf
            });
            let send = tokio::spawn(async move {
                let mut s = TcpStream::connect(addr).await.unwrap();
                s.write_u32(payload.len() as u32).await.unwrap();
                s.write_all(&payload).await.unwrap();
            });
            handles.push((send, recv, i));
        }
        let mut received: Vec<(Vec<u8>, usize)> = vec![];
        for (send, recv, node_idx) in handles {
            send.await.unwrap();
            received.push((recv.await.unwrap(), node_idx));
        }
        tcp_times.push(t.elapsed().as_secs_f64() * 1000.0);

        // ── 7. Bundle verification (N-1 receivers) ────────────────────────────
        // Each receiver verifies using its own public key so committee.index()
        // resolves to the correct shard position.
        let t = Instant::now();
        for (payload, node_idx) in &received {
            let shard: AuthenticatedShard = bincode::deserialize(payload).unwrap();
            let receiver_pk = committee.name(*node_idx).unwrap();
            shard
                .verify(&committee)
                .unwrap_or_else(|e| panic!("{}", format!("Shard verification failed on run {run}: {e}")));
        }
        verify_times.push(t.elapsed().as_secs_f64() * 1000.0);

        println!(
            "  run {:>2}  encode={:.2}ms  tree={:.2}ms  proofs={:.2}ms  \
             ser={:.2}ms  tcp={:.2}ms  verify={:.2}ms",
            run + 1,
            split_times[run],
            tree_times[run],
            proof_times[run],
            serialize_times[run],
            tcp_times[run],
            verify_times[run],
        );
    }

    println!("\n── Summary ({RUNS} runs) ──────────────────────────────────────────────────────");
    print_phase("1. RS encode (N/3 data+2N/3 par)", split_times);
    print_phase("2. Merkle tree build", tree_times);
    print_phase("3. Shard proof gen (N nodes)", proof_times);
    print_phase("4. Serialize shards (N)", serialize_times);
    print_phase("5. TCP send+recv (N-1, loopback)", tcp_times);
    print_phase("6. Shard verify (N-1 nodes)", verify_times);

    let (mean_bytes, _, _, _) = stats(wire_bytes_runs);
    println!(
        "\n  Avg wire bytes/batch: {:.0}B  ({:.2}x raw batch size of {BATCH_SIZE_BYTES}B)",
        mean_bytes,
        mean_bytes / BATCH_SIZE_BYTES as f64
    );
}
