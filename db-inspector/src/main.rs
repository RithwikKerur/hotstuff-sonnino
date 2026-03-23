/// Count total bytes stored across all .db-* RocksDB databases.
///
/// Usage (from the repo root):
///   cargo run --manifest-path db-inspector/Cargo.toml -- benchmark/
///
/// Pass the directory containing .db-* folders as the first argument (default: ".").
//cargo run -p db-inspector -- ./
fn main() {
    let search_dir = std::env::args().nth(1).unwrap_or_else(|| ".".to_string());
    let search_path = std::path::Path::new(&search_dir);

    let mut db_dirs: Vec<_> = std::fs::read_dir(search_path)
        .unwrap_or_else(|_| panic!("Failed to read directory: {}", search_dir))
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.is_dir()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with(".db-"))
                    .unwrap_or(false)
        })
        .collect();
    db_dirs.sort();

    if db_dirs.is_empty() {
        eprintln!("No .db-* directories found in '{}'", search_dir);
        std::process::exit(1);
    }

    // bincode encodes enum variants as a little-endian u32.
    // MempoolMessage::AuthenticatedShard is variant index 0.
    const SHARD_TAG: &[u8] = &[0, 0, 0, 0];

    let mut grand_shards = (0u64, 0u64);   // (count, bytes)
    let mut grand_sentinel = (0u64, 0u64);
    let mut grand_other = (0u64, 0u64);

    for db_path in &db_dirs {
        let name = db_path.file_name().unwrap().to_string_lossy();
        let db = rocksdb::DB::open_default(db_path)
            .unwrap_or_else(|e| panic!("Failed to open {}: {}", name, e));

        let mut shards = (0u64, 0u64);
        let mut sentinel = (0u64, 0u64);
        let mut other = (0u64, 0u64);

        for (k, v) in db.iterator(rocksdb::IteratorMode::Start) {
            let entry_bytes = k.len() as u64 + v.len() as u64;
            if k.len() == 40 && v.starts_with(SHARD_TAG) {
                // root (32 B) || shard_index_u64 (8 B) → AuthenticatedShard value
                shards.0 += 1;
                shards.1 += entry_bytes;
            } else if k.len() == 32 && v.as_ref() == [1u8] {
                // sentinel written at root key to signal payload availability
                sentinel.0 += 1;
                sentinel.1 += entry_bytes;
            } else {
                // consensus blocks, votes, or other mempool data
                other.0 += 1;
                other.1 += entry_bytes;
            }
        }

        fn avg(count: u64, bytes: u64) -> u64 { if count > 0 { bytes / count } else { 0 } }

        println!("{}:", name);
        println!(
            "  Shards    {:>6} entries  {:>10} bytes  ({:.2} KB)  avg {:>6} B/entry",
            shards.0, shards.1, shards.1 as f64 / 1024.0, avg(shards.0, shards.1)
        );
        println!(
            "  Sentinels {:>6} entries  {:>10} bytes  ({:.2} KB)  avg {:>6} B/entry",
            sentinel.0, sentinel.1, sentinel.1 as f64 / 1024.0, avg(sentinel.0, sentinel.1)
        );
        println!(
            "  Other     {:>6} entries  {:>10} bytes  ({:.2} KB)  avg {:>6} B/entry",
            other.0, other.1, other.1 as f64 / 1024.0, avg(other.0, other.1)
        );

        grand_shards.0 += shards.0; grand_shards.1 += shards.1;
        grand_sentinel.0 += sentinel.0; grand_sentinel.1 += sentinel.1;
        grand_other.0 += other.0; grand_other.1 += other.1;
    }

    fn avg(count: u64, bytes: u64) -> u64 { if count > 0 { bytes / count } else { 0 } }

    println!("{}", "-".repeat(72));
    println!("TOTAL across {} DBs:", db_dirs.len());
    println!(
        "  Shards    {:>6} entries  {:>10} bytes  ({:.2} KB)  avg {:>6} B/entry",
        grand_shards.0, grand_shards.1, grand_shards.1 as f64 / 1024.0,
        avg(grand_shards.0, grand_shards.1)
    );
    println!(
        "  Sentinels {:>6} entries  {:>10} bytes  ({:.2} KB)  avg {:>6} B/entry",
        grand_sentinel.0, grand_sentinel.1, grand_sentinel.1 as f64 / 1024.0,
        avg(grand_sentinel.0, grand_sentinel.1)
    );
    println!(
        "  Other     {:>6} entries  {:>10} bytes  ({:.2} KB)  avg {:>6} B/entry",
        grand_other.0, grand_other.1, grand_other.1 as f64 / 1024.0,
        avg(grand_other.0, grand_other.1)
    );
}
