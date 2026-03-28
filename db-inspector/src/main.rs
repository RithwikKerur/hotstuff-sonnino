/// Count total bytes stored across all .db-* RocksDB databases.
///
/// Usage (from the repo root):
///   cargo run -p db-inspector -- benchmark/
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

    // Shards are stored as raw bytes keyed by root (32 bytes) || pubkey (32 bytes) = 64 bytes.
    const SHARD_KEY_LEN: usize = 64;

    let mut grand_shard_keys: u64 = 0;
    let mut grand_shard_bytes: u64 = 0;
    let mut grand_other_keys: u64 = 0;
    let mut grand_other_bytes: u64 = 0;

    for db_path in &db_dirs {
        let name = db_path.file_name().unwrap().to_string_lossy();
        let db = rocksdb::DB::open_default(db_path)
            .unwrap_or_else(|e| panic!("Failed to open {}: {}", name, e));

        let mut shard_keys: u64 = 0;
        let mut shard_bytes: u64 = 0;
        let mut other_keys: u64 = 0;
        let mut other_bytes: u64 = 0;

        // Track key-length distribution for "other" entries
        let mut key_len_hist: std::collections::BTreeMap<usize, (u64, u64)> = std::collections::BTreeMap::new();

        for item in db.iterator(rocksdb::IteratorMode::Start) {
            let (k, v) = item.expect("iterator error");
            let entry_bytes = k.len() as u64 + v.len() as u64;
            if k.len() == SHARD_KEY_LEN {
                shard_keys += 1;
                shard_bytes += entry_bytes;
            } else {
                other_keys += 1;
                other_bytes += entry_bytes;
                let e = key_len_hist.entry(k.len()).or_insert((0, 0));
                e.0 += 1;
                e.1 += entry_bytes;
            }
        }

        let shard_avg = if shard_keys > 0 { shard_bytes / shard_keys } else { 0 };
        println!("=== {} ===", name);
        println!(
            "  Shards (key=64B): {:>6} entries  {:>10} bytes  ({:.2} KB)  avg {:>6} B/entry",
            shard_keys, shard_bytes, shard_bytes as f64 / 1024.0, shard_avg,
        );

        if other_keys > 0 {
            println!("  Other entries:    {:>6} entries  {:>10} bytes  ({:.2} KB)",
                other_keys, other_bytes, other_bytes as f64 / 1024.0);
            for (klen, (count, bytes)) in &key_len_hist {
                let avg = bytes / count;
                println!("    key_len={:>4}B: {:>6} entries  {:>10} bytes  avg {:>6} B/entry",
                    klen, count, bytes, avg);
            }
        }
        println!();

        grand_shard_keys += shard_keys;
        grand_shard_bytes += shard_bytes;
        grand_other_keys += other_keys;
        grand_other_bytes += other_bytes;
    }

    let grand_avg = if grand_shard_keys > 0 { grand_shard_bytes / grand_shard_keys } else { 0 };
    println!("{}", "=".repeat(72));
    println!(
        "TOTAL Shards: {:>6} entries  {:>10} bytes  ({:.2} KB)  avg {:>6} B/entry  across {} DBs",
        grand_shard_keys, grand_shard_bytes, grand_shard_bytes as f64 / 1024.0,
        grand_avg, db_dirs.len()
    );
    println!(
        "TOTAL Other:  {:>6} entries  {:>10} bytes  ({:.2} KB)  across {} DBs",
        grand_other_keys, grand_other_bytes, grand_other_bytes as f64 / 1024.0,
        db_dirs.len()
    );
}
