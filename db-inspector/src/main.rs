/// Count total bytes stored across all .db-* RocksDB databases.
///
/// Usage (from the repo root):
///   cargo run --manifest-path db-inspector/Cargo.toml -- benchmark/
///
/// Pass the directory containing .db-* folders as the first argument (default: ".").

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

    let mut grand_keys: u64 = 0;
    let mut grand_bytes: u64 = 0;

    for db_path in &db_dirs {
        let name = db_path.file_name().unwrap().to_string_lossy();
        let db = rocksdb::DB::open_default(db_path)
            .unwrap_or_else(|e| panic!("Failed to open {}: {}", name, e));

        let mut keys: u64 = 0;
        let mut bytes: u64 = 0;

        for (k, v) in db.iterator(rocksdb::IteratorMode::Start) {
            keys += 1;
            bytes += k.len() as u64 + v.len() as u64;
        }

        println!(
            "{:<12}  {:>8} entries  {:>12} bytes  ({:.2} KB)",
            name,
            keys,
            bytes,
            bytes as f64 / 1024.0
        );
        grand_keys += keys;
        grand_bytes += bytes;
    }

    println!("{}", "-".repeat(60));
    println!(
        "{:<12}  {:>8} entries  {:>12} bytes  ({:.2} KB)  across {} DBs",
        "TOTAL",
        grand_keys,
        grand_bytes,
        grand_bytes as f64 / 1024.0,
        db_dirs.len()
    );
}
