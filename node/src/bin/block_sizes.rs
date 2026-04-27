use consensus::Block;
use rocksdb::{Options, DB};
use std::path::PathBuf;

//./target/debug/block_sizes


fn main() {
    let db_paths: Vec<PathBuf> = (0..4)
        .map(|i| PathBuf::from(format!("benchmark/.db-{}", i)))
        .filter(|p| p.exists())
        .collect();

    if db_paths.is_empty() {
        eprintln!("No .db-N directories found under benchmark/. Run from the repo root.");
        std::process::exit(1);
    }

    let mut opts = Options::default();
    opts.set_error_if_exists(false);

    let mut all_sizes: Vec<usize> = Vec::new();

    for path in &db_paths {
        let db = match DB::open_for_read_only(&opts, path, false) {
            Ok(db) => db,
            Err(e) => {
                eprintln!("Failed to open {:?}: {}", path, e);
                continue;
            }
        };

        let mut empty_count = 0usize;
        let mut node_sizes: Vec<usize> = Vec::new();
        let iter = db.iterator(rocksdb::IteratorMode::Start);

        for item in iter {
            let (_, value) = item.expect("DB iteration failed");
            if let Ok(block) = bincode::deserialize::<Block>(&value) {
                if block.round == 0 {
                    continue; // skip genesis
                }
                let payload_bytes: usize = block.payload.iter().map(|b| b.len()).sum();
                if payload_bytes == 0 {
                    empty_count += 1;
                } else {
                    node_sizes.push(payload_bytes);
                }
            }
        }

        if node_sizes.is_empty() {
            println!("{:?}: no non-empty blocks found ({} empty)", path, empty_count);
            continue;
        }

        let total: usize = node_sizes.iter().sum();
        let avg = total / node_sizes.len();
        let max = *node_sizes.iter().max().unwrap();
        let min = *node_sizes.iter().min().unwrap();

        println!(
            "{:?}: {} empty, {} non-empty | total={} B  avg={} B  min={} B  max={} B",
            path,
            empty_count,
            node_sizes.len(),
            total,
            avg,
            min,
            max,
        );

        all_sizes.extend(node_sizes);
    }

    if !all_sizes.is_empty() {
        let total: usize = all_sizes.iter().sum();
        let avg = total / all_sizes.len();
        let max = *all_sizes.iter().max().unwrap();
        println!(
            "\nAll nodes combined: {} non-empty blocks | total={} B  avg={} B  max={} B",
            all_sizes.len(),
            total,
            avg,
            max,
        );
    }
}
