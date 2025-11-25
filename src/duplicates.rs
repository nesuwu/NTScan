use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::model::{DuplicateGroup, DuplicateScanResult};

pub fn find_duplicates(root: &Path, min_size: u64) -> Result<DuplicateScanResult> {
    let mut files_by_size: HashMap<u64, Vec<PathBuf>> = HashMap::new();
    let mut total_files_scanned: u64 = 0;

    collect_files(root, min_size, &mut files_by_size, &mut total_files_scanned)?;

    let candidates: Vec<(u64, Vec<PathBuf>)> = files_by_size
        .into_iter()
        .filter(|(_, paths)| paths.len() > 1)
        .collect();

    let mut groups: Vec<DuplicateGroup> = Vec::new();

    for (size, paths) in candidates {
        let mut by_hash: HashMap<[u8; 32], Vec<PathBuf>> = HashMap::new();

        for path in paths {
            if let Ok(hash) = hash_file(&path) {
                by_hash.entry(hash).or_default().push(path);
            }
        }

        for (hash, paths) in by_hash {
            if paths.len() > 1 {
                groups.push(DuplicateGroup { hash, size, paths });
            }
        }
    }

    groups.sort_by(|a, b| b.reclaimable_bytes().cmp(&a.reclaimable_bytes()));

    let total_reclaimable: u64 = groups.iter().map(|g| g.reclaimable_bytes()).sum();

    Ok(DuplicateScanResult {
        groups,
        total_files_scanned,
        total_reclaimable,
    })
}

fn collect_files(
    dir: &Path,
    min_size: u64,
    map: &mut HashMap<u64, Vec<PathBuf>>,
    count: &mut u64,
) -> Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };

        if meta.is_dir() {
            let _ = collect_files(&path, min_size, map, count);
        } else if meta.is_file() {
            let size = meta.len();
            if size >= min_size {
                *count += 1;
                map.entry(size).or_default().push(path);
            }
        }
    }

    Ok(())
}

fn hash_file(path: &Path) -> Result<[u8; 32]> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::Hasher;

    let file = File::open(path)?;
    let mut reader = BufReader::with_capacity(1024 * 1024, file);
    let mut hashers = [
        DefaultHasher::new(),
        DefaultHasher::new(),
        DefaultHasher::new(),
        DefaultHasher::new(),
    ];
    let mut buffer = [0u8; 32768];
    let mut pos: usize = 0;

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        for byte in &buffer[..bytes_read] {
            hashers[pos % 4].write_u8(*byte);
            pos += 1;
        }
    }

    let mut result = [0u8; 32];
    for (i, h) in hashers.iter().enumerate() {
        let hash = h.finish().to_le_bytes();
        result[i * 8..(i + 1) * 8].copy_from_slice(&hash);
    }

    Ok(result)
}

pub fn print_duplicate_report(result: &DuplicateScanResult) {
    println!("Duplicate File Report");
    println!("=====================");
    println!();
    println!("Files scanned: {}", result.total_files_scanned);
    println!("Duplicate groups: {}", result.groups.len());
    println!(
        "Total reclaimable: {}",
        crate::util::fmt_bytes(result.total_reclaimable)
    );
    println!();

    for (i, group) in result.groups.iter().enumerate() {
        println!(
            "Group {} - {} ({} copies)",
            i + 1,
            crate::util::fmt_bytes(group.size),
            group.paths.len()
        );
        println!(
            "  Reclaimable: {}",
            crate::util::fmt_bytes(group.reclaimable_bytes())
        );
        for path in &group.paths {
            println!("    {}", path.display());
        }
        println!();
    }
}
