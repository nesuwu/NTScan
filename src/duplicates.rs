use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use sha2::{Digest, Sha256};
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

use crate::model::{DuplicateGroup, DuplicateScanResult};

const HASH_CACHE_MAGIC: &[u8; 8] = b"NTSH0001";
const HASH_CACHE_ENV_PATH: &str = "NTSCAN_HASH_CACHE_PATH";
const MAX_HASH_CACHE_ENTRIES: u64 = 2_000_000;
const MAX_HASH_CACHE_PATH_BYTES: usize = 16 * 1024;

struct HashCache {
    entries: Mutex<HashMap<String, CachedHash>>,
    dirty: std::sync::atomic::AtomicBool,
    file_path: PathBuf,
}

#[derive(Clone, Copy)]
struct CachedHash {
    mtime_sec: u64,
    mtime_nanos: u32,
    size: u64,
    hash: [u8; 32],
}

impl HashCache {
    fn new(path_override: Option<PathBuf>) -> Self {
        let file_path = path_override.unwrap_or_else(resolve_hash_cache_path);

        let mut cache = Self {
            entries: Mutex::new(HashMap::new()),
            dirty: std::sync::atomic::AtomicBool::new(false),
            file_path,
        };
        let _ = cache.load();
        cache
    }

    fn get(&self, path: &Path, size: u64, mtime: Option<SystemTime>) -> Option<[u8; 32]> {
        let (mtime_sec, mtime_nanos) = system_time_to_tuple(mtime?);
        let key = path.to_string_lossy().to_lowercase();
        let guard = self.entries.lock().unwrap();
        if let Some(entry) = guard.get(&key)
            && entry.size == size
            && entry.mtime_sec == mtime_sec
            && entry.mtime_nanos == mtime_nanos
        {
            return Some(entry.hash);
        }
        None
    }

    fn insert(&self, path: &Path, size: u64, mtime: Option<SystemTime>, hash: [u8; 32]) {
        let Some(mtime) = mtime else { return };
        let (mtime_sec, mtime_nanos) = system_time_to_tuple(mtime);
        let key = path.to_string_lossy().to_lowercase();
        let entry = CachedHash {
            mtime_sec,
            mtime_nanos,
            size,
            hash,
        };
        self.entries.lock().unwrap().insert(key, entry);
        self.dirty.store(true, Ordering::Relaxed);
    }

    fn load(&mut self) -> Result<()> {
        if !self.file_path.exists() {
            return Ok(());
        }
        let file = File::open(&self.file_path)?;
        let mut reader = BufReader::new(file);

        let mut magic = [0u8; 8];
        if reader.read_exact(&mut magic).is_err() || &magic != HASH_CACHE_MAGIC {
            return Ok(());
        }

        let mut buf8 = [0u8; 8];
        if reader.read_exact(&mut buf8).is_err() {
            return Ok(());
        }
        let count = u64::from_le_bytes(buf8);
        if count > MAX_HASH_CACHE_ENTRIES {
            return Ok(());
        }

        let mut buf2 = [0u8; 2];
        let mut guard = self.entries.lock().unwrap();

        for _ in 0..count {
            if reader.read_exact(&mut buf2).is_err() {
                break;
            }
            let path_len = u16::from_le_bytes(buf2) as usize;
            if path_len == 0 || path_len > MAX_HASH_CACHE_PATH_BYTES {
                break;
            }

            let mut path_buf = vec![0u8; path_len];
            if reader.read_exact(&mut path_buf).is_err() {
                break;
            }
            let key = String::from_utf8_lossy(&path_buf).to_string();

            let mut data = [0u8; 52];
            if reader.read_exact(&mut data).is_err() {
                break;
            }

            let entry = CachedHash {
                mtime_sec: u64::from_le_bytes(data[0..8].try_into().unwrap()),
                mtime_nanos: u32::from_le_bytes(data[8..12].try_into().unwrap()),
                size: u64::from_le_bytes(data[12..20].try_into().unwrap()),
                hash: data[20..52].try_into().unwrap(),
            };
            guard.insert(key, entry);
        }
        Ok(())
    }

    fn save(&self) -> Result<()> {
        if !self.dirty.load(Ordering::Relaxed) {
            return Ok(());
        }

        let temp_path = self.file_path.with_extension("tmp");
        let file = File::create(&temp_path)?;
        let mut writer = BufWriter::with_capacity(4 * 1024 * 1024, file);

        writer.write_all(HASH_CACHE_MAGIC)?;

        let guard = self.entries.lock().unwrap();
        writer.write_all(&(guard.len() as u64).to_le_bytes())?;

        for (key, entry) in guard.iter() {
            let key_bytes = key.as_bytes();
            if key_bytes.len() > u16::MAX as usize {
                continue;
            }
            writer.write_all(&(key_bytes.len() as u16).to_le_bytes())?;
            writer.write_all(key_bytes)?;
            writer.write_all(&entry.mtime_sec.to_le_bytes())?;
            writer.write_all(&entry.mtime_nanos.to_le_bytes())?;
            writer.write_all(&entry.size.to_le_bytes())?;
            writer.write_all(&entry.hash)?;
        }

        writer.flush()?;
        drop(writer);
        drop(guard);
        let _ = fs::rename(temp_path, &self.file_path);
        self.dirty.store(false, Ordering::Relaxed);
        Ok(())
    }
}

fn system_time_to_tuple(t: SystemTime) -> (u64, u32) {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs(), d.subsec_nanos()),
        Err(_) => (0, 0),
    }
}

struct Progress {
    total_candidates: u64,
    hashed: AtomicU64,
    cache_hits: AtomicU64,
    bytes_hashed: AtomicU64,
}

impl Progress {
    fn new(total: u64) -> Self {
        Self {
            total_candidates: total,
            hashed: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            bytes_hashed: AtomicU64::new(0),
        }
    }

    fn record_hash(&self, bytes: u64) {
        let done = self.hashed.fetch_add(1, Ordering::Relaxed) + 1;
        self.bytes_hashed.fetch_add(bytes, Ordering::Relaxed);
        if done.is_multiple_of(50) || done == self.total_candidates {
            self.print_status();
        }
    }

    fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
        let done = self.hashed.fetch_add(1, Ordering::Relaxed) + 1;
        if done.is_multiple_of(50) || done == self.total_candidates {
            self.print_status();
        }
    }

    fn print_status(&self) {
        let done = self.hashed.load(Ordering::Relaxed);
        let hits = self.cache_hits.load(Ordering::Relaxed);
        let bytes = self.bytes_hashed.load(Ordering::Relaxed);
        eprint!(
            "\rHashing: {}/{} files ({} cached, {} hashed)    ",
            done,
            self.total_candidates,
            hits,
            crate::util::fmt_bytes(bytes)
        );
    }
}

/// Scans a directory for duplicate files based on size and SHA-256 content hash.
///
/// # Algorithm
///
/// 1. **Size Grouping**: Recursively walks the directory to find all files larger than `min_size`.
///    Files are grouped by their file size. Unique sizes are discarded immediately.
/// 2. **Hashing**: For groups with multiple files, the content is hashed using SHA-256.
///    A persistent on-disk cache is used to avoid re-hashing unchanged files.
/// 3. **Verification**: Files with matching hashes are grouped together as duplicates.
///
/// This approach is efficient because it only performs expensive IO (hashing) on files
/// that already share the same size, which is a strong filter.
pub fn find_duplicates(root: &Path, min_size: u64) -> Result<DuplicateScanResult> {
    find_duplicates_with_cache(root, min_size, None)
}

pub fn find_duplicates_with_cache(
    root: &Path,
    min_size: u64,
    hash_cache_path: Option<PathBuf>,
) -> Result<DuplicateScanResult> {
    let mut files_by_size: HashMap<u64, Vec<PathBuf>> = HashMap::new();
    let mut total_files_scanned: u64 = 0;
    let mut visited_dirs: HashSet<PathBuf> = HashSet::new();

    eprint!("Collecting files...\r");
    collect_files(
        root,
        min_size,
        &mut files_by_size,
        &mut total_files_scanned,
        &mut visited_dirs,
    )?;
    eprintln!(
        "Collected {} files                    ",
        total_files_scanned
    );

    let candidates: Vec<(u64, Vec<PathBuf>)> = files_by_size
        .into_iter()
        .filter(|(_, paths)| paths.len() > 1)
        .collect();

    let total_to_hash: u64 = candidates.iter().map(|(_, p)| p.len() as u64).sum();
    eprintln!("Found {} potential duplicates to hash", total_to_hash);

    let cache = HashCache::new(hash_cache_path);
    let progress = Progress::new(total_to_hash);
    let mut groups: Vec<DuplicateGroup> = Vec::new();

    for (size, paths) in candidates {
        let mut by_hash: HashMap<[u8; 32], Vec<PathBuf>> = HashMap::new();

        for path in paths {
            let mtime = fs::metadata(&path).ok().and_then(|m| m.modified().ok());

            if let Some(hash) = cache.get(&path, size, mtime) {
                progress.record_cache_hit();
                by_hash.entry(hash).or_default().push(path);
                continue;
            }

            match hash_file_sha256(&path) {
                Ok(hash) => {
                    progress.record_hash(size);
                    cache.insert(&path, size, mtime, hash);
                    by_hash.entry(hash).or_default().push(path);
                }
                Err(_) => {
                    progress.record_hash(0);
                }
            }
        }

        for (hash, paths) in by_hash {
            if paths.len() > 1 {
                groups.push(DuplicateGroup { hash, size, paths });
            }
        }
    }

    eprintln!();
    let _ = cache.save();

    groups.sort_by_key(|b| std::cmp::Reverse(b.reclaimable_bytes()));

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
    visited_dirs: &mut HashSet<PathBuf>,
) -> Result<()> {
    let normalized = fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    if !visited_dirs.insert(normalized) {
        return Ok(());
    }

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };

        if is_reparse_point(&meta) {
            continue;
        }

        if meta.is_dir() {
            let _ = collect_files(&path, min_size, map, count, visited_dirs);
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

fn hash_file_sha256(path: &Path) -> Result<[u8; 32]> {
    let file = File::open(path)?;
    let mut reader = BufReader::with_capacity(1024 * 1024, file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hasher.finalize().into())
}

fn resolve_hash_cache_path() -> PathBuf {
    if let Some(path) = std::env::var_os(HASH_CACHE_ENV_PATH) {
        let path = PathBuf::from(path);
        if !path.as_os_str().is_empty() {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            return path;
        }
    }

    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        let mut dir = PathBuf::from(local_app_data);
        dir.push("ntscan");
        let _ = fs::create_dir_all(&dir);
        return dir.join("hash_cache");
    }

    std::env::temp_dir().join("ntscan_hash.cache")
}

fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        (metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0) != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

/// Prints the results of a duplicate file scan to STDOUT.
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
        let hash_hex: String = group.hash.iter().map(|b| format!("{:02x}", b)).collect();
        println!(
            "Group {} - {} ({} copies) [{}...]",
            i + 1,
            crate::util::fmt_bytes(group.size),
            group.paths.len(),
            &hash_hex[..16]
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
