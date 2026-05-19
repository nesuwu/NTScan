use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use redb::{Database, ReadableTable, TableDefinition};

use crate::model::ScanMode;

const DIR_CACHE_ENV_PATH: &str = "NTSCAN_DIR_CACHE_PATH";
const DIR_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("dir_scan_v1");

// Binary layout per entry (29 bytes):
//   [0..8]   mtime_sec: u64 LE
//   [8..12]  mtime_nanos: u32 LE
//   [12..20] logical_size: u64 LE
//   [20..28] allocated_size: u64 LE  (meaningful only when flags & ALLOC_PRESENT)
//   [28]     flags: u8
//              bit 0 (ALLOC_PRESENT)  — Accurate mode data was computed
//              bit 1 (ALLOC_COMPLETE) — allocation lookup succeeded for entire subtree
const ENTRY_BYTES: usize = 29;
const ALLOC_PRESENT: u8 = 0b01;
const ALLOC_COMPLETE: u8 = 0b10;

#[derive(Clone, Copy)]
struct Slot {
    mtime_sec: u64,
    mtime_nanos: u32,
    logical_size: u64,
    allocated_size: u64,
    flags: u8,
}

/// Totals returned to the caller on a cache hit.
#[derive(Clone, Copy, Debug)]
pub struct CachedDir {
    pub logical_size: u64,
    pub allocated_size: Option<u64>,
    pub allocated_complete: bool,
}

const NUM_SHARDS: usize = 64;

fn shard_index(key: &str) -> usize {
    let mut h = DefaultHasher::new();
    key.hash(&mut h);
    (h.finish() as usize) & (NUM_SHARDS - 1)
}

fn system_time_to_tuple(t: SystemTime) -> (u64, u32) {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs(), d.subsec_nanos()),
        Err(_) => (0, 0),
    }
}

fn normalize(path: &Path) -> String {
    path.to_string_lossy().to_lowercase()
}

/// Directory-level scan result cache.
///
/// Stores the total recursive sizes for each directory, keyed by its
/// lowercased path. When the directory's mtime matches the cached mtime the
/// entire subtree recursion is skipped and the cached totals are returned
/// immediately — reducing repeat scans to a series of cheap metadata stats
/// rather than a full filesystem walk.
///
/// All entries are loaded into RAM on construction. The on-disk database is
/// closed after loading and reopened only in `save()`.
pub struct DirScanCache {
    shards: Vec<Mutex<HashMap<String, Slot>>>,
    dirty: Arc<AtomicBool>,
    file_path: PathBuf,
}

impl Default for DirScanCache {
    fn default() -> Self {
        if let Some(raw) = std::env::var_os(DIR_CACHE_ENV_PATH) {
            let path = PathBuf::from(&raw);
            if !path.as_os_str().is_empty() {
                if let Some(parent) = path.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                return Self::new(path);
            }
        }
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            let mut dir = PathBuf::from(local);
            dir.push("ntscan");
            if fs::create_dir_all(&dir).is_ok() {
                return Self::new(dir.join("dir_scan.redb"));
            }
        }
        Self::new(std::env::temp_dir().join("ntscan_dir_scan.redb"))
    }
}

impl DirScanCache {
    pub fn new(path: PathBuf) -> Self {
        let shards: Vec<Mutex<HashMap<String, Slot>>> = (0..NUM_SHARDS)
            .map(|_| Mutex::new(HashMap::new()))
            .collect();

        if let Ok(db) = Database::open(&path) {
            let _ = load(&db, &shards);
        }

        Self {
            shards,
            dirty: Arc::new(AtomicBool::new(false)),
            file_path: path,
        }
    }

    /// Returns cached totals if the directory mtime matches.
    ///
    /// In Accurate mode a cache entry is only valid if it was computed with
    /// Accurate mode (allocation data present). Fast-mode hits are always used.
    pub fn get(
        &self,
        path: &Path,
        current_mtime: Option<SystemTime>,
        mode: ScanMode,
    ) -> Option<CachedDir> {
        let (mtime_sec, mtime_nanos) = system_time_to_tuple(current_mtime?);
        let key = normalize(path);
        let guard = self.shards[shard_index(&key)].lock().unwrap();

        if let Some(slot) = guard.get(&key)
            && slot.mtime_sec == mtime_sec
            && slot.mtime_nanos == mtime_nanos
        {
            if mode == ScanMode::Accurate && (slot.flags & ALLOC_PRESENT) == 0 {
                return None;
            }
            return Some(CachedDir {
                logical_size: slot.logical_size,
                allocated_size: if slot.flags & ALLOC_PRESENT != 0 {
                    Some(slot.allocated_size)
                } else {
                    None
                },
                allocated_complete: slot.flags & ALLOC_COMPLETE != 0,
            });
        }
        None
    }

    /// Stores or refreshes the cached totals for a directory.
    pub fn insert(
        &self,
        path: &Path,
        mtime: Option<SystemTime>,
        logical_size: u64,
        allocated_size: Option<u64>,
        allocated_complete: bool,
    ) {
        let Some(mtime) = mtime else { return };
        let (mtime_sec, mtime_nanos) = system_time_to_tuple(mtime);

        let mut flags: u8 = 0;
        if allocated_size.is_some() {
            flags |= ALLOC_PRESENT;
        }
        if allocated_complete {
            flags |= ALLOC_COMPLETE;
        }

        let slot = Slot {
            mtime_sec,
            mtime_nanos,
            logical_size,
            allocated_size: allocated_size.unwrap_or(0),
            flags,
        };

        let key = normalize(path);
        self.shards[shard_index(&key)]
            .lock()
            .unwrap()
            .insert(key, slot);
        self.dirty.store(true, Ordering::Relaxed);
    }

    /// Flushes all in-memory entries to the redb database.
    pub fn save(&self) -> io::Result<()> {
        if !self.dirty.load(Ordering::Relaxed) {
            return Ok(());
        }

        let mut snapshot: Vec<(String, Slot)> = Vec::new();
        for shard in &self.shards {
            let guard = shard.lock().unwrap();
            snapshot.extend(guard.iter().map(|(k, v)| (k.clone(), *v)));
        }

        let db = open_or_recreate(&self.file_path)?;
        write_snapshot(&db, &snapshot)?;
        self.dirty.store(false, Ordering::Relaxed);
        Ok(())
    }
}

fn load(db: &Database, shards: &[Mutex<HashMap<String, Slot>>]) -> io::Result<()> {
    let read_txn = match db.begin_read() {
        Ok(t) => t,
        Err(_) => return Ok(()),
    };
    let table = match read_txn.open_table(DIR_TABLE) {
        Ok(t) => t,
        Err(_) => return Ok(()),
    };
    let iter = match table.iter() {
        Ok(it) => it,
        Err(_) => return Ok(()),
    };
    for result in iter {
        let (key, value) = match result {
            Ok(kv) => kv,
            Err(_) => break,
        };
        let bytes = value.value();
        if bytes.len() < ENTRY_BYTES {
            continue;
        }
        let slot = Slot {
            mtime_sec: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            mtime_nanos: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            logical_size: u64::from_le_bytes(bytes[12..20].try_into().unwrap()),
            allocated_size: u64::from_le_bytes(bytes[20..28].try_into().unwrap()),
            flags: bytes[28],
        };
        let path_str = key.value().to_string();
        let idx = shard_index(&path_str);
        shards[idx].lock().unwrap().insert(path_str, slot);
    }
    Ok(())
}

fn write_snapshot(db: &Database, snapshot: &[(String, Slot)]) -> io::Result<()> {
    let write_txn = db
        .begin_write()
        .map_err(|e| io::Error::other(e.to_string()))?;
    {
        let mut table = write_txn
            .open_table(DIR_TABLE)
            .map_err(|e| io::Error::other(e.to_string()))?;
        for (key, slot) in snapshot {
            let mut bytes = [0u8; ENTRY_BYTES];
            bytes[0..8].copy_from_slice(&slot.mtime_sec.to_le_bytes());
            bytes[8..12].copy_from_slice(&slot.mtime_nanos.to_le_bytes());
            bytes[12..20].copy_from_slice(&slot.logical_size.to_le_bytes());
            bytes[20..28].copy_from_slice(&slot.allocated_size.to_le_bytes());
            bytes[28] = slot.flags;
            table
                .insert(key.as_str(), &bytes[..])
                .map_err(|e| io::Error::other(e.to_string()))?;
        }
    }
    write_txn
        .commit()
        .map_err(|e| io::Error::other(e.to_string()))
}

fn open_or_recreate(path: &Path) -> io::Result<Database> {
    match Database::create(path) {
        Ok(db) => Ok(db),
        Err(_) => {
            let _ = fs::remove_file(path);
            Database::create(path).map_err(|e| io::Error::other(e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn round_trip_save_and_load() {
        let dir = tempdir().expect("failed to create temp dir");
        let cache_path = dir.path().join("dir_scan.redb");
        let target = dir.path().join("subdir");

        let cache = DirScanCache::new(cache_path.clone());
        cache.insert(&target, Some(SystemTime::now()), 1024, Some(2048), true);
        cache.save().expect("save should succeed");

        let cache2 = DirScanCache::new(cache_path);
        let key = normalize(&target);
        let idx = shard_index(&key);
        assert!(
            cache2.shards[idx].lock().unwrap().contains_key(&key),
            "loaded cache should contain the saved entry"
        );
    }

    #[test]
    fn cache_hit_requires_matching_mtime() {
        let dir = tempdir().unwrap();
        let cache = DirScanCache::new(dir.path().join("test.redb"));
        let target = dir.path().join("foo");
        let t1 = SystemTime::now();

        cache.insert(&target, Some(t1), 500, None, false);

        // Same mtime → hit
        assert!(cache.get(&target, Some(t1), ScanMode::Fast).is_some());

        // Different mtime → miss
        let t2 = t1 + std::time::Duration::from_secs(1);
        assert!(cache.get(&target, Some(t2), ScanMode::Fast).is_none());
    }

    #[test]
    fn accurate_mode_requires_alloc_data() {
        let dir = tempdir().unwrap();
        let cache = DirScanCache::new(dir.path().join("test2.redb"));
        let target = dir.path().join("bar");
        let t = SystemTime::now();

        // Inserted without allocation data (Fast mode scan)
        cache.insert(&target, Some(t), 100, None, false);

        // Fast mode → hit
        assert!(cache.get(&target, Some(t), ScanMode::Fast).is_some());
        // Accurate mode → miss (no alloc data)
        assert!(cache.get(&target, Some(t), ScanMode::Accurate).is_none());
    }
}
