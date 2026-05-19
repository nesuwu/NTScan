use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use redb::{Database, ReadableTable, TableDefinition};

use crate::cache::DirScanCache;
use crate::model::{ErrorStats, ProgressEvent, ScanErrorKind, ScanOptions, SkipStats};

const CACHE_ENV_PATH: &str = "NTSCAN_CACHE_PATH";
const SCAN_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("scan_attributes_v2");

/// A thread-safe flag to signal cancellation across multiple worker threads.
///
/// This primitive wraps an `AtomicBool` inside an `Arc`, making it cheap to clone
/// and share. It is primarily used to gracefully stop parallel directory traversals
/// when the user requests an abort (e.g. pressing `q` or `Esc`).
///
/// # Example
///
/// ```rust
/// use ntscan::context::CancelFlag;
/// use std::thread;
///
/// let flag = CancelFlag::new();
/// let worker_flag = flag.clone();
///
/// thread::spawn(move || {
///     // Worker checks the flag periodically
///     if worker_flag.is_cancelled() {
///         return;
///     }
///     // Perform work...
/// });
///
/// // Main thread signals cancellation
/// flag.cancel();
/// ```
#[derive(Clone)]
pub struct CancelFlag {
    inner: Arc<AtomicBool>,
}

impl Default for CancelFlag {
    fn default() -> Self {
        Self::new()
    }
}

impl CancelFlag {
    /// Creates a new cancellation flag.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Signals cancellation to all observers.
    pub fn cancel(&self) {
        self.inner.store(true, AtomicOrdering::Release);
    }

    /// Checks if cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.inner.load(AtomicOrdering::Acquire)
    }
}

#[derive(Clone, Copy, Debug)]
struct CachedAttributes {
    mtime_sec: u64,
    mtime_nanos: u32,
    logical_size: u64,
    allocated_size: u64,
    // Hardlink identity: (volume_serial, file_id). 0/0 = not cached.
    vol_serial: u64,
    file_id: u64,
}

/// Persisted cache for file attributes to speed up subsequent scans.
///
/// On construction, **all** entries are read from the redb database into 256
/// in-memory shards so every scanner thread gets pure-RAM lookups with no disk
/// I/O during the scan. The database handle is closed after loading and reopened
/// only on `save()`, avoiding file-lock contention between concurrent instances.
pub struct ScanCache {
    shards: Vec<Mutex<HashMap<String, CachedAttributes>>>,
    dirty: Arc<AtomicBool>,
    file_path: PathBuf,
}

impl Default for ScanCache {
    fn default() -> Self {
        if let Some(path) = std::env::var_os(CACHE_ENV_PATH) {
            let path = PathBuf::from(path);
            if !path.as_os_str().is_empty() {
                if let Some(parent) = path.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                return Self::new(path);
            }
        }

        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            let mut dir = PathBuf::from(local_app_data);
            dir.push("ntscan");
            if fs::create_dir_all(&dir).is_ok() {
                return Self::new(dir.join("scan.redb"));
            }
        }
        Self::new(std::env::temp_dir().join("ntscan_scan.redb"))
    }
}

impl ScanCache {
    /// Opens the database at `path`, loads all persisted entries into RAM, then
    /// closes the database handle. Every subsequent lookup is served from the
    /// in-memory shards with no disk access.
    pub fn new(path: PathBuf) -> Self {
        let shards: Vec<Mutex<HashMap<String, CachedAttributes>>> =
            (0..256).map(|_| Mutex::new(HashMap::new())).collect();

        if let Ok(db) = Database::open(&path) {
            let _ = load_into_shards(&db, &shards);
            // db handle is dropped here — file lock released until save()
        }

        Self {
            shards,
            dirty: Arc::new(AtomicBool::new(false)),
            file_path: path,
        }
    }

    /// Retrieves cached attributes if the file size and modification time match.
    ///
    /// ADS data is intentionally NOT cached — NTFS does not update `LastWriteTime`
    /// when alternate data streams change, so ADS must always be queried fresh.
    ///
    /// Returns `(allocated_size, ids)` where `ids` is `Some((vol_serial, file_id))`
    /// if the hardlink identity was cached, or `None` if not.
    pub fn get_attributes(
        &self,
        path: &Path,
        current_size: u64,
        current_mtime: Option<SystemTime>,
    ) -> Option<(u64, Option<(u64, u64)>)> {
        let (mtime_sec, mtime_nanos) = system_time_to_tuple(current_mtime?);
        let key = normalize_key(path);
        let idx = shard_index(self.shards.len(), &key);

        let guard = self.shards[idx].lock().unwrap();
        if let Some(entry) = guard.get(&key)
            && entry.logical_size == current_size
            && entry.mtime_sec == mtime_sec
            && entry.mtime_nanos == mtime_nanos
        {
            let ids = if entry.vol_serial != 0 || entry.file_id != 0 {
                Some((entry.vol_serial, entry.file_id))
            } else {
                None
            };
            return Some((entry.allocated_size, ids));
        }
        None
    }

    /// Updates or inserts attributes for a given path.
    ///
    /// ADS data is deliberately excluded — see [`get_attributes`].
    pub fn insert_attributes(
        &self,
        path: PathBuf,
        mtime: Option<SystemTime>,
        logical: u64,
        allocated: u64,
        ids: Option<(u64, u64)>,
    ) {
        let (mtime_sec, mtime_nanos) = if let Some(t) = mtime {
            system_time_to_tuple(t)
        } else {
            return;
        };

        let (vol_serial, file_id) = ids.unwrap_or((0, 0));
        let entry = CachedAttributes {
            mtime_sec,
            mtime_nanos,
            logical_size: logical,
            allocated_size: allocated,
            vol_serial,
            file_id,
        };

        let key = normalize_key(&path);
        let idx = shard_index(self.shards.len(), &key);
        self.shards[idx].lock().unwrap().insert(key, entry);
        self.dirty.store(true, AtomicOrdering::Relaxed);
    }

    /// Flushes all in-memory entries to the redb database in one transaction.
    pub fn save(&self) -> io::Result<()> {
        if !self.dirty.load(AtomicOrdering::Relaxed) {
            return Ok(());
        }

        let mut snapshot: Vec<(String, CachedAttributes)> = Vec::new();
        for shard in &self.shards {
            let guard = shard.lock().unwrap();
            snapshot.extend(guard.iter().map(|(k, v)| (k.clone(), *v)));
        }

        let db = open_or_recreate_db(&self.file_path)?;
        write_snapshot(&db, &snapshot)?;
        self.dirty.store(false, AtomicOrdering::Relaxed);
        Ok(())
    }
}

/// Reads all rows from the redb table into the shard map.
fn load_into_shards(
    db: &Database,
    shards: &[Mutex<HashMap<String, CachedAttributes>>],
) -> io::Result<()> {
    let read_txn = match db.begin_read() {
        Ok(t) => t,
        Err(_) => return Ok(()),
    };
    let table = match read_txn.open_table(SCAN_TABLE) {
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
        let path_str = key.value().to_string();
        let bytes = value.value();
        if bytes.len() < 44 {
            continue;
        }
        let entry = CachedAttributes {
            mtime_sec: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            mtime_nanos: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            logical_size: u64::from_le_bytes(bytes[12..20].try_into().unwrap()),
            allocated_size: u64::from_le_bytes(bytes[20..28].try_into().unwrap()),
            vol_serial: u64::from_le_bytes(bytes[28..36].try_into().unwrap()),
            file_id: u64::from_le_bytes(bytes[36..44].try_into().unwrap()),
        };
        let idx = shard_index(shards.len(), &path_str);
        shards[idx].lock().unwrap().insert(path_str, entry);
    }
    Ok(())
}

/// Writes all entries to the database in a single transaction.
fn write_snapshot(db: &Database, snapshot: &[(String, CachedAttributes)]) -> io::Result<()> {
    let write_txn = db
        .begin_write()
        .map_err(|e| io::Error::other(e.to_string()))?;
    {
        let mut table = write_txn
            .open_table(SCAN_TABLE)
            .map_err(|e| io::Error::other(e.to_string()))?;
        for (path_str, attr) in snapshot {
            let mut bytes = [0u8; 44];
            bytes[0..8].copy_from_slice(&attr.mtime_sec.to_le_bytes());
            bytes[8..12].copy_from_slice(&attr.mtime_nanos.to_le_bytes());
            bytes[12..20].copy_from_slice(&attr.logical_size.to_le_bytes());
            bytes[20..28].copy_from_slice(&attr.allocated_size.to_le_bytes());
            bytes[28..36].copy_from_slice(&attr.vol_serial.to_le_bytes());
            bytes[36..44].copy_from_slice(&attr.file_id.to_le_bytes());
            table
                .insert(path_str.as_str(), &bytes[..])
                .map_err(|e| io::Error::other(e.to_string()))?;
        }
    }
    write_txn
        .commit()
        .map_err(|e| io::Error::other(e.to_string()))
}

/// Opens or creates the redb database. If the file exists but is corrupt/old-format,
/// removes it and starts fresh.
fn open_or_recreate_db(path: &Path) -> io::Result<Database> {
    match Database::create(path) {
        Ok(db) => Ok(db),
        Err(_) => {
            let _ = fs::remove_file(path);
            Database::create(path).map_err(|e| io::Error::other(e.to_string()))
        }
    }
}

fn shard_index(num_shards: usize, key: &str) -> usize {
    let mut s = DefaultHasher::new();
    key.hash(&mut s);
    (s.finish() as usize) & (num_shards - 1)
}

fn normalize_key(path: &Path) -> String {
    path.to_string_lossy().to_lowercase()
}

fn system_time_to_tuple(t: SystemTime) -> (u64, u32) {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs(), d.subsec_nanos()),
        Err(_) => (0, 0),
    }
}

const VISITED_SHARDS: usize = 64;

/// Sharded visited-set to reduce lock contention under parallel scanning.
///
/// The previous single-`Mutex` design forced every rayon thread to serialize on
/// one lock for every file's dedup check. With 64 shards, threads only contend
/// when they happen to hash to the same bucket — which is rare enough to
/// effectively eliminate the bottleneck.
struct Visited {
    #[cfg(windows)]
    id_shards: Vec<Mutex<VisitedIdShard>>,
    path_shards: Vec<Mutex<std::collections::HashSet<PathBuf>>>,
}

#[cfg(windows)]
#[derive(Default)]
struct VisitedIdShard {
    alloc_ids: std::collections::HashSet<FileIdentity>,
    logical_ids: std::collections::HashSet<FileIdentity>,
}

impl Default for Visited {
    fn default() -> Self {
        let mut path_shards = Vec::with_capacity(VISITED_SHARDS);
        for _ in 0..VISITED_SHARDS {
            path_shards.push(Mutex::new(std::collections::HashSet::new()));
        }

        #[cfg(windows)]
        let id_shards = {
            let mut v = Vec::with_capacity(VISITED_SHARDS);
            for _ in 0..VISITED_SHARDS {
                v.push(Mutex::new(VisitedIdShard::default()));
            }
            v
        };

        Self {
            #[cfg(windows)]
            id_shards,
            path_shards,
        }
    }
}

impl Visited {
    fn path_shard_index(path: &Path) -> usize {
        let mut s = DefaultHasher::new();
        path.hash(&mut s);
        (s.finish() as usize) & (VISITED_SHARDS - 1)
    }

    #[cfg(windows)]
    fn id_shard_index(id: &FileIdentity) -> usize {
        let mut s = DefaultHasher::new();
        id.hash(&mut s);
        (s.finish() as usize) & (VISITED_SHARDS - 1)
    }
}

/// Shared context passed to scanning threads, containing options, cache, and synchronization primitives.
///
/// This struct acts as the "nervous system" for the scanner, aggregating:
/// * **Configuration**: Read-only options (`ScanOptions`).
/// * **State**: Mutable shared state (cache, visited paths, error stats).
/// * **Control**: Synchronization primitives (cancellation flag, progress channel).
///
/// It is designed to be cheap to clone (`Arc`-wrapped internals) so it can be
/// easily moved into closures for `rayon` parallel iterators.
#[derive(Clone)]
pub struct ScanContext {
    options: ScanOptions,
    cache: Arc<ScanCache>,
    dir_cache: Arc<DirScanCache>,
    visited: Arc<Visited>,
    progress: Option<Sender<ProgressEvent>>,
    cancel: CancelFlag,
    cancel_noted: Arc<AtomicBool>,
    errors: ErrorStats,
    skipped: SkipStats,
}

impl ScanContext {
    /// Creates a new ScanContext with default cache settings.
    pub fn new(
        options: ScanOptions,
        progress: Option<Sender<ProgressEvent>>,
        cancel: CancelFlag,
        errors: ErrorStats,
    ) -> Self {
        Self::with_cache(
            options,
            progress,
            cancel,
            errors,
            Arc::new(ScanCache::default()),
        )
    }

    /// Creates a new ScanContext with a provided file-level cache; the
    /// directory-level cache is initialised from its default on-disk location.
    pub fn with_cache(
        options: ScanOptions,
        progress: Option<Sender<ProgressEvent>>,
        cancel: CancelFlag,
        errors: ErrorStats,
        cache: Arc<ScanCache>,
    ) -> Self {
        Self::with_caches(
            options,
            progress,
            cancel,
            errors,
            cache,
            Arc::new(DirScanCache::default()),
        )
    }

    /// Creates a new ScanContext with explicit file-level and directory-level caches.
    ///
    /// Use this when the caller wants to share a single `DirScanCache` across
    /// multiple navigation sessions so cached directory totals survive between
    /// them without additional disk I/O.
    pub fn with_caches(
        options: ScanOptions,
        progress: Option<Sender<ProgressEvent>>,
        cancel: CancelFlag,
        errors: ErrorStats,
        cache: Arc<ScanCache>,
        dir_cache: Arc<DirScanCache>,
    ) -> Self {
        Self {
            options,
            cache,
            dir_cache,
            visited: Arc::new(Visited::default()),
            progress,
            cancel,
            cancel_noted: Arc::new(AtomicBool::new(false)),
            errors,
            skipped: SkipStats::default(),
        }
    }

    /// Flushes both the file-level and directory-level caches to disk.
    pub fn save_cache(&self) -> io::Result<()> {
        self.cache.save()?;
        self.dir_cache.save()
    }

    /// Emits a progress event to the listener, if configured.
    pub fn emit(&self, event: ProgressEvent) {
        if let Some(tx) = &self.progress {
            let _ = tx.send(event);
        }
    }

    /// Checks if a file has been seen before for both logical and allocation dedup.
    /// Returns `(is_first_logical, is_first_alloc)`.
    ///
    /// This calls `file_identity()` once and checks both dedup sets in a single
    /// shard lock, halving the per-file kernel call overhead compared to two
    /// separate identity lookups.
    pub fn mark_file_unique(&self, path: &Path) -> (bool, bool) {
        #[cfg(windows)]
        {
            if let Some(id) = file_identity(path) {
                let idx = Visited::id_shard_index(&id);
                let mut shard = self.visited.id_shards[idx].lock().unwrap();
                let logical_new = shard.logical_ids.insert(id);
                let alloc_new = shard.alloc_ids.insert(id);
                return (logical_new, alloc_new);
            }
        }

        // Fallback for non-Windows or if ID retrieval fails
        #[cfg(not(windows))]
        {
            if let Ok(normalized) = fs::canonicalize(path) {
                let idx = Visited::path_shard_index(&normalized);
                let mut shard = self.visited.path_shards[idx].lock().unwrap();
                let alloc_new = shard.insert(normalized);
                return (true, alloc_new);
            }
            return (true, true);
        }

        // Windows fallback when file_identity fails: use canonical path for alloc,
        // always count logical (safe over-count)
        #[cfg(windows)]
        {
            if let Ok(normalized) = fs::canonicalize(path) {
                let idx = Visited::path_shard_index(&normalized);
                let mut shard = self.visited.path_shards[idx].lock().unwrap();
                let alloc_new = shard.insert(normalized);
                return (true, alloc_new);
            }
            (true, true)
        }
    }

    /// Hard-link dedup using a file identity computed by the caller.
    ///
    /// This is the fast path used by the scanner: the scanner already opens a
    /// single handle per file (for allocation size + ADS), reads
    /// `BY_HANDLE_FILE_INFORMATION` from it, and passes the
    /// `(volume_serial, file_index)` pair here. That avoids the extra
    /// `CreateFileW` round-trip `mark_file_unique` would otherwise make via
    /// [`file_identity`].
    ///
    /// `ids == None` means the caller could not open the file (locked/system
    /// file); we then fall back to a canonical-path dedup, mirroring
    /// [`Self::mark_file_unique`]'s fallback semantics.
    #[cfg(windows)]
    pub fn mark_file_unique_by_id(&self, ids: Option<(u64, u64)>, path: &Path) -> (bool, bool) {
        if let Some((volume_serial, file_index)) = ids {
            let id = FileIdentity::from_parts(volume_serial, file_index);
            let idx = Visited::id_shard_index(&id);
            let mut shard = self.visited.id_shards[idx].lock().unwrap();
            let logical_new = shard.logical_ids.insert(id);
            let alloc_new = shard.alloc_ids.insert(id);
            return (logical_new, alloc_new);
        }

        if let Ok(normalized) = fs::canonicalize(path) {
            let idx = Visited::path_shard_index(&normalized);
            let mut shard = self.visited.path_shards[idx].lock().unwrap();
            let alloc_new = shard.insert(normalized);
            return (true, alloc_new);
        }
        (true, true)
    }

    /// Atomically checks if a path has been visited and marks it.
    /// Returns `true` if the path is new (not previously visited).
    ///
    /// This method is critical for preventing infinite loops when following symbolic links.
    /// Note: canonicalize is intentionally kept here because symlink targets need resolution.
    pub fn mark_if_new(&self, path: PathBuf) -> bool {
        let normalized = fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
        let identity = file_identity(&normalized).or_else(|| file_identity(&path));

        let path_idx = Visited::path_shard_index(&normalized);
        let by_path = self.visited.path_shards[path_idx]
            .lock()
            .unwrap()
            .insert(normalized);

        #[cfg(windows)]
        let by_id = identity
            .map(|id| {
                let id_idx = Visited::id_shard_index(&id);
                self.visited.id_shards[id_idx]
                    .lock()
                    .unwrap()
                    .alloc_ids
                    .insert(id)
            })
            .unwrap_or(false);
        #[cfg(not(windows))]
        let by_id = identity.is_some();
        by_path || by_id
    }

    /// Returns the scan options.
    pub fn options(&self) -> ScanOptions {
        self.options
    }

    /// Returns `true` if a progress listener is attached.
    ///
    /// Used to skip `PathBuf` clones for progress events when nobody is
    /// listening (e.g. a headless CLI scan without a live TUI).
    pub fn has_progress(&self) -> bool {
        self.progress.is_some()
    }

    /// Returns a reference to the file-level attribute cache.
    pub fn cache(&self) -> &ScanCache {
        self.cache.as_ref()
    }

    /// Returns a reference to the directory-level size cache.
    pub fn dir_cache(&self) -> &DirScanCache {
        self.dir_cache.as_ref()
    }

    /// Returns the cancellation flag.
    pub fn cancel_flag(&self) -> &CancelFlag {
        &self.cancel
    }

    /// Records cancellation once per scan session.
    pub fn note_cancelled(&self) {
        if !self.cancel_noted.swap(true, AtomicOrdering::Relaxed) {
            self.errors.record(ScanErrorKind::Cancelled);
        }
    }

    /// Returns the error statistics.
    pub fn errors(&self) -> &ErrorStats {
        &self.errors
    }

    /// Records a skipped entry.
    pub fn record_skipped(&self) {
        self.skipped.record();
    }

    /// Returns the total number of skipped entries.
    pub fn skipped_count(&self) -> usize {
        self.skipped.count()
    }

    /// Records a scan error.
    pub fn record_error(&self, kind: ScanErrorKind) {
        self.errors.record(kind);
    }
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
struct FileIdentity {
    volume_serial: u64,
    file_id: [u8; 16],
}

#[cfg(windows)]
impl FileIdentity {
    /// Builds an identity from the `(dwVolumeSerialNumber, 64-bit file index)`
    /// pair the scanner reads out of `BY_HANDLE_FILE_INFORMATION`. The 64-bit
    /// index is zero-padded into the 128-bit slot, matching the layout
    /// produced by [`file_identity`].
    fn from_parts(volume_serial: u64, file_index: u64) -> Self {
        let mut file_id = [0u8; 16];
        file_id[0..8].copy_from_slice(&file_index.to_le_bytes());
        Self {
            volume_serial,
            file_id,
        }
    }
}

#[cfg(not(windows))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
struct FileIdentity;

fn file_identity(path: &Path) -> Option<FileIdentity> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_FLAG_BACKUP_SEMANTICS,
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            GetFileInformationByHandle, OPEN_EXISTING,
        };
        use windows::core::PCWSTR;

        // Paths from read_dir() are already absolute. Avoid the expensive
        // fs::canonicalize() call (multiple kernel round-trips on Windows).
        // CreateFileW handles absolute paths fine; we only need the \\?\ prefix
        // for paths longer than MAX_PATH (260 chars).
        let needs_long_prefix =
            path.as_os_str().len() > 248 && !path.to_string_lossy().starts_with("\\\\?\\");
        let wide_path: Vec<u16> = if needs_long_prefix {
            let mut prefixed = std::ffi::OsString::from("\\\\?\\");
            prefixed.push(path.as_os_str());
            let mut w: Vec<u16> = prefixed.encode_wide().collect();
            w.push(0);
            w
        } else {
            let mut w: Vec<u16> = path.as_os_str().encode_wide().collect();
            w.push(0);
            w
        };

        // 2. Open with 0 access rights. This allows opening file for metadata query
        // even if we lack Read/Write permissions (e.g., locked system files).
        let handle_result = unsafe {
            CreateFileW(
                PCWSTR(wide_path.as_ptr()),
                0, // 0 = No specific rights, just object query
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                HANDLE(0),
            )
        };

        if let Ok(handle) = handle_result {
            let mut info = BY_HANDLE_FILE_INFORMATION::default();
            let result = unsafe { GetFileInformationByHandle(handle, &mut info) };
            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(handle);
            }

            if result.is_ok() {
                // Combine high and low parts of the index
                let idx = ((info.nFileIndexHigh as u64) << 32) | (info.nFileIndexLow as u64);

                // Map to our 128-bit ID storage (zero-padded)
                let mut id = [0u8; 16];
                id[0..8].copy_from_slice(&idx.to_le_bytes());

                return Some(FileIdentity {
                    volume_serial: info.dwVolumeSerialNumber as u64,
                    file_id: id,
                });
            }
        }

        None
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;
    use tempfile::tempdir;

    #[test]
    fn round_trip_save_and_load() {
        let dir = tempdir().expect("failed to create temp directory");
        let cache_path = dir.path().join("scan.redb");

        let cache = ScanCache::new(cache_path.clone());
        cache.insert_attributes(
            dir.path().join("item.txt"),
            Some(SystemTime::now()),
            1024,
            2048,
            Some((42, 99)),
        );
        cache.save().expect("save should succeed");

        let cache2 = ScanCache::new(cache_path);
        let key = normalize_key(&dir.path().join("item.txt"));
        let idx = shard_index(cache2.shards.len(), &key);
        assert!(
            cache2.shards[idx].lock().unwrap().contains_key(&key),
            "loaded cache should contain the saved entry"
        );
    }
}
