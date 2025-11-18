use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::fs::{self, File};
use std::hash::{Hash, Hasher};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::model::{ErrorStats, ProgressEvent, ScanErrorKind, ScanOptions};

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
    pub fn new() -> Self {
        Self {
            inner: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn cancel(&self) {
        self.inner.store(true, AtomicOrdering::Release);
    }

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
    ads_bytes: u64,
    ads_count: u32,
}

pub struct ScanCache {
    // Key is String (lowercased path) to handle Windows case-insensitivity
    shards: Vec<Mutex<HashMap<String, CachedAttributes>>>,
    dirty: Arc<AtomicBool>,
    file_path: PathBuf,
}

const CACHE_MAGIC: &[u8; 8] = b"NTSC0003"; // Version 3 (Case Insensitive)

impl Default for ScanCache {
    fn default() -> Self {
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            let mut path = PathBuf::from(local_app_data);
            path.push("ntscan");
            if fs::create_dir_all(&path).is_ok() {
                path.push("cache");
                return Self::new(path);
            }
        }
        let mut path = std::env::temp_dir();
        path.push("ntscan.cache");
        Self::new(path)
    }
}

impl ScanCache {
    pub fn new(path: PathBuf) -> Self {
        let num_shards = 256; // Increased for concurrency
        let mut shards = Vec::with_capacity(num_shards);
        for _ in 0..num_shards {
            shards.push(Mutex::new(HashMap::new()));
        }

        let cache = Self {
            shards,
            dirty: Arc::new(AtomicBool::new(false)),
            file_path: path,
        };

        let _ = cache.load();
        cache
    }

    pub fn get_attributes(
        &self,
        path: &Path,
        current_size: u64,
        current_mtime: Option<SystemTime>,
    ) -> Option<(u64, u64, usize)> {
        let (mtime_sec, mtime_nanos) = system_time_to_tuple(current_mtime?);
        let key = normalize_key(path);
        let idx = self.shard_index(&key);

        let guard = self.shards[idx].lock().unwrap();
        if let Some(entry) = guard.get(&key)
            && entry.logical_size == current_size
            && entry.mtime_sec == mtime_sec
            && entry.mtime_nanos == mtime_nanos
        {
            return Some((
                entry.allocated_size,
                entry.ads_bytes,
                entry.ads_count as usize,
            ));
        }
        None
    }

    pub fn insert_attributes(
        &self,
        path: PathBuf,
        mtime: Option<SystemTime>,
        logical: u64,
        allocated: u64,
        ads_bytes: u64,
        ads_count: usize,
    ) {
        let (mtime_sec, mtime_nanos) = if let Some(t) = mtime {
            system_time_to_tuple(t)
        } else {
            return;
        };

        let entry = CachedAttributes {
            mtime_sec,
            mtime_nanos,
            logical_size: logical,
            allocated_size: allocated,
            ads_bytes,
            ads_count: ads_count as u32,
        };

        let key = normalize_key(&path);
        let idx = self.shard_index(&key);
        let mut guard = self.shards[idx].lock().unwrap();
        guard.insert(key, entry);
        self.dirty.store(true, AtomicOrdering::Relaxed);
    }

    pub fn save(&self) -> io::Result<()> {
        if !self.dirty.load(AtomicOrdering::Relaxed) {
            return Ok(());
        }

        let temp_path = self.file_path.with_extension("tmp");
        let file = File::create(&temp_path)?;
        // 8MB Buffer for large writes
        let mut writer = BufWriter::with_capacity(8 * 1024 * 1024, file);

        writer.write_all(CACHE_MAGIC)?;

        let mut total_entries = 0usize;
        for shard in &self.shards {
            total_entries += shard.lock().unwrap().len();
        }

        writer.write_all(&(total_entries as u64).to_le_bytes())?;

        for shard in &self.shards {
            let guard = shard.lock().unwrap();
            for (path_str, attr) in guard.iter() {
                let path_bytes = path_str.as_bytes();

                if path_bytes.len() > u16::MAX as usize {
                    continue;
                }

                writer.write_all(&(path_bytes.len() as u16).to_le_bytes())?;
                writer.write_all(path_bytes)?;

                writer.write_all(&attr.mtime_sec.to_le_bytes())?;
                writer.write_all(&attr.mtime_nanos.to_le_bytes())?;
                writer.write_all(&attr.logical_size.to_le_bytes())?;
                writer.write_all(&attr.allocated_size.to_le_bytes())?;
                writer.write_all(&attr.ads_bytes.to_le_bytes())?;
                writer.write_all(&attr.ads_count.to_le_bytes())?;
            }
        }

        writer.flush()?;
        drop(writer);
        let _ = fs::rename(temp_path, &self.file_path);
        self.dirty.store(false, AtomicOrdering::Relaxed);
        Ok(())
    }

    fn load(&self) -> io::Result<()> {
        if !self.file_path.exists() {
            return Ok(());
        }

        let file = File::open(&self.file_path)?;
        let mut reader = BufReader::new(file);

        let mut magic_buf = [0u8; 8];
        if reader.read_exact(&mut magic_buf).is_err() || &magic_buf != CACHE_MAGIC {
            return Ok(());
        }

        let mut buf_u64 = [0u8; 8];
        if reader.read_exact(&mut buf_u64).is_err() {
            return Ok(());
        }
        let count = u64::from_le_bytes(buf_u64);

        let mut buf_u16 = [0u8; 2];

        for _ in 0..count {
            if reader.read_exact(&mut buf_u16).is_err() {
                break;
            }
            let path_len = u16::from_le_bytes(buf_u16) as usize;

            let mut path_buf = vec![0u8; path_len];
            if reader.read_exact(&mut path_buf).is_err() {
                break;
            }

            // We read back the string directly
            let path_str = String::from_utf8_lossy(&path_buf).to_string();

            let mut attr_buf = [0u8; 40];
            if reader.read_exact(&mut attr_buf).is_err() {
                break;
            }

            let mtime_sec = u64::from_le_bytes(attr_buf[0..8].try_into().unwrap());
            let mtime_nanos = u32::from_le_bytes(attr_buf[8..12].try_into().unwrap());
            let logical_size = u64::from_le_bytes(attr_buf[12..20].try_into().unwrap());
            let allocated_size = u64::from_le_bytes(attr_buf[20..28].try_into().unwrap());
            let ads_bytes = u64::from_le_bytes(attr_buf[28..36].try_into().unwrap());
            let ads_count = u32::from_le_bytes(attr_buf[36..40].try_into().unwrap());

            let entry = CachedAttributes {
                mtime_sec,
                mtime_nanos,
                logical_size,
                allocated_size,
                ads_bytes,
                ads_count,
            };

            let idx = self.shard_index(&path_str);
            self.shards[idx].lock().unwrap().insert(path_str, entry);
        }
        Ok(())
    }

    fn shard_index(&self, key: &str) -> usize {
        let mut s = DefaultHasher::new();
        key.hash(&mut s);
        (s.finish() as usize) & (self.shards.len() - 1)
    }
}

fn normalize_key(path: &Path) -> String {
    // Lowercase the path string for cache consistency on Windows
    path.to_string_lossy().to_lowercase()
}

fn system_time_to_tuple(t: SystemTime) -> (u64, u32) {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs(), d.subsec_nanos()),
        Err(_) => (0, 0),
    }
}

#[derive(Default)]
struct Visited {
    state: Mutex<VisitedState>,
}

#[cfg(windows)]
#[derive(Default)]
struct VisitedState {
    paths: std::collections::HashSet<PathBuf>,
    ids: std::collections::HashSet<FileIdentity>,
}

#[cfg(not(windows))]
#[derive(Default)]
struct VisitedState {
    paths: std::collections::HashSet<PathBuf>,
}

#[derive(Clone)]
pub struct ScanContext {
    options: ScanOptions,
    cache: Arc<ScanCache>,
    visited: Arc<Visited>,
    progress: Option<Sender<ProgressEvent>>,
    cancel: CancelFlag,
    errors: ErrorStats,
}

impl ScanContext {
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

    pub fn with_cache(
        options: ScanOptions,
        progress: Option<Sender<ProgressEvent>>,
        cancel: CancelFlag,
        errors: ErrorStats,
        cache: Arc<ScanCache>,
    ) -> Self {
        Self {
            options,
            cache,
            visited: Arc::new(Visited::default()),
            progress,
            cancel,
            errors,
        }
    }

    pub fn save_cache(&self) {
        let _ = self.cache.save();
    }

    pub fn emit(&self, event: ProgressEvent) {
        if let Some(tx) = &self.progress {
            let _ = tx.send(event);
        }
    }

    pub fn mark_if_new(&self, path: PathBuf) -> bool {
        let normalized = fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
        let identity = file_identity(&normalized).or_else(|| file_identity(&path));

        let mut state = self.visited.state.lock().unwrap();
        let by_path = state.paths.insert(normalized);
        #[cfg(windows)]
        let by_id = identity.map(|id| state.ids.insert(id)).unwrap_or(false);
        #[cfg(not(windows))]
        let by_id = identity.is_some();
        by_path || by_id
    }

    pub fn options(&self) -> ScanOptions {
        self.options
    }

    pub fn cache(&self) -> &ScanCache {
        self.cache.as_ref()
    }

    pub fn cancel_flag(&self) -> &CancelFlag {
        &self.cancel
    }

    pub fn errors(&self) -> &ErrorStats {
        &self.errors
    }

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

#[cfg(not(windows))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
struct FileIdentity;

fn file_identity(path: &Path) -> Option<FileIdentity> {
    #[cfg(windows)]
    {
        use std::ffi::c_void;
        use std::fs::OpenOptions;
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_ID_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ,
            FILE_SHARE_WRITE, FileIdInfo, GetFileInformationByHandleEx,
        };

        let share_mode = FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0;
        let file = OpenOptions::new()
            .read(true)
            .share_mode(share_mode)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0)
            .open(path)
            .ok()?;

        let mut info = FILE_ID_INFO::default();
        unsafe {
            GetFileInformationByHandleEx(
                HANDLE(file.as_raw_handle() as isize),
                FileIdInfo,
                &mut info as *mut _ as *mut c_void,
                std::mem::size_of::<FILE_ID_INFO>() as u32,
            )
            .ok()?;
        }

        Some(FileIdentity {
            volume_serial: info.VolumeSerialNumber,
            file_id: info.FileId.Identifier,
        })
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        None
    }
}
