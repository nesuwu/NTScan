use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use crate::model::{
    DirectoryReport, ErrorStats, ProgressEvent, ScanErrorKind, ScanMode, ScanOptions,
};

/// Cooperative cancellation flag shared across scanner tasks.
///
/// ```rust
/// use ntscan::context::CancelFlag;
///
/// let flag = CancelFlag::new();
/// assert!(!flag.is_cancelled());
/// flag.cancel();
/// assert!(flag.is_cancelled());
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
    /// Creates a fresh flag in the non-cancelled state.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Signals all listeners that cancellation has been requested.
    pub fn cancel(&self) {
        self.inner.store(true, AtomicOrdering::Release);
    }

    /// Returns whether the flag has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.inner.load(AtomicOrdering::Acquire)
    }
}

/// Thread-safe cache of directory scan results.
///
/// ```rust
/// use ntscan::context::ScanCache;
/// use ntscan::model::ScanMode;
///
/// let cache = ScanCache::default();
/// assert!(cache.get(std::path::Path::new("."), ScanMode::Fast, None).is_none());
/// ```
#[derive(Default)]
pub struct ScanCache {
    inner: Mutex<HashMap<PathBuf, Vec<CachedReport>>>,
}

impl ScanCache {
    /// Retrieves a cached directory report for the same mode and modification time.
    pub fn get(
        &self,
        path: &Path,
        mode: ScanMode,
        mtime: Option<SystemTime>,
    ) -> Option<DirectoryReport> {
        let guard = self.inner.lock().unwrap();
        guard.get(path).and_then(|records| {
            records
                .iter()
                .find(|record| record.mode == mode && record.mtime == mtime)
                .map(|record| record.report.clone())
        })
    }

    /// Stores a freshly produced directory report in the cache.
    pub fn insert(
        &self,
        path: PathBuf,
        mode: ScanMode,
        mtime: Option<SystemTime>,
        report: DirectoryReport,
    ) {
        let mut guard = self.inner.lock().unwrap();
        let records = guard.entry(path).or_default();
        if let Some(existing) = records.iter_mut().find(|rec| rec.mode == mode) {
            *existing = CachedReport {
                mode,
                mtime,
                report,
            };
        } else {
            records.push(CachedReport {
                mode,
                mtime,
                report,
            });
        }
    }
}

#[derive(Default)]
struct Visited {
    state: Mutex<VisitedState>,
}

#[cfg(windows)]
#[derive(Default)]
struct VisitedState {
    paths: HashSet<PathBuf>,
    ids: HashSet<FileIdentity>,
}

#[cfg(not(windows))]
#[derive(Default)]
struct VisitedState {
    paths: HashSet<PathBuf>,
}

/// Shared scanning context that exposes progress, caching, and cancellation helpers.
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
    /// Builds a new context that can be shared between threads.
    ///
    /// ```rust
    /// use ntscan::context::{CancelFlag, ScanContext};
    /// use ntscan::model::{ErrorStats, ScanMode, ScanOptions};
    /// use std::sync::mpsc;
    ///
    /// let options = ScanOptions { mode: ScanMode::Fast, follow_symlinks: false };
    /// let (tx, _rx) = mpsc::channel();
    /// let ctx = ScanContext::new(options, Some(tx), CancelFlag::new(), ErrorStats::default());
    /// assert!(!ctx.cancel_flag().is_cancelled());
    /// ```
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

    /// Builds a context that reuses an existing directory cache.
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

    /// Sends a progress event if a listener is registered.
    pub fn emit(&self, event: ProgressEvent) {
        if let Some(tx) = &self.progress {
            let _ = tx.send(event);
        }
    }

    /// Returns `true` if the path has never been seen during this scan.
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

    /// Exposes the scan options in use.
    pub fn options(&self) -> ScanOptions {
        self.options
    }

    /// Provides access to the shared directory cache.
    pub fn cache(&self) -> &ScanCache {
        self.cache.as_ref()
    }

    /// Returns the cancellation flag used by in-flight work.
    pub fn cancel_flag(&self) -> &CancelFlag {
        &self.cancel
    }

    /// Provides access to the shared error counters.
    pub fn errors(&self) -> &ErrorStats {
        &self.errors
    }

    /// Records an error using the shared statistics bucket.
    pub fn record_error(&self, kind: ScanErrorKind) {
        self.errors.record(kind);
    }
}

struct CachedReport {
    mode: ScanMode,
    mtime: Option<SystemTime>,
    report: DirectoryReport,
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
