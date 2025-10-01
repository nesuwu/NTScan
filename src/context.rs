use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use crate::model::{DirectoryReport, ProgressEvent, ScanMode, ScanOptions};

/// Cooperative cancellation flag shared across scanner tasks.
///
/// ```rust
/// use foldersizer_cli::context::CancelFlag;
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

impl CancelFlag {
    /// Creates a fresh flag in the non-cancelled state.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Signals all listeners that cancellation has been requested.
    pub fn cancel(&self) {
        self.inner.store(true, AtomicOrdering::Relaxed);
    }

    /// Returns whether the flag has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.inner.load(AtomicOrdering::Relaxed)
    }
}

/// Thread-safe cache of directory scan results.
///
/// ```rust
/// use foldersizer_cli::context::ScanCache;
/// use foldersizer_cli::model::ScanMode;
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
        let records = guard.entry(path).or_insert_with(Vec::new);
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
    seen: Mutex<HashSet<PathBuf>>,
}

/// Shared scanning context that exposes progress, caching, and cancellation helpers.
#[derive(Clone)]
pub struct ScanContext {
    options: ScanOptions,
    cache: Arc<ScanCache>,
    visited: Arc<Visited>,
    progress: Option<Sender<ProgressEvent>>,
    cancel: CancelFlag,
}

impl ScanContext {
    /// Builds a new context that can be shared between threads.
    ///
    /// ```rust
    /// use foldersizer_cli::context::{CancelFlag, ScanContext};
    /// use foldersizer_cli::model::{ScanMode, ScanOptions};
    /// use std::sync::mpsc;
    ///
    /// let options = ScanOptions { mode: ScanMode::Fast, follow_symlinks: false };
    /// let (tx, _rx) = mpsc::channel();
    /// let ctx = ScanContext::new(options, Some(tx), CancelFlag::new());
    /// assert!(!ctx.cancel_flag().is_cancelled());
    /// ```
    pub fn new(
        options: ScanOptions,
        progress: Option<Sender<ProgressEvent>>,
        cancel: CancelFlag,
    ) -> Self {
        Self {
            options,
            cache: Arc::new(ScanCache::default()),
            visited: Arc::new(Visited::default()),
            progress,
            cancel,
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
        let mut guard = self.visited.seen.lock().unwrap();
        guard.insert(path)
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
}

struct CachedReport {
    mode: ScanMode,
    mtime: Option<SystemTime>,
    report: DirectoryReport,
}
