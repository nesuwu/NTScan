use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

/// Available scanning strategies.
///
/// ```rust
/// use ntscan::model::ScanMode;
/// assert_eq!(ScanMode::Fast.label(), "Fast");
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanMode {
    Fast,
    Accurate,
}

/// Parameters supplied to every scan run.
///
/// ```rust
/// use ntscan::model::{ScanMode, ScanOptions};
///
/// let opts = ScanOptions { mode: ScanMode::Fast, follow_symlinks: false };
/// assert!(!opts.follow_symlinks);
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScanOptions {
    pub mode: ScanMode,
    pub follow_symlinks: bool,
}

/// Categorisation for errors surfaced during scanning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScanErrorKind {
    AccessDenied,
    SharingViolation,
    ADSFailed,
    Cancelled,
    Other,
}

/// Thread-safe accumulator for error statistics.
///
/// ```rust
/// use ntscan::model::{ErrorStats, ScanErrorKind};
///
/// let stats = ErrorStats::default();
/// stats.record(ScanErrorKind::Other);
/// assert_eq!(stats.snapshot()[&ScanErrorKind::Other], 1);
/// ```
#[derive(Default, Clone)]
pub struct ErrorStats {
    counts: Arc<Mutex<HashMap<ScanErrorKind, usize>>>,
}

impl ErrorStats {
    /// Increments the counter for the provided error kind.
    pub fn record(&self, kind: ScanErrorKind) {
        let mut guard = self.counts.lock().unwrap();
        *guard.entry(kind).or_insert(0) += 1;
    }

    /// Returns a copy of the current error counters.
    pub fn snapshot(&self) -> HashMap<ScanErrorKind, usize> {
        self.counts.lock().unwrap().clone()
    }
}

/// Aggregated information for a scanned directory.
#[derive(Clone)]
pub struct DirectoryReport {
    pub path: PathBuf,
    pub mtime: Option<SystemTime>,
    pub logical_size: u64,
    pub allocated_size: Option<u64>,
    pub entries: Vec<EntryReport>,
}

/// Per-entry information used for both reports and the TUI.
#[derive(Clone)]
pub struct EntryReport {
    pub name: String,
    pub path: PathBuf,
    pub kind: EntryKind,
    pub logical_size: u64,
    pub allocated_size: Option<u64>,
    pub percent_of_parent: f64,
    pub ads_bytes: u64,
    pub ads_count: usize,
    pub error: Option<String>,
}

/// Classification for an entry appearing in the output.
#[derive(Clone, Copy, Debug)]
pub enum EntryKind {
    Directory,
    SymlinkDirectory,
    Other,
    Skipped,
}

impl EntryKind {
    /// Returns a short label suitable for compact UI rendering.
    pub fn short_label(self) -> &'static str {
        match self {
            EntryKind::Directory => "DIR",
            EntryKind::SymlinkDirectory => "LNKD",
            EntryKind::Other => "OTHER",
            EntryKind::Skipped => "SKIP",
        }
    }
}

/// Progress notifications streamed from worker threads.
pub enum ProgressEvent {
    Started(PathBuf),
    CacheHit(PathBuf),
    Completed {
        path: PathBuf,
        logical: u64,
        allocated: Option<u64>,
    },
    EntryError {
        path: PathBuf,
        message: String,
    },
    Skipped(PathBuf, String),
}

/// Work item handed to directory-processing threads.
#[derive(Clone)]
pub struct ChildJob {
    pub name: String,
    pub path: PathBuf,
    pub was_symlink: bool,
}

/// Result of pre-scanning a directory to queue follow-up work.
pub struct DirectoryPlan {
    pub directories: Vec<ChildJob>,
    pub precomputed_entries: Vec<EntryReport>,
    pub file_logical: u64,
    pub file_allocated: Option<u64>,
}

/// Summary of alternate data streams attached to a file.
#[derive(Default)]
pub struct AdsSummary {
    pub total_bytes: u64,
    pub count: usize,
}

impl ScanMode {
    /// Human-readable label for the mode.
    pub fn label(self) -> &'static str {
        match self {
            ScanMode::Fast => "Fast",
            ScanMode::Accurate => "Accurate",
        }
    }
}
