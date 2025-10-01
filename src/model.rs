use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanMode {
    Fast,
    Accurate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScanOptions {
    pub mode: ScanMode,
    pub follow_symlinks: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScanErrorKind {
    AccessDenied,
    SharingViolation,
    ADSFailed,
    PathTooLong,
    Cancelled,
    Other,
}

#[derive(Default, Clone)]
pub struct ErrorStats {
    counts: Arc<Mutex<HashMap<ScanErrorKind, usize>>>,
}

impl ErrorStats {
    pub fn record(&self, kind: ScanErrorKind) {
        let mut guard = self.counts.lock().unwrap();
        *guard.entry(kind).or_insert(0) += 1;
    }

    pub fn snapshot(&self) -> HashMap<ScanErrorKind, usize> {
        self.counts.lock().unwrap().clone()
    }
}

#[derive(Clone)]
pub struct DirectoryReport {
    pub path: PathBuf,
    pub mtime: Option<SystemTime>,
    pub logical_size: u64,
    pub allocated_size: Option<u64>,
    pub entries: Vec<EntryReport>,
}

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

#[derive(Clone, Copy, Debug)]
pub enum EntryKind {
    Directory,
    SymlinkDirectory,
    Other,
    Skipped,
}

impl EntryKind {
    pub fn short_label(self) -> &'static str {
        match self {
            EntryKind::Directory => "DIR",
            EntryKind::SymlinkDirectory => "LNKD",
            EntryKind::Other => "OTHER",
            EntryKind::Skipped => "SKIP",
        }
    }
}

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

#[derive(Clone)]
pub struct ChildJob {
    pub name: String,
    pub path: PathBuf,
    pub was_symlink: bool,
}

pub struct DirectoryPlan {
    pub directories: Vec<ChildJob>,
    pub precomputed_entries: Vec<EntryReport>,
    pub file_logical: u64,
    pub file_allocated: Option<u64>,
}

#[derive(Default)]
pub struct AdsSummary {
    pub total_bytes: u64,
    pub count: usize,
}

impl ScanMode {
    pub fn label(self) -> &'static str {
        match self {
            ScanMode::Fast => "Fast",
            ScanMode::Accurate => "Accurate",
        }
    }
}
