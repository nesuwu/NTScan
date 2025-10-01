use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Condvar, Mutex};
use std::time::SystemTime;

use crate::model::{DirectoryReport, ErrorStats, ProgressEvent, ScanMode, ScanOptions};

#[derive(Clone)]
pub struct CancelFlag {
    inner: Arc<AtomicBool>,
}

impl CancelFlag {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn cancel(&self) {
        self.inner.store(true, AtomicOrdering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.load(AtomicOrdering::Relaxed)
    }
}

#[derive(Default)]
pub struct ScanCache {
    inner: Mutex<HashMap<PathBuf, Vec<CachedReport>>>,
}

impl ScanCache {
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

#[derive(Clone)]
pub struct IoGate {
    inner: Arc<(Mutex<usize>, Condvar)>,
}

pub struct IoPermit {
    gate: IoGate,
}

impl IoGate {
    pub fn new(permits: usize) -> Self {
        Self {
            inner: Arc::new((Mutex::new(permits), Condvar::new())),
        }
    }

    pub fn acquire(&self) -> IoPermit {
        let (lock, cvar) = &*self.inner;
        let mut guard = lock.lock().unwrap();
        while *guard == 0 {
            guard = cvar.wait(guard).unwrap();
        }
        *guard -= 1;
        IoPermit { gate: self.clone() }
    }
}

impl Drop for IoPermit {
    fn drop(&mut self) {
        let (lock, cvar) = &*self.gate.inner;
        let mut guard = lock.lock().unwrap();
        *guard += 1;
        cvar.notify_one();
    }
}

#[derive(Clone)]
pub struct ScanContext {
    options: ScanOptions,
    cache: Arc<ScanCache>,
    visited: Arc<Visited>,
    progress: Option<Sender<ProgressEvent>>,
    cancel: CancelFlag,
    io_gate: IoGate,
    errors: ErrorStats,
}

impl ScanContext {
    pub fn new(
        options: ScanOptions,
        progress: Option<Sender<ProgressEvent>>,
        cancel: CancelFlag,
        io_gate: IoGate,
        errors: ErrorStats,
    ) -> Self {
        Self {
            options,
            cache: Arc::new(ScanCache::default()),
            visited: Arc::new(Visited::default()),
            progress,
            cancel,
            io_gate,
            errors,
        }
    }

    pub fn emit(&self, event: ProgressEvent) {
        if let Some(tx) = &self.progress {
            let _ = tx.send(event);
        }
    }

    pub fn mark_if_new(&self, path: PathBuf) -> bool {
        let mut guard = self.visited.seen.lock().unwrap();
        guard.insert(path)
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

    pub fn io_gate(&self) -> &IoGate {
        &self.io_gate
    }
}

struct CachedReport {
    mode: ScanMode,
    mtime: Option<SystemTime>,
    report: DirectoryReport,
}
