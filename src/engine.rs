use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::Sender;

use anyhow::{Context, Result};

use crate::context::{CancelFlag, ScanCache, ScanContext};
use crate::duplicates::find_duplicates_with_cache;
use crate::model::{DirectoryReport, DuplicateScanResult, ErrorStats, ProgressEvent, ScanOptions};
use crate::scanner::scan_directory;

/// Runs a full directory scan and returns the final report.
///
/// This is a UI-agnostic entry point intended for CLI tools, FFI, and future frontends.
pub fn run_scan(
    target: &Path,
    options: ScanOptions,
    cache_path: Option<PathBuf>,
    progress: Option<Sender<ProgressEvent>>,
) -> Result<DirectoryReport> {
    run_scan_with_cancel(target, options, cache_path, progress, CancelFlag::new())
}

/// Runs a full directory scan using a caller-provided cancellation flag.
pub fn run_scan_with_cancel(
    target: &Path,
    options: ScanOptions,
    cache_path: Option<PathBuf>,
    progress: Option<Sender<ProgressEvent>>,
    cancel: CancelFlag,
) -> Result<DirectoryReport> {
    let cache = cache_path.map(ScanCache::new).unwrap_or_default();

    let context = Arc::new(ScanContext::with_cache(
        options,
        progress,
        cancel,
        ErrorStats::default(),
        Arc::new(cache),
    ));

    if options.follow_symlinks
        && let Ok(canon) = std::fs::canonicalize(target)
    {
        context.mark_if_new(canon);
    }

    let report = scan_directory(target, &context)
        .with_context(|| format!("failed to scan {}", target.display()))?;
    context.save_cache();
    Ok(report)
}

/// Runs duplicate-file detection independent of any UI.
pub fn run_duplicates(
    target: &Path,
    min_size: u64,
    hash_cache_path: Option<PathBuf>,
) -> Result<DuplicateScanResult> {
    find_duplicates_with_cache(target, min_size, hash_cache_path)
}
