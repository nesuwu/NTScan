use std::cmp::Ordering;
use std::ffi::c_void;
use std::fs::{self, Metadata};
use std::io;
use std::os::windows::{ffi::OsStrExt, io::AsRawHandle};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use rayon::prelude::*;
use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_HANDLE_EOF, ERROR_SHARING_VIOLATION, HANDLE,
};
use windows::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_STANDARD_INFO, FileStandardInfo, FindClose,
    FindFirstStreamW, FindNextStreamW, GetCompressedFileSizeW, GetFileInformationByHandleEx,
    STREAM_INFO_LEVELS, WIN32_FIND_STREAM_DATA,
};
use windows::core::{HRESULT, PCWSTR};

use crate::context::ScanContext;
use crate::model::{
    AdsSummary, ChildJob, DirectoryPlan, DirectoryReport, EntryKind, EntryReport, ProgressEvent,
    ScanErrorKind, ScanMode,
};

const CANCEL_CHECK_INTERVAL: usize = 64;

#[cfg(test)]
static FORCE_ALLOCATED_SIZE_FAILURE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
static FORCE_ALLOCATED_SIZE_FAILURE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Debug)]
struct ScanCancelled;

impl std::fmt::Display for ScanCancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("scan cancelled")
    }
}

impl std::error::Error for ScanCancelled {}

fn cancelled_error(context: &ScanContext) -> anyhow::Error {
    context.note_cancelled();
    anyhow!(ScanCancelled)
}

fn check_cancelled(context: &ScanContext) -> Result<()> {
    if context.cancel_flag().is_cancelled() {
        return Err(cancelled_error(context));
    }
    Ok(())
}

pub fn is_scan_cancelled(err: &anyhow::Error) -> bool {
    err.chain()
        .any(|cause| cause.downcast_ref::<ScanCancelled>().is_some())
}

/// Scans a single directory, aggregating its total size and collecting children.
///
/// This function performs the following steps:
/// 1. **Metadata Retrieval**: Fetches basic metadata (mtime, attributes) for the directory.
/// 2. **Plan Preparation**: Enumerates entries and splits them into sub-directories and files.
///    See [`prepare_directory_plan`] for details.
/// 3. **Parallel Execution**: Processes sub-directories in parallel using `rayon`, recursively
///    calling `scan_directory`.
/// 4. **Aggregation**: Sums up the results from all children and local files to produce
///    a final `DirectoryReport`.
pub fn scan_directory(path: &Path, context: &ScanContext) -> Result<DirectoryReport> {
    let result = scan_directory_inner(path, context);
    if let Err(err) = &result
        && !is_scan_cancelled(err)
    {
        context.record_error(classify_anyhow_error(err));
    }
    result
}

fn scan_directory_inner(path: &Path, context: &ScanContext) -> Result<DirectoryReport> {
    check_cancelled(context)?;
    context.emit(ProgressEvent::Started(path.to_path_buf()));

    let metadata = fs::metadata(path)
        .with_context(|| format!("metadata access failed for {}", path.display()))?;
    let mtime = metadata.modified().ok();

    let plan = prepare_directory_plan(path, context)?;

    let DirectoryPlan {
        directories,
        mut precomputed_entries,
        file_logical,
        file_allocated,
        file_allocated_complete,
    } = plan;

    let mut dir_entries: Vec<EntryReport> = directories
        .into_par_iter()
        .try_fold(Vec::new, |mut acc, job| -> Result<Vec<EntryReport>> {
            check_cancelled(context)?;
            acc.push(process_directory_child(job, context)?);
            Ok(acc)
        })
        .try_reduce(
            Vec::new,
            |mut left, mut right| -> Result<Vec<EntryReport>> {
                left.append(&mut right);
                Ok(left)
            },
        )?;

    let directories_logical: u64 = dir_entries.iter().map(|entry| entry.logical_size).sum();
    let total_logical = file_logical + directories_logical;

    let mut total_allocated = match (context.options().mode, file_allocated) {
        (ScanMode::Accurate, value) => value,
        _ => None,
    };
    // Default to false: it is only meaningful when we actually collected
    // allocation data (Accurate mode). The Accurate branch below sets it
    // to file_allocated_complete and refines it per child.
    let mut allocated_complete = false;

    if context.options().mode == ScanMode::Accurate {
        allocated_complete = file_allocated_complete;
        if let Some(total) = total_allocated.as_mut() {
            for entry in &dir_entries {
                allocated_complete &= entry.allocated_complete;
                if let Some(alloc) = entry.allocated_size {
                    *total += alloc;
                }
            }
        } else {
            allocated_complete = false;
        }
    } else if let Some(total) = total_allocated.as_mut() {
        for entry in &dir_entries {
            if let Some(alloc) = entry.allocated_size {
                *total += alloc;
            }
        }
    }

    precomputed_entries.append(&mut dir_entries);
    let mut entries = precomputed_entries;

    for entry in &mut entries {
        entry.percent_of_parent = if total_logical == 0 {
            0.0
        } else {
            (entry.logical_size as f64 / total_logical as f64) * 100.0
        };
    }

    entries.sort_by(|a, b| match b.logical_size.cmp(&a.logical_size) {
        Ordering::Equal => a.name.cmp(&b.name),
        other => other,
    });

    let report = DirectoryReport {
        path: path.to_path_buf(),
        mtime,
        logical_size: total_logical,
        allocated_size: total_allocated,
        allocated_complete,
        entries,
    };

    context.emit(ProgressEvent::Completed {
        path: path.to_path_buf(),
        logical: report.logical_size,
        allocated: report.allocated_size,
        allocated_complete: report.allocated_complete,
    });

    Ok(report)
}

/// Reads a directory and segregates entries into sub-directories (for parallel
/// scanning) and files/other (for immediate summation).
///
/// The function runs in two phases:
///
/// 1. **Classification** (sequential) — iterates `read_dir` once, performing only
///    lightweight metadata checks.  Directories are queued for later parallel
///    recursion; files are collected with their resolved `Metadata` for Phase 2;
///    errors and skipped entries are emitted immediately.
///
/// 2. **File processing** (parallel above [`FILE_PARALLEL_THRESHOLD`]) — the
///    expensive per-file work (allocation size, ADS enumeration, hard-link dedup)
///    runs in parallel via rayon when the file count justifies the dispatch
///    overhead.  This removes the bottleneck that previously serialised all file
///    work when a single directory contains many thousands of entries (e.g. a
///    Downloads or temp folder).
pub fn prepare_directory_plan(path: &Path, context: &ScanContext) -> Result<DirectoryPlan> {
    check_cancelled(context)?;

    let mut directories = Vec::new();
    let mut precomputed_entries = Vec::new();
    let mut pending_files: Vec<PendingFile> = Vec::new();

    let read_dir = fs::read_dir(path)
        .with_context(|| format!("failed to read directory {}", path.display()))?;

    // ── Phase 1: classify entries (sequential) ──────────────────────────
    for (index, entry) in read_dir.enumerate() {
        if index % CANCEL_CHECK_INTERVAL == 0 {
            check_cancelled(context)?;
        }

        let entry = entry.with_context(|| format!("failed to iterate {}", path.display()))?;
        let name = entry.file_name().to_string_lossy().to_string();
        let entry_path = entry.path();

        // Use symlink metadata so reparse points (symlinks/junctions) stay visible.
        let symlink_metadata = match fs::symlink_metadata(&entry_path) {
            Ok(meta) => meta,
            Err(err) => {
                context.record_error(classify_io_error(&err));
                context.emit(ProgressEvent::EntryError {
                    path: entry_path.clone(),
                    message: format!("metadata error: {}", err),
                });
                precomputed_entries.push(entry_with_error(
                    name,
                    entry_path.clone(),
                    EntryKind::Other,
                    format!("metadata error: {}", err),
                ));
                continue;
            }
        };

        let is_reparse_point = is_reparse_point(&symlink_metadata);
        let is_symlink = symlink_metadata.file_type().is_symlink() || is_reparse_point;

        let target_metadata: Option<Metadata> = if is_symlink {
            if !context.options().follow_symlinks {
                context.record_skipped();
                context.emit(ProgressEvent::Skipped(
                    entry_path.clone(),
                    String::from("symlink not followed (use --follow-symlinks)"),
                ));
                precomputed_entries.push(entry_with_skip(
                    name,
                    entry_path.clone(),
                    EntryKind::Skipped,
                    "symlink not followed (use --follow-symlinks)",
                ));
                continue;
            }
            match fs::metadata(&entry_path) {
                Ok(meta) => Some(meta),
                Err(err) => {
                    context.record_error(classify_io_error(&err));
                    context.emit(ProgressEvent::EntryError {
                        path: entry_path.clone(),
                        message: format!("symlink target metadata failed: {}", err),
                    });
                    precomputed_entries.push(entry_with_error(
                        name,
                        entry_path.clone(),
                        EntryKind::Other,
                        format!("symlink target metadata failed: {}", err),
                    ));
                    continue;
                }
            }
        } else {
            Some(symlink_metadata)
        };

        let meta = match target_metadata {
            Some(m) => m,
            None => continue,
        };

        if meta.is_dir() {
            check_cancelled(context)?;
            directories.push(ChildJob {
                name,
                path: entry_path,
                was_symlink: is_symlink,
            });
            continue;
        }

        if meta.is_file() {
            // Defer the expensive per-file work to Phase 2.
            pending_files.push(PendingFile {
                name,
                path: entry_path,
                meta,
            });
            continue;
        }

        precomputed_entries.push(entry_with_error(
            name,
            entry_path.clone(),
            EntryKind::Other,
            "unsupported entry type",
        ));
        context.record_error(ScanErrorKind::Other);
    }

    // ── Phase 2: process files (parallel for large directories) ─────────
    let initial_allocated = match context.options().mode {
        ScanMode::Fast => None,
        ScanMode::Accurate => Some(0u64),
    };
    let (file_logical, file_allocated, file_allocated_complete, file_entries) =
        process_pending_files(&pending_files, initial_allocated, context)?;

    precomputed_entries.extend(file_entries);

    Ok(DirectoryPlan {
        directories,
        precomputed_entries,
        file_logical,
        file_allocated,
        file_allocated_complete,
    })
}

/// Lightweight pre-classified file info collected during Phase 1.
/// The expensive work (allocation, ADS, dedup) is deferred to Phase 2.
struct PendingFile {
    name: String,
    path: PathBuf,
    meta: Metadata,
}

/// Per-file result produced by [`process_single_file`].
struct FileResult {
    accounted_logical: u64,
    /// Amount to add to the directory's `file_allocated` total.
    /// `None` in Fast mode (allocation not tracked).
    alloc_add: Option<u64>,
    allocated_complete: bool,
    entry: Option<EntryReport>,
}

/// Minimum file count before rayon parallel dispatch kicks in.
/// Below this threshold the sequential path avoids dispatch overhead.
const FILE_PARALLEL_THRESHOLD: usize = 128;

/// Processes a batch of files, switching between sequential and parallel
/// execution depending on count.
fn process_pending_files(
    files: &[PendingFile],
    initial_allocated: Option<u64>,
    context: &ScanContext,
) -> Result<(u64, Option<u64>, bool, Vec<EntryReport>)> {
    if files.is_empty() {
        let complete = context.options().mode == ScanMode::Accurate;
        return Ok((0, initial_allocated, complete, Vec::new()));
    }

    let results: Vec<FileResult> = if files.len() >= FILE_PARALLEL_THRESHOLD {
        files
            .par_iter()
            .map(|file| process_single_file(file, context))
            .collect::<Result<Vec<_>>>()?
    } else {
        files
            .iter()
            .map(|file| process_single_file(file, context))
            .collect::<Result<Vec<_>>>()?
    };

    let mut file_logical = 0u64;
    let mut file_allocated = initial_allocated;
    let mut file_allocated_complete = context.options().mode == ScanMode::Accurate;
    let mut entries = Vec::new();

    for result in results {
        file_logical += result.accounted_logical;
        file_allocated_complete &= result.allocated_complete;
        if let Some(add) = result.alloc_add {
            if let Some(total) = file_allocated.as_mut() {
                *total += add;
            }
        }
        if let Some(entry) = result.entry {
            entries.push(entry);
        }
    }

    Ok((file_logical, file_allocated, file_allocated_complete, entries))
}

/// Processes a single file: computes sizes, checks hard-link dedup, and
/// optionally builds an [`EntryReport`] for display.
fn process_single_file(file: &PendingFile, context: &ScanContext) -> Result<FileResult> {
    check_cancelled(context)?;

    let (logical, allocated, allocated_complete) =
        accumulate_file_sizes(&file.path, &file.meta, context)?;

    let (is_first_logical, is_first_alloc) = context.mark_file_unique(&file.path);

    let accounted_logical = if is_first_logical { logical } else { 0 };

    // Mirror the original accounting: non-first alloc instances contribute 0
    // so the total stays correct while the entry is still displayable.
    let alloc_add = allocated.map(|a| if is_first_alloc { a } else { 0 });

    let is_hardlink_duplicate = !is_first_logical || !is_first_alloc;

    let entry = if context.options().show_files {
        let (ads_bytes, ads_count) = if context.options().mode == ScanMode::Accurate {
            context
                .cache()
                .get_attributes(&file.path, file.meta.len(), file.meta.modified().ok())
                .map(|(_, bytes, count)| (bytes, count))
                .unwrap_or((0, 0))
        } else {
            (0, 0)
        };

        let accounted_allocated = allocated.map(|a| if is_first_alloc { a } else { 0 });

        let display_name = if is_hardlink_duplicate {
            format!("{} (hardlink duplicate)", file.name)
        } else {
            file.name.clone()
        };

        Some(EntryReport {
            name: display_name,
            path: file.path.clone(),
            kind: EntryKind::File,
            logical_size: accounted_logical,
            allocated_size: accounted_allocated,
            allocated_complete,
            percent_of_parent: 0.0,
            ads_bytes,
            ads_count,
            error: None,
            skip_reason: None,
            modified: file.meta.modified().ok(),
        })
    } else {
        None
    };

    Ok(FileResult {
        accounted_logical,
        alloc_add,
        allocated_complete,
        entry,
    })
}

/// Recursively scans a subdirectory, handling symlink cycles if configured.
pub fn process_directory_child(job: ChildJob, context: &ScanContext) -> Result<EntryReport> {
    check_cancelled(context)?;

    if context.options().follow_symlinks
        && job.was_symlink
        && let Ok(canon) = fs::canonicalize(&job.path)
        && !context.mark_if_new(canon)
    {
        context.record_skipped();
        context.emit(ProgressEvent::Skipped(
            job.path.clone(),
            String::from("cycle detected"),
        ));
        return Ok(entry_with_skip(
            job.name,
            job.path,
            EntryKind::SymlinkDirectory,
            "skipped (already visited target)",
        ));
    }

    check_cancelled(context)?;
    match scan_directory(&job.path, context) {
        Ok(report) => Ok(EntryReport {
            name: job.name,
            path: job.path,
            kind: if job.was_symlink {
                EntryKind::SymlinkDirectory
            } else {
                EntryKind::Directory
            },
            logical_size: report.logical_size,
            allocated_size: report.allocated_size,
            allocated_complete: report.allocated_complete,
            percent_of_parent: 0.0,
            ads_bytes: 0,
            ads_count: 0,
            error: None,
            skip_reason: None,
            modified: report.mtime,
        }),
        Err(err) if is_scan_cancelled(&err) => Err(err),
        Err(err) => {
            context.emit(ProgressEvent::EntryError {
                path: job.path.clone(),
                message: format!("directory scan failed: {}", err),
            });
            Ok(entry_with_error(
                job.name,
                job.path,
                if job.was_symlink {
                    EntryKind::SymlinkDirectory
                } else {
                    EntryKind::Directory
                },
                format!("directory scan failed: {}", err),
            ))
        }
    }
}

fn accumulate_file_sizes(
    path: &Path,
    meta: &Metadata,
    context: &ScanContext,
) -> Result<(u64, Option<u64>, bool)> {
    check_cancelled(context)?;
    let mut logical = meta.len();
    let mut allocated = None;
    let mut allocated_complete = true;

    if context.options().mode == ScanMode::Fast {
        return Ok((logical, None, false));
    }

    if context.options().mode == ScanMode::Accurate {
        check_cancelled(context)?;
        let mtime = meta.modified().ok();

        if let Some((cached_alloc, cached_ads_bytes, _)) =
            context.cache().get_attributes(path, logical, mtime)
        {
            logical += cached_ads_bytes;
            allocated = Some(cached_alloc);
            return Ok((logical, allocated, allocated_complete));
        }

        check_cancelled(context)?;
        let mut ads_summary = AdsSummary::default();
        match collect_ads(path) {
            Ok(ads) => {
                logical += ads.total_bytes;
                ads_summary = ads;
            }
            Err(err) => {
                context.record_error(ScanErrorKind::ADSFailed);
                context.emit(ProgressEvent::EntryError {
                    path: path.to_path_buf(),
                    message: format!("ADS enumeration failed: {}", err),
                });
            }
        }

        check_cancelled(context)?;
        let alloc_size = match get_allocated_size_fast(path) {
            Ok(size) => size,
            Err(err) => {
                let kind = classify_anyhow_error(&err);
                context.record_error(kind);
                context.emit(ProgressEvent::EntryError {
                    path: path.to_path_buf(),
                    message: format!("allocation size failed: {}", err),
                });
                allocated_complete = false;
                0
            }
        };
        allocated = Some(alloc_size);

        // Avoid caching a synthetic zero when allocation lookup fails.
        if allocated_complete {
            context.cache().insert_attributes(
                path.to_path_buf(),
                mtime,
                meta.len(),
                alloc_size,
                ads_summary.total_bytes,
                ads_summary.count,
            );
        }
    }

    Ok((logical, allocated, allocated_complete))
}

fn get_allocated_size_fast(path: &Path) -> Result<u64> {
    #[cfg(test)]
    if FORCE_ALLOCATED_SIZE_FAILURE.load(std::sync::atomic::Ordering::Relaxed) {
        return Err(anyhow!(
            "forced allocation lookup failure for {}",
            path.display()
        ));
    }

    let wide = path_to_wide(path);
    unsafe {
        let mut high: u32 = 0;
        let low = GetCompressedFileSizeW(PCWSTR(wide.as_ptr()), Some(&mut high as *mut u32));
        if low == u32::MAX {
            use windows::Win32::Foundation::GetLastError;
            let err = GetLastError();
            if err.is_err() {
                return get_allocated_size(path);
            }
        }
        Ok(((high as u64) << 32) | (low as u64))
    }
}

fn entry_with_error(
    name: String,
    path: PathBuf,
    kind: EntryKind,
    message: impl Into<String>,
) -> EntryReport {
    EntryReport {
        name,
        path,
        kind,
        logical_size: 0,
        allocated_size: None,
        allocated_complete: true,
        percent_of_parent: 0.0,
        ads_bytes: 0,
        ads_count: 0,
        error: Some(message.into()),
        skip_reason: None,
        modified: None,
    }
}

fn entry_with_skip(
    name: String,
    path: PathBuf,
    kind: EntryKind,
    reason: impl Into<String>,
) -> EntryReport {
    EntryReport {
        name,
        path,
        kind,
        logical_size: 0,
        allocated_size: None,
        allocated_complete: true,
        percent_of_parent: 0.0,
        ads_bytes: 0,
        ads_count: 0,
        error: None,
        skip_reason: Some(reason.into()),
        modified: None,
    }
}

fn get_allocated_size(path: &Path) -> Result<u64> {
    let file = fs::File::open(path)?;
    let mut info: FILE_STANDARD_INFO = unsafe { std::mem::zeroed() };
    unsafe {
        GetFileInformationByHandleEx(
            HANDLE(file.as_raw_handle() as isize),
            FileStandardInfo,
            &mut info as *mut _ as *mut c_void,
            std::mem::size_of::<FILE_STANDARD_INFO>() as u32,
        )?;
    }
    Ok(info.AllocationSize as u64)
}

fn collect_ads(path: &Path) -> Result<AdsSummary> {
    const FIND_STREAM_INFO_STANDARD: STREAM_INFO_LEVELS = STREAM_INFO_LEVELS(0);

    let wide = path_to_wide(path);
    let mut data = WIN32_FIND_STREAM_DATA::default();
    let handle = match unsafe {
        FindFirstStreamW(
            PCWSTR(wide.as_ptr()),
            FIND_STREAM_INFO_STANDARD,
            &mut data as *mut _ as *mut c_void,
            0,
        )
    } {
        Ok(handle) => handle,
        Err(err) => {
            if err.code() == hresult_from_win32(ERROR_HANDLE_EOF.0) {
                return Ok(AdsSummary::default());
            }
            return Err(anyhow!(
                "FindFirstStreamW failed for {}: {}",
                path.display(),
                err
            ));
        }
    };

    let guard = HandleGuard::new(handle);
    let mut summary = AdsSummary::default();
    accumulate_stream(&data, &mut summary);

    loop {
        match unsafe { FindNextStreamW(guard.handle(), &mut data as *mut _ as *mut c_void) } {
            Ok(()) => accumulate_stream(&data, &mut summary),
            Err(err) => {
                if err.code() == hresult_from_win32(ERROR_HANDLE_EOF.0) {
                    break;
                }
                return Err(anyhow!(
                    "FindNextStreamW failed for {}: {}",
                    path.display(),
                    err
                ));
            }
        }
    }

    Ok(summary)
}

fn accumulate_stream(data: &WIN32_FIND_STREAM_DATA, summary: &mut AdsSummary) {
    if let Some(name) = utf16_to_string(&data.cStreamName)
        && name != "::$DATA"
    {
        let size = data.StreamSize;
        if size > 0 {
            summary.total_bytes += size as u64;
            summary.count += 1;
        }
    }
}

struct HandleGuard {
    handle: HANDLE,
}

impl HandleGuard {
    fn new(handle: HANDLE) -> Self {
        Self { handle }
    }

    fn handle(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = FindClose(self.handle);
        }
    }
}

fn hresult_from_win32(code: u32) -> HRESULT {
    if code == 0 {
        HRESULT(0)
    } else {
        let value = ((code & 0x0000_FFFF) | 0x8007_0000) as i32;
        HRESULT(value)
    }
}

fn utf16_to_string(buffer: &[u16]) -> Option<String> {
    let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    if len == 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&buffer[..len]))
}

fn path_to_wide(path: &Path) -> Vec<u16> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    wide
}

fn classify_io_error(err: &io::Error) -> ScanErrorKind {
    #[cfg(windows)]
    {
        if let Some(code) = err.raw_os_error() {
            if code == ERROR_ACCESS_DENIED.0 as i32 {
                return ScanErrorKind::AccessDenied;
            }
            if code == ERROR_SHARING_VIOLATION.0 as i32 {
                return ScanErrorKind::SharingViolation;
            }
        }
    }
    match err.kind() {
        io::ErrorKind::PermissionDenied => ScanErrorKind::AccessDenied,
        _ => ScanErrorKind::Other,
    }
}

fn classify_anyhow_error(err: &anyhow::Error) -> ScanErrorKind {
    if let Some(io_err) = err.downcast_ref::<io::Error>() {
        classify_io_error(io_err)
    } else {
        ScanErrorKind::Other
    }
}

/// Checks if a file/directory is a reparse point (junction, mount point, or symlink).
///
/// Rust's `is_symlink()` only detects symbolic links, not NTFS junctions.
/// Windows system directories like `C:\Documents and Settings` are junctions
/// pointing to `C:\Users`, and would cause massive double-counting if followed.
fn is_reparse_point(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    let attrs = metadata.file_attributes();
    (attrs & FILE_ATTRIBUTE_REPARSE_POINT.0) != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Arc;

    use tempfile::tempdir;

    use crate::context::{CancelFlag, ScanCache, ScanContext};
    use crate::model::{EntryKind, ErrorStats, ScanErrorKind, ScanMode, ScanOptions};

    struct ForcedAllocationFailureGuard;

    impl ForcedAllocationFailureGuard {
        fn enable() -> Self {
            FORCE_ALLOCATED_SIZE_FAILURE.store(true, std::sync::atomic::Ordering::SeqCst);
            Self
        }
    }

    impl Drop for ForcedAllocationFailureGuard {
        fn drop(&mut self) {
            FORCE_ALLOCATED_SIZE_FAILURE.store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[test]
    fn allocated_lookup_failure_marks_subtree_partial_without_crashing() {
        let _lock = FORCE_ALLOCATED_SIZE_FAILURE_LOCK
            .lock()
            .expect("failed to acquire allocation failure test lock");
        let _force_failure = ForcedAllocationFailureGuard::enable();

        let root = tempdir().expect("failed to create temp directory");
        let child_dir = root.path().join("child");
        fs::create_dir(&child_dir).expect("failed to create child directory");
        fs::write(root.path().join("root.bin"), b"root data").expect("failed to write root file");
        fs::write(child_dir.join("leaf.bin"), b"leaf data").expect("failed to write child file");

        let options = ScanOptions {
            mode: ScanMode::Accurate,
            follow_symlinks: false,
            show_files: true,
        };
        let errors = ErrorStats::default();
        let context = ScanContext::with_cache(
            options,
            None,
            CancelFlag::new(),
            errors,
            Arc::new(ScanCache::default()),
        );

        let report = scan_directory(root.path(), &context).expect("scan should complete");
        assert!(
            report.logical_size > 0,
            "logical size should still be collected even when allocation lookups fail"
        );
        assert!(
            report.allocated_size.is_some(),
            "allocated total should still be reported in accurate mode"
        );
        assert!(
            !report.allocated_complete,
            "root report must be marked partial when any allocation lookup fails"
        );

        let child_entry = report
            .entries
            .iter()
            .find(|entry| entry.path == child_dir && matches!(entry.kind, EntryKind::Directory))
            .expect("expected child directory entry");
        assert!(
            !child_entry.allocated_complete,
            "child subtree must be marked partial"
        );

        let error_snapshot = context.errors().snapshot();
        assert!(
            *error_snapshot.get(&ScanErrorKind::Other).unwrap_or(&0) >= 1,
            "allocation lookup failures should be recorded as scan errors"
        );
    }
}
