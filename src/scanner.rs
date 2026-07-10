use std::cell::RefCell;
use std::cmp::Ordering;
use std::ffi::c_void;
use std::fs;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use rayon::prelude::*;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_HANDLE_EOF, ERROR_NO_MORE_FILES,
    ERROR_SHARING_VIOLATION, FILETIME, HANDLE,
};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_FLAGS_AND_ATTRIBUTES, FILE_LIST_DIRECTORY, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_STANDARD_INFO, FIND_FIRST_EX_LARGE_FETCH, FileIdBothDirectoryInfo,
    FileStandardInfo, FindClose, FindExInfoBasic, FindExSearchNameMatch, FindFirstFileExW,
    FindFirstStreamW, FindNextFileW, FindNextStreamW, GetCompressedFileSizeW,
    GetFileInformationByHandle, GetFileInformationByHandleEx, OPEN_EXISTING, STREAM_INFO_LEVELS,
    WIN32_FIND_DATAW, WIN32_FIND_STREAM_DATA,
};
use windows::core::{HRESULT, PCWSTR};

use crate::context::ScanContext;
use crate::model::{
    AdsSummary, ChildJob, DirectoryPlan, DirectoryReport, EntryKind, EntryReport, ProgressEvent,
    ScanErrorKind, ScanMode,
};

const CANCEL_CHECK_INTERVAL: usize = 64;

/// Minimum file count before rayon parallel dispatch kicks in.
/// Below this threshold the sequential path avoids dispatch overhead.
///
/// Lowered from 128 → 32 (Change 6): with the single-handle file path
/// (Change 2) each file now does meaningfully more kernel work, so the
/// break-even point where parallel dispatch pays for itself drops. A
/// 32-file directory of mixed content already amortises the rayon
/// fork/join overhead.
const FILE_PARALLEL_THRESHOLD: usize = 32;

#[cfg(test)]
static FORCE_ALLOCATED_SIZE_FAILURE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
static FORCE_ALLOCATED_SIZE_FAILURE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

// ── Change 5: ADS enumeration on an already-open handle ─────────────────
//
// `FindFirstStreamW`/`FindNextStreamW` re-open the file by path internally.
// `NtQueryInformationFile(FileStreamInformation)` lets us enumerate streams
// through the handle we already opened for the allocation-size + identity
// query, removing one path-based open per file.

#[repr(C)]
struct IoStatusBlock {
    status: usize,
    information: usize,
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryInformationFile(
        file_handle: HANDLE,
        io_status_block: *mut IoStatusBlock,
        file_information: *mut c_void,
        length: u32,
        file_information_class: i32,
    ) -> i32;
}

/// `FILE_INFORMATION_CLASS::FileStreamInformation`.
const FILE_STREAM_INFORMATION: i32 = 22;
const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
/// Header is `NextEntryOffset:u32 + StreamNameLength:u32 + StreamSize:i64 +
/// StreamAllocationSize:i64`, then `StreamName` WCHARs.
const FILE_STREAM_INFO_HEADER: usize = 24;

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
/// 1. **Metadata Retrieval**: Fetches basic metadata (mtime) for the directory.
/// 2. **Early dispatch traversal**: Enumerates entries via `FindFirstFileExW`
///    and, the moment a sub-directory is discovered, hands it to a rayon
///    worker (Change 1) instead of waiting for the whole directory to be
///    classified first.
/// 3. **Aggregation**: Sums the results from all children and local files to
///    produce a final `DirectoryReport`.
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
    // Change 7: only pay the PathBuf clone when someone is listening.
    if context.has_progress() {
        context.emit(ProgressEvent::Started(path.to_path_buf()));
    }

    let metadata = fs::metadata(path)
        .with_context(|| format!("metadata access failed for {}", path.display()))?;
    let mtime = metadata.modified().ok();

    // Change 1: dispatch sub-directories the instant they are found, rather
    // than draining the whole directory into a Vec first. Child results flow
    // back over an mpsc channel so the classify loop never blocks on them.
    let (tx, rx) = mpsc::channel::<Result<EntryReport>>();
    let mut pending_files: Vec<PendingFile> = Vec::new();
    let mut precomputed: Vec<EntryReport> = Vec::new();

    rayon::scope(|s| -> Result<()> {
        let iter = DirIter::new(path)?;
        for (index, raw) in iter.enumerate() {
            if index % CANCEL_CHECK_INTERVAL == 0 {
                check_cancelled(context)?;
            }
            let raw = raw?;
            match classify(raw, path, context) {
                Classified::Dir(job) => {
                    let tx = tx.clone();
                    s.spawn(move |_| {
                        let _ = tx.send(process_directory_child(job, context));
                    });
                }
                Classified::File(pending) => pending_files.push(pending),
                Classified::Pre(entry) => precomputed.push(entry),
            }
        }
        Ok(())
    })?;
    drop(tx);

    let initial_allocated = match context.options().mode {
        ScanMode::Fast => None,
        ScanMode::Accurate => Some(0u64),
    };
    let (file_logical, file_allocated, file_allocated_complete, file_entries) =
        process_pending_files(&pending_files, initial_allocated, context)?;
    precomputed.extend(file_entries);

    let mut dir_entries: Vec<EntryReport> = Vec::new();
    for item in rx {
        // `process_directory_child` only returns Err on cancellation; any
        // other failure becomes an error entry. Propagate cancellation.
        dir_entries.push(item?);
    }

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

    precomputed.append(&mut dir_entries);
    let mut entries = precomputed;

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

    if context.has_progress() {
        context.emit(ProgressEvent::Completed {
            path: path.to_path_buf(),
            logical: report.logical_size,
            allocated: report.allocated_size,
            allocated_complete: report.allocated_complete,
        });
    }

    // Persist this directory's totals so future scans can skip the subtree walk
    // when the mtime hasn't changed.
    context.dir_cache().insert(
        path,
        mtime,
        report.logical_size,
        report.allocated_size,
        report.allocated_complete,
    );

    Ok(report)
}

/// Reads a directory and segregates entries into sub-directories (for parallel
/// scanning) and files/other (for immediate summation).
///
/// This is the non-early-dispatch variant kept for the TUI driver in
/// `modes.rs`, which dispatches the returned `directories` itself. It shares
/// [`classify`] and [`WinDirIter`] with [`scan_directory_inner`] so the
/// per-entry semantics stay identical, then runs the deferred per-file work
/// (allocation size, ADS, hard-link dedup) in parallel above
/// [`FILE_PARALLEL_THRESHOLD`].
pub fn prepare_directory_plan(path: &Path, context: &ScanContext) -> Result<DirectoryPlan> {
    check_cancelled(context)?;

    let mut directories = Vec::new();
    let mut precomputed_entries = Vec::new();
    let mut pending_files: Vec<PendingFile> = Vec::new();

    let iter = DirIter::new(path)?;
    for (index, raw) in iter.enumerate() {
        if index % CANCEL_CHECK_INTERVAL == 0 {
            check_cancelled(context)?;
        }
        let raw = raw?;
        match classify(raw, path, context) {
            Classified::Dir(job) => {
                check_cancelled(context)?;
                directories.push(job);
            }
            Classified::File(pending) => pending_files.push(pending),
            Classified::Pre(entry) => precomputed_entries.push(entry),
        }
    }

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

// ── Directory enumeration (Change 3 + Change 4) ─────────────────────────

thread_local! {
    /// Reused per-thread UTF-16 scratch buffer (Change 4). Avoids a fresh
    /// `Vec<u16>` allocation for every `GetCompressedFileSizeW` /
    /// `FindFirstFileExW` call on the hot path.
    static WIDE_BUF: RefCell<Vec<u16>> = const { RefCell::new(Vec::new()) };
}

/// Runs `f` with a NUL-terminated wide encoding of `path` in the thread-local
/// scratch buffer. The pointer is valid only for the duration of `f`; `f` must
/// not call another `with_wide_*` helper (the `RefCell` is held).
fn with_wide_path<R>(path: &Path, f: impl FnOnce(*const u16) -> R) -> R {
    WIDE_BUF.with(|cell| {
        let mut buf = cell.borrow_mut();
        buf.clear();
        buf.extend(path.as_os_str().encode_wide());
        buf.push(0);
        f(buf.as_ptr())
    })
}

/// Like [`with_wide_path`] but appends a `\*` search glob for
/// `FindFirstFileExW`.
fn with_wide_search<R>(dir: &Path, f: impl FnOnce(*const u16) -> R) -> R {
    WIDE_BUF.with(|cell| {
        let mut buf = cell.borrow_mut();
        buf.clear();
        buf.extend(dir.as_os_str().encode_wide());
        let sep = matches!(buf.last(), Some(&c) if c == u16::from(b'\\') || c == u16::from(b'/'));
        if !sep {
            buf.push(u16::from(b'\\'));
        }
        buf.push(u16::from(b'*'));
        buf.push(0);
        f(buf.as_ptr())
    })
}

/// Hard-link identity knowledge for one enumerated file (Change 8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FileIds {
    /// `(volume_serial, 64-bit file id)` came batched with the directory
    /// listing — dedup needs no per-file syscalls.
    Known(u64, u64),
    /// Handle enumeration worked but the filesystem reports no file id
    /// (e.g. FAT). Such filesystems have no hardlinks; treat as unique.
    NoneOnVolume,
    /// Find-based enumeration — resolve identity per file as before.
    Unknown,
}

/// One raw directory entry, already carrying the attributes, size and mtime
/// so no per-entry `stat` round-trip is needed (Change 3). The handle-based
/// iterator (Change 8) additionally fills `allocated` and `ids`.
struct RawEntry {
    name: String,
    attributes: u32,
    len: u64,
    modified: Option<SystemTime>,
    /// `AllocationSize` from the directory index; `None` on the find path.
    allocated: Option<u64>,
    ids: FileIds,
}

/// Size + mtime of a classified file, carried into Phase 2 in place of a
/// `std::fs::Metadata` (which would have cost a second `stat`).
struct EntryInfo {
    len: u64,
    modified: Option<SystemTime>,
    /// `AllocationSize` from the directory index; `None` on the find path.
    allocated: Option<u64>,
    ids: FileIds,
}

/// Directory iterator using `FindFirstFileExW` with `FindExInfoBasic`
/// (skip the 8.3 short-name lookup) and `FIND_FIRST_EX_LARGE_FETCH`
/// (batch more entries per kernel transition) — Change 3.
struct WinDirIter {
    handle: HANDLE,
    data: WIN32_FIND_DATAW,
    first: bool,
    done: bool,
}

impl WinDirIter {
    fn new(dir: &Path) -> Result<Self> {
        let mut data: WIN32_FIND_DATAW = unsafe { std::mem::zeroed() };
        let handle = with_wide_search(dir, |pattern| unsafe {
            FindFirstFileExW(
                PCWSTR(pattern),
                FindExInfoBasic,
                &mut data as *mut _ as *mut c_void,
                FindExSearchNameMatch,
                None,
                FIND_FIRST_EX_LARGE_FETCH,
            )
        })
        .with_context(|| format!("failed to read directory {}", dir.display()))?;

        Ok(Self {
            handle,
            data,
            first: true,
            done: false,
        })
    }
}

impl Iterator for WinDirIter {
    type Item = Result<RawEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.done {
                return None;
            }
            if self.first {
                self.first = false;
            } else {
                match unsafe { FindNextFileW(self.handle, &mut self.data) } {
                    Ok(()) => {}
                    Err(err) => {
                        self.done = true;
                        if err.code() == hresult_from_win32(ERROR_NO_MORE_FILES.0) {
                            return None;
                        }
                        return Some(Err(anyhow!("FindNextFileW failed: {}", err)));
                    }
                }
            }

            let name = wide_name(&self.data.cFileName);
            if name == "." || name == ".." {
                continue;
            }
            let len = ((self.data.nFileSizeHigh as u64) << 32) | (self.data.nFileSizeLow as u64);
            return Some(Ok(RawEntry {
                name,
                attributes: self.data.dwFileAttributes,
                len,
                modified: filetime_to_systemtime(self.data.ftLastWriteTime),
                allocated: None,
                ids: FileIds::Unknown,
            }));
        }
    }
}

impl Drop for WinDirIter {
    fn drop(&mut self) {
        unsafe {
            let _ = FindClose(self.handle);
        }
    }
}

// ── Change 8: FileId-batched directory enumeration ──────────────────────
//
// `GetFileInformationByHandleEx(FileIdBothDirectoryInfo)` returns, per entry
// and batched in one buffer: name, attributes, sizes, mtime, AllocationSize
// and the 64-bit FileId. That removes the per-file `CreateFileW` that Fast
// mode paid purely for hardlink dedup, and the identity handle +
// `GetCompressedFileSizeW` that Accurate mode paid per file. Filesystems
// that don't support the info class fall back to `WinDirIter` per directory.

/// Buffer size for one `FileIdBothDirectoryInfo` batch.
const DIR_ENUM_BUF_LEN: usize = 64 * 1024;

// `FILE_ID_BOTH_DIR_INFO` field offsets (natural layout; asserted against
// the real struct in the tests below).
const IDBOTH_NEXT_OFFSET: usize = 0;
const IDBOTH_LAST_WRITE: usize = 24;
const IDBOTH_END_OF_FILE: usize = 40;
const IDBOTH_ALLOCATION: usize = 48;
const IDBOTH_ATTRIBUTES: usize = 56;
const IDBOTH_NAME_LEN: usize = 60;
const IDBOTH_FILE_ID: usize = 96;
const IDBOTH_NAME: usize = 104;

/// Parses one `FileIdBothDirectoryInfo` batch buffer into raw entries,
/// skipping `.`/`..`. Pure byte parsing — no Win32 — so it unit-tests
/// anywhere. Malformed records are skipped defensively; the chain ends at
/// `NextEntryOffset == 0` or the buffer edge.
fn parse_id_both_dir_buffer(buf: &[u8], vol_serial: Option<u64>, out: &mut Vec<RawEntry>) {
    let mut base = 0usize;
    loop {
        if base + IDBOTH_NAME > buf.len() {
            return;
        }
        let u32_at =
            |at: usize| u32::from_le_bytes(buf[base + at..base + at + 4].try_into().unwrap());
        let u64_at =
            |at: usize| u64::from_le_bytes(buf[base + at..base + at + 8].try_into().unwrap());

        let next = u32_at(IDBOTH_NEXT_OFFSET) as usize;
        let name_len = u32_at(IDBOTH_NAME_LEN) as usize;
        let name_end = base + IDBOTH_NAME + name_len;
        if name_len.is_multiple_of(2) && name_end <= buf.len() {
            let wide: Vec<u16> = buf[base + IDBOTH_NAME..name_end]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let name = String::from_utf16_lossy(&wide);
            if name != "." && name != ".." {
                let file_id = u64_at(IDBOTH_FILE_ID);
                let ids = match (vol_serial, file_id) {
                    (Some(vol), id) if id != 0 => FileIds::Known(vol, id),
                    (Some(_), _) => FileIds::NoneOnVolume,
                    (None, _) => FileIds::Unknown,
                };
                out.push(RawEntry {
                    name,
                    attributes: u32_at(IDBOTH_ATTRIBUTES),
                    len: u64_at(IDBOTH_END_OF_FILE),
                    modified: ticks_to_systemtime(u64_at(IDBOTH_LAST_WRITE)),
                    allocated: Some(u64_at(IDBOTH_ALLOCATION)),
                    ids,
                });
            }
        }
        if next == 0 {
            return;
        }
        base += next;
    }
}

/// Directory iterator over `FileIdBothDirectoryInfo` batches (Change 8).
struct DirHandleIter {
    handle: HANDLE,
    vol_serial: Option<u64>,
    buf: Vec<u8>,
    batch: std::vec::IntoIter<RawEntry>,
    done: bool,
}

impl DirHandleIter {
    /// Opens the directory and probes the first batch. `None` means the
    /// caller should fall back to [`WinDirIter`] (open failed, or the
    /// filesystem doesn't support the info class).
    fn new(dir: &Path) -> Option<Self> {
        let handle = open_path_handle(dir, FILE_LIST_DIRECTORY.0, FILE_FLAG_BACKUP_SEMANTICS)?;
        let mut iter = Self {
            handle,
            vol_serial: read_identity(handle).map(|(vol, _)| vol),
            buf: vec![0u8; DIR_ENUM_BUF_LEN],
            batch: Vec::new().into_iter(),
            done: false,
        };
        match iter.fill() {
            Ok(_) => Some(iter),
            Err(_) => None,
        }
    }

    /// Fetches and parses the next batch. `Ok(false)` = enumeration done.
    fn fill(&mut self) -> Result<bool> {
        if self.done {
            return Ok(false);
        }
        match unsafe {
            GetFileInformationByHandleEx(
                self.handle,
                FileIdBothDirectoryInfo,
                self.buf.as_mut_ptr() as *mut c_void,
                self.buf.len() as u32,
            )
        } {
            Ok(()) => {
                let mut entries = Vec::new();
                parse_id_both_dir_buffer(&self.buf, self.vol_serial, &mut entries);
                self.batch = entries.into_iter();
                Ok(true)
            }
            Err(err) if err.code() == hresult_from_win32(ERROR_NO_MORE_FILES.0) => {
                self.done = true;
                Ok(false)
            }
            Err(err) => Err(anyhow!("FileIdBothDirectoryInfo query failed: {}", err)),
        }
    }
}

impl Iterator for DirHandleIter {
    type Item = Result<RawEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(entry) = self.batch.next() {
                return Some(Ok(entry));
            }
            match self.fill() {
                Ok(true) => continue,
                Ok(false) => return None,
                Err(err) => {
                    self.done = true;
                    return Some(Err(err));
                }
            }
        }
    }
}

impl Drop for DirHandleIter {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

/// Per-directory enumeration source: handle-batched where supported,
/// find-based everywhere else. The find variant is boxed because
/// `WIN32_FIND_DATAW` is ~600 bytes.
enum DirIter {
    Handle(DirHandleIter),
    Find(Box<WinDirIter>),
}

impl DirIter {
    fn new(dir: &Path) -> Result<Self> {
        if let Some(iter) = DirHandleIter::new(dir) {
            return Ok(Self::Handle(iter));
        }
        Ok(Self::Find(Box::new(WinDirIter::new(dir)?)))
    }
}

impl Iterator for DirIter {
    type Item = Result<RawEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Handle(iter) => iter.next(),
            Self::Find(iter) => iter.next(),
        }
    }
}

fn wide_name(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

fn filetime_to_systemtime(ft: FILETIME) -> Option<SystemTime> {
    ticks_to_systemtime(((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64))
}

/// Converts 100ns ticks since 1601-01-01 into a `SystemTime`.
fn ticks_to_systemtime(ticks: u64) -> Option<SystemTime> {
    if ticks == 0 {
        return None;
    }
    // 100ns ticks since 1601-01-01; offset to the Unix epoch.
    const EPOCH_DIFF_SECS: u64 = 11_644_473_600;
    let secs_since_1601 = ticks / 10_000_000;
    if secs_since_1601 < EPOCH_DIFF_SECS {
        return None;
    }
    let nanos = ((ticks % 10_000_000) * 100) as u32;
    Some(UNIX_EPOCH + Duration::new(secs_since_1601 - EPOCH_DIFF_SECS, nanos))
}

/// Outcome of classifying one raw directory entry.
enum Classified {
    Dir(ChildJob),
    File(PendingFile),
    /// A finished entry (error/skip) to surface in the report as-is.
    Pre(EntryReport),
}

/// Replicates the original Phase-1 classification: reparse points obey the
/// `--follow-symlinks` policy (skip or resolve the target), directories become
/// jobs, everything else becomes a deferred file.
fn classify(raw: RawEntry, parent: &Path, context: &ScanContext) -> Classified {
    let path = parent.join(&raw.name);
    let is_symlink = (raw.attributes & FILE_ATTRIBUTE_REPARSE_POINT.0) != 0;

    let (len, modified, is_dir, allocated, ids) = if is_symlink {
        if !context.options().follow_symlinks {
            context.record_skipped();
            if context.has_progress() {
                context.emit(ProgressEvent::Skipped(
                    path.clone(),
                    String::from("symlink not followed (use --follow-symlinks)"),
                ));
            }
            return Classified::Pre(entry_with_skip(
                raw.name,
                path,
                EntryKind::Skipped,
                "symlink not followed (use --follow-symlinks)",
            ));
        }
        match fs::metadata(&path) {
            // Metadata describes the symlink target, so the batched
            // allocation/identity of the link entry don't apply.
            Ok(meta) => (
                meta.len(),
                meta.modified().ok(),
                meta.is_dir(),
                None,
                FileIds::Unknown,
            ),
            Err(err) => {
                context.record_error(classify_io_error(&err));
                if context.has_progress() {
                    context.emit(ProgressEvent::EntryError {
                        path: path.clone(),
                        message: format!("symlink target metadata failed: {}", err),
                    });
                }
                return Classified::Pre(entry_with_error(
                    raw.name,
                    path,
                    EntryKind::Other,
                    format!("symlink target metadata failed: {}", err),
                ));
            }
        }
    } else {
        let is_dir = (raw.attributes & FILE_ATTRIBUTE_DIRECTORY.0) != 0;
        (raw.len, raw.modified, is_dir, raw.allocated, raw.ids)
    };

    if is_dir {
        return Classified::Dir(ChildJob {
            name: raw.name,
            path,
            was_symlink: is_symlink,
        });
    }

    Classified::File(PendingFile {
        name: raw.name,
        path,
        info: EntryInfo {
            len,
            modified,
            allocated,
            ids,
        },
    })
}

/// Lightweight pre-classified file info collected during classification.
/// The expensive work (allocation, ADS, dedup) is deferred to Phase 2.
struct PendingFile {
    name: String,
    path: PathBuf,
    info: EntryInfo,
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
        if let Some(add) = result.alloc_add
            && let Some(total) = file_allocated.as_mut()
        {
            *total += add;
        }
        if let Some(entry) = result.entry {
            entries.push(entry);
        }
    }

    Ok((
        file_logical,
        file_allocated,
        file_allocated_complete,
        entries,
    ))
}

/// Processes a single file: computes sizes, checks hard-link dedup, and
/// optionally builds an [`EntryReport`] for display.
fn process_single_file(file: &PendingFile, context: &ScanContext) -> Result<FileResult> {
    check_cancelled(context)?;

    let (logical, allocated, allocated_complete, handle_ids, ads) =
        file_metrics(&file.path, &file.info, context)?;

    // Change 8: prefer the identity that came batched with the directory
    // enumeration — no per-file syscalls. Fall back to the per-file
    // identity paths (Change 2) only for find-based entries.
    let (is_first_logical, is_first_alloc) = match file.info.ids {
        FileIds::Known(vol, id) => context.mark_file_unique_by_id(Some((vol, id)), &file.path),
        FileIds::NoneOnVolume => (true, true),
        FileIds::Unknown => {
            if context.options().mode == ScanMode::Accurate {
                context.mark_file_unique_by_id(handle_ids, &file.path)
            } else {
                context.mark_file_unique(&file.path)
            }
        }
    };

    let accounted_logical = if is_first_logical { logical } else { 0 };

    // Mirror the original accounting: non-first alloc instances contribute 0
    // so the total stays correct while the entry is still displayable.
    let alloc_add = allocated.map(|a| if is_first_alloc { a } else { 0 });

    let is_hardlink_duplicate = !is_first_logical || !is_first_alloc;

    let entry = if context.options().show_files {
        let (ads_bytes, ads_count) = if context.options().mode == ScanMode::Accurate {
            (ads.total_bytes, ads.count)
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
            modified: file.info.modified,
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
        if context.has_progress() {
            context.emit(ProgressEvent::Skipped(
                job.path.clone(),
                String::from("cycle detected"),
            ));
        }
        return Ok(entry_with_skip(
            job.name,
            job.path,
            EntryKind::SymlinkDirectory,
            "skipped (already visited target)",
        ));
    }

    check_cancelled(context)?;

    // Directory-level cache: check before starting a full subtree walk. Only
    // applied here (not in scan_directory_inner) so that direct scan_directory
    // callers (tests, CLI) always get fully-populated entries.
    let dir_mtime = fs::metadata(&job.path).ok().and_then(|m| m.modified().ok());
    if let Some(cached) = context
        .dir_cache()
        .get(&job.path, dir_mtime, context.options().mode)
    {
        if context.has_progress() {
            context.emit(ProgressEvent::CacheHit(job.path.clone()));
        }
        return Ok(EntryReport {
            name: job.name,
            path: job.path,
            kind: if job.was_symlink {
                EntryKind::SymlinkDirectory
            } else {
                EntryKind::Directory
            },
            logical_size: cached.logical_size,
            allocated_size: cached.allocated_size,
            allocated_complete: cached.allocated_complete,
            percent_of_parent: 0.0,
            ads_bytes: 0,
            ads_count: 0,
            error: None,
            skip_reason: None,
            modified: dir_mtime,
        });
    }

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
            if context.has_progress() {
                context.emit(ProgressEvent::EntryError {
                    path: job.path.clone(),
                    message: format!("directory scan failed: {}", err),
                });
            }
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

// ── Change 2: one handle per file in Accurate mode ──────────────────────

/// RAII wrapper closing a `CreateFileW` handle on drop.
struct FileHandleGuard(HANDLE);

impl Drop for FileHandleGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// Opens a query-only handle (0 access rights, so locked/system files still
/// open) with reparse semantics, matching `context::file_identity`.
fn open_query_handle(path: &Path) -> Option<HANDLE> {
    open_path_handle(
        path,
        0,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
    )
}

/// Opens a handle with the given access rights and flags.
fn open_path_handle(path: &Path, access: u32, flags: FILE_FLAGS_AND_ATTRIBUTES) -> Option<HANDLE> {
    // CreateFileW handles absolute paths fine; only paths beyond MAX_PATH
    // need the \\?\ prefix.
    let needs_long_prefix =
        path.as_os_str().len() > 248 && !path.to_string_lossy().starts_with("\\\\?\\");
    let wide: Vec<u16> = if needs_long_prefix {
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

    unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            flags,
            HANDLE(0),
        )
        .ok()
    }
}

/// Reads `(dwVolumeSerialNumber, 64-bit file index)` from an open handle.
fn read_identity(handle: HANDLE) -> Option<(u64, u64)> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(handle, &mut info) }.is_ok() {
        let idx = ((info.nFileIndexHigh as u64) << 32) | (info.nFileIndexLow as u64);
        Some((info.dwVolumeSerialNumber as u64, idx))
    } else {
        None
    }
}

/// Result of [`file_metrics`]: logical size, allocation size (if computed),
/// whether allocation is complete, hard-link identity, and ADS summary.
type FileMetrics = (u64, Option<u64>, bool, Option<(u64, u64)>, AdsSummary);

/// Computes logical size, allocation size, hard-link identity and ADS for a
/// file. In Accurate mode this opens **one** handle and reuses it for the
/// identity read, ADS enumeration and (on `GetCompressedFileSizeW` failure)
/// the allocation-size fallback — Change 2 + Change 5.
fn file_metrics(path: &Path, info: &EntryInfo, context: &ScanContext) -> Result<FileMetrics> {
    check_cancelled(context)?;

    if context.options().mode == ScanMode::Fast {
        return Ok((info.len, None, false, None, AdsSummary::default()));
    }

    // Accurate mode.
    check_cancelled(context)?;
    let mtime = info.modified;
    let mut logical = info.len;

    // Forced-failure tests exercise the fallback allocation lookup, which
    // the batched path would bypass entirely.
    #[cfg(test)]
    let batched_alloc = if FORCE_ALLOCATED_SIZE_FAILURE.load(std::sync::atomic::Ordering::Relaxed) {
        None
    } else {
        info.allocated
    };
    #[cfg(not(test))]
    let batched_alloc = info.allocated;

    // Handle-enumeration path (Change 8): allocation size and identity came
    // batched with the directory listing, so the only per-file work left is
    // ADS enumeration. The attribute cache is skipped — a hit couldn't save
    // anything (ADS is always queried fresh).
    if let Some(alloc) = batched_alloc {
        let handle = open_query_handle(path);
        let _guard = handle.map(FileHandleGuard);
        let ids = match info.ids {
            FileIds::Known(vol, id) => Some((vol, id)),
            FileIds::NoneOnVolume => None,
            FileIds::Unknown => handle.and_then(read_identity),
        };
        check_cancelled(context)?;
        let ads = collect_ads_with_fallback(path, handle, context);
        logical += ads.total_bytes;
        return Ok((logical, Some(alloc), true, ids, ads));
    }

    // Find-based fallback path. Check cache before opening any handles — a
    // hit skips CreateFileW, read_identity, and GetCompressedFileSizeW. ADS
    // is always queried fresh because NTFS does not update LastWriteTime
    // when streams change.
    if let Some((cached_alloc, cached_ids)) = context.cache().get_attributes(path, info.len, mtime)
    {
        let ads = collect_ads(path).unwrap_or_default();
        logical += ads.total_bytes;
        return Ok((logical, Some(cached_alloc), true, cached_ids, ads));
    }

    let handle = open_query_handle(path);
    let _guard = handle.map(FileHandleGuard);
    let ids = handle.and_then(read_identity);

    check_cancelled(context)?;
    let ads = collect_ads_with_fallback(path, handle, context);
    logical += ads.total_bytes;

    check_cancelled(context)?;
    let mut allocated_complete = true;
    let alloc_size = match get_allocated_size_fast(path, handle) {
        Ok(size) => size,
        Err(err) => {
            let kind = classify_anyhow_error(&err);
            context.record_error(kind);
            if context.has_progress() {
                context.emit(ProgressEvent::EntryError {
                    path: path.to_path_buf(),
                    message: format!("allocation size failed: {}", err),
                });
            }
            allocated_complete = false;
            0
        }
    };

    // Avoid caching a synthetic zero when allocation lookup fails.
    if allocated_complete {
        context
            .cache()
            .insert_attributes(path.to_path_buf(), mtime, info.len, alloc_size, ids);
    }

    Ok((logical, Some(alloc_size), allocated_complete, ids, ads))
}

fn get_allocated_size_fast(path: &Path, handle: Option<HANDLE>) -> Result<u64> {
    #[cfg(test)]
    if FORCE_ALLOCATED_SIZE_FAILURE.load(std::sync::atomic::Ordering::Relaxed) {
        return Err(anyhow!(
            "forced allocation lookup failure for {}",
            path.display()
        ));
    }

    let (low, high) = with_wide_path(path, |p| unsafe {
        let mut high: u32 = 0;
        let low = GetCompressedFileSizeW(PCWSTR(p), Some(&mut high as *mut u32));
        (low, high)
    });

    if low == u32::MAX {
        use windows::Win32::Foundation::GetLastError;
        let err = unsafe { GetLastError() };
        if err.is_err() {
            // Reuse the already-open handle instead of opening a new one.
            return match handle {
                Some(h) => get_allocated_size_via_handle(h),
                None => get_allocated_size(path),
            };
        }
    }
    Ok(((high as u64) << 32) | (low as u64))
}

fn get_allocated_size_via_handle(handle: HANDLE) -> Result<u64> {
    let mut info: FILE_STANDARD_INFO = unsafe { std::mem::zeroed() };
    unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileStandardInfo,
            &mut info as *mut _ as *mut c_void,
            std::mem::size_of::<FILE_STANDARD_INFO>() as u32,
        )?;
    }
    Ok(info.AllocationSize as u64)
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

/// Last-resort allocation size: opens its own handle. Only reached when no
/// shared handle was available and `GetCompressedFileSizeW` failed.
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

/// Enumerates alternate data streams through an already-open handle using
/// `NtQueryInformationFile(FileStreamInformation)` (Change 5).
fn collect_ads_via_handle(handle: HANDLE) -> Result<AdsSummary> {
    let mut buf: Vec<u8> = vec![0u8; 4096];

    loop {
        let mut iosb = IoStatusBlock {
            status: 0,
            information: 0,
        };
        let status = unsafe {
            NtQueryInformationFile(
                handle,
                &mut iosb,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                FILE_STREAM_INFORMATION,
            )
        };
        if status == 0 {
            break;
        }
        let code = status as u32;
        if code == STATUS_BUFFER_OVERFLOW
            || code == STATUS_BUFFER_TOO_SMALL
            || code == STATUS_INFO_LENGTH_MISMATCH
        {
            if buf.len() >= 1 << 20 {
                return Err(anyhow!("stream info exceeded 1 MiB"));
            }
            let new_len = buf.len() * 2;
            buf.resize(new_len, 0);
            continue;
        }
        return Err(anyhow!(
            "NtQueryInformationFile(FileStreamInformation) failed: {:#010x}",
            code
        ));
    }

    let mut summary = AdsSummary::default();
    let mut offset = 0usize;
    loop {
        if offset + FILE_STREAM_INFO_HEADER > buf.len() {
            break;
        }
        let base = offset;
        let next = u32::from_le_bytes(buf[base..base + 4].try_into().unwrap()) as usize;
        let name_len = u32::from_le_bytes(buf[base + 4..base + 8].try_into().unwrap()) as usize;
        let stream_size = i64::from_le_bytes(buf[base + 8..base + 16].try_into().unwrap());
        let name_start = base + FILE_STREAM_INFO_HEADER;

        if name_start + name_len <= buf.len() {
            let wide: Vec<u16> = buf[name_start..name_start + name_len]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let name = String::from_utf16_lossy(&wide);
            if name != "::$DATA" && stream_size > 0 {
                summary.total_bytes += stream_size as u64;
                summary.count += 1;
            }
        }

        if next == 0 {
            break;
        }
        offset += next;
        if offset <= base {
            break;
        }
    }

    Ok(summary)
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

/// Runs ADS enumeration, preferring the handle-based NT query and falling
/// back to path-based `FindFirstStreamW`. Failures are recorded as
/// `ADSFailed` and degrade to an empty summary, matching prior behavior.
fn collect_ads_with_fallback(
    path: &Path,
    handle: Option<HANDLE>,
    context: &ScanContext,
) -> AdsSummary {
    let res = match handle {
        Some(h) => collect_ads_via_handle(h).or_else(|_| collect_ads(path)),
        None => collect_ads(path),
    };
    match res {
        Ok(ads) => ads,
        Err(err) => {
            context.record_error(ScanErrorKind::ADSFailed);
            if context.has_progress() {
                context.emit(ProgressEvent::EntryError {
                    path: path.to_path_buf(),
                    message: format!("ADS enumeration failed: {}", err),
                });
            }
            AdsSummary::default()
        }
    }
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

    /// Builds one `FILE_ID_BOTH_DIR_INFO` record with the given name.
    fn make_id_both_record(
        name: &str,
        next_offset: u32,
        len: u64,
        alloc: u64,
        attrs: u32,
        file_id: u64,
        mtime_ticks: u64,
    ) -> Vec<u8> {
        let wide: Vec<u16> = name.encode_utf16().collect();
        let name_bytes: Vec<u8> = wide.iter().flat_map(|w| w.to_le_bytes()).collect();
        let mut rec = vec![0u8; IDBOTH_NAME + name_bytes.len()];
        rec[IDBOTH_NEXT_OFFSET..IDBOTH_NEXT_OFFSET + 4].copy_from_slice(&next_offset.to_le_bytes());
        rec[IDBOTH_LAST_WRITE..IDBOTH_LAST_WRITE + 8].copy_from_slice(&mtime_ticks.to_le_bytes());
        rec[IDBOTH_END_OF_FILE..IDBOTH_END_OF_FILE + 8].copy_from_slice(&len.to_le_bytes());
        rec[IDBOTH_ALLOCATION..IDBOTH_ALLOCATION + 8].copy_from_slice(&alloc.to_le_bytes());
        rec[IDBOTH_ATTRIBUTES..IDBOTH_ATTRIBUTES + 4].copy_from_slice(&attrs.to_le_bytes());
        rec[IDBOTH_NAME_LEN..IDBOTH_NAME_LEN + 4]
            .copy_from_slice(&(name_bytes.len() as u32).to_le_bytes());
        rec[IDBOTH_FILE_ID..IDBOTH_FILE_ID + 8].copy_from_slice(&file_id.to_le_bytes());
        rec[IDBOTH_NAME..IDBOTH_NAME + name_bytes.len()].copy_from_slice(&name_bytes);
        rec
    }

    #[test]
    fn handle_iter_engages_on_ntfs_and_fills_ids() {
        let root = tempdir().expect("failed to create temp directory");
        fs::write(root.path().join("a.bin"), b"data").expect("write failed");
        fs::create_dir(root.path().join("sub")).expect("mkdir failed");

        let iter = DirIter::new(root.path()).expect("DirIter must open");
        assert!(
            matches!(iter, DirIter::Handle(_)),
            "NTFS temp dir must use the handle-batched iterator, not the find fallback"
        );

        let entries: Vec<RawEntry> = iter.map(|e| e.expect("entry must parse")).collect();
        assert_eq!(entries.len(), 2);
        let file = entries
            .iter()
            .find(|e| e.name == "a.bin")
            .expect("file entry present");
        assert_eq!(file.len, 4);
        assert!(file.allocated.is_some(), "batched allocation expected");
        assert!(
            matches!(file.ids, FileIds::Known(_, _)),
            "batched file id expected, got {:?}",
            file.ids
        );
    }

    #[test]
    fn id_both_offsets_match_win32_struct() {
        use std::mem::offset_of;
        use windows::Win32::Storage::FileSystem::FILE_ID_BOTH_DIR_INFO;

        assert_eq!(
            offset_of!(FILE_ID_BOTH_DIR_INFO, NextEntryOffset),
            IDBOTH_NEXT_OFFSET
        );
        assert_eq!(
            offset_of!(FILE_ID_BOTH_DIR_INFO, LastWriteTime),
            IDBOTH_LAST_WRITE
        );
        assert_eq!(
            offset_of!(FILE_ID_BOTH_DIR_INFO, EndOfFile),
            IDBOTH_END_OF_FILE
        );
        assert_eq!(
            offset_of!(FILE_ID_BOTH_DIR_INFO, AllocationSize),
            IDBOTH_ALLOCATION
        );
        assert_eq!(
            offset_of!(FILE_ID_BOTH_DIR_INFO, FileAttributes),
            IDBOTH_ATTRIBUTES
        );
        assert_eq!(
            offset_of!(FILE_ID_BOTH_DIR_INFO, FileNameLength),
            IDBOTH_NAME_LEN
        );
        assert_eq!(offset_of!(FILE_ID_BOTH_DIR_INFO, FileId), IDBOTH_FILE_ID);
        assert_eq!(offset_of!(FILE_ID_BOTH_DIR_INFO, FileName), IDBOTH_NAME);
    }

    #[test]
    fn parse_id_both_skips_dots_and_reads_fields() {
        // 2000-01-01 in 100ns ticks since 1601: (11644473600 + 946684800) * 1e7
        let ticks = 12_591_158_400u64 * 10_000_000;
        let dot = make_id_both_record(".", 0, 0, 0, 0x10, 5, ticks);
        let dotdot = make_id_both_record("..", 0, 0, 0, 0x10, 6, ticks);
        let file = make_id_both_record("file.txt", 0, 1234, 4096, 0x80, 77, ticks);

        let mut buf = Vec::new();
        let records = [dot, dotdot, file];
        let last = records.len() - 1;
        for (i, mut rec) in records.into_iter().enumerate() {
            // Chain: point each record at the next (8-aligned like the kernel).
            let padded = rec.len().div_ceil(8) * 8;
            rec.resize(padded, 0);
            let next = if i == last { 0u32 } else { padded as u32 };
            rec[0..4].copy_from_slice(&next.to_le_bytes());
            buf.extend_from_slice(&rec);
        }

        let mut out = Vec::new();
        parse_id_both_dir_buffer(&buf, Some(42), &mut out);

        assert_eq!(out.len(), 1, "dot entries must be skipped");
        let entry = &out[0];
        assert_eq!(entry.name, "file.txt");
        assert_eq!(entry.len, 1234);
        assert_eq!(entry.allocated, Some(4096));
        assert_eq!(entry.attributes, 0x80);
        assert_eq!(entry.ids, FileIds::Known(42, 77));
        assert!(entry.modified.is_some());
    }

    #[test]
    fn parse_id_both_id_zero_and_no_volume() {
        let rec = make_id_both_record("a.bin", 0, 1, 1, 0x80, 0, 0);
        let mut out = Vec::new();
        parse_id_both_dir_buffer(&rec, Some(42), &mut out);
        assert_eq!(out[0].ids, FileIds::NoneOnVolume);
        assert_eq!(out[0].modified, None);

        let mut out = Vec::new();
        parse_id_both_dir_buffer(&rec, None, &mut out);
        assert_eq!(out[0].ids, FileIds::Unknown);
    }

    #[test]
    fn parse_id_both_handles_truncated_and_empty_buffers() {
        let mut out = Vec::new();
        parse_id_both_dir_buffer(&[], None, &mut out);
        assert!(out.is_empty());

        // Header only, no room for the name: skipped without panicking.
        let rec = make_id_both_record("longname.dat", 0, 1, 1, 0x80, 9, 0);
        parse_id_both_dir_buffer(&rec[..IDBOTH_NAME + 2], None, &mut out);
        assert!(out.is_empty());
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
