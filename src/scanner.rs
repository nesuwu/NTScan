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
    FILE_STANDARD_INFO, FileStandardInfo, FindClose, FindFirstStreamW, FindNextStreamW,
    GetCompressedFileSizeW, GetFileInformationByHandleEx, STREAM_INFO_LEVELS,
    WIN32_FIND_STREAM_DATA,
};
use windows::core::{HRESULT, PCWSTR};

use crate::context::ScanContext;
use crate::model::{
    AdsSummary, ChildJob, DirectoryPlan, DirectoryReport, EntryKind, EntryReport, ProgressEvent,
    ScanErrorKind, ScanMode,
};

pub fn scan_directory(path: &Path, context: &ScanContext) -> Result<DirectoryReport> {
    context.emit(ProgressEvent::Started(path.to_path_buf()));

    let metadata = fs::metadata(path)
        .inspect_err(|err| {
            context.record_error(classify_io_error(err));
        })
        .with_context(|| format!("metadata access failed for {}", path.display()))?;
    let mtime = metadata.modified().ok();

    let plan = prepare_directory_plan(path, context)?;

    let DirectoryPlan {
        directories,
        mut precomputed_entries,
        file_logical,
        file_allocated,
    } = plan;

    let mut dir_entries: Vec<EntryReport> = directories
        .into_par_iter()
        .map(|job| process_directory_child(job, context))
        .collect();

    precomputed_entries.append(&mut dir_entries);
    let mut entries = precomputed_entries;

    let directories_logical: u64 = entries.iter().map(|entry| entry.logical_size).sum();
    let total_logical = file_logical + directories_logical;

    let mut total_allocated = match (context.options().mode, file_allocated) {
        (ScanMode::Accurate, value) => value,
        _ => None,
    };

    if let Some(total) = total_allocated.as_mut() {
        for entry in &entries {
            if let Some(alloc) = entry.allocated_size {
                *total += alloc;
            }
        }
    }

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
        entries,
    };

    context.emit(ProgressEvent::Completed {
        path: path.to_path_buf(),
        logical: report.logical_size,
        allocated: report.allocated_size,
    });

    Ok(report)
}

pub fn prepare_directory_plan(path: &Path, context: &ScanContext) -> Result<DirectoryPlan> {
    let mut directories = Vec::new();
    let mut precomputed_entries = Vec::new();
    let mut file_logical = 0u64;
    let mut file_allocated = match context.options().mode {
        ScanMode::Fast => None,
        ScanMode::Accurate => Some(0u64),
    };

    let read_dir = fs::read_dir(path)
        .inspect_err(|err| {
            context.record_error(classify_io_error(err));
        })
        .with_context(|| format!("failed to read directory {}", path.display()))?;

    for entry in read_dir {
        let entry = entry
            .inspect_err(|err| {
                context.record_error(classify_io_error(err));
            })
            .with_context(|| format!("failed to iterate {}", path.display()))?;
        let name = entry.file_name().to_string_lossy().to_string();
        let entry_path = entry.path();

        // OPTIMIZATION: Use entry.metadata() to avoid re-querying the OS.
        // This uses the data returned by FindNextFile (directory iteration) on Windows.
        let symlink_metadata = match entry.metadata() {
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

        let is_symlink = symlink_metadata.file_type().is_symlink();

        let target_metadata: Option<Metadata> = if is_symlink {
            if !context.options().follow_symlinks {
                context.emit(ProgressEvent::Skipped(
                    entry_path.clone(),
                    String::from("symlink not followed (use --follow-symlinks)"),
                ));
                context.record_error(ScanErrorKind::Other);
                precomputed_entries.push(entry_with_error(
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
            directories.push(ChildJob {
                name,
                path: entry_path,
                was_symlink: is_symlink,
            });
            continue;
        }

        if meta.is_file() {
            let (logical, allocated) = accumulate_file_sizes(&entry_path, &meta, context);
            file_logical += logical;
            if let Some(total) = file_allocated.as_mut()
                && let Some(add) = allocated
            {
                *total += add;
            }
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

    Ok(DirectoryPlan {
        directories,
        precomputed_entries,
        file_logical,
        file_allocated,
    })
}

pub fn process_directory_child(job: ChildJob, context: &ScanContext) -> EntryReport {
    if context.options().follow_symlinks
        && job.was_symlink
        && let Ok(canon) = fs::canonicalize(&job.path)
        && !context.mark_if_new(canon)
    {
        context.emit(ProgressEvent::Skipped(
            job.path.clone(),
            String::from("cycle detected"),
        ));
        context.record_error(ScanErrorKind::Other);
        return entry_with_error(
            job.name,
            job.path,
            EntryKind::SymlinkDirectory,
            "skipped (already visited target)",
        );
    }

    match scan_directory(&job.path, context) {
        Ok(report) => EntryReport {
            name: job.name,
            path: job.path,
            kind: if job.was_symlink {
                EntryKind::SymlinkDirectory
            } else {
                EntryKind::Directory
            },
            logical_size: report.logical_size,
            allocated_size: report.allocated_size,
            percent_of_parent: 0.0,
            ads_bytes: 0,
            ads_count: 0,
            error: None,
            modified: report.mtime,
        },
        Err(err) => {
            context.emit(ProgressEvent::EntryError {
                path: job.path.clone(),
                message: format!("directory scan failed: {}", err),
            });
            entry_with_error(
                job.name,
                job.path,
                EntryKind::Directory,
                format!("directory scan failed: {}", err),
            )
        }
    }
}

fn accumulate_file_sizes(
    path: &Path,
    meta: &Metadata,
    context: &ScanContext,
) -> (u64, Option<u64>) {
    let mut logical = meta.len();
    let mut allocated = None;

    if context.options().mode == ScanMode::Fast {
        return (logical, None);
    }

    if context.options().mode == ScanMode::Accurate {
        let mtime = meta.modified().ok();

        if let Some((cached_alloc, cached_ads_bytes, _)) =
            context.cache().get_attributes(path, logical, mtime)
        {
            logical += cached_ads_bytes;
            allocated = Some(cached_alloc);
            return (logical, allocated);
        }

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

        let alloc_size = match get_allocated_size_fast(path) {
            Ok(size) => size,
            Err(err) => {
                let kind = classify_anyhow_error(&err);
                context.record_error(kind);
                context.emit(ProgressEvent::EntryError {
                    path: path.to_path_buf(),
                    message: format!("allocation size failed: {}", err),
                });
                0
            }
        };
        allocated = Some(alloc_size);

        context.cache().insert_attributes(
            path.to_path_buf(),
            mtime,
            meta.len(),
            alloc_size,
            ads_summary.total_bytes,
            ads_summary.count,
        );
    }

    (logical, allocated)
}

fn get_allocated_size_fast(path: &Path) -> Result<u64> {
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
        percent_of_parent: 0.0,
        ads_bytes: 0,
        ads_count: 0,
        error: Some(message.into()),
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
