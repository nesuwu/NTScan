use std::ffi::{CStr, CString, c_char};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::engine;
use crate::model::{EntryKind, ScanMode, ScanOptions};

#[derive(Serialize)]
struct FfiEnvelope<T>
where
    T: Serialize,
{
    ok: bool,
    data: Option<T>,
    error: Option<String>,
}

#[derive(Serialize)]
struct FfiDirectoryReport {
    path: String,
    modified_unix_secs: Option<i64>,
    logical_size: u64,
    allocated_size: Option<u64>,
    entries: Vec<FfiEntryReport>,
}

#[derive(Serialize)]
struct FfiEntryReport {
    name: String,
    path: String,
    kind: String,
    logical_size: u64,
    allocated_size: Option<u64>,
    percent_of_parent: f64,
    ads_bytes: u64,
    ads_count: usize,
    error: Option<String>,
    skip_reason: Option<String>,
    modified_unix_secs: Option<i64>,
}

#[derive(Serialize)]
struct FfiDuplicateResult {
    total_files_scanned: u64,
    total_reclaimable: u64,
    groups: Vec<FfiDuplicateGroup>,
}

#[derive(Serialize)]
struct FfiDuplicateGroup {
    hash_hex: String,
    size: u64,
    reclaimable_bytes: u64,
    paths: Vec<String>,
}

#[unsafe(no_mangle)]
pub extern "C" fn ntscan_scan_directory_json(
    path: *const c_char,
    mode: u32,
    follow_symlinks: bool,
    show_files: bool,
    cache_path: *const c_char,
) -> *mut c_char {
    let response = (|| -> Result<FfiDirectoryReport, String> {
        let target = required_path(path)?;
        let cache_path = optional_path(cache_path)?;
        let options = ScanOptions {
            mode: scan_mode_from_u32(mode),
            follow_symlinks,
            show_files,
        };

        let report =
            engine::run_scan(&target, options, cache_path, None).map_err(|err| err.to_string())?;

        Ok(FfiDirectoryReport {
            path: report.path.to_string_lossy().into_owned(),
            modified_unix_secs: unix_seconds(report.mtime),
            logical_size: report.logical_size,
            allocated_size: report.allocated_size,
            entries: report
                .entries
                .into_iter()
                .map(|entry| FfiEntryReport {
                    name: entry.name,
                    path: entry.path.to_string_lossy().into_owned(),
                    kind: entry_kind_name(entry.kind).to_string(),
                    logical_size: entry.logical_size,
                    allocated_size: entry.allocated_size,
                    percent_of_parent: entry.percent_of_parent,
                    ads_bytes: entry.ads_bytes,
                    ads_count: entry.ads_count,
                    error: entry.error,
                    skip_reason: entry.skip_reason,
                    modified_unix_secs: unix_seconds(entry.modified),
                })
                .collect(),
        })
    })();

    envelope_to_c_string(response)
}

#[unsafe(no_mangle)]
pub extern "C" fn ntscan_find_duplicates_json(
    path: *const c_char,
    min_size: u64,
    hash_cache_path: *const c_char,
) -> *mut c_char {
    let response = (|| -> Result<FfiDuplicateResult, String> {
        let target = required_path(path)?;
        let cache_path = optional_path(hash_cache_path)?;
        let result =
            engine::run_duplicates(&target, min_size, cache_path).map_err(|err| err.to_string())?;

        let groups = result
            .groups
            .into_iter()
            .map(|group| {
                let hash_hex: String = group.hash.iter().map(|b| format!("{:02x}", b)).collect();
                FfiDuplicateGroup {
                    hash_hex,
                    size: group.size,
                    reclaimable_bytes: group.reclaimable_bytes(),
                    paths: group
                        .paths
                        .into_iter()
                        .map(|p| p.to_string_lossy().into_owned())
                        .collect(),
                }
            })
            .collect();

        Ok(FfiDuplicateResult {
            total_files_scanned: result.total_files_scanned,
            total_reclaimable: result.total_reclaimable,
            groups,
        })
    })();

    envelope_to_c_string(response)
}

#[unsafe(no_mangle)]
/// # Safety
/// `ptr` must be a pointer previously returned by one of this library's
/// `*_json` exports and not already freed.
pub unsafe extern "C" fn ntscan_free_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(ptr);
    }
}

fn envelope_to_c_string<T>(response: Result<T, String>) -> *mut c_char
where
    T: Serialize,
{
    let envelope = match response {
        Ok(data) => FfiEnvelope {
            ok: true,
            data: Some(data),
            error: None,
        },
        Err(error) => FfiEnvelope::<T> {
            ok: false,
            data: None,
            error: Some(error),
        },
    };

    match serde_json::to_string(&envelope) {
        Ok(json) => into_c_string(json),
        Err(err) => {
            let fallback = format!(
                "{{\"ok\":false,\"data\":null,\"error\":\"serialization failed: {}\"}}",
                err
            );
            into_c_string(fallback)
        }
    }
}

fn into_c_string(value: String) -> *mut c_char {
    match CString::new(value) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => CString::new("{\"ok\":false,\"data\":null,\"error\":\"invalid string payload\"}")
            .expect("fallback JSON is valid")
            .into_raw(),
    }
}

fn scan_mode_from_u32(mode: u32) -> ScanMode {
    if mode == 1 {
        ScanMode::Accurate
    } else {
        ScanMode::Fast
    }
}

fn required_path(ptr: *const c_char) -> Result<PathBuf, String> {
    let path = c_string_to_string(ptr)?;
    if path.is_empty() {
        return Err(String::from("path must not be empty"));
    }
    Ok(PathBuf::from(path))
}

fn optional_path(ptr: *const c_char) -> Result<Option<PathBuf>, String> {
    if ptr.is_null() {
        return Ok(None);
    }
    let value = c_string_to_string(ptr)?;
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(PathBuf::from(value)))
    }
}

fn c_string_to_string(ptr: *const c_char) -> Result<String, String> {
    if ptr.is_null() {
        return Err(String::from("received null C string"));
    }

    let raw = unsafe { CStr::from_ptr(ptr) };
    raw.to_str()
        .map(|s| s.to_string())
        .map_err(|_| String::from("path must be valid UTF-8"))
}

fn unix_seconds(time: Option<SystemTime>) -> Option<i64> {
    match time {
        Some(t) => match t.duration_since(UNIX_EPOCH) {
            Ok(duration) => Some(duration.as_secs() as i64),
            Err(err) => Some(-(err.duration().as_secs() as i64)),
        },
        None => None,
    }
}

fn entry_kind_name(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::Directory => "directory",
        EntryKind::SymlinkDirectory => "symlink_directory",
        EntryKind::File => "file",
        EntryKind::Other => "other",
        EntryKind::Skipped => "skipped",
    }
}
