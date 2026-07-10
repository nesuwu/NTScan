# NTScan Library Documentation

This document covers NTScan as a reusable library, with emphasis on C# interop through the exported C ABI.

## Version and Scope

- Crate: `ntscan`
- Current crate version: `0.6.1`
- Primary library entry points:
  - Rust-native API in `src/engine.rs`
  - C ABI JSON API in `src/ffi.rs` (feature-gated by `ffi`)

## Build Outputs

`Cargo.toml` sets:

- `crate-type = ["rlib", "cdylib"]`

So you can build:

- Rust library (`rlib`) for Rust consumers
- Native dynamic library (`cdylib`) for P/Invoke (`ntscan.dll` on Windows)

### Build Rust library

```powershell
cargo build --release --lib
```

### Build C ABI (DLL) without TUI

```powershell
cargo build --release --lib --no-default-features --features ffi
```

Output (Windows):

- `target\release\ntscan.dll`

## Feature Flags

- `default = ["tui"]`
- `ffi = ["serde", "serde_json"]`
- `tui` and `ffi` are independent

For embedding in C# you typically want:

- `--no-default-features --features ffi`

## Rust API (Native)

UI-agnostic entry points live in `src/engine.rs`.

### `run_scan`

```rust
pub fn run_scan(
    target: &Path,
    options: ScanOptions,
    cache_path: Option<PathBuf>,
    progress: Option<Sender<ProgressEvent>>,
) -> anyhow::Result<DirectoryReport>
```

`ScanOptions`:

- `mode`: `ScanMode::Fast | ScanMode::Accurate`
- `follow_symlinks`: follow symlinks/junctions when `true`
- `show_files`: include per-file entries in `DirectoryReport.entries`

Behavior:

- Fast mode: metadata-focused, `allocated_size` is `None`
- Accurate mode: computes allocation size and ADS stats
- Scan cache is persisted automatically after successful run

### `run_scan_with_cancel`

Like `run_scan`, but caller provides `CancelFlag`.

### `run_duplicates`

```rust
pub fn run_duplicates(
    target: &Path,
    min_size: u64,
    hash_cache_path: Option<PathBuf>,
) -> anyhow::Result<DuplicateScanResult>
```

Behavior:

- Recursively collects files >= `min_size`
- Size-groups first, then SHA-256 hashes only candidate groups
- Uses persistent hash cache to avoid re-hashing unchanged files
- Returns groups sorted by reclaimable bytes (descending)

## C ABI (FFI) API

Available when compiled with `--features ffi`.

### Exported functions

```c
char* ntscan_scan_directory_json(
    const char* path,
    uint32_t mode,
    bool follow_symlinks,
    bool show_files,
    const char* cache_path
);

char* ntscan_find_duplicates_json(
    const char* path,
    uint64_t min_size,
    const char* hash_cache_path
);

void ntscan_free_string(char* ptr);
```

### Parameter semantics

- `path`: required, must be non-null, non-empty, UTF-8
- `mode`: `1 = Accurate`, any other value = `Fast`
- `follow_symlinks`: include symlink/junction targets
- `show_files`: include per-file entries in `entries`
- `cache_path`, `hash_cache_path`:
  - `null` => use default cache path logic
  - empty string => treated like `null`

### Return contract

Both API functions return a heap-allocated UTF-8 JSON string.
Always free it with `ntscan_free_string`.

Envelope format:

```json
{
  "ok": true,
  "data": { ... },
  "error": null
}
```

or

```json
{
  "ok": false,
  "data": null,
  "error": "..."
}
```

## JSON Schemas Returned by FFI

### Scan result: `ntscan_scan_directory_json`

`data` shape:

```json
{
  "path": "C:\\Data",
  "modified_unix_secs": 1739462131,
  "logical_size": 123456,
  "allocated_size": 131072,
  "allocated_complete": true,
  "entries": [
    {
      "name": "subdir",
      "path": "C:\\Data\\subdir",
      "kind": "directory",
      "logical_size": 100000,
      "allocated_size": 106496,
      "allocated_complete": true,
      "percent_of_parent": 81.0,
      "ads_bytes": 0,
      "ads_count": 0,
      "error": null,
      "skip_reason": null,
      "modified_unix_secs": 1739462000
    }
  ]
}
```

`kind` values:

- `directory`
- `symlink_directory`
- `file`
- `other`
- `skipped`

Notes:

- In `Fast` mode, `allocated_size` is generally `null`.
- `allocated_complete = false` means one or more allocation lookups failed.
- `show_files = false` suppresses normal file entries (directory/skip/error entries can still appear).

### Duplicate result: `ntscan_find_duplicates_json`

`data` shape:

```json
{
  "total_files_scanned": 1024,
  "total_reclaimable": 73400320,
  "groups": [
    {
      "hash_hex": "f3ab...",
      "size": 1048576,
      "reclaimable_bytes": 2097152,
      "paths": [
        "C:\\Data\\a.bin",
        "C:\\Data\\copy\\a.bin",
        "C:\\Data\\backup\\a.bin"
      ]
    }
  ]
}
```

## Default Cache Paths

If no cache path override is provided:

- Scan cache:
  - `NTSCAN_CACHE_PATH` env var (if set and non-empty), else
  - `%LOCALAPPDATA%\ntscan\cache`, else
  - `%TEMP%\ntscan.cache`
- Hash cache:
  - `NTSCAN_HASH_CACHE_PATH` env var (if set and non-empty), else
  - `%LOCALAPPDATA%\ntscan\hash_cache`, else
  - `%TEMP%\ntscan_hash.cache`

## C# Usage (Recommended)

### 1. P/Invoke declarations with UTF-8 marshalling

Use `LibraryImport` (NET 7+) so Rust receives UTF-8 paths.

```csharp
using System.Runtime.InteropServices;

internal static partial class NativeNtScan
{
    [LibraryImport("ntscan", EntryPoint = "ntscan_scan_directory_json", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial nint ScanDirectoryJson(
        string path,
        uint mode,
        [MarshalAs(UnmanagedType.I1)] bool followSymlinks,
        [MarshalAs(UnmanagedType.I1)] bool showFiles,
        string? cachePath);

    [LibraryImport("ntscan", EntryPoint = "ntscan_find_duplicates_json", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial nint FindDuplicatesJson(
        string path,
        ulong minSize,
        string? hashCachePath);

    [LibraryImport("ntscan", EntryPoint = "ntscan_free_string")]
    internal static partial void FreeString(nint ptr);
}
```

If you use `DllImport` instead, annotate string parameters with `UnmanagedType.LPUTF8Str`.

### 2. Envelope and DTO models

```csharp
using System.Text.Json.Serialization;

public sealed class FfiEnvelope<T>
{
    [JsonPropertyName("ok")] public bool Ok { get; set; }
    [JsonPropertyName("data")] public T? Data { get; set; }
    [JsonPropertyName("error")] public string? Error { get; set; }
}

public sealed class DirectoryReportDto
{
    [JsonPropertyName("path")] public string Path { get; set; } = "";
    [JsonPropertyName("modified_unix_secs")] public long? ModifiedUnixSecs { get; set; }
    [JsonPropertyName("logical_size")] public ulong LogicalSize { get; set; }
    [JsonPropertyName("allocated_size")] public ulong? AllocatedSize { get; set; }
    [JsonPropertyName("allocated_complete")] public bool AllocatedComplete { get; set; }
    [JsonPropertyName("entries")] public List<EntryReportDto> Entries { get; set; } = new();
}

public sealed class EntryReportDto
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("path")] public string Path { get; set; } = "";
    [JsonPropertyName("kind")] public string Kind { get; set; } = "";
    [JsonPropertyName("logical_size")] public ulong LogicalSize { get; set; }
    [JsonPropertyName("allocated_size")] public ulong? AllocatedSize { get; set; }
    [JsonPropertyName("allocated_complete")] public bool AllocatedComplete { get; set; }
    [JsonPropertyName("percent_of_parent")] public double PercentOfParent { get; set; }
    [JsonPropertyName("ads_bytes")] public ulong AdsBytes { get; set; }
    [JsonPropertyName("ads_count")] public int AdsCount { get; set; }
    [JsonPropertyName("error")] public string? Error { get; set; }
    [JsonPropertyName("skip_reason")] public string? SkipReason { get; set; }
    [JsonPropertyName("modified_unix_secs")] public long? ModifiedUnixSecs { get; set; }
}

public sealed class DuplicateScanResultDto
{
    [JsonPropertyName("total_files_scanned")] public ulong TotalFilesScanned { get; set; }
    [JsonPropertyName("total_reclaimable")] public ulong TotalReclaimable { get; set; }
    [JsonPropertyName("groups")] public List<DuplicateGroupDto> Groups { get; set; } = new();
}

public sealed class DuplicateGroupDto
{
    [JsonPropertyName("hash_hex")] public string HashHex { get; set; } = "";
    [JsonPropertyName("size")] public ulong Size { get; set; }
    [JsonPropertyName("reclaimable_bytes")] public ulong ReclaimableBytes { get; set; }
    [JsonPropertyName("paths")] public List<string> Paths { get; set; } = new();
}
```

### 3. Safe wrapper (always frees native memory)

```csharp
using System.Runtime.InteropServices;
using System.Text.Json;

public enum NtScanMode : uint
{
    Fast = 0,
    Accurate = 1
}

public static class NtScanClient
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = false
    };

    public static DirectoryReportDto ScanDirectory(
        string path,
        NtScanMode mode = NtScanMode.Fast,
        bool followSymlinks = false,
        bool showFiles = false,
        string? cachePath = null)
    {
        string json = TakeJson(() => NativeNtScan.ScanDirectoryJson(path, (uint)mode, followSymlinks, showFiles, cachePath));
        var envelope = JsonSerializer.Deserialize<FfiEnvelope<DirectoryReportDto>>(json, JsonOptions)
            ?? throw new InvalidOperationException("Failed to deserialize scan response");

        if (!envelope.Ok)
            throw new InvalidOperationException(envelope.Error ?? "NTScan scan failed");

        return envelope.Data ?? throw new InvalidOperationException("Scan response did not include data");
    }

    public static DuplicateScanResultDto FindDuplicates(
        string path,
        ulong minSize,
        string? hashCachePath = null)
    {
        string json = TakeJson(() => NativeNtScan.FindDuplicatesJson(path, minSize, hashCachePath));
        var envelope = JsonSerializer.Deserialize<FfiEnvelope<DuplicateScanResultDto>>(json, JsonOptions)
            ?? throw new InvalidOperationException("Failed to deserialize duplicate response");

        if (!envelope.Ok)
            throw new InvalidOperationException(envelope.Error ?? "NTScan duplicate scan failed");

        return envelope.Data ?? throw new InvalidOperationException("Duplicate response did not include data");
    }

    private static string TakeJson(Func<nint> call)
    {
        nint ptr = call();
        if (ptr == nint.Zero)
            throw new InvalidOperationException("NTScan returned null pointer");

        try
        {
            return Marshal.PtrToStringUTF8(ptr)
                ?? throw new InvalidOperationException("NTScan returned invalid UTF-8");
        }
        finally
        {
            NativeNtScan.FreeString(ptr);
        }
    }
}
```

### 4. Example: quick size scan

```csharp
var report = NtScanClient.ScanDirectory(
    path: @"C:\Data",
    mode: NtScanMode.Fast,
    followSymlinks: false,
    showFiles: false);

Console.WriteLine($"Path: {report.Path}");
Console.WriteLine($"Logical bytes: {report.LogicalSize:N0}");
Console.WriteLine($"Entries: {report.Entries.Count}");
```

### 5. Example: accurate scan with per-file output

```csharp
var report = NtScanClient.ScanDirectory(
    path: @"C:\Data",
    mode: NtScanMode.Accurate,
    followSymlinks: true,
    showFiles: true,
    cachePath: @"C:\Temp\ntscan\scan.cache");

Console.WriteLine($"Allocated complete: {report.AllocatedComplete}");
Console.WriteLine($"Allocated bytes: {report.AllocatedSize?.ToString("N0") ?? "(partial/none)"}");

foreach (var top in report.Entries.Take(10))
{
    Console.WriteLine($"{top.PercentOfParent,6:F2}%  {top.LogicalSize,14:N0}  {top.Kind,-18}  {top.Name}");
}
```

### 6. Example: duplicate detection

```csharp
var dup = NtScanClient.FindDuplicates(
    path: @"C:\Data",
    minSize: 1UL * 1024 * 1024, // 1 MiB
    hashCachePath: @"C:\Temp\ntscan\hash.cache");

Console.WriteLine($"Files scanned: {dup.TotalFilesScanned:N0}");
Console.WriteLine($"Reclaimable bytes: {dup.TotalReclaimable:N0}");

foreach (var g in dup.Groups.Take(5))
{
    Console.WriteLine($"{g.ReclaimableBytes,14:N0} reclaimable | size {g.Size,12:N0} | copies {g.Paths.Count}");
    foreach (var p in g.Paths)
        Console.WriteLine($"  {p}");
}
```

## Common Integration Pitfalls

- Forgetting to call `ntscan_free_string` for every successful FFI call.
- Using ANSI marshalling instead of UTF-8 for path strings.
- Passing `mode = 2` expecting a third mode (it is treated as Fast).
- Assuming `allocated_size` is always present (it is null in Fast mode).
- Assuming `allocated_complete = true` in Accurate mode when some files are inaccessible.

## Minimal Deployment Notes for C# Apps

- Ensure `ntscan.dll` is discoverable at runtime:
  - next to your executable, or
  - in a path probed by native loader
- Keep CRT/runtime environment consistent with your build/deployment strategy.
- On publish, include `ntscan.dll` as content/copy output.

## Quick Reference

- Fast scan: `mode = 0`
- Accurate scan: `mode = 1`
- Optional cache args: `null` or `""`
- Free returned strings: always call `ntscan_free_string`
- FFI response shape: `{ ok, data, error }`
