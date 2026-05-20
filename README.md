# NTScan ![Build](https://github.com/nesuwu/NTScan/actions/workflows/rust.yml/badge.svg)

A fast directory size scanner for Windows. Point it at an NTFS tree and it
walks the whole thing in parallel, then shows you which folders are eating
the disk. Use it from the command line or in a terminal UI. The core also
builds as a DLL with a C ABI if you want to call it from your own code.

## What it does

- Scans subdirectories the moment it finds them instead of waiting for a full listing
- Two modes. **Fast** reads metadata only. **Accurate** also walks alternate data streams and reports real on-disk allocation
- Counts hardlinked files once, not once per path
- Finds duplicate files by content hash and caches the hashes between runs
- TUI sorts by name, size, or date and has a settings panel
- Won't loop forever on junctions or symlink cycles
- Tracks why files failed: access denied, sharing violation, bad stream

Windows only. It leans on Win32 directory enumeration, `NtQueryInformationFile`,
and NTFS metadata, so it won't build on Linux, macOS, or any non-NT Kernel based system
(ReactOS untested).

## Build

Requires the stable Rust toolchain on Windows.

```powershell
git clone https://github.com/nesuwu/NTScan.git
cd NTScan
cargo build --release
```

The binary is `target\release\ntscan.exe`.

## Usage

```
ntscan [OPTIONS] [TARGET]
```

`TARGET` defaults to the current directory.

| Option | Effect |
| --- | --- |
| `--fast` | Force fast mode (metadata only). Conflicts with `--accurate`. |
| `--accurate` | Accurate mode: include alternate data streams and allocation size. |
| `--follow-symlinks` | Traverse symlinks and junctions; visited targets are skipped. |
| `--duplicates` | Report duplicate files by content hash. |
| `--min-size <BYTES>` | Minimum file size for duplicate detection. Default `1048576` (1 MiB). |
| `--file` | List individual files, not just directory totals. |
| `--delete-permanent` | Deletion features skip the Recycle Bin. Items are unrecoverable. |
| `--debug` | Print only the final table; skip the TUI. |

### Examples

```powershell
ntscan "C:\Data"
ntscan --accurate "C:\Data"
ntscan --duplicates --min-size 1048576 "C:\Data"
ntscan --debug "C:\Data"
```

### Cache locations

```powershell
$env:NTSCAN_CACHE_PATH      = "C:\Temp\ntscan\scan.cache"
$env:NTSCAN_HASH_CACHE_PATH = "C:\Temp\ntscan\hash.cache"
```

- `NTSCAN_CACHE_PATH` sets the scanner metadata cache.
- `NTSCAN_HASH_CACHE_PATH` sets the duplicate-hash cache.

Saved settings persist to `%LOCALAPPDATA%\ntscan\settings.conf`, or
`%TEMP%\ntscan.settings.conf` when `LOCALAPPDATA` is unavailable.

## TUI Keys

| Key | Action |
| --- | --- |
| `Up` / `Down` | Move selection |
| `PageUp` / `PageDown` | Scroll one page |
| `Home` / `End` | First / last entry |
| `s` | Cycle sort: Name, Size, Date |
| `g` | Open settings panel |
| `q` / `Esc` | Quit (`Ctrl+C` cancels the scan) |

In the settings panel: `Up`/`Down` select, `Left`/`Right` toggle, `Enter`
edits a text field, `Ctrl+S` saves persistent defaults.

## Library / DLL

The scanner core (`src/engine.rs`) is UI-agnostic. Build a TUI-free DLL:

```powershell
cargo build --release --lib --no-default-features --features ffi
```

This emits `target\release\ntscan.dll`.

### C ABI

```c
char *ntscan_scan_directory_json(const char *path, unsigned int mode,
                                 bool follow_symlinks, bool show_files,
                                 const char *cache_path);
char *ntscan_find_duplicates_json(const char *path, unsigned long long min_size,
                                  const char *hash_cache_path);
void  ntscan_free_string(char *ptr);
```

`mode` is `0` for fast, `1` for accurate. Pass `null` or an empty string for
`cache_path` / `hash_cache_path` and it uses the defaults. Free every returned
string with `ntscan_free_string` or you leak.

### C# P/Invoke

```csharp
[DllImport("ntscan.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
private static extern IntPtr ntscan_scan_directory_json(
    string path, uint mode, [MarshalAs(UnmanagedType.I1)] bool followSymlinks,
    [MarshalAs(UnmanagedType.I1)] bool showFiles, string? cachePath);

[DllImport("ntscan.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
private static extern IntPtr ntscan_find_duplicates_json(
    string path, ulong minSize, string? hashCachePath);

[DllImport("ntscan.dll", CallingConvention = CallingConvention.Cdecl)]
private static extern void ntscan_free_string(IntPtr ptr);
```

## Development

```powershell
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

`cargo test` runs the unit, integration, and doc tests. The `ci.*` scripts
(`ci.ps1`, `ci.bat`, `ci.fish`, `ci.sh`) run all three steps in one go.

## License

NTScan is forever free and licensed under the [MIT](LICENSE) license.
