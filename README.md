# NTScan ![Build](https://github.com/nesuwu/NTScan/actions/workflows/rust.yml/badge.svg)

NTScan is a Windows directory scanner focused on producing fast, aggregated
size reports for NTFS volumes. It can operate in a traditional CLI mode or via
an interactive TUI that keeps the current progress front and centre.

## Features

- Parallel traversal of directory trees with cooperative cancellation
- Two scanning modes: `fast` (metadata only) and `accurate` (ADS + allocation)
- Interactive TUI with sorting by name, size, or modification date
- In-app Settings popup (`g`) to configure theme colors, cache paths, and defaults
- Cycle guard for junctions and symlinks to avoid infinite recursion
- Detailed error accounting for access, sharing, and ADS failures

## Getting Started

1. Install the latest stable Rust toolchain on Windows (`rustup default stable`).
2. Clone the repository and fetch the dependencies:
   ```powershell
   git clone https://github.com/nesuwu/NTScan.git
   cd NTScan
   cargo fetch
   ```

## Usage

### Fast metadata scan (default)

```powershell
cargo run --release -- "C:\Data"
```

### Accurate scan with ADS and allocation sizes

```powershell
cargo run --release -- --accurate "C:\Data"
```

### Follow symlinks and junctions safely

```powershell
cargo run --release -- --follow-symlinks "C:\Data"
```

### Stream results to the console instead of the TUI

```powershell
cargo run --release -- --debug "C:\Data"
```

### Open the TUI settings popup

While running the TUI, press `g` to open the settings popup (2/3-screen modal).
Use `Up/Down` to select, `Left/Right` to toggle, `Enter` to edit text fields,
and `Ctrl+S` to save persistent defaults.

### Override cache file locations (optional)

```powershell
$env:NTSCAN_CACHE_PATH = "C:\Temp\ntscan\scan.cache"
$env:NTSCAN_HASH_CACHE_PATH = "C:\Temp\ntscan\hash.cache"
cargo run --release -- "C:\Data"
```

- `NTSCAN_CACHE_PATH` overrides the scanner metadata cache path.
- `NTSCAN_HASH_CACHE_PATH` overrides the duplicate-hash cache path.

## TUI Keyboard Shortcuts

- `Up` / `Down`: Move selection
- `PageUp` / `PageDown`: Scroll by a viewport-sized page
- `Home` / `End`: Jump to the first or last entry
- `s`: Cycle sorting mode (`Name → Size → Date`)
- `g`: Open settings popup (theme/colors, cache paths, default scan behavior)
- `q` or `Esc`: Quit (Ctrl+C also cancels the scan)

## Development

Run the full quality gate locally before opening a PR:

```powershell
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

The test run includes unit tests, integration tests, and documentation tests.

Saved settings are persisted to `%LOCALAPPDATA%\ntscan\settings.conf` by default
(or `%TEMP%\ntscan.settings.conf` when `LOCALAPPDATA` is unavailable).

## Library + DLL Usage

The scanner core is now UI-agnostic (`src/engine.rs`), and the TUI is split
into smaller files:

- `src/tui/types.rs`
- `src/tui/app.rs`
- `src/tui/render.rs`

Build a **TUI-free DLL** for C#/PInvoke:

```powershell
cargo build --release --lib --no-default-features --features ffi
```

On Windows this emits `target\release\ntscan.dll`.

### Exported C ABI

- `ntscan_scan_directory_json(path, mode, follow_symlinks, show_files, cache_path)`
- `ntscan_find_duplicates_json(path, min_size, hash_cache_path)`
- `ntscan_free_string(ptr)`

`mode`: `0 = Fast`, `1 = Accurate`  
`cache_path`/`hash_cache_path`: pass `null` (or empty string) to use defaults.

### Minimal C# P/Invoke Sketch

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

## License

NTScan is distributed under the terms of the [MIT License](LICENSE).
