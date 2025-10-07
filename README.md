# NTScan ![Build](https://github.com/nesuwu/NTScan/actions/workflows/rust.yml/badge.svg)

NTScan is a Windows directory scanner focused on producing fast, aggregated
size reports for NTFS volumes. It can operate in a traditional CLI mode or via
an interactive TUI that keeps the current progress front and centre.

## Features

- Parallel traversal of directory trees with cooperative cancellation
- Two scanning modes: `fast` (metadata only) and `accurate` (ADS + allocation)
- Interactive TUI with sorting by name, size, or modification date
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

## TUI Keyboard Shortcuts

- `Up` / `Down`: Move selection
- `PageUp` / `PageDown`: Scroll by a viewport-sized page
- `Home` / `End`: Jump to the first or last entry
- `s`: Cycle sorting mode (`Name → Size → Date`)
- `q` or `Esc`: Quit (Ctrl+C also cancels the scan)

## Development

Run the full quality gate locally before opening a PR:

```powershell
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

The test run includes unit tests, integration tests, and documentation tests.

## License

NTScan is distributed under the terms of the [MIT License](LICENSE).
