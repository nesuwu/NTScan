#[cfg(feature = "tui")]
fn main() -> anyhow::Result<()> {
    ntscan::modes::run()
}

#[cfg(not(feature = "tui"))]
fn main() -> anyhow::Result<()> {
    Err(anyhow::anyhow!(
        "The CLI/TUI binary requires the `tui` feature. Build with `--features tui`."
    ))
}
