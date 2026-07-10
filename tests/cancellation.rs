use std::fs;
use std::path::Path;
use std::sync::{Arc, mpsc};
use std::thread;

use anyhow::{Result, anyhow, bail};
use ntscan::context::{CancelFlag, ScanCache, ScanContext};
use ntscan::model::{ErrorStats, ProgressEvent, ScanErrorKind, ScanMode, ScanOptions};
use ntscan::scanner::{is_scan_cancelled, scan_directory};
use tempfile::TempDir;

fn create_large_tree(root: &Path) -> Result<usize> {
    let mut total_dirs = 1usize; // root

    for a in 0..18 {
        let level1 = root.join(format!("d-{a:02}"));
        fs::create_dir(&level1)?;
        total_dirs += 1;

        for b in 0..10 {
            let level2 = level1.join(format!("sub-{b:02}"));
            fs::create_dir(&level2)?;
            total_dirs += 1;

            for c in 0..8 {
                let leaf = level2.join(format!("leaf-{c:02}"));
                fs::create_dir(&leaf)?;
                fs::write(leaf.join("payload.bin"), [b'X'; 16])?;
                total_dirs += 1;
            }
        }
    }

    Ok(total_dirs)
}

#[test]
fn scan_directory_cancels_mid_traversal_and_stops_early() -> Result<()> {
    let root = TempDir::new()?;
    let total_dirs = create_large_tree(root.path())?;

    let (progress_tx, progress_rx) = mpsc::channel();
    let cancel = CancelFlag::new();
    let context = Arc::new(ScanContext::with_cache(
        ScanOptions {
            mode: ScanMode::Fast,
            follow_symlinks: false,
            show_files: false,
        },
        Some(progress_tx),
        cancel.clone(),
        ErrorStats::default(),
        Arc::new(ScanCache::new(root.path().join("scan-cache.bin"))),
    ));

    let errors = context.errors().clone();
    let scan_root = root.path().to_path_buf();
    let scan_ctx = Arc::clone(&context);
    drop(context);

    let scan_thread = thread::spawn(move || scan_directory(&scan_root, scan_ctx.as_ref()));

    let cancel_after = 12usize;
    let cancel_for_monitor = cancel.clone();
    let monitor = thread::spawn(move || {
        let mut started_dirs = 0usize;
        while let Ok(event) = progress_rx.recv() {
            if matches!(event, ProgressEvent::Started(_)) {
                started_dirs += 1;
                if started_dirs >= cancel_after && !cancel_for_monitor.is_cancelled() {
                    cancel_for_monitor.cancel();
                }
            }
        }
        started_dirs
    });

    let result = scan_thread
        .join()
        .map_err(|_| anyhow!("scan thread panicked"))?;
    let started_dirs = monitor
        .join()
        .map_err(|_| anyhow!("progress monitor panicked"))?;

    let err = match result {
        Ok(_) => bail!("scan unexpectedly completed without cancellation"),
        Err(err) => err,
    };

    assert!(
        is_scan_cancelled(&err),
        "expected a cancelled scan error, got: {err:#}",
    );
    assert!(
        started_dirs < total_dirs,
        "expected cancellation to stop before full traversal (started {started_dirs}, total {total_dirs})",
    );

    let cancelled_count = errors
        .snapshot()
        .get(&ScanErrorKind::Cancelled)
        .copied()
        .unwrap_or(0);
    assert!(
        cancelled_count >= 1,
        "expected cancelled errors to be recorded",
    );

    Ok(())
}
