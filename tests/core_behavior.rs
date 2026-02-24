use std::collections::HashSet;
use std::fs;
use std::sync::Arc;

use anyhow::Result;
use ntscan::context::{CancelFlag, ScanCache, ScanContext};
use ntscan::duplicates::find_duplicates;
use ntscan::model::{ChildJob, EntryKind, ErrorStats, ScanMode, ScanOptions};
use ntscan::scanner::{process_directory_child, scan_directory};
use tempfile::TempDir;

fn build_fast_context(cache_home: &TempDir, show_files: bool) -> ScanContext {
    let cache_path = cache_home.path().join("scan-cache.bin");
    ScanContext::with_cache(
        ScanOptions {
            mode: ScanMode::Fast,
            follow_symlinks: false,
            show_files,
        },
        None,
        CancelFlag::new(),
        ErrorStats::default(),
        Arc::new(ScanCache::new(cache_path)),
    )
}

#[test]
fn scan_directory_fast_mode_aggregates_sizes_and_sorts_entries() -> Result<()> {
    let root = TempDir::new()?;
    fs::create_dir(root.path().join("child"))?;
    fs::write(root.path().join("big.bin"), vec![b'A'; 30])?;
    fs::write(root.path().join("small.bin"), vec![b'B'; 10])?;
    fs::write(root.path().join("child").join("nested.bin"), vec![b'C'; 20])?;

    let context = build_fast_context(&root, true);
    let report = scan_directory(root.path(), &context)?;

    assert_eq!(report.logical_size, 60);
    assert_eq!(report.allocated_size, None);
    assert_eq!(report.entries.len(), 3);

    assert_eq!(report.entries[0].name, "big.bin");
    assert!(matches!(report.entries[0].kind, EntryKind::File));
    assert_eq!(report.entries[0].logical_size, 30);
    assert!((report.entries[0].percent_of_parent - 50.0).abs() < 0.001);

    assert_eq!(report.entries[1].name, "child");
    assert!(matches!(report.entries[1].kind, EntryKind::Directory));
    assert_eq!(report.entries[1].logical_size, 20);
    assert!((report.entries[1].percent_of_parent - 33.333).abs() < 0.01);

    assert_eq!(report.entries[2].name, "small.bin");
    assert!(matches!(report.entries[2].kind, EntryKind::File));
    assert_eq!(report.entries[2].logical_size, 10);
    assert!((report.entries[2].percent_of_parent - 16.666).abs() < 0.01);

    Ok(())
}

#[test]
fn scan_directory_without_show_files_only_lists_directories() -> Result<()> {
    let root = TempDir::new()?;
    fs::create_dir(root.path().join("child"))?;
    fs::write(root.path().join("root-file.bin"), vec![b'X'; 7])?;
    fs::write(root.path().join("child").join("nested.bin"), vec![b'Y'; 11])?;

    let context = build_fast_context(&root, false);
    let report = scan_directory(root.path(), &context)?;

    assert_eq!(report.logical_size, 18);
    assert_eq!(report.entries.len(), 1);
    assert_eq!(report.entries[0].name, "child");
    assert!(matches!(report.entries[0].kind, EntryKind::Directory));
    assert_eq!(report.entries[0].logical_size, 11);

    Ok(())
}

#[test]
fn process_directory_child_preserves_symlink_kind_when_scan_fails() -> Result<()> {
    let root = TempDir::new()?;
    let context = build_fast_context(&root, true);
    let path = root.path().join("missing-symlink-target");

    let report = process_directory_child(
        ChildJob {
            name: "missing-symlink-target".to_string(),
            path: path.clone(),
            was_symlink: true,
        },
        &context,
    )?;

    assert!(matches!(report.kind, EntryKind::SymlinkDirectory));
    assert_eq!(report.path, path);
    assert!(report.error.is_some());

    Ok(())
}

#[test]
fn find_duplicates_groups_matching_files_and_reports_reclaimable_bytes() -> Result<()> {
    let root = TempDir::new()?;
    let a = root.path().join("dup-a.txt");
    let b = root.path().join("dup-b.txt");
    let unique = root.path().join("unique.txt");

    fs::write(&a, b"same-content")?;
    fs::write(&b, b"same-content")?;
    fs::write(unique, b"different")?;

    let result = find_duplicates(root.path(), 1)?;

    assert_eq!(result.total_files_scanned, 3);
    assert_eq!(result.groups.len(), 1);
    assert_eq!(result.total_reclaimable, b"same-content".len() as u64);

    let group = &result.groups[0];
    assert_eq!(group.size, b"same-content".len() as u64);
    assert_eq!(group.paths.len(), 2);

    let actual: HashSet<_> = group.paths.iter().cloned().collect();
    let expected = HashSet::from([a, b]);
    assert_eq!(actual, expected);

    Ok(())
}

#[test]
fn find_duplicates_respects_minimum_size_filter() -> Result<()> {
    let root = TempDir::new()?;
    fs::write(root.path().join("tiny-a.bin"), b"aa")?;
    fs::write(root.path().join("tiny-b.bin"), b"aa")?;
    fs::write(root.path().join("large.bin"), vec![b'Z'; 16])?;

    let result = find_duplicates(root.path(), 10)?;

    assert_eq!(result.total_files_scanned, 1);
    assert!(result.groups.is_empty());
    assert_eq!(result.total_reclaimable, 0);

    Ok(())
}
