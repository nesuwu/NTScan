use std::collections::HashSet;
use std::fs;
use std::sync::Arc;

use anyhow::Result;
use ntscan::context::{CancelFlag, ScanCache, ScanContext};
use ntscan::duplicates::find_duplicates;
use ntscan::model::{ChildJob, EntryKind, ErrorStats, ScanMode, ScanOptions};
use ntscan::scanner::{process_directory_child, scan_directory};
use tempfile::TempDir;

fn build_context(cache_home: &TempDir, mode: ScanMode, show_files: bool) -> ScanContext {
    let cache_path = cache_home.path().join("scan-cache.bin");
    ScanContext::with_cache(
        ScanOptions {
            mode,
            follow_symlinks: false,
            show_files,
        },
        None,
        CancelFlag::new(),
        ErrorStats::default(),
        Arc::new(ScanCache::new(cache_path)),
    )
}

fn build_fast_context(cache_home: &TempDir, show_files: bool) -> ScanContext {
    build_context(cache_home, ScanMode::Fast, show_files)
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

#[cfg(windows)]
#[test]
fn hardlink_entries_are_accounted_once_and_marked_in_display() -> Result<()> {
    let root = TempDir::new()?;
    let primary_dir = root.path().join("primary");
    let secondary_dir = root.path().join("secondary");
    fs::create_dir(&primary_dir)?;
    fs::create_dir(&secondary_dir)?;

    let primary_file = primary_dir.join("payload.bin");
    let secondary_link = secondary_dir.join("payload-link.bin");
    fs::write(&primary_file, vec![b'H'; 64])?;
    fs::hard_link(&primary_file, &secondary_link)?;

    let context = build_fast_context(&root, true);
    let root_report = scan_directory(root.path(), &context)?;

    assert_eq!(root_report.logical_size, 64);
    let root_child_sum: u64 = root_report
        .entries
        .iter()
        .map(|entry| entry.logical_size)
        .sum();
    assert_eq!(root_child_sum, root_report.logical_size);
    assert!(
        root_report
            .entries
            .iter()
            .all(|entry| entry.percent_of_parent <= 100.0),
        "all entry percentages must stay <= 100 even with hardlinks",
    );

    let primary_report = scan_directory(&primary_dir, &context)?;
    let secondary_report = scan_directory(&secondary_dir, &context)?;

    let duplicate_report = if primary_report.logical_size == 0 {
        &primary_report
    } else {
        &secondary_report
    };

    assert_eq!(duplicate_report.entries.len(), 1);
    let duplicate = &duplicate_report.entries[0];
    assert!(matches!(duplicate.kind, EntryKind::File));
    assert_eq!(duplicate.logical_size, 0);
    assert_eq!(duplicate.percent_of_parent, 0.0);
    assert!(
        duplicate.name.ends_with("(hardlink duplicate)"),
        "duplicate file rows should carry a hardlink suffix",
    );

    Ok(())
}

#[cfg(windows)]
#[test]
fn accurate_mode_hardlink_allocated_sizes_match_accounted_totals() -> Result<()> {
    let root = TempDir::new()?;
    let original = root.path().join("same-data.bin");
    let alias = root.path().join("same-data-link.bin");
    fs::write(&original, vec![b'A'; 4097])?;
    fs::hard_link(&original, &alias)?;

    let context = build_context(&root, ScanMode::Accurate, true);
    let report = scan_directory(root.path(), &context)?;

    let total_allocated = report
        .allocated_size
        .expect("accurate mode should return allocated totals");
    let summed_allocated: u64 = report
        .entries
        .iter()
        .map(|entry| entry.allocated_size.unwrap_or(0))
        .sum();

    assert_eq!(report.logical_size, 4097);
    assert_eq!(summed_allocated, total_allocated);
    assert_eq!(
        report
            .entries
            .iter()
            .filter(|entry| entry.name.ends_with("(hardlink duplicate)"))
            .count(),
        1,
    );

    let duplicate = report
        .entries
        .iter()
        .find(|entry| entry.name.ends_with("(hardlink duplicate)"))
        .expect("expected one duplicate hardlink entry");
    assert_eq!(duplicate.logical_size, 0);
    assert_eq!(duplicate.allocated_size, Some(0));
    assert_eq!(duplicate.percent_of_parent, 0.0);

    Ok(())
}
