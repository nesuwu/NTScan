mod tests {
    use super::*;

    #[test]
    fn total_allocated_marks_partial_when_any_entry_is_incomplete() {
        let app = App::new(AppParams {
            target: PathBuf::from("."),
            directories: Vec::new(),
            static_entries: vec![EntryReport {
                name: "sample.bin".to_string(),
                path: PathBuf::from(".\\sample.bin"),
                kind: EntryKind::File,
                logical_size: 10,
                allocated_size: Some(8),
                allocated_complete: false,
                percent_of_parent: 0.0,
                ads_bytes: 0,
                ads_count: 0,
                error: None,
                skip_reason: None,
                modified: None,
            }],
            file_logical: 0,
            file_allocated: Some(4),
            file_allocated_complete: true,
            mode: ScanMode::Accurate,
            cancel: CancelFlag::new(),
            errors: ErrorStats::default(),
            show_files: true,
            delete_permanent: false,
            msg_tx: None,
            settings: AppSettings::default(),
        });

        let (total_allocated, allocated_complete) = app
            .total_allocated()
            .expect("accurate mode should produce allocated totals");
        assert_eq!(total_allocated, 12);
        assert!(!allocated_complete, "totals must be marked partial");

        let report = app
            .build_final_report()
            .expect("app with no pending directories should build final report");
        assert!(!report.allocated_complete);
    }
}
