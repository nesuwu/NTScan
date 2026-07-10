mod tests {
    use super::*;

    fn test_app() -> App {
        App::new(AppParams {
            // Root target: no ".." row, so an empty app has zero rows.
            target: PathBuf::from("C:\\"),
            directories: Vec::new(),
            static_entries: Vec::new(),
            file_logical: 0,
            file_allocated: None,
            file_allocated_complete: true,
            mode: ScanMode::Fast,
            cancel: CancelFlag::new(),
            errors: ErrorStats::default(),
            show_files: false,
            delete_permanent: false,
            msg_tx: None,
            settings: AppSettings::default(),
            cold_cache: false,
        })
    }

    fn press(app: &mut App, code: KeyCode) -> Option<AppAction> {
        app.handle_key(KeyEvent::new(code, KeyModifiers::NONE))
    }

    #[test]
    fn vim_and_arrow_aliases_map_to_back_and_open() {
        let mut app = test_app();
        for code in [KeyCode::Char('h'), KeyCode::Left, KeyCode::Backspace] {
            assert!(
                matches!(press(&mut app, code), Some(AppAction::GoBack)),
                "{:?} must map to GoBack",
                code
            );
        }
        // No rows — open is a no-op but must not quit or crash.
        for code in [KeyCode::Char('l'), KeyCode::Right, KeyCode::Enter] {
            assert!(press(&mut app, code).is_none());
        }
        assert!(!app.should_exit());
    }

    #[test]
    fn sort_keys_switch_and_reverse() {
        let mut app = test_app();
        assert_eq!(app.sort_mode, SortMode::DEFAULT);
        press(&mut app, KeyCode::Char('n'));
        assert_eq!(
            app.sort_mode,
            SortMode {
                key: SortKey::Name,
                reverse: false
            }
        );
        press(&mut app, KeyCode::Char('n'));
        assert_eq!(
            app.sort_mode,
            SortMode {
                key: SortKey::Name,
                reverse: true
            }
        );
        press(&mut app, KeyCode::Char('s'));
        assert_eq!(
            app.sort_mode,
            SortMode {
                key: SortKey::Size,
                reverse: false
            }
        );
        press(&mut app, KeyCode::Char('s'));
        assert_eq!(
            app.sort_mode,
            SortMode {
                key: SortKey::Size,
                reverse: true
            }
        );
        press(&mut app, KeyCode::Char('d'));
        assert_eq!(
            app.sort_mode,
            SortMode {
                key: SortKey::Date,
                reverse: false
            }
        );
    }

    #[test]
    fn help_popup_opens_and_any_key_closes() {
        let mut app = test_app();
        press(&mut app, KeyCode::Char('?'));
        assert!(app.help_popup);
        // The next key only closes the popup — no quit, no action.
        assert!(press(&mut app, KeyCode::Char('q')).is_none());
        assert!(!app.help_popup);
        assert!(!app.should_exit());
    }

    fn tpress(tutorial: &mut Tutorial, code: KeyCode) {
        tutorial.handle_key(KeyEvent::new(code, KeyModifiers::NONE));
    }

    #[test]
    fn tutorial_full_flow_completes() {
        let mut t = Tutorial::new(&AppSettings::default());
        assert_eq!(t.step, 0);
        tpress(&mut t, KeyCode::Char('j')); // down
        assert_eq!(t.step, 1);
        tpress(&mut t, KeyCode::Up);
        assert_eq!(t.step, 2);
        // Selection is on ".." — Enter there is GoBack, must not advance.
        tpress(&mut t, KeyCode::Enter);
        assert_eq!(t.step, 2);
        tpress(&mut t, KeyCode::Down); // onto a directory
        tpress(&mut t, KeyCode::Enter); // open → swaps to Games mock
        assert_eq!(t.step, 3);
        assert!(t.app.target().ends_with("Games"));
        tpress(&mut t, KeyCode::Char('h')); // back → root mock
        assert_eq!(t.step, 4);
        assert!(!t.app.target().ends_with("Games"));
        tpress(&mut t, KeyCode::Char('n'));
        assert_eq!(t.step, 5);
        tpress(&mut t, KeyCode::Char('s'));
        assert_eq!(t.step, 6);
        tpress(&mut t, KeyCode::Char('?'));
        assert!(t.app.help_popup);
        assert_eq!(t.step, 6);
        tpress(&mut t, KeyCode::Char('x')); // closes help → advances
        assert!(!t.app.help_popup);
        assert_eq!(t.step, 7);
        assert!(!t.finished);
        tpress(&mut t, KeyCode::Enter);
        assert!(t.finished);
        assert!(!t.quit);
    }

    #[test]
    fn tutorial_esc_skips_and_ctrl_c_quits() {
        let mut t = Tutorial::new(&AppSettings::default());
        tpress(&mut t, KeyCode::Esc);
        assert!(t.finished && !t.quit);

        let mut t = Tutorial::new(&AppSettings::default());
        t.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(t.quit);
    }

    #[test]
    fn tutorial_blocks_delete_and_settings() {
        let mut t = Tutorial::new(&AppSettings::default());
        for code in [
            KeyCode::Delete,
            KeyCode::Char('x'),
            KeyCode::Char('g'),
            KeyCode::F(2),
        ] {
            tpress(&mut t, code);
        }
        assert!(t.app.confirm_delete.is_none());
        assert!(t.app.settings_popup.is_none());
        assert!(!t.app.should_exit());
        assert!(!t.finished);
    }

    #[test]
    fn settings_popup_esc_saves_and_classifies_changes() {
        // Redirect the settings file away from the user's real one.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.conf");
        unsafe { std::env::set_var("NTSCAN_SETTINGS_PATH", &path) };

        let mut app = test_app();

        // Unchanged draft: Esc just closes, nothing saved, no action.
        press(&mut app, KeyCode::Char('g'));
        assert!(app.settings_popup.is_some());
        assert!(press(&mut app, KeyCode::Esc).is_none());
        assert!(app.settings_popup.is_none());
        assert!(!path.exists());

        // 'z' reverts a stepped value.
        press(&mut app, KeyCode::Char('g'));
        press(&mut app, KeyCode::Right); // Theme → Ocean
        press(&mut app, KeyCode::Char('z'));
        assert!(press(&mut app, KeyCode::Esc).is_none());
        assert!(!path.exists());

        // Theme-only change → UpdateSettings (no rescan) + file written.
        press(&mut app, KeyCode::Char('g'));
        press(&mut app, KeyCode::Right);
        let action = press(&mut app, KeyCode::Esc);
        assert!(matches!(action, Some(AppAction::UpdateSettings(_))));
        assert_eq!(app.settings.theme, ThemePreset::Ocean);
        assert!(path.exists());

        // Scan-affecting change → ApplySettings (rescan).
        press(&mut app, KeyCode::Char('g'));
        press(&mut app, KeyCode::Char('j')); // Scan mode
        press(&mut app, KeyCode::Char('l')); // Fast → Accurate
        let action = press(&mut app, KeyCode::Esc);
        assert!(matches!(action, Some(AppAction::ApplySettings(_))));
        assert_eq!(app.settings.default_mode, ScanMode::Accurate);

        // Custom theme reveals the hex color fields; editing one sticks.
        press(&mut app, KeyCode::Char('g'));
        press(&mut app, KeyCode::Right); // Ocean → Amber
        press(&mut app, KeyCode::Right); // Amber → Forest
        press(&mut app, KeyCode::Right); // Forest → Custom
        assert_eq!(
            SettingsField::visible(&app.settings_popup.as_ref().unwrap().draft).len(),
            14
        );
        press(&mut app, KeyCode::Char('j')); // Color: done
        press(&mut app, KeyCode::Enter); // edit
        app.settings_popup.as_mut().unwrap().input = String::from("#a6e3a1");
        press(&mut app, KeyCode::Enter); // apply
        let action = press(&mut app, KeyCode::Esc);
        assert!(matches!(action, Some(AppAction::UpdateSettings(_))));
        assert_eq!(app.settings.theme, ThemePreset::Custom);
        assert_eq!(app.settings.custom_colors.ok, (0xa6, 0xe3, 0xa1));

        // Invalid hex → error popup, edit stays open, nothing applied.
        press(&mut app, KeyCode::Char('g'));
        press(&mut app, KeyCode::Char('j'));
        press(&mut app, KeyCode::Enter);
        app.settings_popup.as_mut().unwrap().input = String::from("nope");
        press(&mut app, KeyCode::Enter);
        assert!(app.error_popup.is_some());
        press(&mut app, KeyCode::Enter); // dismiss error
        assert!(app.settings_popup.as_ref().unwrap().editing);
        press(&mut app, KeyCode::Esc); // cancel edit
        assert!(press(&mut app, KeyCode::Esc).is_none()); // nothing changed
        assert_eq!(app.settings.custom_colors.ok, (0xa6, 0xe3, 0xa1));

        unsafe { std::env::remove_var("NTSCAN_SETTINGS_PATH") };
    }

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
            cold_cache: false,
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
