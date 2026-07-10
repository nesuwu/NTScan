/// First-run interactive tutorial.
///
/// Runs the real `App` against generated sample data, so every key behaves
/// exactly like it does in a live scan — but nothing on disk is read,
/// scanned, or deleted. One guided step per core interaction; Esc skips.
struct TutorialStep {
    title: &'static str,
    body: &'static str,
}

const TUTORIAL_STEPS: [TutorialStep; 8] = [
    TutorialStep {
        title: "Move down — press ↓ (or j)",
        body: "This list is sample data. The highlighted row is your selection.",
    },
    TutorialStep {
        title: "Move up — press ↑ (or k)",
        body: "Same keys, opposite direction. PgUp/PgDn and Home/End jump farther.",
    },
    TutorialStep {
        title: "Open a folder — select one, press → / l / Enter",
        body: "Sizes always show the whole subtree, so drilling down finds the space hogs.",
    },
    TutorialStep {
        title: "Go back — press ← / h / Backspace",
        body: "Back restores the previous view instantly when nothing changed.",
    },
    TutorialStep {
        title: "Sort by name — press n",
        body: "Pressing the active sort key again reverses it. Headers show ▲/▼.",
    },
    TutorialStep {
        title: "Sort by size — press s",
        body: "Size is the default — biggest first. d sorts by modified date.",
    },
    TutorialStep {
        title: "Open help — press ? (any key closes it)",
        body: "The full key list lives there; no need to memorize anything now.",
    },
    TutorialStep {
        title: "Done! Press Enter to scan your real folder",
        body: "Delete is Del/x (asks first), settings F2/g. Replay anytime: ntscan --tutorial",
    },
];

const TUTORIAL_ROOT: &str = "C:\\NTScan Tutorial";
const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

const TUTORIAL_ROOT_DIRS: [(&str, f64, u64); 6] = [
    ("Games", 48.7, 12),
    ("Videos", 23.4, 3),
    ("Projects", 9.1, 0),
    ("Music", 6.8, 240),
    ("Downloads", 3.5, 1),
    ("OldBackups", 1.2, 730),
];

const TUTORIAL_GAMES_DIRS: [(&str, f64, u64); 4] = [
    ("Steam", 31.0, 20),
    ("Epic", 11.5, 45),
    ("ModLibrary", 4.1, 12),
    ("Saves", 2.1, 0),
];

pub struct Tutorial {
    app: App,
    step: usize,
    /// Tutorial over (completed or skipped) — proceed to the real scan.
    finished: bool,
    /// Ctrl+C — quit the program entirely.
    quit: bool,
    settings: AppSettings,
}

impl Tutorial {
    pub fn new(settings: &AppSettings) -> Self {
        Self {
            app: mock_tutorial_app(
                settings,
                PathBuf::from(TUTORIAL_ROOT),
                &TUTORIAL_ROOT_DIRS,
            ),
            step: 0,
            finished: false,
            quit: false,
            settings: settings.clone(),
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }

        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.quit = true;
            return;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            return;
        }

        // Help popup open: any key closes it (App handles that). Closing it
        // is what completes the help step.
        if self.app.help_popup {
            self.app.handle_key(key);
            if self.step == 6 && !self.app.help_popup {
                self.step = 7;
            }
            return;
        }

        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                self.finished = true;
                return;
            }
            KeyCode::Enter if self.step + 1 >= TUTORIAL_STEPS.len() => {
                self.finished = true;
                return;
            }
            _ => {}
        }

        // Only harmless keys reach the App: navigation, sorting, help.
        // Delete, settings, and quit stay blocked — the data is fake.
        let action = match key.code {
            KeyCode::Up
            | KeyCode::Down
            | KeyCode::Left
            | KeyCode::Right
            | KeyCode::PageUp
            | KeyCode::PageDown
            | KeyCode::Home
            | KeyCode::End
            | KeyCode::Enter
            | KeyCode::Backspace
            | KeyCode::F(1) => self.app.handle_key(key),
            KeyCode::Char(ch)
                if matches!(
                    ch.to_ascii_lowercase(),
                    'j' | 'k' | 'h' | 'l' | 'n' | 's' | 'd' | '?'
                ) =>
            {
                self.app.handle_key(key)
            }
            _ => None,
        };

        match self.step {
            0 if matches!(key.code, KeyCode::Down | KeyCode::Char('j') | KeyCode::Char('J')) => {
                self.step = 1;
            }
            1 if matches!(key.code, KeyCode::Up | KeyCode::Char('k') | KeyCode::Char('K')) => {
                self.step = 2;
            }
            2 => {
                if matches!(action, Some(AppAction::ChangeDirectory(_))) {
                    self.app = mock_tutorial_app(
                        &self.settings,
                        Path::new(TUTORIAL_ROOT).join("Games"),
                        &TUTORIAL_GAMES_DIRS,
                    );
                    self.step = 3;
                }
            }
            3 => {
                if matches!(action, Some(AppAction::GoBack)) {
                    self.app = mock_tutorial_app(
                        &self.settings,
                        PathBuf::from(TUTORIAL_ROOT),
                        &TUTORIAL_ROOT_DIRS,
                    );
                    self.step = 4;
                }
            }
            4 if matches!(key.code, KeyCode::Char('n') | KeyCode::Char('N')) => {
                self.step = 5;
            }
            5 if matches!(key.code, KeyCode::Char('s') | KeyCode::Char('S')) => {
                self.step = 6;
            }
            // Step 6 advances when the help popup closes (handled above).
            _ => {}
        }
    }
}

/// Builds a completed fake scan session: every directory reports finished so
/// the table looks exactly like a real result.
fn mock_tutorial_app(settings: &AppSettings, target: PathBuf, dirs: &[(&str, f64, u64)]) -> App {
    let directories = dirs
        .iter()
        .map(|(name, _, _)| ChildJob {
            name: (*name).to_string(),
            path: target.join(name),
            was_symlink: false,
        })
        .collect();

    let mut app = App::new(AppParams {
        target: target.clone(),
        directories,
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
        settings: settings.clone(),
        cold_cache: false,
    });

    for (name, gib, days_ago) in dirs {
        app.handle_message(AppMessage::DirectoryFinished(EntryReport {
            name: (*name).to_string(),
            path: target.join(name),
            kind: EntryKind::Directory,
            logical_size: (gib * GIB) as u64,
            allocated_size: None,
            allocated_complete: true,
            percent_of_parent: 0.0,
            ads_bytes: 0,
            ads_count: 0,
            error: None,
            skip_reason: None,
            modified: SystemTime::now().checked_sub(Duration::from_secs(days_ago * 86_400)),
        }));
    }
    app.handle_message(AppMessage::AllDone);
    app
}

pub fn draw_tutorial(frame: &mut Frame<'_>, tutorial: &mut Tutorial) {
    draw_app(frame, &mut tutorial.app);

    let area = frame.size();
    let height = 5.min(area.height);
    let banner = ratatui::layout::Rect {
        x: area.x,
        y: area.y + area.height - height,
        width: area.width,
        height,
    };
    frame.render_widget(Clear, banner);

    let step = &TUTORIAL_STEPS[tutorial.step.min(TUTORIAL_STEPS.len() - 1)];
    let lines = vec![
        Line::from(format!(
            "Step {}/{} — {}",
            tutorial.step + 1,
            TUTORIAL_STEPS.len(),
            step.title
        ))
        .style(Style::default().add_modifier(Modifier::BOLD)),
        Line::from(step.body),
        Line::from("Sample data only — your disk is untouched. Esc skips the tutorial."),
    ];

    let palette = tutorial.app.palette();
    let block = Block::default()
        .title("Tutorial")
        .borders(Borders::ALL)
        .style(Style::default().fg(palette.running));
    frame.render_widget(Paragraph::new(lines).block(block), banner);
}

/// Runs the tutorial event loop. Returns `false` when the user chose to quit
/// the program (Ctrl+C) instead of continuing to the real scan.
pub fn run_tutorial(
    terminal: &mut ratatui::Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>,
    settings: &AppSettings,
) -> std::io::Result<bool> {
    let mut tutorial = Tutorial::new(settings);
    loop {
        terminal.draw(|frame| draw_tutorial(frame, &mut tutorial))?;
        if crossterm::event::poll(Duration::from_millis(200))?
            && let crossterm::event::Event::Key(key) = crossterm::event::read()?
        {
            tutorial.handle_key(key);
        }
        if tutorial.quit {
            return Ok(false);
        }
        if tutorial.finished {
            return Ok(true);
        }
    }
}
