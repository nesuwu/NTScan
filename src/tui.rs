use std::cmp::Ordering;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};

use crate::context::CancelFlag;
use crate::model::{ChildJob, DirectoryReport, EntryReport, ErrorStats, ScanErrorKind, ScanMode};
use crate::report::format_size;
#[derive(Clone)]
struct AppDirectory {
    name: String,
    path: PathBuf,
    was_symlink: bool,
    status: DirectoryStatus,
}

#[derive(Clone)]
enum DirectoryStatus {
    Pending,
    Running,
    Finished(EntryReport),
}

#[derive(Clone)]
/// Messages exchanged between scanning workers and the UI.
///
/// ```rust
/// use foldersizer_cli::tui::AppMessage;
///
/// let msg = AppMessage::AllDone;
/// matches!(msg, AppMessage::AllDone);
/// ```
pub enum AppMessage {
    DirectoryStarted(PathBuf),
    DirectoryFinished(EntryReport),
    AllDone,
}

/// State container that drives the interactive TUI.
///
/// ```rust,no_run
/// use foldersizer_cli::context::CancelFlag;
/// use foldersizer_cli::model::{ChildJob, EntryReport, ErrorStats, ScanMode};
/// use foldersizer_cli::tui::App;
///
/// let app = App::new(
///     std::path::PathBuf::from("."),
///     Vec::<ChildJob>::new(),
///     Vec::<EntryReport>::new(),
///     0,
///     None,
///     ScanMode::Fast,
///     CancelFlag::new(),
///     ErrorStats::default(),
/// );
/// assert_eq!(app.total_logical(), 0);
/// ```
pub struct App {
    target: PathBuf,
    mode: ScanMode,
    directories: Vec<AppDirectory>,
    static_entries: Vec<EntryReport>,
    file_logical: u64,
    file_allocated: Option<u64>,
    start: Instant,
    total_dirs: usize,
    completed_dirs: usize,
    all_done: bool,
    should_quit: bool,
    cancel: CancelFlag,
    errors: ErrorStats,
}
impl App {
    /// Constructs a new TUI state machine pinned to a target directory.
    ///
    /// ```rust,no_run
    /// # use foldersizer_cli::context::CancelFlag;
    /// # use foldersizer_cli::model::{ChildJob, EntryReport, ErrorStats, ScanMode};
    /// # use foldersizer_cli::tui::App;
    /// let app = App::new(
    ///     std::path::PathBuf::from("."),
    ///     Vec::<ChildJob>::new(),
    ///     Vec::<EntryReport>::new(),
    ///     0,
    ///     None,
    ///     ScanMode::Fast,
    ///     CancelFlag::new(),
    ///     ErrorStats::default(),
    /// );
    /// assert_eq!(app.total_logical(), 0);
    /// ```
    pub fn new(
        target: PathBuf,
        directories: Vec<ChildJob>,
        static_entries: Vec<EntryReport>,
        file_logical: u64,
        file_allocated: Option<u64>,
        mode: ScanMode,
        cancel: CancelFlag,
        errors: ErrorStats,
    ) -> Self {
        let total_dirs = directories.len();
        let directories = directories
            .into_iter()
            .map(|job| AppDirectory {
                name: job.name,
                path: job.path,
                was_symlink: job.was_symlink,
                status: DirectoryStatus::Pending,
            })
            .collect();

        Self {
            target,
            mode,
            directories,
            static_entries,
            file_logical,
            file_allocated,
            start: Instant::now(),
            total_dirs,
            completed_dirs: 0,
            all_done: false,
            should_quit: false,
            cancel,
            errors,
        }
    }

    /// Applies a message produced by the worker threads to the UI state.
    ///
    /// ```rust
    /// # use foldersizer_cli::context::CancelFlag;
    /// # use foldersizer_cli::model::{ChildJob, EntryReport, ErrorStats, ScanMode};
    /// # use foldersizer_cli::tui::{App, AppMessage};
    /// let mut app = App::new(
    ///     std::path::PathBuf::from("."),
    ///     Vec::<ChildJob>::new(),
    ///     Vec::<EntryReport>::new(),
    ///     0,
    ///     None,
    ///     ScanMode::Fast,
    ///     CancelFlag::new(),
    ///     ErrorStats::default(),
    /// );
    /// app.handle_message(AppMessage::AllDone);
    /// ```
    pub fn handle_message(&mut self, message: AppMessage) {
        match message {
            AppMessage::DirectoryStarted(path) => self.mark_started(&path),
            AppMessage::DirectoryFinished(report) => self.apply_report(report),
            AppMessage::AllDone => self.mark_all_done(),
        }
    }

    /// Reacts to a keyboard event emitted by crossterm.
    ///
    /// ```rust
    /// # use crossterm::event::{KeyCode, KeyEvent};
    /// # use foldersizer_cli::context::CancelFlag;
    /// # use foldersizer_cli::model::{ChildJob, EntryReport, ErrorStats, ScanMode};
    /// # use foldersizer_cli::tui::App;
    /// let mut app = App::new(
    ///     std::path::PathBuf::from("."),
    ///     Vec::<ChildJob>::new(),
    ///     Vec::<EntryReport>::new(),
    ///     0,
    ///     None,
    ///     ScanMode::Fast,
    ///     CancelFlag::new(),
    ///     ErrorStats::default(),
    /// );
    /// app.handle_key(KeyEvent::from(KeyCode::Char('q')));
    /// ```
    pub fn handle_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => {
                self.should_quit = true;
                self.cancel.cancel();
                self.errors.record(ScanErrorKind::Cancelled);
            }
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.should_quit = true;
                self.cancel.cancel();
                self.errors.record(ScanErrorKind::Cancelled);
            }
            _ => {}
        }
    }

    /// Advances periodic UI state such as timers.
    ///
    /// ```rust
    /// # use foldersizer_cli::context::CancelFlag;
    /// # use foldersizer_cli::model::{ChildJob, EntryReport, ErrorStats, ScanMode};
    /// # use foldersizer_cli::tui::App;
    /// let mut app = App::new(
    ///     std::path::PathBuf::from("."),
    ///     Vec::<ChildJob>::new(),
    ///     Vec::<EntryReport>::new(),
    ///     0,
    ///     None,
    ///     ScanMode::Fast,
    ///     CancelFlag::new(),
    ///     ErrorStats::default(),
    /// );
    /// app.tick();
    /// ```
    pub fn tick(&mut self) {
        // UI tick hook (spinner, timers) will live here; keep results visible until the user quits
    }

    /// Indicates whether the UI loop should terminate.
    ///
    /// ```rust
    /// # use foldersizer_cli::context::CancelFlag;
    /// # use foldersizer_cli::model::{ChildJob, EntryReport, ErrorStats, ScanMode};
    /// # use foldersizer_cli::tui::App;
    /// let app = App::new(
    ///     std::path::PathBuf::from("."),
    ///     Vec::<ChildJob>::new(),
    ///     Vec::<EntryReport>::new(),
    ///     0,
    ///     None,
    ///     ScanMode::Fast,
    ///     CancelFlag::new(),
    ///     ErrorStats::default(),
    /// );
    /// assert!(!app.should_exit());
    /// ```
    pub fn should_exit(&self) -> bool {
        self.should_quit
    }

    /// Returns the combined logical size of all known entries.
    ///
    /// ```rust
    /// # use foldersizer_cli::context::CancelFlag;
    /// # use foldersizer_cli::model::{ChildJob, EntryReport, ErrorStats, ScanMode};
    /// # use foldersizer_cli::tui::App;
    /// let app = App::new(
    ///     std::path::PathBuf::from("."),
    ///     Vec::<ChildJob>::new(),
    ///     Vec::<EntryReport>::new(),
    ///     0,
    ///     None,
    ///     ScanMode::Fast,
    ///     CancelFlag::new(),
    ///     ErrorStats::default(),
    /// );
    /// assert_eq!(app.total_logical(), 0);
    /// ```
    pub fn total_logical(&self) -> u64 {
        let mut total = self.file_logical;
        total += self
            .directories
            .iter()
            .filter_map(|dir| match &dir.status {
                DirectoryStatus::Finished(report) => Some(report.logical_size),
                _ => None,
            })
            .sum::<u64>();
        total += self
            .static_entries
            .iter()
            .map(|entry| entry.logical_size)
            .sum::<u64>();
        total
    }

    /// Returns the aggregated on-disk allocation size when available.
    ///
    /// ```rust
    /// # use foldersizer_cli::context::CancelFlag;
    /// # use foldersizer_cli::model::{ChildJob, EntryReport, ErrorStats, ScanMode};
    /// # use foldersizer_cli::tui::App;
    /// let app = App::new(
    ///     std::path::PathBuf::from("."),
    ///     Vec::<ChildJob>::new(),
    ///     Vec::<EntryReport>::new(),
    ///     0,
    ///     Some(0),
    ///     ScanMode::Accurate,
    ///     CancelFlag::new(),
    ///     ErrorStats::default(),
    /// );
    /// assert!(app.total_allocated().is_some());
    /// ```
    pub fn total_allocated(&self) -> Option<u64> {
        match self.mode {
            ScanMode::Fast => None,
            ScanMode::Accurate => {
                let mut total = self.file_allocated?;
                for entry in &self.static_entries {
                    total += entry.allocated_size?;
                }
                for directory in &self.directories {
                    if let DirectoryStatus::Finished(report) = &directory.status {
                        total += report.allocated_size?;
                    } else {
                        return None;
                    }
                }
                Some(total)
            }
        }
    }

    /// Provides read-only access to the accumulated error statistics.
    ///
    /// ```rust
    /// # use foldersizer_cli::context::CancelFlag;
    /// # use foldersizer_cli::model::{ChildJob, EntryReport, ErrorStats, ScanErrorKind, ScanMode};
    /// # use foldersizer_cli::tui::App;
    /// let app = App::new(
    ///     std::path::PathBuf::from("."),
    ///     Vec::<ChildJob>::new(),
    ///     Vec::<EntryReport>::new(),
    ///     0,
    ///     None,
    ///     ScanMode::Fast,
    ///     CancelFlag::new(),
    ///     ErrorStats::default(),
    /// );
    /// assert_eq!(app.errors().snapshot().get(&ScanErrorKind::Other), None);
    /// ```
    pub fn errors(&self) -> &ErrorStats {
        &self.errors
    }

    /// Collapses the current state into a final directory report when complete.
    ///
    /// ```rust,no_run
    /// # use foldersizer_cli::context::CancelFlag;
    /// # use foldersizer_cli::model::{ChildJob, EntryReport, ErrorStats, ScanMode};
    /// # use foldersizer_cli::tui::App;
    /// let app = App::new(
    ///     std::path::PathBuf::from("."),
    ///     Vec::<ChildJob>::new(),
    ///     Vec::<EntryReport>::new(),
    ///     0,
    ///     None,
    ///     ScanMode::Fast,
    ///     CancelFlag::new(),
    ///     ErrorStats::default(),
    /// );
    /// assert!(app.build_final_report().is_none());
    /// ```
    pub fn build_final_report(&self) -> Option<DirectoryReport> {
        if self.completed_dirs != self.total_dirs {
            return None;
        }

        let mut entries: Vec<EntryReport> = self.static_entries.clone();
        for directory in &self.directories {
            match &directory.status {
                DirectoryStatus::Finished(report) => entries.push(report.clone()),
                _ => return None,
            }
        }

        let mut total_logical = self.file_logical;
        total_logical += entries.iter().map(|entry| entry.logical_size).sum::<u64>();

        let mut total_allocated = match (self.mode, self.file_allocated) {
            (ScanMode::Accurate, Some(value)) => Some(value),
            (ScanMode::Accurate, None) => None,
            _ => None,
        };

        if let Some(acc) = total_allocated.as_mut() {
            for entry in &entries {
                if let Some(size) = entry.allocated_size {
                    *acc += size;
                } else {
                    total_allocated = None;
                    break;
                }
            }
        }

        let denom = total_logical as f64;
        for entry in &mut entries {
            entry.percent_of_parent = if denom == 0.0 {
                0.0
            } else {
                (entry.logical_size as f64 / denom) * 100.0
            };
        }

        entries.sort_by(|a, b| match b.logical_size.cmp(&a.logical_size) {
            Ordering::Equal => a.name.cmp(&b.name),
            other => other,
        });

        let mtime = fs::metadata(&self.target)
            .ok()
            .and_then(|meta| meta.modified().ok());

        Some(DirectoryReport {
            path: self.target.clone(),
            mtime,
            logical_size: total_logical,
            allocated_size: total_allocated,
            entries,
        })
    }

    fn mark_started(&mut self, path: &Path) {
        for directory in &mut self.directories {
            if directory.path == path {
                if matches!(directory.status, DirectoryStatus::Pending) {
                    directory.status = DirectoryStatus::Running;
                }
                break;
            }
        }
    }

    fn apply_report(&mut self, report: EntryReport) {
        for directory in &mut self.directories {
            if directory.path == report.path {
                directory.status = DirectoryStatus::Finished(report.clone());
                self.completed_dirs += 1;
                break;
            }
        }
        self.static_entries.push(report);
    }

    fn mark_all_done(&mut self) {
        self.all_done = true;
    }

    fn rows(&self) -> Vec<Row<'static>> {
        let total_logical = self.total_logical();
        let mut rows = Vec::new();

        for directory in &self.directories {
            let type_label = if directory.was_symlink {
                "LNKD".to_string()
            } else {
                "DIR".to_string()
            };

            let (status, logical, allocated, ads, percent, style) = match &directory.status {
                DirectoryStatus::Pending => (
                    "WAIT".to_string(),
                    "...".to_string(),
                    "...".to_string(),
                    "...".to_string(),
                    "...".to_string(),
                    Style::default().fg(Color::DarkGray),
                ),
                DirectoryStatus::Running => (
                    "SCAN".to_string(),
                    "...".to_string(),
                    "...".to_string(),
                    "...".to_string(),
                    "...".to_string(),
                    Style::default().fg(Color::Yellow),
                ),
                DirectoryStatus::Finished(report) => {
                    let logical = format_size(report.logical_size);
                    let allocated = report
                        .allocated_size
                        .map(format_size)
                        .unwrap_or_else(|| "-".to_string());
                    let ads = if report.ads_count > 0 {
                        format_size(report.ads_bytes)
                    } else {
                        "-".to_string()
                    };
                    let percent = if total_logical > 0 {
                        format!(
                            "{:.2}",
                            (report.logical_size as f64 / total_logical as f64) * 100.0
                        )
                    } else {
                        "0.00".to_string()
                    };
                    let style = if report.error.is_some() {
                        Style::default().fg(Color::Red)
                    } else {
                        Style::default().fg(Color::Green)
                    };
                    let status = if report.error.is_some() {
                        "ERR".to_string()
                    } else {
                        "DONE".to_string()
                    };
                    (status, logical, allocated, ads, percent, style)
                }
            };

            rows.push(
                Row::new(vec![
                    Cell::from(directory.name.clone()),
                    Cell::from(type_label),
                    Cell::from(status),
                    Cell::from(logical),
                    Cell::from(allocated),
                    Cell::from(ads),
                    Cell::from(percent),
                ])
                .style(style),
            );
        }

        for entry in &self.static_entries {
            let status = if entry.error.is_some() { "ERR" } else { "DONE" };
            let style = if entry.error.is_some() {
                Style::default().fg(Color::Red)
            } else {
                Style::default().fg(Color::Green)
            };
            let logical = format_size(entry.logical_size);
            let allocated = entry
                .allocated_size
                .map(format_size)
                .unwrap_or_else(|| "-".to_string());
            let ads = if entry.ads_count > 0 {
                format_size(entry.ads_bytes)
            } else {
                "-".to_string()
            };
            let percent = if total_logical > 0 {
                format!(
                    "{:.2}",
                    (entry.logical_size as f64 / total_logical as f64) * 100.0
                )
            } else {
                "0.00".to_string()
            };

            rows.push(
                Row::new(vec![
                    Cell::from(entry.name.clone()),
                    Cell::from(entry.kind.short_label().to_string()),
                    Cell::from(status.to_string()),
                    Cell::from(logical),
                    Cell::from(allocated),
                    Cell::from(ads),
                    Cell::from(percent),
                ])
                .style(style),
            );
        }

        if self.file_logical > 0 {
            let logical = format_size(self.file_logical);
            let allocated = self
                .file_allocated
                .map(format_size)
                .unwrap_or_else(|| "-".to_string());
            let percent = if total_logical > 0 {
                format!(
                    "{:.2}",
                    (self.file_logical as f64 / total_logical as f64) * 100.0
                )
            } else {
                "0.00".to_string()
            };
            rows.push(
                Row::new(vec![
                    Cell::from(String::from("[files]")),
                    Cell::from(String::from("FILE")),
                    Cell::from(String::from("DONE")),
                    Cell::from(logical),
                    Cell::from(allocated),
                    Cell::from(String::from("-")),
                    Cell::from(percent),
                ])
                .style(Style::default().fg(Color::Green)),
            );
        }

        rows
    }
}

/// Renders the current application state into the provided frame.
///
/// ```rust,ignore
/// use foldersizer_cli::context::CancelFlag;
/// use foldersizer_cli::model::{ChildJob, EntryReport, ErrorStats, ScanMode};
/// use foldersizer_cli::tui::{draw_app, App};
///
/// let app = App::new(
///     std::path::PathBuf::from("."),
///     Vec::<ChildJob>::new(),
///     Vec::<EntryReport>::new(),
///     0,
///     None,
///     ScanMode::Fast,
///     CancelFlag::new(),
///     ErrorStats::default(),
/// );
/// // call `draw_app(frame, &app)` inside a ratatui `Terminal::draw` callback
/// ```
pub fn draw_app(frame: &mut Frame<'_>, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(6)])
        .split(frame.size());

    let errs = app.errors().snapshot();
    let cncl = *errs.get(&ScanErrorKind::Cancelled).unwrap_or(&0);
    let adsf = *errs.get(&ScanErrorKind::ADSFailed).unwrap_or(&0);
    let accd = *errs.get(&ScanErrorKind::AccessDenied).unwrap_or(&0);
    let shrv = *errs.get(&ScanErrorKind::SharingViolation).unwrap_or(&0);
    let othr = *errs.get(&ScanErrorKind::Other).unwrap_or(&0);

    let total_logical = app.total_logical();
    let allocated_text = app
        .total_allocated()
        .map(format_size)
        .unwrap_or_else(|| String::from("n/a"));
    let header_lines = vec![
        Line::from(format!("Target: {}", app.target.display())),
        Line::from(format!(
            "Mode: {} | Directories: {}/{} | Logical: {} | Allocated: {} | Elapsed: {:.1?}",
            app.mode.label(),
            app.completed_dirs,
            app.total_dirs,
            format_size(total_logical),
            allocated_text,
            app.start.elapsed()
        )),
        Line::from(format!(
            "Errors - Cancelled:{}  ADS:{}  Access:{}  Share:{}  Other:{}",
            cncl, adsf, accd, shrv, othr
        )),
        Line::from("Press q to quit"),
    ];

    let header =
        Paragraph::new(header_lines).block(Block::default().title("Status").borders(Borders::ALL));
    frame.render_widget(header, chunks[0]);

    let column_widths = [
        Constraint::Percentage(40),
        Constraint::Length(6),
        Constraint::Length(8),
        Constraint::Length(14),
        Constraint::Length(14),
        Constraint::Length(9),
        Constraint::Length(6),
    ];
    let table = Table::new(app.rows(), column_widths)
        .header(
            Row::new(vec![
                "Name",
                "Type",
                "Status",
                "Logical",
                "Allocated",
                "ADS",
                "%",
            ])
            .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(Block::default().title("Folders").borders(Borders::ALL))
        .column_spacing(1);
    frame.render_widget(table, chunks[1]);
}
