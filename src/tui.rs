use std::cmp::{Ordering, Reverse};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};

use crate::context::CancelFlag;
use crate::model::{
    ChildJob, DirectoryReport, EntryKind, EntryReport, ErrorStats, ScanErrorKind, ScanMode,
};
use crate::report::format_size;
use time::OffsetDateTime;
use time::macros::format_description;

const MODIFIED_FORMAT: &[time::format_description::FormatItem<'static>] =
    format_description!("[year]-[month]-[day] [hour]:[minute]Z");

fn format_modified(timestamp: Option<SystemTime>) -> (Option<SystemTime>, String) {
    match timestamp {
        Some(ts) => match OffsetDateTime::from(ts).format(MODIFIED_FORMAT) {
            Ok(text) => (Some(ts), text),
            Err(_) => (Some(ts), String::from("-")),
        },
        None => (None, String::from("-")),
    }
}
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
/// use ntscan::tui::AppMessage;
///
/// let msg = AppMessage::AllDone;
/// matches!(msg, AppMessage::AllDone);
/// ```
pub enum AppMessage {
    DirectoryStarted(PathBuf),
    DirectoryFinished(EntryReport),
    AllDone,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SortMode {
    Name,
    Size,
    Date,
}

impl SortMode {
    fn label(self) -> &'static str {
        match self {
            SortMode::Name => "name ↑",
            SortMode::Size => "size ↓",
            SortMode::Date => "date ↓",
        }
    }

    fn next(self) -> Self {
        match self {
            SortMode::Name => SortMode::Size,
            SortMode::Size => SortMode::Date,
            SortMode::Date => SortMode::Name,
        }
    }
}

#[derive(Clone)]
struct RowData {
    name: String,
    name_key: String,
    logical_sort: Option<u64>,
    modified_sort: Option<SystemTime>,
    type_label: String,
    status: String,
    logical_text: String,
    allocated_text: String,
    modified_text: String,
    ads_text: String,
    percent_text: String,
    style: Style,
}

impl RowData {
    fn from_entry(entry: &EntryReport, total_logical: u64) -> Self {
        let name = entry.name.clone();
        let name_key = name.to_lowercase();
        let status = if entry.error.is_some() {
            "ERR".to_string()
        } else {
            "DONE".to_string()
        };
        let style = if entry.error.is_some() {
            Style::default().fg(Color::Red)
        } else {
            Style::default().fg(Color::Green)
        };
        let logical_text = format_size(entry.logical_size);
        let allocated_text = entry
            .allocated_size
            .map(format_size)
            .unwrap_or_else(|| "-".to_string());
        let ads_text = if entry.ads_count > 0 {
            format_size(entry.ads_bytes)
        } else {
            "-".to_string()
        };
        let (modified_sort, modified_text) = format_modified(entry.modified);
        let percent_text = if total_logical > 0 {
            format!(
                "{:.2}",
                (entry.logical_size as f64 / total_logical as f64) * 100.0
            )
        } else {
            "0.00".to_string()
        };

        RowData {
            name,
            name_key,
            logical_sort: Some(entry.logical_size),
            modified_sort,
            type_label: entry.kind.short_label().to_string(),
            status,
            logical_text,
            allocated_text,
            modified_text,
            ads_text,
            percent_text,
            style,
        }
    }

    fn into_row(self, highlighted: bool) -> Row<'static> {
        let highlight_style = Style::default().add_modifier(Modifier::REVERSED);
        let style = if highlighted {
            self.style.patch(highlight_style)
        } else {
            self.style
        };
        Row::new(vec![
            Cell::from(self.name),
            Cell::from(self.type_label),
            Cell::from(self.status),
            Cell::from(self.logical_text),
            Cell::from(self.allocated_text),
            Cell::from(self.modified_text),
            Cell::from(self.ads_text),
            Cell::from(self.percent_text),
        ])
        .style(style)
    }
}

/// State container that drives the interactive TUI.
///
/// ```rust,no_run
/// use ntscan::context::CancelFlag;
/// use ntscan::model::{ChildJob, EntryReport, ErrorStats, ScanMode};
/// use ntscan::tui::App;
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
    completed_at: Option<Instant>,
    total_dirs: usize,
    completed_dirs: usize,
    all_done: bool,
    should_quit: bool,
    cancel: CancelFlag,
    errors: ErrorStats,
    sort_mode: SortMode,
    selected: usize,
    offset: usize,
    last_viewport: usize,
}
impl App {
    /// Constructs a new TUI state machine pinned to a target directory.
    ///
    /// ```rust,no_run
    /// # use ntscan::context::CancelFlag;
    /// # use ntscan::model::{ChildJob, EntryReport, ErrorStats, ScanMode};
    /// # use ntscan::tui::App;
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
            completed_at: None,
            total_dirs,
            completed_dirs: 0,
            all_done: false,
            should_quit: false,
            cancel,
            errors,
            sort_mode: SortMode::Size,
            selected: 0,
            offset: 0,
            last_viewport: 0,
        }
    }

    /// Applies a message produced by the worker threads to the UI state.
    ///
    /// ```rust
    /// # use ntscan::context::CancelFlag;
    /// # use ntscan::model::{ChildJob, EntryReport, ErrorStats, ScanMode};
    /// # use ntscan::tui::{App, AppMessage};
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
        let total = self.total_rows();
        self.ensure_selection_bounds(total);
    }

    /// Reacts to a keyboard event emitted by crossterm.
    ///
    /// ```rust
    /// # use crossterm::event::{KeyCode, KeyEvent};
    /// # use ntscan::context::CancelFlag;
    /// # use ntscan::model::{ChildJob, EntryReport, ErrorStats, ScanMode};
    /// # use ntscan::tui::App;
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
        if key.kind != KeyEventKind::Press {
            return;
        }
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
            KeyCode::Char('s') | KeyCode::Char('S') => {
                self.cycle_sort();
            }
            KeyCode::Down => self.move_selection_by(1),
            KeyCode::Up => self.move_selection_by(-1),
            KeyCode::PageDown => self.move_page(1),
            KeyCode::PageUp => self.move_page(-1),
            KeyCode::Home => self.move_to_top(),
            KeyCode::End => self.move_to_bottom(),
            _ => {}
        }
    }

    fn cycle_sort(&mut self) {
        self.sort_mode = self.sort_mode.next();
        let total = self.total_rows();
        self.ensure_selection_bounds(total);
    }

    fn total_rows(&self) -> usize {
        let mut total = self.directories.len();
        total += self
            .static_entries
            .iter()
            .filter(|entry| {
                !matches!(
                    entry.kind,
                    EntryKind::Directory | EntryKind::SymlinkDirectory
                )
            })
            .count();
        if self.file_logical > 0 {
            total += 1;
        }
        total
    }

    fn ensure_selection_bounds(&mut self, total: usize) {
        if total == 0 {
            self.selected = 0;
            self.offset = 0;
            return;
        }
        if self.selected >= total {
            self.selected = total - 1;
        }
        let viewport = self.last_viewport.max(1);
        let max_offset = total.saturating_sub(viewport);
        if self.offset > max_offset {
            self.offset = max_offset;
        }
        if self.selected < self.offset {
            self.offset = self.selected;
        } else if self.selected >= self.offset + viewport {
            self.offset = self.selected + 1 - viewport;
        }
    }

    fn move_selection_by(&mut self, delta: isize) {
        let total = self.total_rows();
        if total == 0 {
            self.selected = 0;
            self.offset = 0;
            return;
        }
        let current = self.selected.min(total - 1) as isize;
        let max_index = (total - 1) as isize;
        let next = (current + delta).clamp(0, max_index) as usize;
        self.selected = next;
        self.ensure_selection_bounds(total);
    }

    fn move_page(&mut self, delta: isize) {
        let step = self.last_viewport.max(1) as isize;
        self.move_selection_by(delta * step);
    }

    fn move_to_top(&mut self) {
        let total = self.total_rows();
        if total == 0 {
            self.selected = 0;
            self.offset = 0;
            return;
        }
        self.selected = 0;
        self.ensure_selection_bounds(total);
    }

    fn move_to_bottom(&mut self) {
        let total = self.total_rows();
        if total == 0 {
            self.selected = 0;
            self.offset = 0;
            return;
        }
        self.selected = total - 1;
        self.ensure_selection_bounds(total);
    }

    fn elapsed(&self) -> Duration {
        match self.completed_at {
            Some(done) => done.duration_since(self.start),
            None => self.start.elapsed(),
        }
    }

    /// Advances periodic UI state such as timers.
    ///
    /// ```rust
    /// # use ntscan::context::CancelFlag;
    /// # use ntscan::model::{ChildJob, EntryReport, ErrorStats, ScanMode};
    /// # use ntscan::tui::App;
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
    /// # use ntscan::context::CancelFlag;
    /// # use ntscan::model::{ChildJob, EntryReport, ErrorStats, ScanMode};
    /// # use ntscan::tui::App;
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
    /// # use ntscan::context::CancelFlag;
    /// # use ntscan::model::{ChildJob, EntryReport, ErrorStats, ScanMode};
    /// # use ntscan::tui::App;
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
    /// # use ntscan::context::CancelFlag;
    /// # use ntscan::model::{ChildJob, EntryReport, ErrorStats, ScanMode};
    /// # use ntscan::tui::App;
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
    /// # use ntscan::context::CancelFlag;
    /// # use ntscan::model::{ChildJob, EntryReport, ErrorStats, ScanErrorKind, ScanMode};
    /// # use ntscan::tui::App;
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
    /// # use ntscan::context::CancelFlag;
    /// # use ntscan::model::{ChildJob, EntryReport, ErrorStats, ScanMode};
    /// # use ntscan::tui::App;
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
        let is_directory = matches!(
            report.kind,
            EntryKind::Directory | EntryKind::SymlinkDirectory
        );
        if is_directory {
            let path = report.path.clone();
            if let Some(directory) = self.directories.iter_mut().find(|dir| dir.path == path) {
                let was_finished = matches!(directory.status, DirectoryStatus::Finished(_));
                directory.status = DirectoryStatus::Finished(report);
                if !was_finished {
                    self.completed_dirs += 1;
                    if self.completed_dirs == self.total_dirs && self.completed_at.is_none() {
                        self.completed_at = Some(Instant::now());
                    }
                }
                return;
            }
        }
        self.static_entries.push(report);
    }

    fn mark_all_done(&mut self) {
        self.all_done = true;
        if self.completed_at.is_none() {
            self.completed_at = Some(Instant::now());
        }
    }

    fn collect_rows(&self) -> Vec<RowData> {
        let mut rows: Vec<RowData> = Vec::new();
        let total_logical = self.total_logical();

        for directory in &self.directories {
            let name = directory.name.clone();
            let name_key = name.to_lowercase();
            let type_label = if directory.was_symlink {
                "LNKD".to_string()
            } else {
                "DIR".to_string()
            };

            match &directory.status {
                DirectoryStatus::Pending => {
                    rows.push(RowData {
                        name,
                        name_key,
                        logical_sort: None,
                        modified_sort: None,
                        type_label,
                        status: "WAIT".to_string(),
                        logical_text: "...".to_string(),
                        allocated_text: "...".to_string(),
                        modified_text: "-".to_string(),
                        ads_text: "...".to_string(),
                        percent_text: "...".to_string(),
                        style: Style::default().fg(Color::DarkGray),
                    });
                }
                DirectoryStatus::Running => {
                    rows.push(RowData {
                        name,
                        name_key,
                        logical_sort: None,
                        modified_sort: None,
                        type_label,
                        status: "SCAN".to_string(),
                        logical_text: "...".to_string(),
                        allocated_text: "...".to_string(),
                        modified_text: "-".to_string(),
                        ads_text: "...".to_string(),
                        percent_text: "...".to_string(),
                        style: Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    });
                }
                DirectoryStatus::Finished(report) => {
                    let mut data = RowData::from_entry(report, total_logical);
                    data.name = name;
                    data.name_key = name_key;
                    data.type_label = type_label;
                    rows.push(data);
                }
            }
        }

        for entry in &self.static_entries {
            if matches!(
                entry.kind,
                EntryKind::Directory | EntryKind::SymlinkDirectory
            ) {
                continue;
            }
            rows.push(RowData::from_entry(entry, total_logical));
        }

        if self.file_logical > 0 {
            rows.push(RowData {
                name: "[files]".to_string(),
                name_key: "[files]".to_string(),
                logical_sort: Some(self.file_logical),
                modified_sort: None,
                type_label: "FILE".to_string(),
                status: "DONE".to_string(),
                logical_text: format_size(self.file_logical),
                allocated_text: self
                    .file_allocated
                    .map(format_size)
                    .unwrap_or_else(|| "-".to_string()),
                modified_text: "-".to_string(),
                ads_text: "-".to_string(),
                percent_text: if total_logical > 0 {
                    format!(
                        "{:.2}",
                        (self.file_logical as f64 / total_logical as f64) * 100.0
                    )
                } else {
                    "0.00".to_string()
                },
                style: Style::default().fg(Color::Green),
            });
        }

        match self.sort_mode {
            SortMode::Name => {
                rows.sort_by_key(|row| row.name_key.clone());
            }
            SortMode::Size => {
                rows.sort_by_key(|row| {
                    (
                        row.logical_sort.is_none(),
                        Reverse(row.logical_sort.unwrap_or(0)),
                        row.name_key.clone(),
                    )
                });
            }
            SortMode::Date => {
                rows.sort_by_key(|row| {
                    (
                        row.modified_sort.is_none(),
                        Reverse(row.modified_sort.unwrap_or(UNIX_EPOCH)),
                        row.name_key.clone(),
                    )
                });
            }
        }

        rows
    }

    fn visible_rows(&mut self, viewport: usize) -> Vec<Row<'static>> {
        let viewport = viewport.max(1);
        let data = self.collect_rows();
        let total = data.len();
        self.last_viewport = viewport;
        if total == 0 {
            self.selected = 0;
            self.offset = 0;
            return Vec::new();
        }

        self.ensure_selection_bounds(total);

        let start = self.offset;
        let end = (start + viewport).min(total);
        data[start..end]
            .iter()
            .cloned()
            .enumerate()
            .map(|(idx, row)| {
                let absolute_index = start + idx;
                row.into_row(absolute_index == self.selected)
            })
            .collect()
    }
}

/// Renders the current application state into the provided frame.
///
/// ```rust,ignore
/// use ntscan::context::CancelFlag;
/// use ntscan::model::{ChildJob, EntryReport, ErrorStats, ScanMode};
/// use ntscan::tui::{draw_app, App};
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
pub fn draw_app(frame: &mut Frame<'_>, app: &mut App) {
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
            "Mode: {} | Sort: {} | Directories: {}/{} | Logical: {} | Allocated: {} | Elapsed: {:.1?}",
            app.mode.label(),
            app.sort_mode.label(),
            app.completed_dirs,
            app.total_dirs,
            format_size(total_logical),
            allocated_text,
            app.elapsed()
        )),
        Line::from(format!(
            "Errors - Cancelled:{}  ADS:{}  Access:{}  Share:{}  Other:{}",
            cncl, adsf, accd, shrv, othr
        )),
        Line::from("Keys: q/Esc quit | s change sort | Up/Down move | PgUp/PgDn, Home/End page"),
    ];

    let header =
        Paragraph::new(header_lines).block(Block::default().title("Status").borders(Borders::ALL));
    frame.render_widget(header, chunks[0]);

    let column_widths = [
        Constraint::Percentage(35),
        Constraint::Length(6),
        Constraint::Length(8),
        Constraint::Length(14),
        Constraint::Length(14),
        Constraint::Length(18),
        Constraint::Length(9),
        Constraint::Length(6),
    ];
    let viewport = (chunks[1].height as usize).saturating_sub(3).max(1);
    let table = Table::new(app.visible_rows(viewport), column_widths)
        .header(
            Row::new(vec![
                "Name",
                "Type",
                "Status",
                "Logical",
                "Allocated",
                "Modified",
                "ADS",
                "%",
            ])
            .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(Block::default().title("Folders").borders(Borders::ALL))
        .column_spacing(1);
    frame.render_widget(table, chunks[1]);
}
