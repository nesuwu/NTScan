use std::cmp::{Ordering, Reverse};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
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
/// Represents a directory being tracked by the application.
struct AppDirectory {
    name: String,
    path: PathBuf,
    was_symlink: bool,
    status: DirectoryStatus,
}

#[derive(Clone)]
/// The scanning status of a directory.
enum DirectoryStatus {
    Pending,
    Running,
    Finished(EntryReport),
}

#[derive(Clone)]
/// Message passed from worker threads to the main TUI thread.
pub enum AppMessage {
    DirectoryStarted(PathBuf),
    DirectoryFinished(EntryReport),
    AllDone,
    DeleteStarted,
    DeleteSuccess(PathBuf),
    DeleteFailed(PathBuf, String),
}

/// Action triggered by user input in the TUI.
pub enum AppAction {
    ChangeDirectory(PathBuf),
    GoBack,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Available sorting modes for the file list.
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
/// Source of a row in the TUI list.
enum RowOrigin {
    Directory(PathBuf),
    File(PathBuf),
    Files,
    Parent,
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
    origin: RowOrigin,
}

impl RowData {
    fn from_entry(entry: &EntryReport, total_logical: u64, origin: RowOrigin) -> Self {
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
            origin,
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

/// Configuration parameters for initializing the TUI application.
///
/// This struct implements the "Parameter Object" pattern to simplify the `App::new` signature.
/// It aggregates all necessary state required to bootstrap the UI, including the initial
/// target, scan results, and global context.
pub struct AppParams {
    pub target: PathBuf,
    pub directories: Vec<ChildJob>,
    pub static_entries: Vec<EntryReport>,
    pub file_logical: u64,
    pub file_allocated: Option<u64>,
    pub mode: ScanMode,
    pub cancel: CancelFlag,
    pub errors: ErrorStats,
    pub show_files: bool,
    pub delete_permanent: bool,
    pub msg_tx: Option<mpsc::Sender<AppMessage>>,
}

/// The main TUI application state.
///
/// `App` is responsible for:
/// * **State Management**: Tracking the current directory, navigation history, and selection.
/// * **Event Handling**: Processing user input (keyboard) and async messages from the scanner.
/// * **Rendering preparation**: Calculating visible rows and formatting data for the `ratatui` draw cycle.
///
/// It manages the lifecycle of a single scan session. Navigation to a new directory
/// essentially replaces the `App` instance (managed by the runner loop).
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
    rows_cache: Vec<RowData>,
    rows_dirty: bool,
    show_files: bool,
    delete_permanent: bool,
    confirm_delete: Option<PathBuf>,
    msg_tx: Option<mpsc::Sender<AppMessage>>,
    deleting: bool,
    error_popup: Option<String>,
}
impl App {
    /// Creates a new TUI application instance.
    pub fn new(params: AppParams) -> Self {
        let AppParams {
            target,
            directories,
            static_entries,
            file_logical,
            file_allocated,
            mode,
            cancel,
            errors,
            show_files,
            delete_permanent,
            msg_tx,
        } = params;
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
            rows_cache: Vec::new(),
            rows_dirty: true,
            show_files,
            delete_permanent,
            confirm_delete: None,
            msg_tx,
            deleting: false,
            error_popup: None,
        }
    }

    pub fn handle_message(&mut self, message: AppMessage) {
        match message {
            AppMessage::DirectoryStarted(path) => self.mark_started(&path),
            AppMessage::DirectoryFinished(report) => self.apply_report(report),
            AppMessage::AllDone => self.mark_all_done(),
            AppMessage::DeleteStarted => {
                self.deleting = true;
            }
            AppMessage::DeleteSuccess(path) => {
                self.deleting = false;
                // Remove from lists
                if let Some(idx) = self.directories.iter().position(|d| d.path == path) {
                    self.directories.remove(idx);
                } else if let Some(idx) = self.static_entries.iter().position(|e| e.path == path) {
                    self.static_entries.remove(idx);
                }
                self.rows_dirty = true;
                let total = self.total_rows();
                self.ensure_selection_bounds(total);
            }
            AppMessage::DeleteFailed(path, error) => {
                self.deleting = false;
                self.errors.record(ScanErrorKind::Other);
                self.error_popup = Some(format!("Failed to delete {}:\n{}", path.display(), error));
            }
        }
        self.rows_dirty = true;
        let total = self.total_rows();
        self.ensure_selection_bounds(total);
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Option<AppAction> {
        if key.kind != KeyEventKind::Press {
            return None;
        }

        // If error popup is open, any key closes it
        if self.error_popup.is_some() {
            self.error_popup = None;
            return None;
        }

        if self.deleting {
            // Ignore input while deleting
            return None;
        }

        if self.confirm_delete.is_some() {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    self.execute_delete();
                    self.confirm_delete = None;
                    return None;
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    self.confirm_delete = None;
                    return None;
                }
                _ => return None,
            }
        }

        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => {
                self.should_quit = true;
                self.cancel.cancel();
                self.errors.record(ScanErrorKind::Cancelled);
                None
            }
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.should_quit = true;
                self.cancel.cancel();
                self.errors.record(ScanErrorKind::Cancelled);
                None
            }
            KeyCode::Char('s') | KeyCode::Char('S') => {
                self.cycle_sort();
                None
            }
            KeyCode::Char('x') | KeyCode::Char('X') | KeyCode::Delete => {
                self.prepare_delete();
                None
            }
            KeyCode::Down => {
                self.move_selection_by(1);
                None
            }
            KeyCode::Up => {
                self.move_selection_by(-1);
                None
            }
            KeyCode::PageDown => {
                self.move_page(1);
                None
            }
            KeyCode::PageUp => {
                self.move_page(-1);
                None
            }
            KeyCode::Home => {
                self.move_to_top();
                None
            }
            KeyCode::End => {
                self.move_to_bottom();
                None
            }
            KeyCode::Enter => self.activate_selection(),
            KeyCode::Backspace => Some(AppAction::GoBack),
            _ => None,
        }
    }

    fn prepare_delete(&mut self) {
        self.ensure_rows();
        if self.rows_cache.is_empty() {
            return;
        }
        let index = self.selected.min(self.rows_cache.len() - 1);
        let path = match &self.rows_cache[index].origin {
            RowOrigin::Directory(path) => Some(path.clone()),
            RowOrigin::File(path) => Some(path.clone()),
            _ => None,
        };
        self.confirm_delete = path;
    }

    fn execute_delete(&mut self) {
        if let Some(path) = &self.confirm_delete {
            if let Some(tx) = &self.msg_tx {
                let tx = tx.clone();
                let path = path.clone();
                let permanent = self.delete_permanent;
                
                // Notify start
                let _ = tx.send(AppMessage::DeleteStarted);

                thread::spawn(move || {
                    let result = Self::perform_deletion(&path, permanent);

                    match result {
                        Ok(_) => {
                            let _ = tx.send(AppMessage::DeleteSuccess(path));
                        }
                        Err(e) => {
                            let _ = tx.send(AppMessage::DeleteFailed(path, e.to_string()));
                        }
                    }
                });
            }
        }
    }
    
    fn perform_deletion(path: &Path, permanent: bool) -> std::result::Result<(), Box<dyn std::error::Error>> {
        #[cfg(windows)]
        {
            use windows::Win32::UI::Shell::{SHFileOperationW, SHFILEOPSTRUCTW, FO_DELETE, FOF_NOCONFIRMATION, FOF_NOERRORUI, FOF_SILENT, FOF_ALLOWUNDO};
            use std::os::windows::ffi::OsStrExt;

            // SHFileOperation requires double-null terminated strings
            let mut wide_path: Vec<u16> = path.as_os_str().encode_wide().collect();
            wide_path.push(0);
            wide_path.push(0);

            let mut flags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
            if !permanent {
                flags |= FOF_ALLOWUNDO;
            }

            let mut op = SHFILEOPSTRUCTW {
                hwnd: windows::Win32::Foundation::HWND(0),
                wFunc: FO_DELETE,
                pFrom: windows::core::PCWSTR(wide_path.as_ptr()),
                pTo: windows::core::PCWSTR::null(),
                fFlags: flags.0 as u16,
                fAnyOperationsAborted: false.into(),
                hNameMappings: std::ptr::null_mut(),
                lpszProgressTitle: windows::core::PCWSTR::null(),
            };

            let result = unsafe { SHFileOperationW(&mut op) };
            
            if result != 0 {
                 return Err(Box::new(std::io::Error::from_raw_os_error(result)));
            }
            if bool::from(op.fAnyOperationsAborted) {
                 return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Interrupted, "Operation aborted")));
            }
            
            return Ok(());
        }

        #[cfg(not(windows))]
        {
            if permanent {
                // Try standard deletion first
                let result = if path.is_dir() {
                     fs::remove_dir_all(path)
                } else {
                     fs::remove_file(path)
                };
                
                if result.is_ok() {
                    return Ok(());
                }

                // If failed, try to strip Read-Only attribute and retry
                if let Ok(metadata) = fs::metadata(path) {
                    let mut permissions = metadata.permissions();
                    if permissions.readonly() {
                        permissions.set_readonly(false);
                        let _ = fs::set_permissions(path, permissions);
                         // Retry
                        if path.is_dir() {
                             fs::remove_dir_all(path)?;
                        } else {
                             fs::remove_file(path)?;
                        }
                        return Ok(());
                    }
                }

                // If still failed, propagate original error
                result.map_err(|e| e.into())
            } else {
                trash::delete(path).map_err(|e| e.into())
            }
        }
    }

    fn cycle_sort(&mut self) {
        self.sort_mode = self.sort_mode.next();
        self.rows_dirty = true;
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
        if self.target.parent().is_some() {
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

    fn activate_selection(&mut self) -> Option<AppAction> {
        self.ensure_rows();
        if self.rows_cache.is_empty() {
            return None;
        }
        let index = self.selected.min(self.rows_cache.len() - 1);
        match &self.rows_cache[index].origin {
            RowOrigin::Directory(path) => Some(AppAction::ChangeDirectory(path.clone())),
            RowOrigin::Parent => Some(AppAction::GoBack),
            _ => None,
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

    pub fn tick(&mut self) {}

    pub fn should_exit(&self) -> bool {
        self.should_quit
    }

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

    pub fn total_allocated(&self) -> Option<u64> {
        match self.mode {
            ScanMode::Fast => None,
            ScanMode::Accurate => {
                // FIX: Use unwrap_or(0) to ignore errors instead of returning None
                let mut total = self.file_allocated.unwrap_or(0);

                for entry in &self.static_entries {
                    total += entry.allocated_size.unwrap_or(0);
                }

                for directory in &self.directories {
                    if let DirectoryStatus::Finished(report) = &directory.status {
                        total += report.allocated_size.unwrap_or(0);
                    } else {
                        // If a directory is still pending/running, we genuinely can't know the total yet
                        return None;
                    }
                }
                Some(total)
            }
        }
    }

    pub fn errors(&self) -> &ErrorStats {
        &self.errors
    }

    pub fn target(&self) -> &Path {
        &self.target
    }

    pub fn request_cancel(&self) {
        self.cancel.cancel();
    }

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

        // FIX: Robust summation that doesn't fail if one entry is None
        let mut total_allocated = match (self.mode, self.file_allocated) {
            (ScanMode::Accurate, _) => Some(self.file_allocated.unwrap_or(0)),
            _ => None,
        };

        if let Some(acc) = total_allocated.as_mut() {
            for entry in &entries {
                *acc += entry.allocated_size.unwrap_or(0);
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

    fn ensure_rows(&mut self) {
        if self.rows_dirty {
            self.rows_cache = self.collect_rows();
            self.rows_dirty = false;
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
                        origin: RowOrigin::Directory(directory.path.clone()),
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
                        origin: RowOrigin::Directory(directory.path.clone()),
                    });
                }
                DirectoryStatus::Finished(report) => {
                    let mut data = RowData::from_entry(
                        report,
                        total_logical,
                        RowOrigin::Directory(directory.path.clone()),
                    );
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
            rows.push(RowData::from_entry(
                entry,
                total_logical,
                RowOrigin::File(entry.path.clone()),
            ));
        }

        if self.file_logical > 0 && !self.show_files {
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
                origin: RowOrigin::Files,
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

        if self.target.parent().is_some() {
            rows.insert(
                0,
                RowData {
                    name: "..".to_string(),
                    name_key: "..".to_string(),
                    logical_sort: None,
                    modified_sort: None,
                    type_label: "UP".to_string(),
                    status: String::new(),
                    logical_text: String::new(),
                    allocated_text: String::new(),
                    modified_text: String::new(),
                    ads_text: String::new(),
                    percent_text: String::new(),
                    style: Style::default().fg(Color::Cyan),
                    origin: RowOrigin::Parent,
                },
            );
        }

        rows
    }

    fn visible_rows(&mut self, viewport: usize) -> Vec<Row<'static>> {
        let viewport = viewport.max(1);
        self.ensure_rows();
        let total = self.rows_cache.len();
        self.last_viewport = viewport;
        if total == 0 {
            self.selected = 0;
            self.offset = 0;
            return Vec::new();
        }

        self.ensure_selection_bounds(total);

        let start = self.offset;
        let end = (start + viewport).min(total);
        let mut rows = Vec::with_capacity(end.saturating_sub(start));
        for (idx, row) in self.rows_cache[start..end].iter().enumerate() {
            let absolute_index = start + idx;
            rows.push(row.clone().into_row(absolute_index == self.selected));
        }
        rows
    }
}

use ratatui::layout::{Alignment, Rect};
use ratatui::widgets::Clear;

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

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
        Line::from(
            "Keys: q/Esc quit | Enter open dir | Backspace go back | s change sort | Up/Down move | PgUp/PgDn, Home/End page | x/Del delete",
        ),
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

    // 1. Confirmation Popup
    if let Some(path) = &app.confirm_delete {
        let block = Block::default()
            .title("Confirm Deletion")
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::Red));
        let area = centered_rect(60, 25, frame.size());
        frame.render_widget(Clear, area); // Clear background behind popup

        let method = if app.delete_permanent {
            "PERMANENTLY DELETE"
        } else {
            "Move to TRASH"
        };

        let text = vec![
            Line::from(format!("ACTION: {}", method)).alignment(Alignment::Center).style(Style::default().add_modifier(Modifier::BOLD)),
            Line::from("").alignment(Alignment::Center),
            Line::from(format!("Target: {}", path.display())).alignment(Alignment::Center),
            Line::from("").alignment(Alignment::Center),
            Line::from("Press [Y] to CONFIRM").alignment(Alignment::Center).style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            Line::from("Press [N] or [Esc] to CANCEL").alignment(Alignment::Center),
        ];

        let paragraph = Paragraph::new(text)
            .block(block)
            .alignment(Alignment::Center);
        frame.render_widget(paragraph, area);
    }

    // 2. Deletion In-Progress Popup
    if app.deleting {
         let block = Block::default()
            .title("Deleting...")
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::Yellow));
        let area = centered_rect(40, 10, frame.size());
        frame.render_widget(Clear, area); 
        
        let text = vec![
            Line::from("Deleting selected item...").alignment(Alignment::Center),
            Line::from("Please wait.").alignment(Alignment::Center),
        ];
         let paragraph = Paragraph::new(text)
            .block(block)
            .alignment(Alignment::Center);
        frame.render_widget(paragraph, area);
    }

    // 3. Error Popup
    if let Some(err_msg) = &app.error_popup {
        let block = Block::default()
            .title("Deletion Error")
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::Red));
        let area = centered_rect(60, 20, frame.size());
        frame.render_widget(Clear, area);

        let text = vec![
            Line::from("An error occurred during deletion:").alignment(Alignment::Center),
             Line::from("").alignment(Alignment::Center),
            Line::from(err_msg.as_str()).alignment(Alignment::Center),
             Line::from("").alignment(Alignment::Center),
            Line::from("Press any key to close").alignment(Alignment::Center),
        ];
        
        let paragraph = Paragraph::new(text)
            .block(block)
            .alignment(Alignment::Center)
            .wrap(ratatui::widgets::Wrap { trim: true });
        frame.render_widget(paragraph, area);
    }
}
