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
use crate::settings::{AppSettings, ThemePreset, save_settings};
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
    ApplySettings(AppSettings),
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

#[derive(Clone, Copy)]
struct ThemePalette {
    ok: Color,
    error: Color,
    pending: Color,
    running: Color,
    parent: Color,
    border: Color,
}

impl ThemePalette {
    fn from_theme(theme: ThemePreset) -> Self {
        match theme {
            ThemePreset::Default => Self {
                ok: Color::Green,
                error: Color::Red,
                pending: Color::DarkGray,
                running: Color::Yellow,
                parent: Color::Cyan,
                border: Color::White,
            },
            ThemePreset::Ocean => Self {
                ok: Color::LightCyan,
                error: Color::LightRed,
                pending: Color::Blue,
                running: Color::LightBlue,
                parent: Color::Cyan,
                border: Color::Cyan,
            },
            ThemePreset::Amber => Self {
                ok: Color::LightYellow,
                error: Color::LightRed,
                pending: Color::Gray,
                running: Color::Yellow,
                parent: Color::LightMagenta,
                border: Color::Yellow,
            },
            ThemePreset::Forest => Self {
                ok: Color::LightGreen,
                error: Color::LightRed,
                pending: Color::DarkGray,
                running: Color::Green,
                parent: Color::LightCyan,
                border: Color::Green,
            },
        }
    }
}

#[derive(Clone, Copy)]
enum SettingsField {
    Theme,
    DefaultMode,
    FollowSymlinks,
    ShowFiles,
    DeletePermanent,
    DuplicateMinSize,
    ScanCachePath,
    HashCachePath,
}

impl SettingsField {
    const ALL: [SettingsField; 8] = [
        SettingsField::Theme,
        SettingsField::DefaultMode,
        SettingsField::FollowSymlinks,
        SettingsField::ShowFiles,
        SettingsField::DeletePermanent,
        SettingsField::DuplicateMinSize,
        SettingsField::ScanCachePath,
        SettingsField::HashCachePath,
    ];

    fn from_index(index: usize) -> Self {
        Self::ALL
            .get(index)
            .copied()
            .unwrap_or(SettingsField::Theme)
    }

    fn label(self) -> &'static str {
        match self {
            SettingsField::Theme => "Theme Colors",
            SettingsField::DefaultMode => "Default Scan Mode",
            SettingsField::FollowSymlinks => "Default Follow Symlinks",
            SettingsField::ShowFiles => "Default Show Files",
            SettingsField::DeletePermanent => "Default Permanent Delete",
            SettingsField::DuplicateMinSize => "Default Duplicate Min Size (bytes)",
            SettingsField::ScanCachePath => "Scan Cache Path",
            SettingsField::HashCachePath => "Hash Cache Path",
        }
    }

    fn is_text(self) -> bool {
        matches!(
            self,
            SettingsField::DuplicateMinSize
                | SettingsField::ScanCachePath
                | SettingsField::HashCachePath
        )
    }
}

#[derive(Clone)]
struct SettingsPopupState {
    selected: usize,
    editing: bool,
    input: String,
    draft: AppSettings,
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
    fn from_entry(
        entry: &EntryReport,
        total_logical: u64,
        origin: RowOrigin,
        palette: ThemePalette,
    ) -> Self {
        let name = entry.name.clone();
        let name_key = name.to_lowercase();
        let status = if entry.error.is_some() {
            "ERR".to_string()
        } else {
            "DONE".to_string()
        };
        let style = if entry.error.is_some() {
            Style::default().fg(palette.error)
        } else {
            Style::default().fg(palette.ok)
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

