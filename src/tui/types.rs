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
use crate::settings::{
    AppSettings, ThemePreset, format_hex_color, parse_hex_color, save_settings,
};
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
    /// Settings changed in a way that requires restarting the scan session
    /// (mode, symlinks, show-files, scan cache path).
    ApplySettings(AppSettings),
    /// Settings changed cosmetically (theme, delete mode, duplicate options);
    /// the runner only refreshes its copy — no rescan.
    UpdateSettings(AppSettings),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Available sorting columns for the file list.
enum SortKey {
    Name,
    Size,
    Date,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Sort column plus direction. `reverse == false` is the key's natural
/// direction: name ascending, size and date descending.
struct SortMode {
    key: SortKey,
    reverse: bool,
}

impl SortMode {
    const DEFAULT: SortMode = SortMode {
        key: SortKey::Size,
        reverse: false,
    };

    /// Pressing a sort key switches to it in its natural direction;
    /// pressing the active key again flips the direction.
    fn toggle(self, key: SortKey) -> Self {
        SortMode {
            key,
            reverse: self.key == key && !self.reverse,
        }
    }

    fn label(self) -> String {
        let name = match self.key {
            SortKey::Name => "name",
            SortKey::Size => "size",
            SortKey::Date => "date",
        };
        format!("{} {}", name, self.arrow())
    }

    /// Current direction as a table-header arrow.
    fn arrow(self) -> &'static str {
        let natural_ascending = self.key == SortKey::Name;
        if natural_ascending != self.reverse {
            "▲"
        } else {
            "▼"
        }
    }
}

/// Renders a compact usage bar like `███░░░░░  42.1` for a percentage.
fn percent_bar(percent: f64) -> String {
    const WIDTH: usize = 8;
    let clamped = if percent.is_finite() {
        percent.clamp(0.0, 100.0)
    } else {
        0.0
    };
    let filled = ((clamped / 100.0) * WIDTH as f64).round() as usize;
    let mut bar = String::with_capacity(WIDTH * 3 + 6);
    for i in 0..WIDTH {
        bar.push(if i < filled { '█' } else { '░' });
    }
    format!("{} {:>5.1}", bar, clamped)
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
    /// Resolves the palette for the active theme; `Custom` reads the
    /// user-defined hex colors.
    fn from_settings(settings: &AppSettings) -> Self {
        if settings.theme == ThemePreset::Custom {
            let rgb = |(r, g, b): (u8, u8, u8)| Color::Rgb(r, g, b);
            let colors = settings.custom_colors;
            return Self {
                ok: rgb(colors.ok),
                error: rgb(colors.error),
                pending: rgb(colors.pending),
                running: rgb(colors.running),
                parent: rgb(colors.parent),
                border: rgb(colors.border),
            };
        }
        Self::from_theme(settings.theme)
    }

    fn from_theme(theme: ThemePreset) -> Self {
        match theme {
            // Custom is resolved in from_settings; this arm is unreachable
            // there but keeps the match total.
            ThemePreset::Custom => Self::from_theme(ThemePreset::Default),
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SettingsField {
    Theme,
    CustomOk,
    CustomError,
    CustomPending,
    CustomRunning,
    CustomParent,
    CustomBorder,
    DefaultMode,
    FollowSymlinks,
    ShowFiles,
    DeletePermanent,
    DuplicateMinSize,
    ScanCachePath,
    HashCachePath,
}

impl SettingsField {
    const CUSTOM_COLORS: [SettingsField; 6] = [
        SettingsField::CustomOk,
        SettingsField::CustomError,
        SettingsField::CustomPending,
        SettingsField::CustomRunning,
        SettingsField::CustomParent,
        SettingsField::CustomBorder,
    ];

    const COMMON: [SettingsField; 7] = [
        SettingsField::DefaultMode,
        SettingsField::FollowSymlinks,
        SettingsField::ShowFiles,
        SettingsField::DeletePermanent,
        SettingsField::DuplicateMinSize,
        SettingsField::ScanCachePath,
        SettingsField::HashCachePath,
    ];

    /// Fields shown for the current draft: the six hex-color rows only
    /// appear while the theme is Custom.
    fn visible(draft: &AppSettings) -> Vec<SettingsField> {
        let mut fields = vec![SettingsField::Theme];
        if draft.theme == ThemePreset::Custom {
            fields.extend(Self::CUSTOM_COLORS);
        }
        fields.extend(Self::COMMON);
        fields
    }

    fn label(self) -> &'static str {
        match self {
            SettingsField::Theme => "Theme",
            SettingsField::CustomOk => "Color: done",
            SettingsField::CustomError => "Color: error",
            SettingsField::CustomPending => "Color: pending",
            SettingsField::CustomRunning => "Color: running",
            SettingsField::CustomParent => "Color: parent",
            SettingsField::CustomBorder => "Color: border",
            SettingsField::DefaultMode => "Scan mode",
            SettingsField::FollowSymlinks => "Follow symlinks",
            SettingsField::ShowFiles => "Show files",
            SettingsField::DeletePermanent => "Permanent delete",
            SettingsField::DuplicateMinSize => "Duplicate min size",
            SettingsField::ScanCachePath => "Scan cache path",
            SettingsField::HashCachePath => "Hash cache path",
        }
    }

    /// Section heading rendered above the first field of each group.
    fn section(self) -> &'static str {
        match self {
            SettingsField::Theme
            | SettingsField::CustomOk
            | SettingsField::CustomError
            | SettingsField::CustomPending
            | SettingsField::CustomRunning
            | SettingsField::CustomParent
            | SettingsField::CustomBorder => "Appearance",
            SettingsField::DefaultMode | SettingsField::FollowSymlinks | SettingsField::ShowFiles => {
                "Scanning"
            }
            SettingsField::DeletePermanent => "Deletion",
            SettingsField::DuplicateMinSize => "Duplicates",
            SettingsField::ScanCachePath | SettingsField::HashCachePath => "Cache locations",
        }
    }

    /// One-line explanation shown for the selected field.
    fn description(self) -> &'static str {
        match self {
            SettingsField::Theme => {
                "Color palette. Previewed live. Custom unlocks per-color hex fields below."
            }
            SettingsField::CustomOk
            | SettingsField::CustomError
            | SettingsField::CustomPending
            | SettingsField::CustomRunning
            | SettingsField::CustomParent
            | SettingsField::CustomBorder => {
                "Hex color like #a6e3a1 (or #fff). Enter types a value; previewed live."
            }
            SettingsField::DefaultMode => {
                "Fast counts logical sizes only; Accurate adds on-disk allocation and ADS (slower)."
            }
            SettingsField::FollowSymlinks => {
                "Descend into directory symlinks and junctions. Cycles are detected and skipped."
            }
            SettingsField::ShowFiles => "List individual files instead of one combined [files] row.",
            SettingsField::DeletePermanent => {
                "When ON, Del/x bypasses the Recycle Bin. It still asks for confirmation."
            }
            SettingsField::DuplicateMinSize => {
                "Files smaller than this are ignored by --duplicates. Enter types an exact byte count."
            }
            SettingsField::ScanCachePath => {
                "File for the per-file attribute cache. Empty = auto (%LOCALAPPDATA%\\ntscan)."
            }
            SettingsField::HashCachePath => {
                "File for the duplicate-hash cache. Empty = auto (%LOCALAPPDATA%\\ntscan)."
            }
        }
    }

    /// Rendered value for the field, shared by the popup and change markers.
    fn display_value(self, settings: &AppSettings) -> String {
        match self {
            SettingsField::Theme => settings.theme.label().to_string(),
            SettingsField::CustomOk => format_hex_color(settings.custom_colors.ok),
            SettingsField::CustomError => format_hex_color(settings.custom_colors.error),
            SettingsField::CustomPending => format_hex_color(settings.custom_colors.pending),
            SettingsField::CustomRunning => format_hex_color(settings.custom_colors.running),
            SettingsField::CustomParent => format_hex_color(settings.custom_colors.parent),
            SettingsField::CustomBorder => format_hex_color(settings.custom_colors.border),
            SettingsField::DefaultMode => settings.default_mode.label().to_string(),
            SettingsField::FollowSymlinks => bool_label(settings.default_follow_symlinks).to_string(),
            SettingsField::ShowFiles => bool_label(settings.default_show_files).to_string(),
            SettingsField::DeletePermanent => {
                bool_label(settings.default_delete_permanent).to_string()
            }
            SettingsField::DuplicateMinSize => format_size(settings.min_duplicate_size),
            SettingsField::ScanCachePath => settings
                .scan_cache_path
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|| String::from("(auto)")),
            SettingsField::HashCachePath => settings
                .hash_cache_path
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|| String::from("(auto)")),
        }
    }

    fn is_changed(self, draft: &AppSettings, saved: &AppSettings) -> bool {
        self.display_value(draft) != self.display_value(saved)
    }

    fn is_text(self) -> bool {
        matches!(
            self,
            SettingsField::DuplicateMinSize
                | SettingsField::ScanCachePath
                | SettingsField::HashCachePath
                | SettingsField::CustomOk
                | SettingsField::CustomError
                | SettingsField::CustomPending
                | SettingsField::CustomRunning
                | SettingsField::CustomParent
                | SettingsField::CustomBorder
        )
    }
}

/// True when the change can't be applied to the running session and needs a
/// fresh scan (different cache, options that alter traversal or output).
fn settings_require_restart(a: &AppSettings, b: &AppSettings) -> bool {
    a.default_mode != b.default_mode
        || a.default_follow_symlinks != b.default_follow_symlinks
        || a.default_show_files != b.default_show_files
        || a.scan_cache_path != b.scan_cache_path
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
        let status = if entry.is_skipped() {
            "SKIP".to_string()
        } else if entry.error.is_some() {
            "ERR".to_string()
        } else {
            "DONE".to_string()
        };
        let style = if entry.is_skipped() {
            Style::default().fg(palette.pending)
        } else if entry.error.is_some() {
            Style::default().fg(palette.error)
        } else {
            Style::default().fg(palette.ok)
        };
        let logical_text = format_size(entry.logical_size);
        let allocated_text = match entry.allocated_size {
            Some(allocated) => {
                let mut text = format_size(allocated);
                if !entry.allocated_complete {
                    text.push_str(" (partial)");
                }
                text
            }
            None => "-".to_string(),
        };
        let ads_text = if entry.ads_count > 0 {
            format_size(entry.ads_bytes)
        } else {
            "-".to_string()
        };
        let (modified_sort, modified_text) = format_modified(entry.modified);
        let percent_text = if total_logical > 0 {
            percent_bar((entry.logical_size as f64 / total_logical as f64) * 100.0)
        } else {
            percent_bar(0.0)
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

    /// Builds the table row. `show_accurate` controls whether the
    /// Allocated/ADS columns exist at all — Fast mode never fills them, so
    /// the table drops them instead of printing dashes.
    fn into_row(self, highlighted: bool, show_accurate: bool) -> Row<'static> {
        let highlight_style = Style::default().add_modifier(Modifier::REVERSED);
        let style = if highlighted {
            self.style.patch(highlight_style)
        } else {
            self.style
        };
        let mut cells = vec![
            Cell::from(self.name),
            Cell::from(self.type_label),
            Cell::from(self.status),
            Cell::from(self.logical_text),
        ];
        if show_accurate {
            cells.push(Cell::from(self.allocated_text));
        }
        cells.push(Cell::from(self.modified_text));
        if show_accurate {
            cells.push(Cell::from(self.ads_text));
        }
        cells.push(Cell::from(self.percent_text));
        Row::new(cells).style(style)
    }
}
