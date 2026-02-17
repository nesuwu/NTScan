use std::fs;
use std::io;
use std::path::PathBuf;

use crate::model::ScanMode;

const SETTINGS_ENV_PATH: &str = "NTSCAN_SETTINGS_PATH";
pub const DEFAULT_DUPLICATE_MIN_SIZE: u64 = 1_048_576;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThemePreset {
    Default,
    Ocean,
    Amber,
    Forest,
}

impl ThemePreset {
    pub fn as_str(self) -> &'static str {
        match self {
            ThemePreset::Default => "default",
            ThemePreset::Ocean => "ocean",
            ThemePreset::Amber => "amber",
            ThemePreset::Forest => "forest",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ThemePreset::Default => "Default",
            ThemePreset::Ocean => "Ocean",
            ThemePreset::Amber => "Amber",
            ThemePreset::Forest => "Forest",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        if value.eq_ignore_ascii_case("default") {
            Some(ThemePreset::Default)
        } else if value.eq_ignore_ascii_case("ocean") {
            Some(ThemePreset::Ocean)
        } else if value.eq_ignore_ascii_case("amber") {
            Some(ThemePreset::Amber)
        } else if value.eq_ignore_ascii_case("forest") {
            Some(ThemePreset::Forest)
        } else {
            None
        }
    }

    pub fn next(self) -> Self {
        match self {
            ThemePreset::Default => ThemePreset::Ocean,
            ThemePreset::Ocean => ThemePreset::Amber,
            ThemePreset::Amber => ThemePreset::Forest,
            ThemePreset::Forest => ThemePreset::Default,
        }
    }

    pub fn previous(self) -> Self {
        match self {
            ThemePreset::Default => ThemePreset::Forest,
            ThemePreset::Ocean => ThemePreset::Default,
            ThemePreset::Amber => ThemePreset::Ocean,
            ThemePreset::Forest => ThemePreset::Amber,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppSettings {
    pub default_mode: ScanMode,
    pub default_follow_symlinks: bool,
    pub default_show_files: bool,
    pub default_delete_permanent: bool,
    pub min_duplicate_size: u64,
    pub scan_cache_path: Option<PathBuf>,
    pub hash_cache_path: Option<PathBuf>,
    pub theme: ThemePreset,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            default_mode: ScanMode::Fast,
            default_follow_symlinks: false,
            default_show_files: false,
            default_delete_permanent: false,
            min_duplicate_size: DEFAULT_DUPLICATE_MIN_SIZE,
            scan_cache_path: None,
            hash_cache_path: None,
            theme: ThemePreset::Default,
        }
    }
}

pub fn load_settings() -> AppSettings {
    try_load_settings().unwrap_or_default()
}

pub fn try_load_settings() -> io::Result<AppSettings> {
    let path = settings_file_path();
    if !path.exists() {
        return Ok(AppSettings::default());
    }

    let content = fs::read_to_string(path)?;
    Ok(parse_settings(&content))
}

pub fn save_settings(settings: &AppSettings) -> io::Result<()> {
    let path = settings_file_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serialize_settings(settings))
}

fn settings_file_path() -> PathBuf {
    if let Some(path) = std::env::var_os(SETTINGS_ENV_PATH) {
        let path = PathBuf::from(path);
        if !path.as_os_str().is_empty() {
            return path;
        }
    }

    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        let mut path = PathBuf::from(local_app_data);
        path.push("ntscan");
        path.push("settings.conf");
        return path;
    }

    std::env::temp_dir().join("ntscan.settings.conf")
}

fn parse_settings(content: &str) -> AppSettings {
    let mut settings = AppSettings::default();

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };

        let key = key.trim();
        let value = value.trim();

        match key {
            "default_mode" => {
                if value.eq_ignore_ascii_case("fast") {
                    settings.default_mode = ScanMode::Fast;
                } else if value.eq_ignore_ascii_case("accurate") {
                    settings.default_mode = ScanMode::Accurate;
                }
            }
            "default_follow_symlinks" => {
                if let Some(v) = parse_bool(value) {
                    settings.default_follow_symlinks = v;
                }
            }
            "default_show_files" => {
                if let Some(v) = parse_bool(value) {
                    settings.default_show_files = v;
                }
            }
            "default_delete_permanent" => {
                if let Some(v) = parse_bool(value) {
                    settings.default_delete_permanent = v;
                }
            }
            "min_duplicate_size" => {
                if let Ok(v) = value.parse::<u64>() {
                    settings.min_duplicate_size = v;
                }
            }
            "scan_cache_path" => {
                settings.scan_cache_path = parse_optional_path(value);
            }
            "hash_cache_path" => {
                settings.hash_cache_path = parse_optional_path(value);
            }
            "theme" => {
                if let Some(theme) = ThemePreset::from_str(value) {
                    settings.theme = theme;
                }
            }
            _ => {}
        }
    }

    settings
}

fn serialize_settings(settings: &AppSettings) -> String {
    let mode = match settings.default_mode {
        ScanMode::Fast => "fast",
        ScanMode::Accurate => "accurate",
    };

    let scan_cache_path = settings
        .scan_cache_path
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let hash_cache_path = settings
        .hash_cache_path
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();

    format!(
        concat!(
            "# NTScan settings file\n",
            "# Empty cache paths mean \"auto\".\n",
            "default_mode={mode}\n",
            "default_follow_symlinks={follow}\n",
            "default_show_files={show_files}\n",
            "default_delete_permanent={delete_permanent}\n",
            "min_duplicate_size={min_duplicate_size}\n",
            "scan_cache_path={scan_cache_path}\n",
            "hash_cache_path={hash_cache_path}\n",
            "theme={theme}\n"
        ),
        mode = mode,
        follow = settings.default_follow_symlinks,
        show_files = settings.default_show_files,
        delete_permanent = settings.default_delete_permanent,
        min_duplicate_size = settings.min_duplicate_size,
        scan_cache_path = scan_cache_path,
        hash_cache_path = hash_cache_path,
        theme = settings.theme.as_str(),
    )
}

fn parse_bool(value: &str) -> Option<bool> {
    if value.eq_ignore_ascii_case("true")
        || value.eq_ignore_ascii_case("yes")
        || value == "1"
        || value.eq_ignore_ascii_case("on")
    {
        Some(true)
    } else if value.eq_ignore_ascii_case("false")
        || value.eq_ignore_ascii_case("no")
        || value == "0"
        || value.eq_ignore_ascii_case("off")
    {
        Some(false)
    } else {
        None
    }
}

fn parse_optional_path(value: &str) -> Option<PathBuf> {
    if value.is_empty() {
        None
    } else {
        Some(PathBuf::from(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_round_trip_preserves_values() {
        let settings = AppSettings {
            default_mode: ScanMode::Accurate,
            default_follow_symlinks: true,
            default_show_files: true,
            default_delete_permanent: true,
            min_duplicate_size: 42,
            scan_cache_path: Some(PathBuf::from("C:\\cache\\scan.cache")),
            hash_cache_path: Some(PathBuf::from("C:\\cache\\hash.cache")),
            theme: ThemePreset::Forest,
        };

        let encoded = serialize_settings(&settings);
        let decoded = parse_settings(&encoded);

        assert_eq!(decoded, settings);
    }

    #[test]
    fn parse_settings_ignores_invalid_values() {
        let parsed = parse_settings(
            "default_mode=unknown\n\
             default_follow_symlinks=maybe\n\
             min_duplicate_size=abc\n\
             theme=invalid\n",
        );

        assert_eq!(parsed, AppSettings::default());
    }
}
