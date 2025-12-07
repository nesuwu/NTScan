use clap::Parser;
use std::path::PathBuf;

use crate::model::ScanMode;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Parallel folder size scanner focusing on directory totals"
)]
pub struct Args {
    #[arg(default_value = ".", value_hint = clap::ValueHint::DirPath)]
    pub target: PathBuf,

    #[arg(
        long,
        conflicts_with = "accurate",
        help = "Force fast mode (metadata only)"
    )]
    pub fast: bool,

    #[arg(long, help = "Enable accurate mode (ADS + allocation size)")]
    pub accurate: bool,

    #[arg(
        long,
        help = "Follow directory symlinks and junctions (skips already visited targets)"
    )]
    pub follow_symlinks: bool,

    #[arg(long, help = "Print only the final table (legacy behavior)")]
    pub debug: bool,

    #[arg(long, help = "Find duplicate files by content hash")]
    pub duplicates: bool,

    #[arg(
        long,
        default_value = "1048576",
        help = "Minimum file size in bytes for duplicate detection"
    )]
    pub min_size: u64,

    #[arg(long, help = "List all files in the directory")]
    pub file: bool,

    #[arg(
        long,
        help = "Permanently delete files/folders (skipping trash) when using deletion features"
    )]
    pub delete_permanent: bool,
}

impl Args {
    pub fn resolve_mode(&self) -> ScanMode {
        if self.accurate && !self.fast {
            ScanMode::Accurate
        } else {
            ScanMode::Fast
        }
    }
}
