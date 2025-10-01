use clap::Parser;
use std::path::PathBuf;

use crate::model::ScanMode;

/// Command-line arguments for the folder sizing tool.
///
/// ```rust
/// use clap::Parser;
/// use ntscan::args::Args;
///
/// let args = Args::parse_from(["foldersizer-cli", "./some/path"]);
/// assert!(args.target.ends_with("some/path"));
/// ```
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
}

impl Args {
    /// Resolves the desired scanning mode based on the supplied flags.
    ///
    /// ```rust
    /// use ntscan::args::Args;
    /// use ntscan::model::ScanMode;
    /// use std::path::PathBuf;
    ///
    /// let args = Args {
    ///     target: PathBuf::from("."),
    ///     fast: false,
    ///     accurate: true,
    ///     follow_symlinks: false,
    ///     debug: false,
    /// };
    /// assert_eq!(args.resolve_mode(), ScanMode::Accurate);
    /// ```
    pub fn resolve_mode(&self) -> ScanMode {
        if self.accurate && !self.fast {
            ScanMode::Accurate
        } else {
            ScanMode::Fast
        }
    }
}
