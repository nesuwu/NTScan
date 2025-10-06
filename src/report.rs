use crate::model::DirectoryReport;
use crate::util::fmt_bytes;

/// Formats a byte count using binary units.
///
/// ```rust
/// use ntscan::report::format_size;
/// assert_eq!(format_size(1024), "1.00 KiB");
/// ```
pub use crate::util::fmt_bytes as format_size;

/// Prints a tabular directory report to STDOUT.
///
/// ```rust
/// use ntscan::model::DirectoryReport;
/// use ntscan::report::print_report;
///
/// let report = DirectoryReport {
///     path: std::path::PathBuf::from("."),
///     mtime: None,
///     logical_size: 0,
///     allocated_size: None,
///     entries: Vec::new(),
/// };
/// print_report(&report);
/// ```
pub fn print_report(report: &DirectoryReport) {
    println!("Target: {}", report.path.display());
    println!("Logical total: {}", fmt_bytes(report.logical_size));
    if let Some(allocated) = report.allocated_size {
        println!("Allocated total: {}", fmt_bytes(allocated));
    } else {
        println!("Allocated total: n/a (fast mode or partial data)");
    }
    println!("Items: {}", report.entries.len());
    println!("-");
    println!(
        "{:<45} {:>7} {:>14} {:>14} {:>9} {:>8}",
        "Name", "Type", "Logical", "Allocated", "ADS", "%"
    );
    println!(
        "{:-<45} {:-<7} {:-<14} {:-<14} {:-<9} {:-<8}",
        "", "", "", "", "", ""
    );

    for entry in &report.entries {
        let allocated = entry
            .allocated_size
            .map(fmt_bytes)
            .unwrap_or_else(|| String::from("-"));
        let ads_info = if entry.ads_count > 0 {
            fmt_bytes(entry.ads_bytes)
        } else {
            String::from("-")
        };
        let percent = format!("{:.2}", entry.percent_of_parent);
        let label = entry.kind.short_label();
        println!(
            "{:<45} {:>7} {:>14} {:>14} {:>9} {:>8}",
            entry.name,
            label,
            fmt_bytes(entry.logical_size),
            allocated,
            ads_info,
            percent,
        );
        if let Some(error) = &entry.error {
            println!("    ! {}", error);
        }
    }
}
