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
///     allocated_complete: true,
///     entries: Vec::new(),
/// };
/// print_report(&report);
/// ```
pub fn print_report(report: &DirectoryReport) {
    let skipped_count = report
        .entries
        .iter()
        .filter(|entry| entry.is_skipped())
        .count();

    println!("Target: {}", report.path.display());
    println!("Logical total: {}", fmt_bytes(report.logical_size));
    println!("{}", allocated_total_line(report));
    println!("Items: {}", report.entries.len());
    if skipped_count > 0 {
        println!("Skipped: {}", skipped_count);
    }
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
        if let Some(reason) = &entry.skip_reason {
            println!("    - skipped: {}", reason);
        }
    }
}

fn allocated_total_line(report: &DirectoryReport) -> String {
    match report.allocated_size {
        Some(allocated) if report.allocated_complete => {
            format!("Allocated total: {}", fmt_bytes(allocated))
        }
        Some(allocated) => {
            format!("Allocated total (partial): {}", fmt_bytes(allocated))
        }
        None => String::from("Allocated total: n/a (fast mode)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_allocated_totals_are_labeled() {
        let report = DirectoryReport {
            path: std::path::PathBuf::from("."),
            mtime: None,
            logical_size: 0,
            allocated_size: Some(4096),
            allocated_complete: false,
            entries: Vec::new(),
        };

        let line = allocated_total_line(&report);
        assert!(line.contains("(partial)"));
    }
}
