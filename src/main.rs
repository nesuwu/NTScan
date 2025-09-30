use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::fs::{self, Metadata};
use std::io;
use std::os::windows::{ffi::OsStrExt, io::AsRawHandle};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use num_cpus;
use rayon::{ThreadPoolBuilder, prelude::*};
use windows::Win32::Foundation::{ERROR_HANDLE_EOF, HANDLE};
use windows::Win32::Storage::FileSystem::{
    FILE_STANDARD_INFO, FileStandardInfo, FindClose, FindFirstStreamW, FindNextStreamW,
    GetFileInformationByHandleEx, STREAM_INFO_LEVELS, WIN32_FIND_STREAM_DATA,
};
use windows::core::{HRESULT, PCWSTR};

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Parallel folder size scanner focusing on directory totals"
)]
struct Args {
    #[arg(default_value = ".", value_hint = clap::ValueHint::DirPath)]
    target: PathBuf,

    #[arg(
        long,
        conflicts_with = "accurate",
        help = "Force fast mode (metadata only)"
    )]
    fast: bool,

    #[arg(long, help = "Enable accurate mode (ADS + allocation size)")]
    accurate: bool,

    #[arg(
        long,
        help = "Follow directory symlinks and junctions (skips already visited targets)"
    )]
    follow_symlinks: bool,

    #[arg(long, help = "Print only the final table (legacy behavior)")]
    debug: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScanMode {
    Fast,
    Accurate,
}

#[derive(Clone, Copy)]
struct ScanOptions {
    mode: ScanMode,
    follow_symlinks: bool,
}

#[derive(Default)]
struct ScanCache {
    inner: Mutex<HashMap<PathBuf, Vec<CachedReport>>>,
}

#[derive(Clone)]
struct CachedReport {
    mode: ScanMode,
    mtime: Option<SystemTime>,
    report: DirectoryReport,
}

#[derive(Clone)]
struct DirectoryReport {
    path: PathBuf,
    mtime: Option<SystemTime>,
    logical_size: u64,
    allocated_size: Option<u64>,
    entries: Vec<EntryReport>,
}

#[derive(Clone)]
struct EntryReport {
    name: String,
    path: PathBuf,
    kind: EntryKind,
    logical_size: u64,
    allocated_size: Option<u64>,
    percent_of_parent: f64,
    ads_bytes: u64,
    ads_count: usize,
    error: Option<String>,
}

#[derive(Clone, Copy, Debug)]
enum EntryKind {
    Directory,
    SymlinkDirectory,
    Other,
    Skipped,
}

enum ProgressEvent {
    Started(PathBuf),
    CacheHit(PathBuf),
    Completed {
        path: PathBuf,
        logical: u64,
        allocated: Option<u64>,
    },
    EntryError {
        path: PathBuf,
        message: String,
    },
    Skipped(PathBuf, String),
}

#[derive(Default)]
struct Visited {
    seen: Mutex<HashSet<PathBuf>>,
}

#[derive(Clone)]
struct ScanContext {
    options: ScanOptions,
    cache: Arc<ScanCache>,
    visited: Arc<Visited>,
    progress: Option<Sender<ProgressEvent>>,
}

#[derive(Clone)]
struct ChildJob {
    name: String,
    path: PathBuf,
    was_symlink: bool,
}

struct DirectoryPlan {
    directories: Vec<ChildJob>,
    precomputed_entries: Vec<EntryReport>,
    file_logical: u64,
    file_allocated: Option<u64>,
}

#[derive(Default)]
struct AdsSummary {
    total_bytes: u64,
    count: usize,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let threads = std::cmp::max(1, (num_cpus::get() * 3) / 4);
    let _ = ThreadPoolBuilder::new().num_threads(threads).build_global();

    let mut mode = if args.accurate {
        ScanMode::Accurate
    } else {
        ScanMode::Fast
    };
    if args.fast {
        mode = ScanMode::Fast;
    }

    let options = ScanOptions {
        mode,
        follow_symlinks: args.follow_symlinks,
    };

    if args.debug {
        run_debug_mode(&args, options)?;
    } else {
        run_tui_mode(&args, options)?;
    }

    Ok(())
}

impl ScanContext {
    fn new(options: ScanOptions, progress: Option<Sender<ProgressEvent>>) -> Self {
        Self {
            options,
            cache: Arc::new(ScanCache::default()),
            visited: Arc::new(Visited::default()),
            progress,
        }
    }

    fn emit(&self, event: ProgressEvent) {
        if let Some(tx) = &self.progress {
            let _ = tx.send(event);
        }
    }

    fn mark_if_new(&self, path: PathBuf) -> bool {
        let mut guard = self.visited.seen.lock().unwrap();
        guard.insert(path)
    }
}

impl ScanCache {
    fn get(
        &self,
        path: &Path,
        mode: ScanMode,
        mtime: Option<SystemTime>,
    ) -> Option<DirectoryReport> {
        let guard = self.inner.lock().unwrap();
        guard.get(path).and_then(|records| {
            records
                .iter()
                .find(|record| record.mode == mode && record.mtime == mtime)
                .map(|record| record.report.clone())
        })
    }

    fn insert(
        &self,
        path: PathBuf,
        mode: ScanMode,
        mtime: Option<SystemTime>,
        report: DirectoryReport,
    ) {
        let mut guard = self.inner.lock().unwrap();
        let records = guard.entry(path).or_insert_with(Vec::new);
        if let Some(existing) = records.iter_mut().find(|rec| rec.mode == mode) {
            *existing = CachedReport {
                mode,
                mtime,
                report,
            };
        } else {
            records.push(CachedReport {
                mode,
                mtime,
                report,
            });
        }
    }
}

fn scan_directory(path: &Path, context: &ScanContext) -> Result<DirectoryReport> {
    context.emit(ProgressEvent::Started(path.to_path_buf()));

    let metadata = fs::metadata(path)
        .with_context(|| format!("metadata access failed for {}", path.display()))?;
    let mtime = metadata.modified().ok();

    if let Some(cached) = context.cache.get(path, context.options.mode, mtime) {
        context.emit(ProgressEvent::CacheHit(path.to_path_buf()));
        return Ok(cached);
    }

    let plan = prepare_directory_plan(path, context)?;
    let DirectoryPlan {
        directories,
        mut precomputed_entries,
        file_logical,
        file_allocated,
    } = plan;

    let mut dir_entries: Vec<EntryReport> = directories
        .into_par_iter()
        .map(|job| process_directory_child(job, context))
        .collect();

    precomputed_entries.append(&mut dir_entries);
    let mut entries = precomputed_entries;

    let directories_logical: u64 = entries.iter().map(|entry| entry.logical_size).sum();
    let total_logical = file_logical + directories_logical;

    let mut total_allocated = match (context.options.mode, file_allocated) {
        (ScanMode::Accurate, value) => value,
        _ => None,
    };

    if let Some(total) = total_allocated.as_mut() {
        for entry in &entries {
            if let Some(alloc) = entry.allocated_size {
                *total += alloc;
            } else {
                total_allocated = None;
                break;
            }
        }
    }

    for entry in &mut entries {
        entry.percent_of_parent = if total_logical == 0 {
            0.0
        } else {
            (entry.logical_size as f64 / total_logical as f64) * 100.0
        };
    }

    entries.sort_by(|a, b| match b.logical_size.cmp(&a.logical_size) {
        Ordering::Equal => a.name.cmp(&b.name),
        other => other,
    });

    let report = DirectoryReport {
        path: path.to_path_buf(),
        mtime,
        logical_size: total_logical,
        allocated_size: total_allocated,
        entries,
    };

    context.cache.insert(
        path.to_path_buf(),
        context.options.mode,
        mtime,
        report.clone(),
    );

    context.emit(ProgressEvent::Completed {
        path: path.to_path_buf(),
        logical: report.logical_size,
        allocated: report.allocated_size,
    });

    Ok(report)
}

fn prepare_directory_plan(path: &Path, context: &ScanContext) -> Result<DirectoryPlan> {
    let mut directories = Vec::new();
    let mut precomputed_entries = Vec::new();
    let mut file_logical = 0u64;
    let mut file_allocated = match context.options.mode {
        ScanMode::Fast => None,
        ScanMode::Accurate => Some(0u64),
    };

    let read_dir = fs::read_dir(path)
        .with_context(|| format!("failed to read directory {}", path.display()))?;

    for entry in read_dir {
        let entry = entry.with_context(|| format!("failed to iterate {}", path.display()))?;
        let name = entry.file_name().to_string_lossy().to_string();
        let entry_path = entry.path();

        let symlink_metadata = match fs::symlink_metadata(&entry_path) {
            Ok(meta) => meta,
            Err(err) => {
                context.emit(ProgressEvent::EntryError {
                    path: entry_path.clone(),
                    message: format!("symlink metadata error: {}", err),
                });
                precomputed_entries.push(entry_with_error(
                    name,
                    entry_path.clone(),
                    EntryKind::Other,
                    format!("symlink metadata error: {}", err),
                ));
                continue;
            }
        };

        let is_symlink = symlink_metadata.file_type().is_symlink();

        let target_metadata: Option<Metadata> = if is_symlink {
            if !context.options.follow_symlinks {
                context.emit(ProgressEvent::Skipped(
                    entry_path.clone(),
                    String::from("symlink not followed (use --follow-symlinks)"),
                ));
                precomputed_entries.push(entry_with_error(
                    name,
                    entry_path.clone(),
                    EntryKind::Skipped,
                    "symlink not followed (use --follow-symlinks)",
                ));
                continue;
            }
            match fs::metadata(&entry_path) {
                Ok(meta) => Some(meta),
                Err(err) => {
                    context.emit(ProgressEvent::EntryError {
                        path: entry_path.clone(),
                        message: format!("symlink target metadata failed: {}", err),
                    });
                    precomputed_entries.push(entry_with_error(
                        name,
                        entry_path.clone(),
                        EntryKind::Other,
                        format!("symlink target metadata failed: {}", err),
                    ));
                    continue;
                }
            }
        } else {
            Some(symlink_metadata)
        };

        let meta = match target_metadata {
            Some(m) => m,
            None => continue,
        };

        if meta.is_dir() {
            directories.push(ChildJob {
                name,
                path: entry_path,
                was_symlink: is_symlink,
            });
            continue;
        }

        if meta.is_file() {
            let (logical, allocated) = accumulate_file_sizes(&entry_path, &meta, context);
            file_logical += logical;
            if let Some(total) = file_allocated.as_mut() {
                if let Some(add) = allocated {
                    *total += add;
                } else {
                    file_allocated = None;
                }
            }
            continue;
        }

        precomputed_entries.push(entry_with_error(
            name,
            entry_path.clone(),
            EntryKind::Other,
            "unsupported entry type",
        ));
    }

    Ok(DirectoryPlan {
        directories,
        precomputed_entries,
        file_logical,
        file_allocated,
    })
}

fn process_directory_child(job: ChildJob, context: &ScanContext) -> EntryReport {
    if context.options.follow_symlinks && job.was_symlink {
        if let Ok(canon) = fs::canonicalize(&job.path) {
            if !context.mark_if_new(canon) {
                context.emit(ProgressEvent::Skipped(
                    job.path.clone(),
                    String::from("cycle detected"),
                ));
                return entry_with_error(
                    job.name,
                    job.path,
                    EntryKind::SymlinkDirectory,
                    "skipped (already visited target)",
                );
            }
        }
    }

    match scan_directory(&job.path, context) {
        Ok(report) => EntryReport {
            name: job.name,
            path: job.path,
            kind: if job.was_symlink {
                EntryKind::SymlinkDirectory
            } else {
                EntryKind::Directory
            },
            logical_size: report.logical_size,
            allocated_size: report.allocated_size,
            percent_of_parent: 0.0,
            ads_bytes: 0,
            ads_count: 0,
            error: None,
        },
        Err(err) => {
            context.emit(ProgressEvent::EntryError {
                path: job.path.clone(),
                message: format!("directory scan failed: {}", err),
            });
            entry_with_error(
                job.name,
                job.path,
                EntryKind::Directory,
                format!("directory scan failed: {}", err),
            )
        }
    }
}

fn accumulate_file_sizes(
    path: &Path,
    meta: &Metadata,
    context: &ScanContext,
) -> (u64, Option<u64>) {
    let mut logical = meta.len();
    let mut allocated = None;

    if context.options.mode == ScanMode::Accurate {
        match collect_ads(path) {
            Ok(ads) => {
                logical += ads.total_bytes;
            }
            Err(err) => {
                context.emit(ProgressEvent::EntryError {
                    path: path.to_path_buf(),
                    message: format!("ADS enumeration failed: {}", err),
                });
            }
        }

        match get_allocated_size(path) {
            Ok(size) => {
                allocated = Some(size);
            }
            Err(err) => {
                context.emit(ProgressEvent::EntryError {
                    path: path.to_path_buf(),
                    message: format!("allocation size failed: {}", err),
                });
            }
        }
    }

    (logical, allocated)
}

fn entry_with_error(
    name: String,
    path: PathBuf,
    kind: EntryKind,
    message: impl Into<String>,
) -> EntryReport {
    EntryReport {
        name,
        path,
        kind,
        logical_size: 0,
        allocated_size: None,
        percent_of_parent: 0.0,
        ads_bytes: 0,
        ads_count: 0,
        error: Some(message.into()),
    }
}

fn get_allocated_size(path: &Path) -> Result<u64> {
    let file = fs::File::open(path)?;
    let mut info: FILE_STANDARD_INFO = unsafe { std::mem::zeroed() };
    unsafe {
        GetFileInformationByHandleEx(
            HANDLE(file.as_raw_handle() as isize),
            FileStandardInfo,
            &mut info as *mut _ as *mut c_void,
            std::mem::size_of::<FILE_STANDARD_INFO>() as u32,
        )?;
    }
    Ok(info.AllocationSize as u64)
}

fn collect_ads(path: &Path) -> Result<AdsSummary> {
    const FIND_STREAM_INFO_STANDARD: STREAM_INFO_LEVELS = STREAM_INFO_LEVELS(0);

    let wide = path_to_wide(path);
    let mut data = WIN32_FIND_STREAM_DATA::default();
    let handle = match unsafe {
        FindFirstStreamW(
            PCWSTR(wide.as_ptr()),
            FIND_STREAM_INFO_STANDARD,
            &mut data as *mut _ as *mut c_void,
            0,
        )
    } {
        Ok(handle) => handle,
        Err(err) => {
            if err.code() == hresult_from_win32(ERROR_HANDLE_EOF.0) {
                return Ok(AdsSummary::default());
            }
            return Err(anyhow!(
                "FindFirstStreamW failed for {}: {}",
                path.display(),
                err
            ));
        }
    };

    let guard = HandleGuard::new(handle);
    let mut summary = AdsSummary::default();
    accumulate_stream(&data, &mut summary);

    loop {
        match unsafe { FindNextStreamW(guard.handle(), &mut data as *mut _ as *mut c_void) } {
            Ok(()) => accumulate_stream(&data, &mut summary),
            Err(err) => {
                if err.code() == hresult_from_win32(ERROR_HANDLE_EOF.0) {
                    break;
                }
                return Err(anyhow!(
                    "FindNextStreamW failed for {}: {}",
                    path.display(),
                    err
                ));
            }
        }
    }

    Ok(summary)
}

fn accumulate_stream(data: &WIN32_FIND_STREAM_DATA, summary: &mut AdsSummary) {
    if let Some(name) = utf16_to_string(&data.cStreamName) {
        if name != "::$DATA" {
            let size = unsafe { *(&data.StreamSize as *const _ as *const i64) };
            if size > 0 {
                summary.total_bytes += size as u64;
                summary.count += 1;
            }
        }
    }
}

struct HandleGuard {
    handle: HANDLE,
}

impl HandleGuard {
    fn new(handle: HANDLE) -> Self {
        Self { handle }
    }

    fn handle(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = FindClose(self.handle);
        }
    }
}

fn hresult_from_win32(code: u32) -> HRESULT {
    if code == 0 {
        HRESULT(0)
    } else {
        let value = ((code & 0x0000_FFFF) | 0x8007_0000) as i32;
        HRESULT(value)
    }
}

fn utf16_to_string(buffer: &[u16]) -> Option<String> {
    let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    if len == 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&buffer[..len]))
}

fn path_to_wide(path: &Path) -> Vec<u16> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    wide
}

fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", bytes, UNITS[unit])
    } else {
        format!("{:.2} {}", value, UNITS[unit])
    }
}

fn print_report(report: &DirectoryReport) {
    println!("Target: {}", report.path.display());
    println!("Logical total: {}", format_size(report.logical_size));
    if let Some(allocated) = report.allocated_size {
        println!("Allocated total: {}", format_size(allocated));
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
            .map(|size| format_size(size))
            .unwrap_or_else(|| String::from("-"));
        let ads_info = if entry.ads_count > 0 {
            format_size(entry.ads_bytes)
        } else {
            String::from("-")
        };
        let percent = format!("{:.2}", entry.percent_of_parent);
        let label = entry.kind.short_label();
        println!(
            "{:<45} {:>7} {:>14} {:>14} {:>9} {:>8}",
            entry.name,
            label,
            format_size(entry.logical_size),
            allocated,
            ads_info,
            percent,
        );
        if let Some(error) = &entry.error {
            println!("    ! {}", error);
        }
    }
}

impl EntryKind {
    fn short_label(self) -> &'static str {
        match self {
            EntryKind::Directory => "DIR",
            EntryKind::SymlinkDirectory => "LNKD",
            EntryKind::Other => "OTHER",
            EntryKind::Skipped => "SKIP",
        }
    }
}

fn run_debug_mode(args: &Args, options: ScanOptions) -> Result<()> {
    let (progress_tx, progress_rx) = mpsc::channel();
    let printer = std::thread::spawn(move || {
        while let Ok(event) = progress_rx.recv() {
            match event {
                ProgressEvent::Started(path) => eprintln!("[scan] {}", path.display()),
                ProgressEvent::CacheHit(path) => eprintln!("[cache] {}", path.display()),
                ProgressEvent::Completed {
                    path,
                    logical,
                    allocated,
                } => {
                    if let Some(alloc) = allocated {
                        eprintln!(
                            "[done] {} (logical {}, allocated {})",
                            path.display(),
                            format_size(logical),
                            format_size(alloc)
                        );
                    } else {
                        eprintln!(
                            "[done] {} (logical {})",
                            path.display(),
                            format_size(logical)
                        );
                    }
                }
                ProgressEvent::EntryError { path, message } => {
                    eprintln!("[warn] {} -> {}", path.display(), message)
                }
                ProgressEvent::Skipped(path, message) => {
                    eprintln!("[skip] {} -> {}", path.display(), message)
                }
            }
        }
    });

    let context = Arc::new(ScanContext::new(options, Some(progress_tx.clone())));

    if options.follow_symlinks {
        if let Ok(canon) = fs::canonicalize(&args.target) {
            context.mark_if_new(canon);
        }
    }

    let report = scan_directory(&args.target, &context)
        .with_context(|| format!("failed to scan {}", args.target.display()))?;

    drop(progress_tx);
    let _ = printer.join();

    print_report(&report);

    Ok(())
}

fn run_tui_mode(args: &Args, options: ScanOptions) -> Result<()> {
    enable_raw_mode().context("failed to enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("failed to enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("failed to create terminal")?;
    terminal.clear().context("failed to clear terminal")?;

    let result = (|| -> Result<()> {
        let context = Arc::new(ScanContext::new(options, None));

        if options.follow_symlinks {
            if let Ok(canon) = fs::canonicalize(&args.target) {
                context.mark_if_new(canon);
            }
        }

        let DirectoryPlan {
            directories,
            precomputed_entries,
            file_logical,
            file_allocated,
        } = prepare_directory_plan(&args.target, context.as_ref())
            .with_context(|| format!("failed to read {}", args.target.display()))?;

        let mut app = App::new(
            args.target.clone(),
            directories.clone(),
            precomputed_entries,
            file_logical,
            file_allocated,
            options.mode,
        );

        let (msg_tx, msg_rx) = mpsc::channel();

        if directories.is_empty() {
            app.handle_message(AppMessage::AllDone);
        } else {
            let scan_ctx = Arc::clone(&context);
            let tx_pool = msg_tx.clone();
            std::thread::spawn(move || {
                directories.into_par_iter().for_each(|job| {
                    let ctx = Arc::clone(&scan_ctx);
                    let tx = tx_pool.clone();
                    tx.send(AppMessage::DirectoryStarted(job.path.clone())).ok();
                    let report = process_directory_child(job, &ctx);
                    tx.send(AppMessage::DirectoryFinished(report)).ok();
                });
                tx_pool.send(AppMessage::AllDone).ok();
            });
        }
        drop(msg_tx);

        let tick_rate = Duration::from_millis(200);
        let mut last_tick = Instant::now();

        loop {
            while let Ok(message) = msg_rx.try_recv() {
                app.handle_message(message);
            }

            terminal
                .draw(|frame| draw_app(frame, &app))
                .context("failed to draw frame")?;

            let timeout = tick_rate
                .checked_sub(last_tick.elapsed())
                .unwrap_or_else(|| Duration::from_millis(0));
            if event::poll(timeout).context("failed to poll for events")? {
                if let Event::Key(key) = event::read().context("failed to read event")? {
                    app.handle_key(key);
                }
            }

            if last_tick.elapsed() >= tick_rate {
                app.tick();
                last_tick = Instant::now();
            }

            if app.should_exit() {
                break;
            }
        }

        if let Some(report) = app.build_final_report() {
            context
                .cache
                .insert(args.target.clone(), options.mode, report.mtime, report);
        }

        Ok(())
    })();

    disable_raw_mode().context("failed to disable raw mode")?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)
        .context("failed to leave alternate screen")?;
    terminal.show_cursor().context("failed to show cursor")?;

    result
}

fn draw_app(frame: &mut Frame<'_>, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(6)])
        .split(frame.size());

    let total_logical = app.total_logical();
    let allocated_text = app
        .total_allocated()
        .map(|value| format_size(value))
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

enum AppMessage {
    DirectoryStarted(PathBuf),
    DirectoryFinished(EntryReport),
    AllDone,
}

struct App {
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
}

impl App {
    fn new(
        target: PathBuf,
        directories: Vec<ChildJob>,
        static_entries: Vec<EntryReport>,
        file_logical: u64,
        file_allocated: Option<u64>,
        mode: ScanMode,
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
        }
    }

    fn handle_message(&mut self, message: AppMessage) {
        match message {
            AppMessage::DirectoryStarted(path) => self.mark_started(&path),
            AppMessage::DirectoryFinished(report) => self.apply_report(report),
            AppMessage::AllDone => self.mark_all_done(),
        }
    }

    fn handle_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.should_quit = true;
            }
            _ => {}
        }
    }

    fn tick(&mut self) {
        // UI tick hook (spinner, timers) will live here; keep results visible until the user quits
    }

    fn should_exit(&self) -> bool {
        self.should_quit
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
                if !matches!(directory.status, DirectoryStatus::Finished(_)) {
                    self.completed_dirs += 1;
                }
                directory.status = DirectoryStatus::Finished(report);
                break;
            }
        }
    }

    fn mark_all_done(&mut self) {
        self.all_done = true;
    }
    fn total_logical(&self) -> u64 {
        let dir_sum: u64 = self
            .directories
            .iter()
            .filter_map(|dir| match &dir.status {
                DirectoryStatus::Finished(report) => Some(report.logical_size),
                _ => None,
            })
            .sum();
        let static_sum: u64 = self
            .static_entries
            .iter()
            .map(|entry| entry.logical_size)
            .sum();
        self.file_logical + dir_sum + static_sum
    }

    fn total_allocated(&self) -> Option<u64> {
        let mut total = match (self.mode, self.file_allocated) {
            (ScanMode::Accurate, Some(value)) => Some(value),
            (ScanMode::Accurate, None) => None,
            _ => return None,
        };

        if let Some(acc) = total.as_mut() {
            for entry in &self.static_entries {
                if let Some(size) = entry.allocated_size {
                    *acc += size;
                } else {
                    total = None;
                    break;
                }
            }
        }

        if let Some(acc) = total.as_mut() {
            for directory in &self.directories {
                match &directory.status {
                    DirectoryStatus::Finished(report) => {
                        if let Some(size) = report.allocated_size {
                            *acc += size;
                        } else {
                            total = None;
                            break;
                        }
                    }
                    _ => {
                        total = None;
                        break;
                    }
                }
            }
        }

        total
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

    fn build_final_report(&self) -> Option<DirectoryReport> {
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
}

impl ScanMode {
    fn label(self) -> &'static str {
        match self {
            ScanMode::Fast => "Fast",
            ScanMode::Accurate => "Accurate",
        }
    }
}
