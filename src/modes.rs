use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;
use crossterm::{
    event::{self, Event},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use rayon::{ThreadPoolBuilder, prelude::*};

use crate::args::Args;
use crate::context::{CancelFlag, ScanCache, ScanContext};
use crate::model::{DirectoryPlan, ErrorStats, ProgressEvent, ScanMode, ScanOptions};
use crate::report::{format_size, print_report};
use crate::scanner::{prepare_directory_plan, process_directory_child, scan_directory};
use crate::tui::{App, AppAction, AppMessage, AppParams, draw_app};

/// Runs the CLI application by selecting the appropriate mode.
///
/// ```rust,no_run
/// use ntscan::modes;
///
/// if let Err(err) = modes::run() {
///     eprintln!("{err}");
/// }
/// ```
pub fn run() -> Result<()> {
    let mut args = Args::parse();
    let resolved_target =
        resolve_initial_target(&args.target).context("failed to resolve target directory")?;
    args.target = resolved_target;

    let threads = std::cmp::max(1, (num_cpus::get() * 3) / 4);
    let _ = ThreadPoolBuilder::new().num_threads(threads).build_global();

    let mut mode = args.resolve_mode();
    if args.fast {
        mode = ScanMode::Fast;
    }

    let options = ScanOptions {
        mode,
        follow_symlinks: args.follow_symlinks,
    };

    if args.debug {
        run_debug_mode(&args, options)
    } else {
        run_tui_mode(&args, options)
    }
}

/// Executes a streaming console run that prints progress to stderr.
///
/// ```rust,ignore
/// use ntscan::args::Args;
/// use ntscan::model::ScanOptions;
/// use ntscan::modes::run_debug_mode;
///
/// let args = Args::parse_from(["ntscan", "--debug"]);
/// let options = ScanOptions { mode: args.resolve_mode(), follow_symlinks: args.follow_symlinks };
/// run_debug_mode(&args, options).unwrap();
/// ```
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

    let context = Arc::new(ScanContext::new(
        options,
        Some(progress_tx.clone()),
        CancelFlag::new(),
        ErrorStats::default(),
    ));

    if options.follow_symlinks
        && let Ok(canon) = std::fs::canonicalize(&args.target)
    {
        context.mark_if_new(canon);
    }

    let report = scan_directory(&args.target, &context)
        .with_context(|| format!("failed to scan {}", args.target.display()))?;

    drop(progress_tx);
    let _ = printer.join();

    print_report(&report);

    Ok(())
}

/// Launches the interactive TUI run-loop.
///
/// ```rust,ignore
/// use ntscan::args::Args;
/// use ntscan::model::ScanOptions;
/// use ntscan::modes::run_tui_mode;
///
/// let args = Args::parse_from(["ntscan"]);
/// let options = ScanOptions { mode: args.resolve_mode(), follow_symlinks: args.follow_symlinks };
/// run_tui_mode(&args, options).unwrap();
/// ```
fn run_tui_mode(args: &Args, options: ScanOptions) -> Result<()> {
    enable_raw_mode().context("failed to enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("failed to enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("failed to create terminal")?;
    terminal.clear().context("failed to clear terminal")?;

    let result = (|| -> Result<()> {
        let shared_cache = Arc::new(ScanCache::default());
        let (mut app, mut context, mut msg_rx) =
            start_scan_session(args.target.clone(), options, Arc::clone(&shared_cache))?;

        let tick_rate = Duration::from_millis(200);
        let mut last_tick = Instant::now();

        loop {
            while let Ok(message) = msg_rx.try_recv() {
                app.handle_message(message);
            }

            terminal
                .draw(|frame| draw_app(frame, &mut app))
                .context("failed to draw frame")?;

            let timeout = tick_rate
                .checked_sub(last_tick.elapsed())
                .unwrap_or_else(|| Duration::from_millis(0));
            let mut requested_path: Option<PathBuf> = None;
            if event::poll(timeout).context("failed to poll for events")?
                && let Event::Key(key) = event::read().context("failed to read event")?
            {
                if let Some(action) = app.handle_key(key) {
                    if let AppAction::ChangeDirectory(path) = action {
                        requested_path = Some(path);
                    }
                }
            }

            if last_tick.elapsed() >= tick_rate {
                app.tick();
                last_tick = Instant::now();
            }

            if let Some(target) = requested_path {
                app.request_cancel();
                let (next_app, next_context, next_rx) =
                    start_scan_session(target, options, Arc::clone(&shared_cache))?;
                app = next_app;
                context = next_context;
                msg_rx = next_rx;
                last_tick = Instant::now();
                continue;
            }

            if app.should_exit() {
                break;
            }
        }

        if let Some(report) = app.build_final_report() {
            context.cache().insert(
                app.target().to_path_buf(),
                options.mode,
                report.mtime,
                report,
            );
        }

        Ok(())
    })();

    disable_raw_mode().context("failed to disable raw mode")?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)
        .context("failed to leave alternate screen")?;
    terminal.show_cursor().context("failed to show cursor")?;

    result
}

fn start_scan_session(
    target: PathBuf,
    options: ScanOptions,
    cache: Arc<ScanCache>,
) -> Result<(App, Arc<ScanContext>, mpsc::Receiver<AppMessage>)> {
    let cancel = CancelFlag::new();
    let errors = ErrorStats::default();

    let context = Arc::new(ScanContext::with_cache(
        options,
        None,
        cancel.clone(),
        errors.clone(),
        cache,
    ));

    if options.follow_symlinks
        && let Ok(canon) = std::fs::canonicalize(&target)
    {
        context.mark_if_new(canon);
    }

    let DirectoryPlan {
        directories,
        precomputed_entries,
        file_logical,
        file_allocated,
    } = prepare_directory_plan(&target, context.as_ref())
        .with_context(|| format!("failed to read {}", target.display()))?;

    let app_params = AppParams {
        target: target.clone(),
        directories: directories.clone(),
        static_entries: precomputed_entries,
        file_logical,
        file_allocated,
        mode: options.mode,
        cancel: cancel.clone(),
        errors: errors.clone(),
    };

    let mut app = App::new(app_params);
    let (msg_tx, msg_rx) = mpsc::channel();

    if directories.is_empty() {
        app.handle_message(AppMessage::AllDone);
    } else {
        let scan_ctx = Arc::clone(&context);
        let tx_pool = msg_tx.clone();
        std::thread::spawn(move || {
            directories.into_par_iter().for_each(|job| {
                if scan_ctx.cancel_flag().is_cancelled() {
                    return;
                }
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

    Ok((app, context, msg_rx))
}

fn resolve_initial_target(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    let cwd = std::env::current_dir().context("failed to determine current directory")?;
    Ok(cwd.join(path))
}
