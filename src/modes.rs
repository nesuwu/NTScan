use std::io;
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
use crate::context::{CancelFlag, ScanContext};
use crate::model::{DirectoryPlan, ErrorStats, ProgressEvent, ScanMode, ScanOptions};
use crate::report::{format_size, print_report};
use crate::scanner::{prepare_directory_plan, process_directory_child, scan_directory};
use crate::tui::{App, AppMessage, draw_app};

/// Runs the CLI application by selecting the appropriate mode.
///
/// ```rust,no_run
/// use crate::modes;
///
/// if let Err(err) = modes::run() {
///     eprintln!("{err}");
/// }
/// ```
pub fn run() -> Result<()> {
    let args = Args::parse();

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
/// ```rust,no_run
/// use crate::args::Args;
/// use crate::model::ScanOptions;
/// use crate::modes::run_debug_mode;
///
/// let args = Args::parse_from(["foldersizer-cli", "--debug"]);
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
    ));

    if options.follow_symlinks {
        if let Ok(canon) = std::fs::canonicalize(&args.target) {
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

/// Launches the interactive TUI run-loop.
///
/// ```rust,no_run
/// use crate::args::Args;
/// use crate::model::ScanOptions;
/// use crate::modes::run_tui_mode;
///
/// let args = Args::parse_from(["foldersizer-cli"]);
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
        let cancel = CancelFlag::new();
        let errors = ErrorStats::default();

        let context = Arc::new(ScanContext::new(options, None, cancel.clone()));

        if options.follow_symlinks {
            if let Ok(canon) = std::fs::canonicalize(&args.target) {
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
            cancel.clone(),
            errors.clone(),
        );

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
                .cache()
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
