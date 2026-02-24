use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};
#[cfg(windows)]
use std::sync::{Mutex, OnceLock};
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
#[cfg(windows)]
use windows::Win32::Foundation::{BOOL, FALSE, TRUE};
#[cfg(windows)]
use windows::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT, SetConsoleCtrlHandler};

use crate::args::{Args, CLI_DEFAULT_MIN_SIZE};
use crate::context::{CancelFlag, ScanCache, ScanContext};
use crate::duplicates::print_duplicate_report;
use crate::engine;
use crate::model::{DirectoryPlan, ErrorStats, ProgressEvent, ScanMode, ScanOptions};
use crate::report::{format_size, print_report};
use crate::scanner::{is_scan_cancelled, prepare_directory_plan, process_directory_child};
use crate::settings::{AppSettings, load_settings};
use crate::tui::{App, AppAction, AppMessage, AppParams, draw_app};

#[cfg(windows)]
static DEBUG_CANCEL_SLOT: OnceLock<Mutex<Option<CancelFlag>>> = OnceLock::new();

#[cfg(windows)]
fn debug_cancel_slot() -> &'static Mutex<Option<CancelFlag>> {
    DEBUG_CANCEL_SLOT.get_or_init(|| Mutex::new(None))
}

#[cfg(windows)]
unsafe extern "system" fn debug_ctrl_handler(ctrl: u32) -> BOOL {
    match ctrl {
        CTRL_C_EVENT | CTRL_BREAK_EVENT => {
            if let Ok(guard) = debug_cancel_slot().lock()
                && let Some(cancel) = guard.as_ref()
            {
                cancel.cancel();
            }
            TRUE
        }
        _ => FALSE,
    }
}

#[cfg(windows)]
fn install_debug_cancel_handler(cancel: CancelFlag) -> Result<()> {
    *debug_cancel_slot().lock().unwrap() = Some(cancel);
    unsafe {
        SetConsoleCtrlHandler(Some(debug_ctrl_handler), true)
            .ok()
            .context("failed to install Ctrl+C handler")?;
    }
    Ok(())
}

#[cfg(not(windows))]
fn install_debug_cancel_handler(_cancel: CancelFlag) -> Result<()> {
    Ok(())
}

/// Main entry point for executing the requested scan mode.
pub fn run() -> Result<()> {
    let mut args = Args::parse();
    let settings = load_settings();
    apply_cli_defaults(&mut args, &settings);

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
        show_files: args.file,
    };

    if args.duplicates {
        run_duplicates_mode(&args, &settings)
    } else if args.debug {
        run_debug_mode(&args, options, &settings)
    } else {
        run_tui_mode(&args, options, settings)
    }
}

/// Executes the duplicate file finder mode.
fn run_duplicates_mode(args: &Args, settings: &AppSettings) -> Result<()> {
    eprintln!("Scanning for duplicates in {}...", args.target.display());
    let result = engine::run_duplicates(
        &args.target,
        args.min_size,
        settings.hash_cache_path.clone(),
    )?;
    print_duplicate_report(&result);
    Ok(())
}

/// Executes the debug mode (legacy console output).
fn run_debug_mode(args: &Args, options: ScanOptions, settings: &AppSettings) -> Result<()> {
    let (progress_tx, progress_rx) = mpsc::channel();
    let cancel = CancelFlag::new();
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

    install_debug_cancel_handler(cancel.clone())?;

    let report = engine::run_scan_with_cancel(
        &args.target,
        options,
        settings.scan_cache_path.clone(),
        Some(progress_tx.clone()),
        cancel,
    );
    drop(progress_tx);
    let _ = printer.join();

    match report {
        Ok(report) => {
            print_report(&report);
            Ok(())
        }
        Err(err) if is_scan_cancelled(&err) => {
            eprintln!("Scan cancelled.");
            Ok(())
        }
        Err(err) => Err(err),
    }
}

// Used to store previous states for instant back navigation
struct NavigationState {
    app: App,
    msg_rx: mpsc::Receiver<AppMessage>,
}

/// Executes the interactive TUI mode.
fn run_tui_mode(args: &Args, options: ScanOptions, initial_settings: AppSettings) -> Result<()> {
    enable_raw_mode().context("failed to enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("failed to enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("failed to create terminal")?;
    terminal.clear().context("failed to clear terminal")?;

    let result = (|| -> Result<()> {
        let mut settings = initial_settings;
        let mut options = options;
        let mut delete_permanent = args.delete_permanent;
        let mut shared_cache = Arc::new(scan_cache_from_settings(&settings));
        let (mut app, mut context, mut msg_rx) = start_scan_session(
            args.target.clone(),
            options,
            Arc::clone(&shared_cache),
            delete_permanent,
            settings.clone(),
        )?;

        // History stack for Backspace
        let mut history: Vec<NavigationState> = Vec::new();

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

            let mut action = None;
            if event::poll(timeout).context("failed to poll for events")?
                && let Event::Key(key) = event::read().context("failed to read event")?
            {
                action = app.handle_key(key);
            }

            if last_tick.elapsed() >= tick_rate {
                app.tick();
                last_tick = Instant::now();
            }

            if let Some(act) = action {
                match act {
                    AppAction::ChangeDirectory(target) => {
                        // Save state before leaving
                        app.request_cancel();
                        context.save_cache(); // Partial save on navigation

                        // Start new scan
                        let (next_app, next_context, next_rx) = start_scan_session(
                            target,
                            options,
                            Arc::clone(&shared_cache),
                            delete_permanent,
                            settings.clone(),
                        )?;

                        // Push OLD state to history
                        let old_state = NavigationState { app, msg_rx };
                        history.push(old_state);

                        // Switch to NEW state
                        app = next_app;
                        context = next_context;
                        msg_rx = next_rx;
                        last_tick = Instant::now();
                    }
                    AppAction::GoBack => {
                        // 1. Try In-Memory History (Instant)
                        if let Some(state) = history.pop() {
                            app = state.app;
                            msg_rx = state.msg_rx;

                            // Restore dummy context
                            context = Arc::new(ScanContext::with_cache(
                                options,
                                None,
                                CancelFlag::new(),
                                ErrorStats::default(),
                                Arc::clone(&shared_cache),
                            ));

                            last_tick = Instant::now();
                        }
                        // 2. Fallback to Parent Directory (New Scan)
                        else if let Some(parent) = app.target().parent() {
                            let target = parent.to_path_buf();
                            app.request_cancel();
                            context.save_cache();

                            let (next_app, next_context, next_rx) = start_scan_session(
                                target,
                                options,
                                Arc::clone(&shared_cache),
                                delete_permanent,
                                settings.clone(),
                            )?;

                            app = next_app;
                            context = next_context;
                            msg_rx = next_rx;
                            last_tick = Instant::now();
                        }
                    }
                    AppAction::ApplySettings(new_settings) => {
                        app.request_cancel();
                        context.save_cache();

                        settings = new_settings;
                        options = ScanOptions {
                            mode: settings.default_mode,
                            follow_symlinks: settings.default_follow_symlinks,
                            show_files: settings.default_show_files,
                        };
                        delete_permanent = settings.default_delete_permanent;

                        shared_cache = Arc::new(scan_cache_from_settings(&settings));
                        history.clear();

                        let target = app.target().to_path_buf();
                        let (next_app, next_context, next_rx) = start_scan_session(
                            target,
                            options,
                            Arc::clone(&shared_cache),
                            delete_permanent,
                            settings.clone(),
                        )?;

                        app = next_app;
                        context = next_context;
                        msg_rx = next_rx;
                        last_tick = Instant::now();
                    }
                }
            }

            if app.should_exit() {
                break;
            }
        }

        context.save_cache();
        Ok(())
    })();

    disable_raw_mode().context("failed to disable raw mode")?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)
        .context("failed to leave alternate screen")?;
    terminal.show_cursor().context("failed to show cursor")?;

    result
}

/// Initializes a new scan session for a target directory.
fn start_scan_session(
    target: PathBuf,
    options: ScanOptions,
    cache: Arc<ScanCache>,
    delete_permanent: bool,
    settings: AppSettings,
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

    let (msg_tx, msg_rx) = mpsc::channel();

    let app_params = AppParams {
        target: target.clone(),
        directories: directories.clone(),
        static_entries: precomputed_entries,
        file_logical,
        file_allocated,
        mode: options.mode,
        cancel: cancel.clone(),
        errors: errors.clone(),
        show_files: options.show_files,
        delete_permanent,
        msg_tx: Some(msg_tx.clone()),
        settings,
    };

    let mut app = App::new(app_params);

    if directories.is_empty() {
        app.handle_message(AppMessage::AllDone);
    } else {
        let scan_ctx = Arc::clone(&context);
        let tx_pool = msg_tx.clone();
        std::thread::spawn(move || {
            let _ = directories.into_par_iter().try_for_each(|job| {
                if scan_ctx.cancel_flag().is_cancelled() {
                    return Err(());
                }

                let ctx = Arc::clone(&scan_ctx);
                let tx = tx_pool.clone();
                tx.send(AppMessage::DirectoryStarted(job.path.clone())).ok();
                let report = match process_directory_child(job, &ctx) {
                    Ok(report) => report,
                    Err(_) => return Err(()),
                };
                tx.send(AppMessage::DirectoryFinished(report)).ok();
                Ok(())
            });
            tx_pool.send(AppMessage::AllDone).ok();
        });
    }

    drop(msg_tx);

    Ok((app, context, msg_rx))
}

fn apply_cli_defaults(args: &mut Args, settings: &AppSettings) {
    if !args.fast && !args.accurate && settings.default_mode == ScanMode::Accurate {
        args.accurate = true;
    }
    if !args.follow_symlinks {
        args.follow_symlinks = settings.default_follow_symlinks;
    }
    if !args.file {
        args.file = settings.default_show_files;
    }
    if !args.delete_permanent {
        args.delete_permanent = settings.default_delete_permanent;
    }
    if args.min_size == CLI_DEFAULT_MIN_SIZE {
        args.min_size = settings.min_duplicate_size;
    }
}

fn scan_cache_from_settings(settings: &AppSettings) -> ScanCache {
    if let Some(path) = &settings.scan_cache_path {
        ScanCache::new(path.clone())
    } else {
        ScanCache::default()
    }
}

fn resolve_initial_target(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    let cwd = std::env::current_dir().context("failed to determine current directory")?;
    Ok(cwd.join(path))
}
