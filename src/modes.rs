use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};
#[cfg(windows)]
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result};
use clap::Parser;
use crossterm::{
    event::{self, Event},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    widgets::{Block, Borders, Paragraph},
};
use rayon::{ThreadPoolBuilder, prelude::*};
#[cfg(windows)]
use windows::Win32::Foundation::{BOOL, FALSE, TRUE};
#[cfg(windows)]
use windows::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT, SetConsoleCtrlHandler};

use crate::args::{Args, CLI_DEFAULT_MIN_SIZE};
use crate::cache::DirScanCache;
use crate::context::{CancelFlag, ScanCache, ScanContext};
use crate::duplicates::print_duplicate_report;
use crate::engine;
use crate::model::{
    DirectoryPlan, ErrorStats, ProgressEvent, ScanErrorKind, ScanMode, ScanOptions,
};
use crate::report::{format_size, print_report};
use crate::scanner::{is_scan_cancelled, prepare_directory_plan, process_directory_child};
use crate::settings::{AppSettings, load_settings, save_settings};
use crate::tui::{App, AppAction, AppMessage, AppParams, draw_app, run_tutorial};

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

    if args.purge {
        return run_purge_mode(&settings);
    }

    let resolved_target =
        resolve_initial_target(&args.target).context("failed to resolve target directory")?;
    args.target = resolved_target;

    // Validate before any terminal-mode changes so a bad target produces a
    // plain one-line error instead of a TUI flash.
    let target_meta = std::fs::metadata(&args.target)
        .with_context(|| format!("cannot access target {}", args.target.display()))?;
    if !target_meta.is_dir() {
        anyhow::bail!("target is not a directory: {}", args.target.display());
    }

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

/// Deletes every NTScan cache file and exits. Settings are left untouched.
fn run_purge_mode(settings: &AppSettings) -> Result<()> {
    let targets = [
        (
            "scan cache",
            settings
                .scan_cache_path
                .clone()
                .unwrap_or_else(ScanCache::default_path),
        ),
        ("directory cache", crate::cache::default_dir_cache_path()),
        (
            "hash cache",
            settings
                .hash_cache_path
                .clone()
                .unwrap_or_else(crate::duplicates::resolve_hash_cache_path),
        ),
    ];

    let mut freed: u64 = 0;
    let mut failures = 0usize;
    for (label, path) in targets {
        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        match std::fs::remove_file(&path) {
            Ok(()) => {
                freed += size;
                println!(
                    "removed {} ({}): {}",
                    label,
                    format_size(size),
                    path.display()
                );
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                println!("{}: nothing to remove ({})", label, path.display());
            }
            Err(err) => {
                failures += 1;
                eprintln!("failed to remove {} {}: {}", label, path.display(), err);
            }
        }
    }

    println!("freed {}", format_size(freed));
    if failures > 0 {
        anyhow::bail!("{failures} cache file(s) could not be removed (is another ntscan running?)");
    }
    Ok(())
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
                    allocated_complete,
                } => {
                    if let Some(alloc) = allocated {
                        if allocated_complete {
                            eprintln!(
                                "[done] {} (logical {}, allocated {})",
                                path.display(),
                                format_size(logical),
                                format_size(alloc)
                            );
                        } else {
                            eprintln!(
                                "[done] {} (logical {}, allocated {} (partial))",
                                path.display(),
                                format_size(logical),
                                format_size(alloc)
                            );
                        }
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

    let scan_start = Instant::now();
    let report = engine::run_scan_with_cancel(
        &args.target,
        options,
        settings.scan_cache_path.clone(),
        Some(progress_tx.clone()),
        cancel,
    );
    let scan_elapsed = scan_start.elapsed();
    drop(progress_tx);
    let _ = printer.join();
    eprintln!("[time] scan + cache save took {:.3?}", scan_elapsed);

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

// Used to store previous states for instant back navigation.
//
// Two mtimes are stored to catch different classes of change:
//
//   `snapshot_mtime`       — mtime of this directory itself at the moment we
//                            navigated away.  Catches additions/removals of
//                            direct children (new file, renamed entry, etc.).
//
//   `child_snapshot_mtime` — mtime of the *child directory we navigated into*.
//                            Catches modifications made inside that child while
//                            we were browsing it (deleted files, new files, etc.).
//                            NTFS updates the child's mtime on such changes but
//                            does NOT update the parent's mtime.
struct NavigationState {
    target: PathBuf,
    snapshot_mtime: Option<SystemTime>,
    /// Path of the child directory we descended into.
    child_path: PathBuf,
    /// Mtime of that child at the time we navigated into it.
    child_snapshot_mtime: Option<SystemTime>,
    app: App,
    msg_rx: mpsc::Receiver<AppMessage>,
}

/// Reads a directory's mtime for staleness comparison.
fn dir_mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).ok().and_then(|m| m.modified().ok())
}

/// Executes the interactive TUI mode.
fn run_tui_mode(args: &Args, options: ScanOptions, initial_settings: AppSettings) -> Result<()> {
    enable_raw_mode().context("failed to enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("failed to enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("failed to create terminal")?;
    terminal.clear().context("failed to clear terminal")?;

    // Save failure at exit is reported after the terminal is restored —
    // inside the alternate screen the message would be erased with it.
    let mut exit_save_error: Option<io::Error> = None;

    let result = (|| -> Result<()> {
        let mut settings = initial_settings;
        let mut options = options;
        let mut delete_permanent = args.delete_permanent;

        // First launch (or --tutorial): guided walkthrough on sample data
        // before anything touches the disk.
        if !settings.tutorial_seen || args.tutorial {
            let proceed =
                run_tutorial(&mut terminal, &settings).context("failed to run the tutorial")?;
            if !settings.tutorial_seen {
                settings.tutorial_seen = true;
                let _ = save_settings(&settings);
            }
            if !proceed {
                return Ok(());
            }
        }

        // Paint before any blocking work — no blank alternate screen while
        // caches load or the root directory is read. The two caches load in
        // parallel; Fast mode skips the file-attribute cache entirely.
        draw_startup_frame(&mut terminal, "loading caches…")?;
        let dir_cache_thread = std::thread::spawn(DirScanCache::default);
        let mut shared_cache = Arc::new(ScanCache::for_mode(
            settings.scan_cache_path.clone(),
            options.mode,
        ));
        let mut shared_dir_cache = Arc::new(dir_cache_thread.join().unwrap_or_default());
        let cold_cache = shared_dir_cache.loaded_entries() == 0;

        draw_startup_frame(
            &mut terminal,
            &format!("reading {}…", args.target.display()),
        )?;
        let (mut app, mut context, mut msg_rx) = start_scan_session(
            args.target.clone(),
            options,
            Arc::clone(&shared_cache),
            Arc::clone(&shared_dir_cache),
            delete_permanent,
            settings.clone(),
            cold_cache,
        )?;
        if shared_cache.load_failed() || shared_dir_cache.load_failed() {
            context.record_error(ScanErrorKind::CacheFailed);
        }

        // History stack for Backspace
        let mut history: Vec<NavigationState> = Vec::new();
        // In-flight background cache save (spawned on scan completion).
        let mut pending_save: Option<std::thread::JoinHandle<()>> = None;

        let tick_rate = Duration::from_millis(200);
        let mut last_tick = Instant::now();

        loop {
            while let Ok(message) = msg_rx.try_recv() {
                // Persist caches once a scan session completes so a killed
                // terminal doesn't lose them; the exit save stays as backstop.
                if matches!(message, AppMessage::AllDone) {
                    spawn_cache_save(&context, &mut pending_save);
                }
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
                        // Snapshot both this directory's mtime AND the child we're
                        // about to enter. On GoBack we check both:
                        //  - parent mtime catches new/removed direct children
                        //  - child mtime catches files deleted/added inside the child
                        //    (NTFS only bumps the child's mtime, not the parent's)
                        let snapshot_mtime = dir_mtime(app.target());
                        let snapshot_target = app.target().to_path_buf();
                        let child_snapshot_mtime = dir_mtime(&target);
                        let child_path = target.clone();

                        app.request_cancel();

                        let (next_app, next_context, next_rx) = start_scan_session(
                            target,
                            options,
                            Arc::clone(&shared_cache),
                            Arc::clone(&shared_dir_cache),
                            delete_permanent,
                            settings.clone(),
                            false,
                        )?;

                        let old_state = NavigationState {
                            target: snapshot_target,
                            snapshot_mtime,
                            child_path,
                            child_snapshot_mtime,
                            app,
                            msg_rx,
                        };
                        history.push(old_state);

                        app = next_app;
                        context = next_context;
                        msg_rx = next_rx;
                        last_tick = Instant::now();
                    }
                    AppAction::GoBack => {
                        let mut restored = false;
                        if let Some(state) = history.pop() {
                            let current_mtime = dir_mtime(&state.target);
                            let parent_fresh = match (state.snapshot_mtime, current_mtime) {
                                (Some(snap), Some(curr)) => snap == curr,
                                _ => false,
                            };

                            let child_current_mtime = dir_mtime(&state.child_path);
                            let child_fresh =
                                match (state.child_snapshot_mtime, child_current_mtime) {
                                    (Some(snap), Some(curr)) => snap == curr,
                                    _ => false,
                                };

                            let scan_complete = state.app.is_scan_complete();

                            if parent_fresh && child_fresh && scan_complete {
                                // ── Fast path ───────────────────────────
                                // Nothing changed, restore instantly.
                                app = state.app;
                                // Cosmetic settings (theme, delete mode) may
                                // have changed since this App was snapshotted.
                                app.update_settings(settings.clone());
                                msg_rx = state.msg_rx;

                                context = Arc::new(ScanContext::with_caches(
                                    options,
                                    None,
                                    CancelFlag::new(),
                                    ErrorStats::default(),
                                    Arc::clone(&shared_cache),
                                    Arc::clone(&shared_dir_cache),
                                ));

                                last_tick = Instant::now();
                                restored = true;
                            } else if parent_fresh && scan_complete && !child_fresh {
                                // ── Surgical path ───────────────────────
                                // Only the child we were browsing changed
                                // (e.g. files deleted inside it).  Restore
                                // the parent, keep all other directories'
                                // cached results, and re-scan only the
                                // modified child.
                                let new_cancel = CancelFlag::new();
                                let (new_tx, new_rx) = mpsc::channel();

                                let mut restored_app = state.app;
                                restored_app.update_settings(settings.clone());
                                if let Some(job) = restored_app.invalidate_child_for_rescan(
                                    &state.child_path,
                                    new_cancel.clone(),
                                    new_tx.clone(),
                                ) {
                                    let scan_ctx = Arc::new(ScanContext::with_caches(
                                        options,
                                        None,
                                        new_cancel,
                                        restored_app.errors().clone(),
                                        Arc::clone(&shared_cache),
                                        Arc::clone(&shared_dir_cache),
                                    ));

                                    // Mark the parent as visited for symlink
                                    // cycle detection (same as start_scan_session).
                                    if options.follow_symlinks
                                        && let Ok(canon) = std::fs::canonicalize(&state.target)
                                    {
                                        scan_ctx.mark_if_new(canon);
                                    }

                                    let ctx = Arc::clone(&scan_ctx);
                                    let tx = new_tx.clone();
                                    std::thread::spawn(move || {
                                        tx.send(AppMessage::DirectoryStarted(job.path.clone()))
                                            .ok();
                                        if let Ok(report) = process_directory_child(job, &ctx) {
                                            tx.send(AppMessage::DirectoryFinished(report)).ok();
                                        }
                                        tx.send(AppMessage::AllDone).ok();
                                    });
                                    drop(new_tx);

                                    app = restored_app;
                                    msg_rx = new_rx;
                                    context = scan_ctx;
                                    last_tick = Instant::now();
                                    restored = true;
                                }
                                // If invalidate_child_for_rescan returned None
                                // (shouldn't happen), fall through to full re-scan.
                            }

                            if !restored {
                                // ── Full re-scan ────────────────────────
                                // Parent listing changed, scan was incomplete,
                                // or surgical path fell through.
                                app.request_cancel();

                                let (next_app, next_context, next_rx) = start_scan_session(
                                    state.target,
                                    options,
                                    Arc::clone(&shared_cache),
                                    Arc::clone(&shared_dir_cache),
                                    delete_permanent,
                                    settings.clone(),
                                    false,
                                )?;

                                app = next_app;
                                context = next_context;
                                msg_rx = next_rx;
                                last_tick = Instant::now();
                                restored = true;
                            }
                        }

                        // No history at all — scan the parent directory.
                        if !restored && let Some(parent) = app.target().parent() {
                            let target = parent.to_path_buf();
                            app.request_cancel();

                            let (next_app, next_context, next_rx) = start_scan_session(
                                target,
                                options,
                                Arc::clone(&shared_cache),
                                Arc::clone(&shared_dir_cache),
                                delete_permanent,
                                settings.clone(),
                                false,
                            )?;

                            app = next_app;
                            context = next_context;
                            msg_rx = next_rx;
                            last_tick = Instant::now();
                        }
                    }
                    AppAction::UpdateSettings(new_settings) => {
                        // Cosmetic change (theme, delete mode, duplicate
                        // options) — the App already applied it to itself;
                        // just keep the runner's copy in sync for future
                        // sessions. No rescan.
                        settings = new_settings;
                        delete_permanent = settings.default_delete_permanent;
                    }
                    AppAction::ApplySettings(new_settings) => {
                        app.request_cancel();
                        let _ = context.save_cache();

                        settings = new_settings;
                        options = ScanOptions {
                            mode: settings.default_mode,
                            follow_symlinks: settings.default_follow_symlinks,
                            show_files: settings.default_show_files,
                        };
                        delete_permanent = settings.default_delete_permanent;

                        shared_cache = Arc::new(ScanCache::for_mode(
                            settings.scan_cache_path.clone(),
                            options.mode,
                        ));
                        shared_dir_cache = Arc::new(DirScanCache::default());
                        history.clear();

                        let target = app.target().to_path_buf();
                        let (next_app, next_context, next_rx) = start_scan_session(
                            target,
                            options,
                            Arc::clone(&shared_cache),
                            Arc::clone(&shared_dir_cache),
                            delete_permanent,
                            settings.clone(),
                            shared_dir_cache.loaded_entries() == 0,
                        )?;

                        if shared_cache.load_failed() || shared_dir_cache.load_failed() {
                            next_context.record_error(ScanErrorKind::CacheFailed);
                        }
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

        if let Some(handle) = pending_save.take() {
            let _ = handle.join();
        }
        if let Err(err) = context.save_cache() {
            exit_save_error = Some(err);
        }
        Ok(())
    })();

    disable_raw_mode().context("failed to disable raw mode")?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)
        .context("failed to leave alternate screen")?;
    terminal.show_cursor().context("failed to show cursor")?;

    if let Some(err) = exit_save_error {
        eprintln!(
            "warning: failed to save scan caches ({}); next run will re-scan unchanged directories",
            err
        );
    }

    result
}

/// Initializes a new scan session for a target directory.
fn start_scan_session(
    target: PathBuf,
    options: ScanOptions,
    cache: Arc<ScanCache>,
    dir_cache: Arc<DirScanCache>,
    delete_permanent: bool,
    settings: AppSettings,
    cold_cache: bool,
) -> Result<(App, Arc<ScanContext>, mpsc::Receiver<AppMessage>)> {
    let cancel = CancelFlag::new();
    let errors = ErrorStats::default();

    let context = Arc::new(ScanContext::with_caches(
        options,
        None,
        cancel.clone(),
        errors.clone(),
        cache,
        dir_cache,
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
        file_allocated_complete,
    } = prepare_directory_plan(&target, context.as_ref())
        .with_context(|| format!("failed to read {}", target.display()))?;

    let (msg_tx, msg_rx) = mpsc::channel();

    let app_params = AppParams {
        target: target.clone(),
        directories: directories.clone(),
        static_entries: precomputed_entries,
        file_logical,
        file_allocated,
        file_allocated_complete,
        mode: options.mode,
        cancel: cancel.clone(),
        errors: errors.clone(),
        show_files: options.show_files,
        delete_permanent,
        msg_tx: Some(msg_tx.clone()),
        settings,
        cold_cache,
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

/// Draws a minimal one-off frame so startup work never leaves the alternate
/// screen blank.
fn draw_startup_frame(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    message: &str,
) -> Result<()> {
    let text = message.to_string();
    terminal
        .draw(|frame| {
            let block = Block::default().title("NTScan").borders(Borders::ALL);
            frame.render_widget(Paragraph::new(text.clone()).block(block), frame.size());
        })
        .context("failed to draw startup frame")?;
    Ok(())
}

/// Persists caches on a background thread once a scan session completes, so
/// a killed terminal doesn't lose them. One save runs at a time; if the
/// previous one is still going the new request is skipped (the caches stay
/// dirty, so the exit-time save catches anything missed).
fn spawn_cache_save(context: &Arc<ScanContext>, pending: &mut Option<std::thread::JoinHandle<()>>) {
    if let Some(handle) = pending
        && !handle.is_finished()
    {
        return;
    }
    if let Some(handle) = pending.take() {
        let _ = handle.join();
    }
    let ctx = Arc::clone(context);
    *pending = Some(std::thread::spawn(move || {
        if ctx.save_cache().is_err() {
            ctx.record_error(ScanErrorKind::CacheFailed);
        }
    }));
}

fn resolve_initial_target(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    let cwd = std::env::current_dir().context("failed to determine current directory")?;
    Ok(cwd.join(path))
}
