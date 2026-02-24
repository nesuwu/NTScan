/// Configuration parameters for initializing the TUI application.
///
/// This struct implements the "Parameter Object" pattern to simplify the `App::new` signature.
/// It aggregates all necessary state required to bootstrap the UI, including the initial
/// target, scan results, and global context.
pub struct AppParams {
    pub target: PathBuf,
    pub directories: Vec<ChildJob>,
    pub static_entries: Vec<EntryReport>,
    pub file_logical: u64,
    pub file_allocated: Option<u64>,
    pub file_allocated_complete: bool,
    pub mode: ScanMode,
    pub cancel: CancelFlag,
    pub errors: ErrorStats,
    pub show_files: bool,
    pub delete_permanent: bool,
    pub msg_tx: Option<mpsc::Sender<AppMessage>>,
    pub settings: AppSettings,
}

/// The main TUI application state.
///
/// `App` is responsible for:
/// * **State Management**: Tracking the current directory, navigation history, and selection.
/// * **Event Handling**: Processing user input (keyboard) and async messages from the scanner.
/// * **Rendering preparation**: Calculating visible rows and formatting data for the `ratatui` draw cycle.
///
/// It manages the lifecycle of a single scan session. Navigation to a new directory
/// essentially replaces the `App` instance (managed by the runner loop).
pub struct App {
    target: PathBuf,
    mode: ScanMode,
    directories: Vec<AppDirectory>,
    static_entries: Vec<EntryReport>,
    file_logical: u64,
    file_allocated: Option<u64>,
    file_allocated_complete: bool,
    start: Instant,
    completed_at: Option<Instant>,
    total_dirs: usize,
    completed_dirs: usize,
    all_done: bool,
    should_quit: bool,
    cancel: CancelFlag,
    errors: ErrorStats,
    sort_mode: SortMode,
    selected: usize,
    offset: usize,
    last_viewport: usize,
    rows_cache: Vec<RowData>,
    rows_dirty: bool,
    show_files: bool,
    delete_permanent: bool,
    confirm_delete: Option<PathBuf>,
    msg_tx: Option<mpsc::Sender<AppMessage>>,
    deleting: bool,
    error_popup: Option<String>,
    settings: AppSettings,
    settings_popup: Option<SettingsPopupState>,
}
impl App {
    /// Creates a new TUI application instance.
    pub fn new(params: AppParams) -> Self {
        let AppParams {
            target,
            directories,
            static_entries,
            file_logical,
            file_allocated,
            file_allocated_complete,
            mode,
            cancel,
            errors,
            show_files,
            delete_permanent,
            msg_tx,
            settings,
        } = params;
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
            file_allocated_complete,
            start: Instant::now(),
            completed_at: None,
            total_dirs,
            completed_dirs: 0,
            all_done: false,
            should_quit: false,
            cancel,
            errors,
            sort_mode: SortMode::Size,
            selected: 0,
            offset: 0,
            last_viewport: 0,
            rows_cache: Vec::new(),
            rows_dirty: true,
            show_files,
            delete_permanent,
            confirm_delete: None,
            msg_tx,
            deleting: false,
            error_popup: None,
            settings,
            settings_popup: None,
        }
    }

    pub fn handle_message(&mut self, message: AppMessage) {
        match message {
            AppMessage::DirectoryStarted(path) => self.mark_started(&path),
            AppMessage::DirectoryFinished(report) => self.apply_report(report),
            AppMessage::AllDone => self.mark_all_done(),
            AppMessage::DeleteStarted => {
                self.deleting = true;
            }
            AppMessage::DeleteSuccess(path) => {
                self.deleting = false;
                // Remove from lists
                if let Some(idx) = self.directories.iter().position(|d| d.path == path) {
                    self.directories.remove(idx);
                } else if let Some(idx) = self.static_entries.iter().position(|e| e.path == path) {
                    self.static_entries.remove(idx);
                }
                self.rows_dirty = true;
                let total = self.total_rows();
                self.ensure_selection_bounds(total);
            }
            AppMessage::DeleteFailed(path, error) => {
                self.deleting = false;
                self.errors.record(ScanErrorKind::Other);
                self.error_popup = Some(format!("Failed to delete {}:\n{}", path.display(), error));
            }
        }
        self.rows_dirty = true;
        let total = self.total_rows();
        self.ensure_selection_bounds(total);
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Option<AppAction> {
        if key.kind != KeyEventKind::Press {
            return None;
        }

        // If error popup is open, any key closes it
        if self.error_popup.is_some() {
            self.error_popup = None;
            return None;
        }

        if self.settings_popup.is_some() {
            return self.handle_settings_key(key);
        }

        if self.deleting {
            // Ignore input while deleting
            return None;
        }

        if self.confirm_delete.is_some() {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    self.execute_delete();
                    self.confirm_delete = None;
                    return None;
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    self.confirm_delete = None;
                    return None;
                }
                _ => return None,
            }
        }

        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => {
                self.should_quit = true;
                self.cancel.cancel();
                self.errors.record(ScanErrorKind::Cancelled);
                None
            }
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.should_quit = true;
                self.cancel.cancel();
                self.errors.record(ScanErrorKind::Cancelled);
                None
            }
            KeyCode::Char('s') | KeyCode::Char('S') => {
                self.cycle_sort();
                None
            }
            KeyCode::Char('g') | KeyCode::Char('G') => {
                self.open_settings_popup();
                None
            }
            KeyCode::Char('x') | KeyCode::Char('X') | KeyCode::Delete => {
                self.prepare_delete();
                None
            }
            KeyCode::Down => {
                self.move_selection_by(1);
                None
            }
            KeyCode::Up => {
                self.move_selection_by(-1);
                None
            }
            KeyCode::PageDown => {
                self.move_page(1);
                None
            }
            KeyCode::PageUp => {
                self.move_page(-1);
                None
            }
            KeyCode::Home => {
                self.move_to_top();
                None
            }
            KeyCode::End => {
                self.move_to_bottom();
                None
            }
            KeyCode::Enter => self.activate_selection(),
            KeyCode::Backspace => Some(AppAction::GoBack),
            _ => None,
        }
    }

    fn palette(&self) -> ThemePalette {
        ThemePalette::from_theme(self.settings.theme)
    }

    fn open_settings_popup(&mut self) {
        self.settings_popup = Some(SettingsPopupState {
            selected: 0,
            editing: false,
            input: String::new(),
            draft: self.settings.clone(),
        });
    }

    fn handle_settings_key(&mut self, key: KeyEvent) -> Option<AppAction> {
        let mut should_close = false;
        let mut saved_settings: Option<AppSettings> = None;
        let mut error_message: Option<String> = None;

        {
            let popup = self.settings_popup.as_mut()?;

            if popup.editing {
                match key.code {
                    KeyCode::Esc => {
                        popup.editing = false;
                        popup.input.clear();
                    }
                    KeyCode::Enter => {
                        let field = SettingsField::from_index(popup.selected);
                        let result =
                            Self::apply_text_field(field, &mut popup.draft, popup.input.trim());
                        match result {
                            Ok(()) => {
                                popup.editing = false;
                                popup.input.clear();
                            }
                            Err(err) => error_message = Some(err),
                        }
                    }
                    KeyCode::Backspace => {
                        popup.input.pop();
                    }
                    KeyCode::Char(ch)
                        if !key.modifiers.contains(KeyModifiers::CONTROL)
                            && !key.modifiers.contains(KeyModifiers::ALT) =>
                    {
                        popup.input.push(ch);
                    }
                    _ => {}
                }
                if let Some(message) = error_message {
                    self.error_popup = Some(message);
                }
                return None;
            }

            match key.code {
                KeyCode::Esc => should_close = true,
                KeyCode::Up => {
                    popup.selected = popup.selected.saturating_sub(1);
                }
                KeyCode::Down => {
                    let max = SettingsField::ALL.len().saturating_sub(1);
                    popup.selected = (popup.selected + 1).min(max);
                }
                KeyCode::Left => {
                    Self::step_field_value(popup, false);
                }
                KeyCode::Right => {
                    Self::step_field_value(popup, true);
                }
                KeyCode::Enter => {
                    let field = SettingsField::from_index(popup.selected);
                    if field.is_text() {
                        popup.editing = true;
                        popup.input = Self::field_input_value(field, &popup.draft);
                    } else {
                        Self::step_field_value(popup, true);
                    }
                }
                KeyCode::Char('s') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    saved_settings = Some(popup.draft.clone());
                }
                _ => {}
            }
        }

        if should_close {
            self.settings_popup = None;
            return None;
        }

        if let Some(new_settings) = saved_settings {
            match save_settings(&new_settings) {
                Ok(()) => {
                    self.settings = new_settings.clone();
                    self.delete_permanent = new_settings.default_delete_permanent;
                    self.settings_popup = None;
                    return Some(AppAction::ApplySettings(new_settings));
                }
                Err(err) => {
                    self.error_popup = Some(format!("Failed to save settings:\n{}", err));
                }
            }
        }

        None
    }

    fn step_field_value(popup: &mut SettingsPopupState, forward: bool) {
        match SettingsField::from_index(popup.selected) {
            SettingsField::Theme => {
                popup.draft.theme = if forward {
                    popup.draft.theme.next()
                } else {
                    popup.draft.theme.previous()
                };
            }
            SettingsField::DefaultMode => {
                popup.draft.default_mode = match popup.draft.default_mode {
                    ScanMode::Fast => ScanMode::Accurate,
                    ScanMode::Accurate => ScanMode::Fast,
                };
            }
            SettingsField::FollowSymlinks => {
                popup.draft.default_follow_symlinks = !popup.draft.default_follow_symlinks;
            }
            SettingsField::ShowFiles => {
                popup.draft.default_show_files = !popup.draft.default_show_files;
            }
            SettingsField::DeletePermanent => {
                popup.draft.default_delete_permanent = !popup.draft.default_delete_permanent;
            }
            SettingsField::DuplicateMinSize
            | SettingsField::ScanCachePath
            | SettingsField::HashCachePath => {}
        }
    }

    fn field_input_value(field: SettingsField, draft: &AppSettings) -> String {
        match field {
            SettingsField::DuplicateMinSize => draft.min_duplicate_size.to_string(),
            SettingsField::ScanCachePath => draft
                .scan_cache_path
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
            SettingsField::HashCachePath => draft
                .hash_cache_path
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
            _ => String::new(),
        }
    }

    fn apply_text_field(
        field: SettingsField,
        draft: &mut AppSettings,
        raw_value: &str,
    ) -> Result<(), String> {
        match field {
            SettingsField::DuplicateMinSize => {
                let parsed = raw_value
                    .parse::<u64>()
                    .map_err(|_| String::from("Duplicate min size must be a positive integer"))?;
                if parsed == 0 {
                    return Err(String::from("Duplicate min size must be greater than zero"));
                }
                draft.min_duplicate_size = parsed;
                Ok(())
            }
            SettingsField::ScanCachePath => {
                if raw_value.is_empty() {
                    draft.scan_cache_path = None;
                } else {
                    draft.scan_cache_path = Some(PathBuf::from(raw_value));
                }
                Ok(())
            }
            SettingsField::HashCachePath => {
                if raw_value.is_empty() {
                    draft.hash_cache_path = None;
                } else {
                    draft.hash_cache_path = Some(PathBuf::from(raw_value));
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn prepare_delete(&mut self) {
        self.ensure_rows();
        if self.rows_cache.is_empty() {
            return;
        }
        let index = self.selected.min(self.rows_cache.len() - 1);
        let path = match &self.rows_cache[index].origin {
            RowOrigin::Directory(path) => Some(path.clone()),
            RowOrigin::File(path) => Some(path.clone()),
            _ => None,
        };
        self.confirm_delete = path;
    }

    fn execute_delete(&mut self) {
        if let Some(path) = &self.confirm_delete
            && let Some(tx) = &self.msg_tx
        {
            let tx = tx.clone();
            let path = path.clone();
            let permanent = self.delete_permanent;

            // Notify start
            let _ = tx.send(AppMessage::DeleteStarted);

            thread::spawn(move || {
                let result = Self::perform_deletion(&path, permanent);

                match result {
                    Ok(_) => {
                        let _ = tx.send(AppMessage::DeleteSuccess(path));
                    }
                    Err(e) => {
                        let _ = tx.send(AppMessage::DeleteFailed(path, e.to_string()));
                    }
                }
            });
        }
    }

    fn perform_deletion(
        path: &Path,
        permanent: bool,
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            use windows::Win32::UI::Shell::{
                FO_DELETE, FOF_ALLOWUNDO, FOF_NOCONFIRMATION, FOF_NOERRORUI, FOF_SILENT,
                SHFILEOPSTRUCTW, SHFileOperationW,
            };

            // SHFileOperation requires double-null terminated strings
            let mut wide_path: Vec<u16> = path.as_os_str().encode_wide().collect();
            wide_path.push(0);
            wide_path.push(0);

            let mut flags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
            if !permanent {
                flags |= FOF_ALLOWUNDO;
            }

            let mut op = SHFILEOPSTRUCTW {
                hwnd: windows::Win32::Foundation::HWND(0),
                wFunc: FO_DELETE,
                pFrom: windows::core::PCWSTR(wide_path.as_ptr()),
                pTo: windows::core::PCWSTR::null(),
                fFlags: flags.0 as u16,
                fAnyOperationsAborted: false.into(),
                hNameMappings: std::ptr::null_mut(),
                lpszProgressTitle: windows::core::PCWSTR::null(),
            };

            let result = unsafe { SHFileOperationW(&mut op) };

            if result != 0 {
                return Err(Box::new(std::io::Error::from_raw_os_error(result)));
            }
            if bool::from(op.fAnyOperationsAborted) {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "Operation aborted",
                )));
            }

            Ok(())
        }

        #[cfg(not(windows))]
        {
            if permanent {
                // Try standard deletion first
                let result = if path.is_dir() {
                    fs::remove_dir_all(path)
                } else {
                    fs::remove_file(path)
                };

                if result.is_ok() {
                    return Ok(());
                }

                // If failed, try to strip Read-Only attribute and retry
                if let Ok(metadata) = fs::metadata(path) {
                    let mut permissions = metadata.permissions();
                    if permissions.readonly() {
                        permissions.set_readonly(false);
                        let _ = fs::set_permissions(path, permissions);
                        // Retry
                        if path.is_dir() {
                            fs::remove_dir_all(path)?;
                        } else {
                            fs::remove_file(path)?;
                        }
                        return Ok(());
                    }
                }

                // If still failed, propagate original error
                result.map_err(|e| e.into())
            } else {
                trash::delete(path).map_err(|e| e.into())
            }
        }
    }

    fn cycle_sort(&mut self) {
        self.sort_mode = self.sort_mode.next();
        self.rows_dirty = true;
        let total = self.total_rows();
        self.ensure_selection_bounds(total);
    }

    fn total_rows(&self) -> usize {
        let mut total = self.directories.len();
        total += self
            .static_entries
            .iter()
            .filter(|entry| {
                !matches!(
                    entry.kind,
                    EntryKind::Directory | EntryKind::SymlinkDirectory
                )
            })
            .count();
        if self.file_logical > 0 {
            total += 1;
        }
        if self.target.parent().is_some() {
            total += 1;
        }
        total
    }

    fn ensure_selection_bounds(&mut self, total: usize) {
        if total == 0 {
            self.selected = 0;
            self.offset = 0;
            return;
        }
        if self.selected >= total {
            self.selected = total - 1;
        }
        let viewport = self.last_viewport.max(1);
        let max_offset = total.saturating_sub(viewport);
        if self.offset > max_offset {
            self.offset = max_offset;
        }
        if self.selected < self.offset {
            self.offset = self.selected;
        } else if self.selected >= self.offset + viewport {
            self.offset = self.selected + 1 - viewport;
        }
    }

    fn activate_selection(&mut self) -> Option<AppAction> {
        self.ensure_rows();
        if self.rows_cache.is_empty() {
            return None;
        }
        let index = self.selected.min(self.rows_cache.len() - 1);
        match &self.rows_cache[index].origin {
            RowOrigin::Directory(path) => Some(AppAction::ChangeDirectory(path.clone())),
            RowOrigin::Parent => Some(AppAction::GoBack),
            _ => None,
        }
    }

    fn move_selection_by(&mut self, delta: isize) {
        let total = self.total_rows();
        if total == 0 {
            self.selected = 0;
            self.offset = 0;
            return;
        }
        let current = self.selected.min(total - 1) as isize;
        let max_index = (total - 1) as isize;
        let next = (current + delta).clamp(0, max_index) as usize;
        self.selected = next;
        self.ensure_selection_bounds(total);
    }

    fn move_page(&mut self, delta: isize) {
        let step = self.last_viewport.max(1) as isize;
        self.move_selection_by(delta * step);
    }

    fn move_to_top(&mut self) {
        let total = self.total_rows();
        if total == 0 {
            self.selected = 0;
            self.offset = 0;
            return;
        }
        self.selected = 0;
        self.ensure_selection_bounds(total);
    }

    fn move_to_bottom(&mut self) {
        let total = self.total_rows();
        if total == 0 {
            self.selected = 0;
            self.offset = 0;
            return;
        }
        self.selected = total - 1;
        self.ensure_selection_bounds(total);
    }

    fn elapsed(&self) -> Duration {
        match self.completed_at {
            Some(done) => done.duration_since(self.start),
            None => self.start.elapsed(),
        }
    }

    pub fn tick(&mut self) {}

    pub fn should_exit(&self) -> bool {
        self.should_quit
    }

    pub fn total_logical(&self) -> u64 {
        let mut total = self.file_logical;
        total += self
            .directories
            .iter()
            .filter_map(|dir| match &dir.status {
                DirectoryStatus::Finished(report) => Some(report.logical_size),
                _ => None,
            })
            .sum::<u64>();
        total += self
            .static_entries
            .iter()
            .map(|entry| entry.logical_size)
            .sum::<u64>();
        total
    }

    pub fn total_allocated(&self) -> Option<(u64, bool)> {
        match self.mode {
            ScanMode::Fast => None,
            ScanMode::Accurate => {
                let mut total = self.file_allocated.unwrap_or(0);
                let mut complete = self.file_allocated_complete;

                for entry in &self.static_entries {
                    total += entry.allocated_size.unwrap_or(0);
                    complete &= entry.allocated_complete;
                }

                for directory in &self.directories {
                    if let DirectoryStatus::Finished(report) = &directory.status {
                        total += report.allocated_size.unwrap_or(0);
                        complete &= report.allocated_complete;
                    } else {
                        return None;
                    }
                }
                Some((total, complete))
            }
        }
    }

    pub fn errors(&self) -> &ErrorStats {
        &self.errors
    }

    pub fn skipped_count(&self) -> usize {
        let mut total = self
            .static_entries
            .iter()
            .filter(|entry| entry.is_skipped())
            .count();
        total += self
            .directories
            .iter()
            .filter_map(|directory| match &directory.status {
                DirectoryStatus::Finished(report) if report.is_skipped() => Some(1usize),
                _ => None,
            })
            .sum::<usize>();
        total
    }

    pub fn target(&self) -> &Path {
        &self.target
    }

    pub fn request_cancel(&self) {
        self.cancel.cancel();
    }

    pub fn build_final_report(&self) -> Option<DirectoryReport> {
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
            (ScanMode::Accurate, _) => Some(self.file_allocated.unwrap_or(0)),
            _ => None,
        };
        let mut allocated_complete = true;

        if self.mode == ScanMode::Accurate {
            allocated_complete = self.file_allocated_complete;
            if let Some(acc) = total_allocated.as_mut() {
                for entry in &entries {
                    *acc += entry.allocated_size.unwrap_or(0);
                    allocated_complete &= entry.allocated_complete;
                }
            } else {
                allocated_complete = false;
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
            allocated_complete,
            entries,
        })
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
        let is_directory = matches!(
            report.kind,
            EntryKind::Directory | EntryKind::SymlinkDirectory
        );
        if is_directory {
            let path = report.path.clone();
            if let Some(directory) = self.directories.iter_mut().find(|dir| dir.path == path) {
                let was_finished = matches!(directory.status, DirectoryStatus::Finished(_));
                directory.status = DirectoryStatus::Finished(report);
                if !was_finished {
                    self.completed_dirs += 1;
                    if self.completed_dirs == self.total_dirs && self.completed_at.is_none() {
                        self.completed_at = Some(Instant::now());
                    }
                }
                return;
            }
        }
        self.static_entries.push(report);
    }

    fn mark_all_done(&mut self) {
        self.all_done = true;
        if self.completed_at.is_none() {
            self.completed_at = Some(Instant::now());
        }
    }

    fn ensure_rows(&mut self) {
        if self.rows_dirty {
            self.rows_cache = self.collect_rows();
            self.rows_dirty = false;
        }
    }

    fn collect_rows(&self) -> Vec<RowData> {
        let mut rows: Vec<RowData> = Vec::new();
        let total_logical = self.total_logical();
        let palette = self.palette();

        for directory in &self.directories {
            let name = directory.name.clone();
            let name_key = name.to_lowercase();
            let type_label = if directory.was_symlink {
                "LNKD".to_string()
            } else {
                "DIR".to_string()
            };

            match &directory.status {
                DirectoryStatus::Pending => {
                    rows.push(RowData {
                        name,
                        name_key,
                        logical_sort: None,
                        modified_sort: None,
                        type_label,
                        status: "WAIT".to_string(),
                        logical_text: "...".to_string(),
                        allocated_text: "...".to_string(),
                        modified_text: "-".to_string(),
                        ads_text: "...".to_string(),
                        percent_text: "...".to_string(),
                        style: Style::default().fg(palette.pending),
                        origin: RowOrigin::Directory(directory.path.clone()),
                    });
                }
                DirectoryStatus::Running => {
                    rows.push(RowData {
                        name,
                        name_key,
                        logical_sort: None,
                        modified_sort: None,
                        type_label,
                        status: "SCAN".to_string(),
                        logical_text: "...".to_string(),
                        allocated_text: "...".to_string(),
                        modified_text: "-".to_string(),
                        ads_text: "...".to_string(),
                        percent_text: "...".to_string(),
                        style: Style::default()
                            .fg(palette.running)
                            .add_modifier(Modifier::BOLD),
                        origin: RowOrigin::Directory(directory.path.clone()),
                    });
                }
                DirectoryStatus::Finished(report) => {
                    let mut data = RowData::from_entry(
                        report,
                        total_logical,
                        RowOrigin::Directory(directory.path.clone()),
                        palette,
                    );
                    data.name = name;
                    data.name_key = name_key;
                    data.type_label = type_label;
                    rows.push(data);
                }
            }
        }

        for entry in &self.static_entries {
            if matches!(
                entry.kind,
                EntryKind::Directory | EntryKind::SymlinkDirectory
            ) {
                continue;
            }
            rows.push(RowData::from_entry(
                entry,
                total_logical,
                RowOrigin::File(entry.path.clone()),
                palette,
            ));
        }

        if self.file_logical > 0 && !self.show_files {
            let allocated_text = match self.file_allocated {
                Some(allocated) => {
                    let mut text = format_size(allocated);
                    if !self.file_allocated_complete {
                        text.push_str(" (partial)");
                    }
                    text
                }
                None => "-".to_string(),
            };
            rows.push(RowData {
                name: "[files]".to_string(),
                name_key: "[files]".to_string(),
                logical_sort: Some(self.file_logical),
                modified_sort: None,
                type_label: "FILE".to_string(),
                status: "DONE".to_string(),
                logical_text: format_size(self.file_logical),
                allocated_text,
                modified_text: "-".to_string(),
                ads_text: "-".to_string(),
                percent_text: if total_logical > 0 {
                    format!(
                        "{:.2}",
                        (self.file_logical as f64 / total_logical as f64) * 100.0
                    )
                } else {
                    "0.00".to_string()
                },
                style: Style::default().fg(palette.ok),
                origin: RowOrigin::Files,
            });
        }

        match self.sort_mode {
            SortMode::Name => {
                rows.sort_by_key(|row| row.name_key.clone());
            }
            SortMode::Size => {
                rows.sort_by_key(|row| {
                    (
                        row.logical_sort.is_none(),
                        Reverse(row.logical_sort.unwrap_or(0)),
                        row.name_key.clone(),
                    )
                });
            }
            SortMode::Date => {
                rows.sort_by_key(|row| {
                    (
                        row.modified_sort.is_none(),
                        Reverse(row.modified_sort.unwrap_or(UNIX_EPOCH)),
                        row.name_key.clone(),
                    )
                });
            }
        }

        if self.target.parent().is_some() {
            rows.insert(
                0,
                RowData {
                    name: "..".to_string(),
                    name_key: "..".to_string(),
                    logical_sort: None,
                    modified_sort: None,
                    type_label: "UP".to_string(),
                    status: String::new(),
                    logical_text: String::new(),
                    allocated_text: String::new(),
                    modified_text: String::new(),
                    ads_text: String::new(),
                    percent_text: String::new(),
                    style: Style::default().fg(palette.parent),
                    origin: RowOrigin::Parent,
                },
            );
        }

        rows
    }

    fn visible_rows(&mut self, viewport: usize) -> Vec<Row<'static>> {
        let viewport = viewport.max(1);
        self.ensure_rows();
        let total = self.rows_cache.len();
        self.last_viewport = viewport;
        if total == 0 {
            self.selected = 0;
            self.offset = 0;
            return Vec::new();
        }

        self.ensure_selection_bounds(total);

        let start = self.offset;
        let end = (start + viewport).min(total);
        let mut rows = Vec::with_capacity(end.saturating_sub(start));
        for (idx, row) in self.rows_cache[start..end].iter().enumerate() {
            let absolute_index = start + idx;
            rows.push(row.clone().into_row(absolute_index == self.selected));
        }
        rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn total_allocated_marks_partial_when_any_entry_is_incomplete() {
        let app = App::new(AppParams {
            target: PathBuf::from("."),
            directories: Vec::new(),
            static_entries: vec![EntryReport {
                name: "sample.bin".to_string(),
                path: PathBuf::from(".\\sample.bin"),
                kind: EntryKind::File,
                logical_size: 10,
                allocated_size: Some(8),
                allocated_complete: false,
                percent_of_parent: 0.0,
                ads_bytes: 0,
                ads_count: 0,
                error: None,
                skip_reason: None,
                modified: None,
            }],
            file_logical: 0,
            file_allocated: Some(4),
            file_allocated_complete: true,
            mode: ScanMode::Accurate,
            cancel: CancelFlag::new(),
            errors: ErrorStats::default(),
            show_files: true,
            delete_permanent: false,
            msg_tx: None,
            settings: AppSettings::default(),
        });

        let (total_allocated, allocated_complete) = app
            .total_allocated()
            .expect("accurate mode should produce allocated totals");
        assert_eq!(total_allocated, 12);
        assert!(!allocated_complete, "totals must be marked partial");

        let report = app
            .build_final_report()
            .expect("app with no pending directories should build final report");
        assert!(!report.allocated_complete);
    }
}
