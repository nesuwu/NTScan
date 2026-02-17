use ratatui::layout::{Alignment, Rect};
use ratatui::widgets::Clear;

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn bool_label(value: bool) -> &'static str {
    if value { "On" } else { "Off" }
}

pub fn draw_app(frame: &mut Frame<'_>, app: &mut App) {
    let palette = app.palette();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(6)])
        .split(frame.size());

    let errs = app.errors().snapshot();
    let cncl = *errs.get(&ScanErrorKind::Cancelled).unwrap_or(&0);
    let adsf = *errs.get(&ScanErrorKind::ADSFailed).unwrap_or(&0);
    let accd = *errs.get(&ScanErrorKind::AccessDenied).unwrap_or(&0);
    let shrv = *errs.get(&ScanErrorKind::SharingViolation).unwrap_or(&0);
    let othr = *errs.get(&ScanErrorKind::Other).unwrap_or(&0);

    let total_logical = app.total_logical();
    let allocated_text = app
        .total_allocated()
        .map(format_size)
        .unwrap_or_else(|| String::from("n/a"));
    let header_lines = vec![
        Line::from(format!("Target: {}", app.target.display())),
        Line::from(format!(
            "Mode: {} | Sort: {} | Directories: {}/{} | Logical: {} | Allocated: {} | Elapsed: {:.1?}",
            app.mode.label(),
            app.sort_mode.label(),
            app.completed_dirs,
            app.total_dirs,
            format_size(total_logical),
            allocated_text,
            app.elapsed()
        )),
        Line::from(format!(
            "Errors - Cancelled:{}  ADS:{}  Access:{}  Share:{}  Other:{}",
            cncl, adsf, accd, shrv, othr
        )),
        Line::from(
            "Keys: q/Esc quit | Enter open dir | Backspace go back | s sort | g settings | Up/Down move | PgUp/PgDn, Home/End page | x/Del delete",
        ),
    ];

    let header = Paragraph::new(header_lines).block(
        Block::default()
            .title("Status")
            .borders(Borders::ALL)
            .style(Style::default().fg(palette.border)),
    );
    frame.render_widget(header, chunks[0]);

    let column_widths = [
        Constraint::Percentage(35),
        Constraint::Length(6),
        Constraint::Length(8),
        Constraint::Length(14),
        Constraint::Length(14),
        Constraint::Length(18),
        Constraint::Length(9),
        Constraint::Length(6),
    ];
    let viewport = (chunks[1].height as usize).saturating_sub(3).max(1);
    let table = Table::new(app.visible_rows(viewport), column_widths)
        .header(
            Row::new(vec![
                "Name",
                "Type",
                "Status",
                "Logical",
                "Allocated",
                "Modified",
                "ADS",
                "%",
            ])
            .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(
            Block::default()
                .title("Folders")
                .borders(Borders::ALL)
                .style(Style::default().fg(palette.border)),
        )
        .column_spacing(1);
    frame.render_widget(table, chunks[1]);

    // 1. Confirmation Popup
    if let Some(path) = &app.confirm_delete {
        let block = Block::default()
            .title("Confirm Deletion")
            .borders(Borders::ALL)
            .style(Style::default().fg(palette.error));
        let area = centered_rect(60, 25, frame.size());
        frame.render_widget(Clear, area); // Clear background behind popup

        let method = if app.delete_permanent {
            "PERMANENTLY DELETE"
        } else {
            "Move to TRASH"
        };

        let text = vec![
            Line::from(format!("ACTION: {}", method))
                .alignment(Alignment::Center)
                .style(Style::default().add_modifier(Modifier::BOLD)),
            Line::from("").alignment(Alignment::Center),
            Line::from(format!("Target: {}", path.display())).alignment(Alignment::Center),
            Line::from("").alignment(Alignment::Center),
            Line::from("Press [Y] to CONFIRM")
                .alignment(Alignment::Center)
                .style(
                    Style::default()
                        .fg(palette.error)
                        .add_modifier(Modifier::BOLD),
                ),
            Line::from("Press [N] or [Esc] to CANCEL").alignment(Alignment::Center),
        ];

        let paragraph = Paragraph::new(text)
            .block(block)
            .alignment(Alignment::Center);
        frame.render_widget(paragraph, area);
    }

    // 2. Deletion In-Progress Popup
    if app.deleting {
        let block = Block::default()
            .title("Deleting...")
            .borders(Borders::ALL)
            .style(Style::default().fg(palette.running));
        let area = centered_rect(40, 10, frame.size());
        frame.render_widget(Clear, area);

        let text = vec![
            Line::from("Deleting selected item...").alignment(Alignment::Center),
            Line::from("Please wait.").alignment(Alignment::Center),
        ];
        let paragraph = Paragraph::new(text)
            .block(block)
            .alignment(Alignment::Center);
        frame.render_widget(paragraph, area);
    }

    // 3. Error Popup
    if let Some(err_msg) = &app.error_popup {
        let block = Block::default()
            .title("Deletion Error")
            .borders(Borders::ALL)
            .style(Style::default().fg(palette.error));
        let area = centered_rect(60, 20, frame.size());
        frame.render_widget(Clear, area);

        let text = vec![
            Line::from("An error occurred during deletion:").alignment(Alignment::Center),
            Line::from("").alignment(Alignment::Center),
            Line::from(err_msg.as_str()).alignment(Alignment::Center),
            Line::from("").alignment(Alignment::Center),
            Line::from("Press any key to close").alignment(Alignment::Center),
        ];

        let paragraph = Paragraph::new(text)
            .block(block)
            .alignment(Alignment::Center)
            .wrap(ratatui::widgets::Wrap { trim: true });
        frame.render_widget(paragraph, area);
    }

    if let Some(state) = &app.settings_popup {
        let area = centered_rect(66, 66, frame.size());
        frame.render_widget(Clear, area);

        let mut lines: Vec<Line> = Vec::new();
        lines.push(Line::from(
            "Use Up/Down to select, Left/Right to change values.",
        ));
        lines.push(Line::from(
            "Press Enter to edit text fields, Ctrl+S to save, Esc to close.",
        ));
        lines.push(Line::from(""));

        for (index, field) in SettingsField::ALL.iter().enumerate() {
            let selected = index == state.selected;
            let prefix = if selected { "> " } else { "  " };
            let value = match field {
                SettingsField::Theme => state.draft.theme.label().to_string(),
                SettingsField::DefaultMode => state.draft.default_mode.label().to_string(),
                SettingsField::FollowSymlinks => {
                    bool_label(state.draft.default_follow_symlinks).to_string()
                }
                SettingsField::ShowFiles => bool_label(state.draft.default_show_files).to_string(),
                SettingsField::DeletePermanent => {
                    bool_label(state.draft.default_delete_permanent).to_string()
                }
                SettingsField::DuplicateMinSize => state.draft.min_duplicate_size.to_string(),
                SettingsField::ScanCachePath => state
                    .draft
                    .scan_cache_path
                    .as_ref()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|| String::from("(auto)")),
                SettingsField::HashCachePath => state
                    .draft
                    .hash_cache_path
                    .as_ref()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|| String::from("(auto)")),
            };

            let style = if selected {
                Style::default()
                    .fg(palette.running)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            lines.push(Line::from(format!("{}{}: {}", prefix, field.label(), value)).style(style));
        }

        if state.editing {
            let field = SettingsField::from_index(state.selected);
            lines.push(Line::from(""));
            lines.push(
                Line::from(format!("Editing {}:", field.label()))
                    .style(Style::default().add_modifier(Modifier::BOLD)),
            );
            lines.push(Line::from(state.input.as_str()).style(Style::default().fg(palette.parent)));
            lines.push(Line::from("Press Enter to apply or Esc to cancel edit."));
        }

        let block = Block::default()
            .title("Settings")
            .borders(Borders::ALL)
            .style(Style::default().fg(palette.border));

        let paragraph = Paragraph::new(lines)
            .block(block)
            .wrap(ratatui::widgets::Wrap { trim: true });
        frame.render_widget(paragraph, area);
    }
}
