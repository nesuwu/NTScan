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
    let skipped = app.skipped_count();
    let mut error_parts: Vec<String> = Vec::new();
    for (kind, label) in [
        (ScanErrorKind::Cancelled, "Cancelled"),
        (ScanErrorKind::ADSFailed, "ADS"),
        (ScanErrorKind::AccessDenied, "Access"),
        (ScanErrorKind::SharingViolation, "Share"),
        (ScanErrorKind::CacheFailed, "Cache"),
        (ScanErrorKind::Other, "Other"),
    ] {
        let count = *errs.get(&kind).unwrap_or(&0);
        if count > 0 {
            error_parts.push(format!("{} {}", label, count));
        }
    }
    let errors_text = if error_parts.is_empty() {
        String::from("No errors")
    } else {
        format!("Errors: {}", error_parts.join("  "))
    };

    let total_logical = app.total_logical();
    let allocated_text = app
        .total_allocated()
        .map(|(allocated, complete)| {
            let mut text = format_size(allocated);
            if !complete {
                text.push_str(" (partial)");
            }
            text
        })
        .unwrap_or_else(|| String::from("n/a"));
    let progress_text = if app.all_done {
        format!("done in {:.1?}", app.elapsed())
    } else {
        const SPINNER: [char; 4] = ['|', '/', '-', '\\'];
        let frame_idx = (app.elapsed().as_millis() / 200) as usize % SPINNER.len();
        format!("{} {:.1?}", SPINNER[frame_idx], app.elapsed())
    };
    let header_lines = vec![
        Line::from(format!("Target: {}", app.target.display())),
        Line::from(format!(
            "Mode: {} | Sort: {} | Directories: {}/{} | Logical: {} | Allocated: {} | {}",
            app.mode.label(),
            app.sort_mode.label(),
            app.completed_dirs,
            app.total_dirs,
            format_size(total_logical),
            allocated_text,
            progress_text
        )),
        Line::from(format!("{} | Skipped: {}", errors_text, skipped)),
        Line::from(if app.cold_cache && !app.all_done {
            "First scan — building cache, next runs are faster. Press ? for help."
        } else {
            "Press ? for help"
        }),
    ];

    let header = Paragraph::new(header_lines).block(
        Block::default()
            .title("Status")
            .borders(Borders::ALL)
            .style(Style::default().fg(palette.border)),
    );
    frame.render_widget(header, chunks[0]);

    // Fast mode never fills Allocated/ADS — drop the columns instead of
    // rendering dash-filled ones.
    let show_accurate = app.mode == ScanMode::Accurate;
    let arrow = app.sort_mode.arrow();
    let name_header = if app.sort_mode.key == SortKey::Name {
        format!("Name {}", arrow)
    } else {
        String::from("Name")
    };
    let logical_header = if app.sort_mode.key == SortKey::Size {
        format!("Logical {}", arrow)
    } else {
        String::from("Logical")
    };
    let modified_header = if app.sort_mode.key == SortKey::Date {
        format!("Modified {}", arrow)
    } else {
        String::from("Modified")
    };

    let mut column_widths = vec![
        Constraint::Percentage(35),
        Constraint::Length(6),
        Constraint::Length(8),
        Constraint::Length(14),
    ];
    let mut header_cells = vec![
        Cell::from(name_header),
        Cell::from("Type"),
        Cell::from("Status"),
        Cell::from(logical_header),
    ];
    if show_accurate {
        column_widths.push(Constraint::Length(14));
        header_cells.push(Cell::from("Allocated"));
    }
    column_widths.push(Constraint::Length(18));
    header_cells.push(Cell::from(modified_header));
    if show_accurate {
        column_widths.push(Constraint::Length(9));
        header_cells.push(Cell::from("ADS"));
    }
    column_widths.push(Constraint::Length(16));
    header_cells.push(Cell::from("Size %"));

    let viewport = (chunks[1].height as usize).saturating_sub(3).max(1);
    let table = Table::new(app.visible_rows(viewport, show_accurate), column_widths)
        .header(Row::new(header_cells).style(Style::default().add_modifier(Modifier::BOLD)))
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

    // 3. Error Popup (deletion failures, settings save failures, …)
    if let Some(err_msg) = &app.error_popup {
        let block = Block::default()
            .title("Error")
            .borders(Borders::ALL)
            .style(Style::default().fg(palette.error));
        let area = centered_rect(60, 20, frame.size());
        frame.render_widget(Clear, area);

        let text = vec![
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

    if app.help_popup {
        let area = centered_rect(60, 70, frame.size());
        frame.render_widget(Clear, area);

        let bold = Style::default().add_modifier(Modifier::BOLD);
        let lines = vec![
            Line::from("Navigation").style(bold),
            Line::from("  Up/k, Down/j       move selection"),
            Line::from("  Right/l/Enter      open directory"),
            Line::from("  Left/h/Backspace   go back"),
            Line::from("  PgUp/PgDn          page | Home/End jump"),
            Line::from(""),
            Line::from("Sorting (same key again reverses)").style(bold),
            Line::from("  n by name | s by size | d by date"),
            Line::from(""),
            Line::from("Actions").style(bold),
            Line::from("  Del/x   delete selected (asks first)"),
            Line::from("  F2/g    settings"),
            Line::from("  q/Esc   quit"),
            Line::from(""),
            Line::from("Press any key to close"),
        ];

        let block = Block::default()
            .title("Help")
            .borders(Borders::ALL)
            .style(Style::default().fg(palette.border));
        frame.render_widget(Paragraph::new(lines).block(block), area);
    }

    if let Some(state) = &app.settings_popup {
        let area = centered_rect(70, 80, frame.size());
        frame.render_widget(Clear, area);

        let bold = Style::default().add_modifier(Modifier::BOLD);
        let dim = Style::default().fg(palette.pending);
        let mut lines: Vec<Line> = Vec::new();
        let mut current_section = "";
        let fields = SettingsField::visible(&state.draft);
        let selected_field = fields[state.selected.min(fields.len() - 1)];

        for (index, field) in fields.iter().enumerate() {
            if field.section() != current_section {
                current_section = field.section();
                if !lines.is_empty() {
                    lines.push(Line::from(""));
                }
                lines.push(Line::from(current_section).style(bold));
            }

            let selected = index == state.selected;
            let prefix = if selected { "> " } else { "  " };
            // Mark fields that differ from what's saved on disk.
            let marker = if field.is_changed(&state.draft, &app.settings) {
                "*"
            } else {
                " "
            };
            let value = field.display_value(&state.draft);

            let style = if selected {
                Style::default()
                    .fg(palette.running)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            lines.push(
                Line::from(format!("{}{:<20}{} {}", prefix, field.label(), marker, value))
                    .style(style),
            );
        }

        lines.push(Line::from(""));
        if state.editing {
            lines.push(Line::from(format!("Editing {}:", selected_field.label())).style(bold));
            lines.push(
                Line::from(format!("{}▏", state.input)).style(Style::default().fg(palette.parent)),
            );
            lines.push(Line::from("Enter apply · Esc cancel edit").style(dim));
        } else {
            lines.push(Line::from(selected_field.description()).style(dim));
            lines.push(Line::from(""));
            let footer = if selected_field.is_text() {
                "↑↓ select · ←→ change · Enter type value · z undo all · Esc save & close"
            } else {
                "↑↓ select · ←→ change · z undo all · Esc save & close"
            };
            lines.push(Line::from(footer).style(dim));
        }

        let title = if fields
            .iter()
            .any(|field| field.is_changed(&state.draft, &app.settings))
        {
            "Settings — changes apply when closed"
        } else {
            "Settings"
        };
        let block = Block::default()
            .title(title)
            .borders(Borders::ALL)
            .style(Style::default().fg(palette.border));

        let paragraph = Paragraph::new(lines)
            .block(block)
            .wrap(ratatui::widgets::Wrap { trim: true });
        frame.render_widget(paragraph, area);
    }
}
