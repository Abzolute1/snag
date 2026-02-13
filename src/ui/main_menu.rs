use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame,
};

use crate::app::{AppState, Focus};
use crate::state::TransferDirection;
use crate::ui::theme::current_theme;
use crate::ui::widgets::file_list::format_size;
use crate::ui::widgets::status_bar;

const LOGO: &str = r"  snag";

pub fn draw_main_menu(f: &mut Frame, app: &AppState) {
    let theme = current_theme();
    let area = f.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // Header / logo
            Constraint::Min(5),    // Main content
            Constraint::Length(1), // Status bar
        ])
        .split(area);

    // --- Header ---
    draw_header(f, chunks[0], &theme);

    // --- Main: files + history ---
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(55), // Your files
            Constraint::Percentage(45), // Recent activity
        ])
        .split(chunks[1]);

    draw_file_panel(f, app, main_chunks[0], app.focus == Focus::FileList, &theme);
    draw_history_panel(f, app, main_chunks[1], app.focus == Focus::History, &theme);

    // --- Status bar (context-sensitive) ---
    let hints: &[(&str, &str)] = if app.focus == Focus::History && !app.persisted.history.is_empty()
    {
        &[
            ("⏎", "re-add"),
            ("x", "remove"),
            ("Tab", "files"),
            ("s", "share"),
            ("r", "receive"),
            ("?", "help"),
            ("q", "quit"),
        ]
    } else {
        &[
            ("s", "share"),
            ("r", "receive"),
            ("a", "add files"),
            ("d", "remove"),
            ("S", "settings"),
            ("?", "help"),
            ("q", "quit"),
        ]
    };
    status_bar::draw_status_bar(f, hints, app.status_message.as_deref(), chunks[2]);
}

fn draw_header(f: &mut Frame, area: Rect, theme: &crate::ui::theme::Theme) {
    let line = Line::from(vec![
        Span::styled(
            LOGO,
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("  P2P file sharing", Style::default().fg(theme.fg_dim)),
        Span::raw("    "),
        Span::styled(
            format!("v{}", env!("CARGO_PKG_VERSION")),
            Style::default().fg(theme.fg_dim),
        ),
    ]);
    let header = Paragraph::new(vec![Line::from(""), line]);
    f.render_widget(header, area);
}

fn draw_file_panel(
    f: &mut Frame,
    app: &AppState,
    area: Rect,
    focused: bool,
    theme: &crate::ui::theme::Theme,
) {
    let count = app.persisted.shared_files.len();
    let title_right = if count > 0 {
        format!("{} item{} ", count, if count == 1 { "" } else { "s" })
    } else {
        String::new()
    };

    let block = Block::default()
        .title(Line::from(vec![
            Span::styled(" Your Files ", theme.title_style()),
            Span::styled(title_right, Style::default().fg(theme.fg_dim)),
        ]))
        .borders(Borders::ALL)
        .border_style(theme.border_style(focused));

    if app.persisted.shared_files.is_empty() {
        let lines = vec![
            Line::from(""),
            Line::from(Span::styled(
                "  No files yet. Press [a] to add files to share.",
                theme.dim_style(),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  Once you have files, press [s] to start sharing.",
                theme.dim_style(),
            )),
        ];
        let p = Paragraph::new(lines).block(block);
        f.render_widget(p, area);
        return;
    }

    let inner_width = area.width.saturating_sub(4) as usize;
    let size_width = 12;
    let icon_width = 4; // "  📁 " or "  📄 "
    let name_width = inner_width.saturating_sub(size_width + icon_width);

    let missing_tag = " [missing]";
    let items: Vec<ListItem> = app
        .persisted
        .shared_files
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let icon = if entry.is_dir { " /" } else { "  " };
            let effective_name_width = if entry.missing {
                name_width.saturating_sub(missing_tag.len())
            } else {
                name_width
            };
            let display_name = if entry.name.len() > effective_name_width {
                let truncated: String = entry
                    .name
                    .chars()
                    .take(effective_name_width.saturating_sub(3))
                    .collect();
                format!("{}...", truncated)
            } else {
                entry.name.clone()
            };
            let tag_str = if entry.missing { missing_tag } else { "" };
            let padding = name_width
                .saturating_sub(display_name.len())
                .saturating_sub(tag_str.len());

            let name_color = if entry.missing {
                theme.fg_dim
            } else {
                theme.fg
            };
            let mut spans = vec![
                Span::styled(
                    format!("  {}", display_name),
                    Style::default().fg(name_color),
                ),
                Span::styled(icon, Style::default().fg(theme.accent_dim)),
            ];
            if entry.missing {
                spans.push(Span::styled(
                    missing_tag,
                    Style::default().fg(theme.warning),
                ));
            }
            spans.push(Span::raw(" ".repeat(padding)));
            spans.push(Span::styled(
                format!("{:>width$}", format_size(entry.size), width = size_width),
                theme.dim_style(),
            ));
            let line = Line::from(spans);

            if focused && i == app.selected_index {
                ListItem::new(line).style(theme.selected_style())
            } else {
                ListItem::new(line)
            }
        })
        .collect();

    let list = List::new(items).block(block);
    let mut state = ListState::default();
    if focused {
        state.select(Some(app.selected_index));
    }
    f.render_stateful_widget(list, area, &mut state);
}

fn draw_history_panel(
    f: &mut Frame,
    app: &AppState,
    area: Rect,
    focused: bool,
    theme: &crate::ui::theme::Theme,
) {
    let count = app.persisted.history.len();
    let title_right = if count > 0 {
        format!("{} ", count)
    } else {
        String::new()
    };

    let block = Block::default()
        .title(Line::from(vec![
            Span::styled(" Recent Activity ", theme.title_style()),
            Span::styled(title_right, Style::default().fg(theme.fg_dim)),
        ]))
        .borders(Borders::ALL)
        .border_style(theme.border_style(focused));

    if app.persisted.history.is_empty() {
        let msg = Paragraph::new(Line::from(Span::styled(
            "  No transfers yet",
            theme.dim_style(),
        )))
        .block(block);
        f.render_widget(msg, area);
        return;
    }

    let items: Vec<ListItem> = app
        .persisted
        .history
        .iter()
        .enumerate()
        .take(area.height.saturating_sub(2) as usize) // fit in panel
        .map(|(i, entry)| {
            let arrow = match entry.direction {
                TransferDirection::Upload => "↑",
                TransferDirection::Download => "↓",
            };
            let arrow_color = match entry.direction {
                TransferDirection::Upload => theme.accent,
                TransferDirection::Download => theme.success,
            };
            let status_icon = match entry.status {
                crate::state::TransferResult::Complete => "✓",
                crate::state::TransferResult::Failed => "✗",
                crate::state::TransferResult::Cancelled => "○",
            };
            let status_color = match entry.status {
                crate::state::TransferResult::Complete => theme.success,
                crate::state::TransferResult::Failed => theme.error,
                crate::state::TransferResult::Cancelled => theme.fg_dim,
            };

            // show a + hint for entries that can be re-added
            let re_add_hint = if entry.path.is_some() { " +" } else { "  " };

            let line = Line::from(vec![
                Span::raw("  "),
                Span::styled(arrow, Style::default().fg(arrow_color)),
                Span::raw(" "),
                Span::raw(format!("{:<24}", entry.file_name)),
                Span::styled(
                    format!("{:>10}", format_size(entry.bytes)),
                    theme.dim_style(),
                ),
                Span::raw("  "),
                Span::styled(&entry.timestamp, theme.dim_style()),
                Span::raw("  "),
                Span::styled(status_icon, Style::default().fg(status_color)),
                Span::styled(re_add_hint, Style::default().fg(theme.accent)),
            ]);

            if focused && i == app.history_selected {
                ListItem::new(line).style(theme.selected_style())
            } else {
                ListItem::new(line)
            }
        })
        .collect();

    let list = List::new(items).block(block);
    let mut state = ListState::default();
    if focused {
        state.select(Some(app.history_selected));
    }
    f.render_stateful_widget(list, area, &mut state);
}
