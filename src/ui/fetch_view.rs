use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::app::{AppState, Focus};
use crate::ui::theme::current_theme;
use crate::ui::widgets::{file_list, status_bar, transfer_bar};

pub fn draw_fetch(f: &mut Frame, app: &AppState) {
    let theme = current_theme();
    let area = f.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(5),    // Main content
            Constraint::Length(1), // Status bar
        ])
        .split(area);

    draw_header(f, app, chunks[0], &theme);

    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(chunks[1]);

    let files_focused = app.focus == Focus::FileList;
    file_list::draw_file_list(
        f,
        &app.catalog.entries,
        app.selected_index,
        files_focused,
        "Available Files",
        "",
        false,
        Some(&app.fetch_selected),
        main_chunks[0],
    );

    let downloads_focused = app.focus == Focus::History;
    draw_downloads(f, app, main_chunks[1], downloads_focused, &theme);

    let keys = if app.connected {
        vec![
            ("space", "select"),
            ("enter", "download"),
            ("a", "all"),
            ("?", "help"),
            ("q", "quit"),
        ]
    } else {
        vec![("?", "help"), ("q", "quit")]
    };

    status_bar::draw_status_bar(f, &keys, app.status_message.as_deref(), chunks[2]);
}

fn draw_header(f: &mut Frame, app: &AppState, area: Rect, theme: &crate::ui::theme::Theme) {
    let status = if app.connected {
        Span::styled("Connected", Style::default().fg(theme.success))
    } else {
        Span::styled("Connecting...", Style::default().fg(theme.warning))
    };

    let block = Block::default()
        .title(Line::from(vec![
            Span::styled(" snag ", theme.title_style()),
            Span::styled("─ ", Style::default().fg(theme.fg_dim)),
            status,
        ]))
        .borders(Borders::ALL)
        .border_style(theme.border_style(false));

    let auth_words = crate::share_code::extract_auth_words(&app.share_code);
    let code_line = Line::from(vec![
        Span::raw("  Code: "),
        Span::styled(
            &auth_words,
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        ),
    ]);

    let header = Paragraph::new(code_line).block(block);
    f.render_widget(header, area);
}

fn draw_downloads(
    f: &mut Frame,
    app: &AppState,
    area: Rect,
    focused: bool,
    theme: &crate::ui::theme::Theme,
) {
    let block = Block::default()
        .title(Span::styled(" Downloads ", theme.title_style()))
        .borders(Borders::ALL)
        .border_style(theme.border_style(focused));

    let active_transfers: Vec<_> = app
        .transfers
        .iter()
        .filter(|t| {
            matches!(
                t.status,
                crate::transfer::manager::TransferStatus::Downloading
            )
        })
        .collect();

    if active_transfers.is_empty() {
        let msg = Paragraph::new(Line::from(Span::styled(
            "  Select files and press Enter to download",
            theme.dim_style(),
        )))
        .block(block);
        f.render_widget(msg, area);
        return;
    }

    let inner = block.inner(area);
    f.render_widget(block, area);

    let bar_constraints: Vec<Constraint> = active_transfers
        .iter()
        .map(|_| Constraint::Length(2))
        .collect();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(bar_constraints)
        .split(inner);

    for (i, transfer) in active_transfers.iter().enumerate() {
        if i < chunks.len() {
            transfer_bar::draw_transfer_bar(f, transfer, chunks[i]);
        }
    }
}
