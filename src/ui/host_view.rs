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

pub fn draw_host(f: &mut Frame, app: &AppState) {
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
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    let files_focused = app.focus == Focus::FileList;
    file_list::draw_file_list(
        f,
        &app.catalog.entries,
        app.selected_index,
        files_focused,
        "Shared Files",
        &format!("{} files", app.catalog.entries.len()),
        true,
        None,
        main_chunks[0],
    );

    let activity_focused = app.focus == Focus::History;
    draw_activity(f, app, main_chunks[1], activity_focused, &theme);

    status_bar::draw_status_bar(
        f,
        &[
            ("a", "add"),
            ("r", "remove"),
            ("l", "limit"),
            ("c", "copy code"),
            ("?", "help"),
            ("q", "quit"),
        ],
        app.status_message.as_deref(),
        chunks[2],
    );
}

fn draw_header(f: &mut Frame, app: &AppState, area: Rect, theme: &crate::ui::theme::Theme) {
    let block = Block::default()
        .title(Line::from(vec![
            Span::styled(" snag ", theme.title_style()),
            Span::styled("─ Sending ", Style::default().fg(theme.fg_dim)),
        ]))
        .borders(Borders::ALL)
        .border_style(theme.border_style(false));

    let code_display = if app.share_code.is_empty() {
        Span::styled("generating...", Style::default().fg(theme.warning))
    } else {
        Span::styled(
            &app.share_code,
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        )
    };

    let mut code_spans = vec![
        Span::raw("  Share Code: "),
        code_display,
        Span::raw("          Peers: "),
        Span::styled(
            format!("{}", app.peers.len()),
            Style::default().fg(theme.accent),
        ),
    ];

    // Append limit info inline
    if let Some(ref limit) = app.share_limit {
        let limit_text = match limit {
            crate::app::ShareLimit::MaxDownloads(n) => {
                let remaining = n.saturating_sub(app.completed_downloads);
                format!("  |  {} download(s) left", remaining)
            }
            crate::app::ShareLimit::Countdown { expires_at } => {
                let remaining = expires_at.saturating_duration_since(std::time::Instant::now());
                let mins = remaining.as_secs() / 60;
                let secs = remaining.as_secs() % 60;
                format!("  |  {}m {}s left", mins, secs)
            }
            crate::app::ShareLimit::Deadline { expires_at } => {
                format!("  |  until {}", expires_at.format("%H:%M"))
            }
        };
        code_spans.push(Span::styled(limit_text, Style::default().fg(theme.warning)));
    }

    let code_line = Line::from(code_spans);

    let header = Paragraph::new(code_line).block(block);
    f.render_widget(header, area);
}

fn draw_activity(
    f: &mut Frame,
    app: &AppState,
    area: Rect,
    focused: bool,
    theme: &crate::ui::theme::Theme,
) {
    let block = Block::default()
        .title(Span::styled(" Activity ", theme.title_style()))
        .borders(Borders::ALL)
        .border_style(theme.border_style(focused));

    if app.transfers.is_empty() {
        let msg = Paragraph::new(Line::from(Span::styled(
            "  No active transfers",
            theme.dim_style(),
        )))
        .block(block);
        f.render_widget(msg, area);
        return;
    }

    let inner = block.inner(area);
    f.render_widget(block, area);

    let bar_constraints: Vec<Constraint> = app
        .transfers
        .iter()
        .map(|_| Constraint::Length(2))
        .collect();

    let transfer_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(bar_constraints)
        .split(inner);

    for (i, transfer) in app.transfers.iter().enumerate() {
        if i < transfer_chunks.len() {
            transfer_bar::draw_transfer_bar(f, transfer, transfer_chunks[i]);
        }
    }
}
