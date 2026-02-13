use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph},
    Frame,
};

use crate::app::AppState;
use crate::ui::theme::current_theme;
use crate::ui::widgets::file_list::format_size;

pub fn draw_file_browser(f: &mut Frame, app: &AppState) {
    let theme = current_theme();

    let area = centered_rect(70, 80, f.area());
    f.render_widget(Clear, area);

    let path_display = app.browser_path.display().to_string();
    let block = Block::default()
        .title(Line::from(vec![
            Span::styled(" Add File ", theme.title_style()),
            Span::styled(
                format!("─ {} ", path_display),
                Style::default().fg(theme.fg_dim),
            ),
        ]))
        .borders(Borders::ALL)
        .border_style(theme.border_style(true))
        .style(Style::default().bg(theme.bg));

    if app.browser_entries.is_empty() {
        let items = vec![ListItem::new(Line::from(Span::styled(
            "  (empty directory)",
            theme.dim_style(),
        )))];
        let list = List::new(items).block(block);
        f.render_widget(list, area);
        return;
    }

    let items: Vec<ListItem> = app
        .browser_entries
        .iter()
        .enumerate()
        .map(|(i, path)| {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| path.display().to_string());

            let (display, size_str) = if path.is_dir() {
                (format!("  {}/", name), String::new())
            } else {
                let size = path.metadata().map(|m| m.len()).unwrap_or(0);
                (format!("  {}", name), format_size(size))
            };

            let line = Line::from(vec![
                Span::raw(display),
                Span::raw("  "),
                Span::styled(size_str, theme.dim_style()),
            ]);

            if i == app.browser_selected {
                ListItem::new(line).style(theme.selected_style())
            } else if path.is_dir() {
                ListItem::new(line).style(Style::default().fg(theme.accent))
            } else {
                ListItem::new(line)
            }
        })
        .collect();

    // Split area: main list + hint bar at bottom
    let inner_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(1)])
        .split(area);

    let list = List::new(items).block(block);
    let mut state = ListState::default();
    state.select(Some(app.browser_selected));
    f.render_stateful_widget(list, inner_chunks[0], &mut state);

    // Hint bar
    let hints = Line::from(vec![
        Span::styled(" space", Style::default().fg(theme.accent)),
        Span::styled(" add file/folder  ", theme.dim_style()),
        Span::styled("enter", Style::default().fg(theme.accent)),
        Span::styled(" open folder  ", theme.dim_style()),
        Span::styled("backspace", Style::default().fg(theme.accent)),
        Span::styled(" up  ", theme.dim_style()),
        Span::styled("esc", Style::default().fg(theme.accent)),
        Span::styled(" close", theme.dim_style()),
    ]);
    f.render_widget(Paragraph::new(hints), inner_chunks[1]);
}

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
