use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

use crate::app::AppState;
use crate::ui::theme::current_theme;

pub fn draw_code_input(f: &mut Frame, app: &AppState) {
    let theme = current_theme();
    let area = centered_rect(60, 30, f.area());

    f.render_widget(Clear, area);

    let block = Block::default()
        .title(Span::styled(" Enter Share Code ", theme.title_style()))
        .borders(Borders::ALL)
        .border_style(theme.border_style(true))
        .style(Style::default().bg(theme.bg));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // padding
            Constraint::Length(1), // instruction
            Constraint::Length(2), // padding
            Constraint::Length(1), // input field
            Constraint::Length(2), // padding
            Constraint::Length(1), // hint
            Constraint::Min(0),
        ])
        .split(inner);

    // Instruction
    let instruction = Line::from(Span::styled(
        "  Paste the code from the sender:",
        Style::default().fg(theme.fg),
    ));
    f.render_widget(Paragraph::new(instruction), chunks[1]);

    // Input field with cursor
    let display_code = if app.code_input.is_empty() {
        Span::styled(
            "  e.g. fox-rain-lamp-K7XM9PR2",
            Style::default().fg(theme.fg_dim),
        )
    } else {
        Span::styled(
            format!("  {}_", app.code_input),
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        )
    };
    f.render_widget(Paragraph::new(Line::from(display_code)), chunks[3]);

    // Hint
    let hint = Line::from(vec![
        Span::styled("  [Enter]", Style::default().fg(theme.accent)),
        Span::styled(" connect  ", theme.dim_style()),
        Span::styled("[Esc]", Style::default().fg(theme.accent)),
        Span::styled(" back", theme.dim_style()),
    ]);
    f.render_widget(Paragraph::new(hint), chunks[5]);
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
