use ratatui::{
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

use crate::ui::theme::current_theme;

/// Draw the bottom status bar with keybinding hints
pub fn draw_status_bar(
    f: &mut Frame,
    keys: &[(&str, &str)],
    status_message: Option<&str>,
    area: Rect,
) {
    let theme = current_theme();

    let mut spans = Vec::new();
    spans.push(Span::raw(" "));

    if let Some(msg) = status_message {
        spans.push(Span::styled(msg, Style::default().fg(theme.warning)));
        spans.push(Span::raw("  │  "));
    }

    for (i, (key, desc)) in keys.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("  "));
        }
        spans.push(Span::styled(
            format!("[{}]", key),
            Style::default().fg(theme.accent),
        ));
        spans.push(Span::styled(
            format!(" {}", desc),
            Style::default().fg(theme.fg_dim),
        ));
    }

    let line = Line::from(spans);
    let bar = Paragraph::new(line);
    f.render_widget(bar, area);
}
