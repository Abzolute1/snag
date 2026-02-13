use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

use crate::app::AppState;
use crate::ui::theme::current_theme;

pub fn draw_limit_overlay(f: &mut Frame, app: &AppState) {
    let theme = current_theme();
    let area = centered_rect(50, 50, f.area());
    f.render_widget(Clear, area);

    let block = Block::default()
        .title(Span::styled(" Set Share Limit ", theme.title_style()))
        .borders(Borders::ALL)
        .border_style(theme.border_style(true))
        .style(Style::default().bg(theme.bg));

    if app.limit_input_step == 0 {
        // Menu: choose limit type
        let options = [
            "Max downloads",
            "Countdown (minutes)",
            "Deadline (hours from now)",
            "Clear limit",
        ];

        let mut lines = vec![Line::from("")];
        for (i, opt) in options.iter().enumerate() {
            let marker = if i == app.limit_menu_selected {
                " > "
            } else {
                "   "
            };
            let style = if i == app.limit_menu_selected {
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme.fg)
            };
            lines.push(Line::from(Span::styled(
                format!("{}{}", marker, opt),
                style,
            )));
        }
        lines.push(Line::from(""));

        // Show current limit
        if let Some(ref limit) = app.share_limit {
            let current = match limit {
                crate::app::ShareLimit::MaxDownloads(n) => {
                    let remaining = n.saturating_sub(app.completed_downloads);
                    format!("Current: {} download(s) remaining", remaining)
                }
                crate::app::ShareLimit::Countdown { expires_at } => {
                    let remaining = expires_at.saturating_duration_since(std::time::Instant::now());
                    let mins = remaining.as_secs() / 60;
                    let secs = remaining.as_secs() % 60;
                    format!("Current: {}m {}s remaining", mins, secs)
                }
                crate::app::ShareLimit::Deadline { expires_at } => {
                    format!("Current: until {}", expires_at.format("%b %d %H:%M"))
                }
            };
            lines.push(Line::from(Span::styled(
                format!("  {}", current),
                Style::default().fg(theme.fg_dim),
            )));
            lines.push(Line::from(""));
        }

        lines.push(Line::from(Span::styled(
            "  enter: select  esc: cancel",
            theme.dim_style(),
        )));

        let p = Paragraph::new(lines).block(block);
        f.render_widget(p, area);
    } else {
        // Value input
        let prompt = match app.limit_menu_selected {
            0 => "Max downloads:",
            1 => "Minutes from now:",
            2 => "Hours from now:",
            _ => "Value:",
        };

        let cursor = if app.limit_input_value.is_empty() {
            "_".to_string()
        } else {
            format!("{}_", app.limit_input_value)
        };

        let lines = vec![
            Line::from(""),
            Line::from(Span::styled(
                format!("  {}", prompt),
                Style::default().fg(theme.fg),
            )),
            Line::from(""),
            Line::from(Span::styled(
                format!("  {}", cursor),
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  enter: confirm  esc: back",
                theme.dim_style(),
            )),
        ];

        let p = Paragraph::new(lines).block(block);
        f.render_widget(p, area);
    }
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
