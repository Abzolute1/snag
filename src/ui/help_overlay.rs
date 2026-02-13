use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

use crate::app::{AppState, Screen};
use crate::ui::theme::current_theme;

pub fn draw_help(f: &mut Frame, app: &AppState) {
    let theme = current_theme();
    let area = centered_rect(60, 70, f.area());

    f.render_widget(Clear, area);

    let block = Block::default()
        .title(Span::styled(" Help ", theme.title_style()))
        .borders(Borders::ALL)
        .border_style(theme.border_style(true))
        .style(Style::default().bg(theme.bg));

    let mut lines = Vec::new();
    lines.push(Line::from(""));

    let section = |title: &str| -> Line {
        Line::from(Span::styled(
            format!("  {}", title),
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        ))
    };

    let row = |key: &str, desc: &str| -> Line {
        Line::from(vec![
            Span::styled(format!("    {:>16}", key), Style::default().fg(theme.fg)),
            Span::raw("  "),
            Span::styled(desc.to_string(), theme.dim_style()),
        ])
    };

    // Navigation
    lines.push(section("Navigation"));
    lines.push(row("up / k", "Move up"));
    lines.push(row("down / j", "Move down"));
    lines.push(row("Tab", "Switch focus between panels"));
    lines.push(row("?", "Toggle this help"));
    lines.push(row("q / Esc", "Quit / go back"));
    lines.push(row("Ctrl+c", "Force quit"));

    lines.push(Line::from(""));

    match app.screen {
        Screen::Dashboard => {
            lines.push(section("Dashboard"));
            lines.push(row("a", "Add files to share"));
            lines.push(row("d / x", "Remove selected item"));
            lines.push(row("s / Enter", "Start sharing your files"));
            lines.push(row("r", "Receive files (enter a code)"));
            lines.push(row("S", "Open settings"));
            lines.push(Line::from(""));
            lines.push(section("History (Tab to focus)"));
            lines.push(row("Enter", "Re-add file to share list"));
            lines.push(row("d / x", "Remove history entry"));
        }
        Screen::Sending => {
            lines.push(section("Sending"));
            lines.push(row("c", "Copy share code to clipboard"));
            lines.push(row("a", "Add more files"));
            lines.push(row("d / x", "Remove selected file"));
            lines.push(row("l", "Set share limit"));
            lines.push(row("Esc / Backspace", "Stop sharing, back to dashboard"));
        }
        Screen::Receiving => {
            lines.push(section("Receiving"));
            lines.push(row("Space", "Toggle file selection"));
            lines.push(row("a", "Select / deselect all"));
            lines.push(row("Enter", "Download selected files"));
            lines.push(row("Esc / Backspace", "Disconnect, back to dashboard"));
        }
    }

    lines.push(Line::from(""));
    lines.push(section("File Browser"));
    lines.push(row("Enter / right", "Open directory / add file"));
    lines.push(row("Space", "Add selected (file or folder)"));
    lines.push(row("Backspace / h", "Go to parent directory"));
    lines.push(row("Esc", "Close browser"));

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Press ? or Esc to close",
        theme.dim_style(),
    )));

    let help = Paragraph::new(lines).block(block);
    f.render_widget(help, area);
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
