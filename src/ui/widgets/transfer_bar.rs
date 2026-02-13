use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

use crate::transfer::manager::TransferInfo;
use crate::ui::theme::current_theme;
use crate::ui::widgets::file_list::format_size;

/// Draw a transfer progress bar:
/// filename    ████████░░░░░░░░  52%  13 MB/s  ETA 3m
pub fn draw_transfer_bar(f: &mut Frame, transfer: &TransferInfo, area: Rect) {
    let theme = current_theme();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(1)])
        .split(area);

    // Line 1: peer/file name
    let name_line = if let Some(ref peer) = transfer.peer_name {
        Line::from(vec![
            Span::raw("  "),
            Span::styled(peer, Style::default().fg(theme.accent)),
            Span::raw(" ← "),
            Span::raw(&transfer.file_name),
        ])
    } else {
        Line::from(vec![Span::raw(format!("  {}", transfer.file_name))])
    };
    f.render_widget(Paragraph::new(name_line), chunks[0]);

    // Line 2: progress bar with stats
    let bar_width = area.width.saturating_sub(35) as usize;
    let filled = (bar_width as f64 * transfer.progress) as usize;
    let empty = bar_width.saturating_sub(filled);

    let bar_filled = "█".repeat(filled);
    let bar_empty = "░".repeat(empty);

    let percent = format!("{:>3.0}%", transfer.progress * 100.0);
    let speed = format!("{}/s", format_size(transfer.speed_bytes_per_sec));
    let eta = format_eta(transfer.eta_seconds);

    let progress_line = Line::from(vec![
        Span::raw("  "),
        Span::styled(&bar_filled, Style::default().fg(theme.progress_filled)),
        Span::styled(&bar_empty, Style::default().fg(theme.progress_empty)),
        Span::raw("  "),
        Span::styled(&percent, Style::default().fg(theme.fg)),
        Span::raw("  "),
        Span::styled(&speed, Style::default().fg(theme.fg_dim)),
        Span::raw("  "),
        Span::styled(&eta, Style::default().fg(theme.fg_dim)),
    ]);
    f.render_widget(Paragraph::new(progress_line), chunks[1]);
}

fn format_eta(seconds: Option<u64>) -> String {
    match seconds {
        None => "ETA --".to_string(),
        Some(s) if s < 60 => format!("ETA {}s", s),
        Some(s) if s < 3600 => format!("ETA {}m {}s", s / 60, s % 60),
        Some(s) => format!("ETA {}h {}m", s / 3600, (s % 3600) / 60),
    }
}
