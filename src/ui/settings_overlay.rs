use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

use crate::app::AppState;
use crate::ui::theme::current_theme;

struct SettingsItem {
    label: &'static str,
    section: Option<&'static str>, // non-None = render section header before this item
}

// 12 settings across 7 categories
const ITEMS: &[SettingsItem] = &[
    SettingsItem {
        label: "Bell sound",
        section: Some("Notifications"),
    },
    SettingsItem {
        label: "Desktop popup",
        section: None,
    },
    SettingsItem {
        label: "Theme",
        section: Some("Appearance"),
    },
    SettingsItem {
        label: "Download directory",
        section: Some("Transfers"),
    },
    SettingsItem {
        label: "Overwrite behavior",
        section: None,
    },
    SettingsItem {
        label: "Compression",
        section: None,
    },
    SettingsItem {
        label: "Listen port",
        section: Some("Network"),
    },
    SettingsItem {
        label: "Bind address",
        section: None,
    },
    SettingsItem {
        label: "Display name",
        section: Some("Identity"),
    },
    SettingsItem {
        label: "Transfer history",
        section: Some("Privacy"),
    },
    SettingsItem {
        label: "History limit",
        section: None,
    },
    SettingsItem {
        label: "Share code words",
        section: Some("Security"),
    },
];

fn get_value(app: &AppState, idx: usize) -> String {
    let cfg = &app.config;
    match idx {
        0 => if cfg.notifications.bell { "on" } else { "off" }.into(),
        1 => if cfg.notifications.desktop {
            "on"
        } else {
            "off"
        }
        .into(),
        2 => {
            let t = &cfg.appearance.theme;
            let mut cap = t.clone();
            if let Some(first) = cap.get_mut(0..1) {
                first.make_ascii_uppercase();
            }
            cap
        }
        3 => cfg.transfers.download_dir.clone(),
        4 => cfg.transfers.overwrite.clone(),
        5 => if cfg.transfers.compression {
            "on"
        } else {
            "off"
        }
        .into(),
        6 => {
            if cfg.network.port == 0 {
                "random".into()
            } else {
                cfg.network.port.to_string()
            }
        }
        7 => cfg.network.bind_address.clone(),
        8 => {
            if cfg.identity.display_name.is_empty() {
                "(hostname)".into()
            } else {
                cfg.identity.display_name.clone()
            }
        }
        9 => if cfg.privacy.history { "on" } else { "off" }.into(),
        10 => cfg.privacy.history_limit.to_string(),
        11 => cfg.security.code_words.to_string(),
        _ => String::new(),
    }
}

pub fn draw_settings(f: &mut Frame, app: &AppState) {
    let theme = current_theme();
    let area = centered_rect(70, 85, f.area());
    f.render_widget(Clear, area);

    let block = Block::default()
        .title(Span::styled(" Settings ", theme.title_style()))
        .borders(Borders::ALL)
        .border_style(theme.border_style(true))
        .style(Style::default().bg(theme.bg));

    let inner = block.inner(area);
    f.render_widget(block, area);

    // Build all the lines: section headers + setting rows
    let mut lines: Vec<Line> = Vec::new();
    // Track which line index corresponds to which item index, so we can highlight
    let mut item_line_indices: Vec<usize> = Vec::new();

    let inner_width = inner.width.saturating_sub(2) as usize;

    lines.push(Line::from(""));

    for (i, item) in ITEMS.iter().enumerate() {
        if let Some(section) = item.section {
            if i > 0 {
                lines.push(Line::from(""));
            }
            lines.push(Line::from(Span::styled(
                format!("  {}", section),
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD),
            )));
        }

        let is_selected = app.settings_selected == i;
        let value = if app.settings_editing && is_selected {
            format!("{}_", app.settings_edit_buf)
        } else {
            get_value(app, i)
        };

        let label_str = format!("  {}", item.label);
        let val_display = format!("[{}]", value);
        let padding = inner_width
            .saturating_sub(label_str.len())
            .saturating_sub(val_display.len());

        let row_style = if is_selected {
            theme.selected_style()
        } else {
            Style::default()
        };

        let val_color = if app.settings_editing && is_selected {
            theme.accent
        } else {
            theme.fg_dim
        };

        let line = Line::from(vec![
            Span::styled(label_str.clone(), row_style.fg(theme.fg)),
            Span::styled(" ".repeat(padding), row_style),
            Span::styled(val_display.clone(), row_style.fg(val_color)),
        ]);

        item_line_indices.push(lines.len());
        lines.push(line);
    }

    // dont bother rendering items that are off-screen — paragraph handles scroll
    // but we need to calculate scroll offset so the selected item stays visible
    let visible_height = inner.height.saturating_sub(2) as usize; // leave room for hint bar
    let selected_line = item_line_indices
        .get(app.settings_selected)
        .copied()
        .unwrap_or(0);
    let scroll = if selected_line >= visible_height {
        (selected_line - visible_height + 2) as u16
    } else {
        0
    };

    // Hint bar at the bottom
    lines.push(Line::from(""));
    let hint = if app.settings_editing {
        "  enter: confirm  esc: cancel"
    } else {
        "  enter: edit  esc: close  space: toggle"
    };
    lines.push(Line::from(Span::styled(hint, theme.dim_style())));

    let content = Paragraph::new(lines).scroll((scroll, 0));
    f.render_widget(content, inner);
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
