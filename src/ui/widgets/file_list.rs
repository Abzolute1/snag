use ratatui::{
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem},
    Frame,
};

use crate::protocol::catalog::CatalogEntry;
use crate::ui::theme::current_theme;

/// Format file size into human-readable string
pub fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    const TB: u64 = 1024 * GB;

    if bytes >= TB {
        format!("{:.1} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Check if a filename has a potentially dangerous extension
pub fn is_dangerous_extension(name: &str) -> bool {
    let dangerous = [
        ".exe",
        ".msi",
        ".bat",
        ".cmd",
        ".com",
        ".scr",
        ".pif",
        ".sh",
        ".bash",
        ".csh",
        ".ksh",
        ".zsh",
        ".ps1",
        ".psm1",
        ".psd1",
        ".vbs",
        ".vbe",
        ".js",
        ".jse",
        ".wsf",
        ".wsh",
        ".jar",
        ".class",
        ".dll",
        ".so",
        ".dylib",
        ".app",
        ".dmg",
        ".pkg",
        ".deb",
        ".rpm",
        ".appimage",
        ".flatpak",
        ".snap",
    ];
    let lower = name.to_lowercase();
    dangerous.iter().any(|ext| lower.ends_with(ext))
}

#[allow(clippy::too_many_arguments)]
pub fn draw_file_list(
    f: &mut Frame,
    entries: &[CatalogEntry],
    selected: usize,
    focused: bool,
    title: &str,
    right_title: &str,
    all_checked: bool,
    check_states: Option<&[bool]>,
    area: Rect,
) {
    let theme = current_theme();

    let block = Block::default()
        .title(Line::from(vec![
            Span::styled(format!(" {} ", title), theme.title_style()),
            Span::styled(
                format!("{} ", right_title),
                Style::default().fg(theme.fg_dim),
            ),
        ]))
        .borders(Borders::ALL)
        .border_style(theme.border_style(focused));

    if entries.is_empty() {
        let items = vec![ListItem::new(Line::from(vec![Span::styled(
            "  No files",
            theme.dim_style(),
        )]))];
        let list = List::new(items).block(block);
        f.render_widget(list, area);
        return;
    }

    // Calculate max name width for alignment
    let inner_width = area.width.saturating_sub(4) as usize;
    let size_width = 12;
    let checkbox_width = 5; // "  [x] "
    let name_width = inner_width.saturating_sub(size_width + checkbox_width);

    let items: Vec<ListItem> = entries
        .iter()
        .enumerate()
        .flat_map(|(i, entry)| {
            let checked = if let Some(states) = check_states {
                states.get(i).copied().unwrap_or(false)
            } else {
                all_checked
            };

            let checkbox = if checked { "[x]" } else { "[ ]" };
            let name = if entry.is_dir {
                format!("{}/", entry.name)
            } else {
                entry.name.clone()
            };
            let size_str = format_size(entry.size);

            let warn = if is_dangerous_extension(&entry.name) {
                " !"
            } else {
                ""
            };

            // Pad name to align sizes
            let display_name = if name.len() + warn.len() > name_width {
                let truncated: String = name
                    .chars()
                    .take(name_width.saturating_sub(3 + warn.len()))
                    .collect();
                format!("{}...{}", truncated, warn)
            } else {
                format!("{}{}", name, warn)
            };
            let padding = name_width.saturating_sub(display_name.len());

            let name_style = if is_dangerous_extension(&entry.name) {
                Style::default().fg(theme.warning)
            } else {
                Style::default()
            };

            let line = Line::from(vec![
                Span::raw(format!("  {} ", checkbox)),
                Span::styled(display_name, name_style),
                Span::raw(" ".repeat(padding)),
                Span::styled(
                    format!("{:>width$}", size_str, width = size_width),
                    theme.dim_style(),
                ),
            ]);

            let mut result_items = vec![if i == selected {
                ListItem::new(line).style(theme.selected_style())
            } else {
                ListItem::new(line)
            }];

            // Add children preview for directories
            if entry.is_dir && !entry.children.is_empty() {
                let max_preview = 8;
                for child in entry.children.iter().take(max_preview) {
                    let child_name = if child.is_dir {
                        format!("{}/", child.name)
                    } else {
                        child.name.clone()
                    };
                    let child_size = format_size(child.size);
                    let child_warn = if is_dangerous_extension(&child.name) {
                        " !"
                    } else {
                        ""
                    };

                    let child_display = format!("        {}{}", child_name, child_warn);
                    let child_padding = name_width
                        .saturating_sub(child_display.len().saturating_sub(checkbox_width));

                    let child_name_style = if is_dangerous_extension(&child.name) {
                        Style::default().fg(theme.warning)
                    } else {
                        theme.dim_style()
                    };

                    let child_line = Line::from(vec![
                        Span::styled(child_display, child_name_style),
                        Span::raw(" ".repeat(child_padding)),
                        Span::styled(
                            format!("{:>width$}", child_size, width = size_width),
                            theme.dim_style(),
                        ),
                    ]);
                    result_items.push(ListItem::new(child_line));
                }
                if entry.children.len() > max_preview {
                    let more = entry.children.len() - max_preview;
                    let more_line = Line::from(Span::styled(
                        format!("        ... and {} more", more),
                        theme.dim_style(),
                    ));
                    result_items.push(ListItem::new(more_line));
                }
            }

            result_items
        })
        .collect();

    let list = List::new(items).block(block);
    f.render_widget(list, area);
}
