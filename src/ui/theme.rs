use ratatui::style::{Color, Modifier, Style};
use std::sync::atomic::{AtomicU8, Ordering};

static ACTIVE_THEME: AtomicU8 = AtomicU8::new(0);

/// All available theme names, in cycling order for the settings UI.
pub const THEME_NAMES: &[&str] = &["orange", "white", "blue", "green", "pink", "nord"];

/// Color theme for the UI
#[derive(Clone, Copy)]
pub struct Theme {
    pub accent: Color,
    pub accent_dim: Color,
    pub fg: Color,
    pub fg_dim: Color,
    pub bg: Color,
    pub border: Color,
    pub border_focus: Color,
    pub selected_bg: Color,
    pub progress_filled: Color,
    pub progress_empty: Color,
    pub success: Color,
    pub error: Color,
    pub warning: Color,
}

impl Theme {
    /// Orange theme (default)
    pub fn orange() -> Self {
        Self {
            accent: Color::Indexed(208),     // orange
            accent_dim: Color::Indexed(166), // darker orange
            fg: Color::White,
            fg_dim: Color::Gray,
            bg: Color::Indexed(233), // near-black bg
            border: Color::DarkGray,
            border_focus: Color::Indexed(208),
            selected_bg: Color::Indexed(236), // dark gray highlight
            progress_filled: Color::Indexed(208),
            progress_empty: Color::DarkGray,
            success: Color::Green,
            error: Color::Red,
            warning: Color::Yellow,
        }
    }

    /// White/minimal theme
    pub fn white() -> Self {
        Self {
            accent: Color::White,
            accent_dim: Color::Gray,
            fg: Color::White,
            fg_dim: Color::Gray,
            bg: Color::Indexed(233),
            border: Color::DarkGray,
            border_focus: Color::White,
            selected_bg: Color::Indexed(237),
            progress_filled: Color::White,
            progress_empty: Color::DarkGray,
            success: Color::Green,
            error: Color::Red,
            warning: Color::Yellow,
        }
    }

    /// Blue/cyan theme
    pub fn blue() -> Self {
        Self {
            accent: Color::Indexed(75),     // light blue
            accent_dim: Color::Indexed(67), // muted blue
            fg: Color::White,
            fg_dim: Color::Gray,
            bg: Color::Indexed(233),
            border: Color::DarkGray,
            border_focus: Color::Indexed(75),
            selected_bg: Color::Indexed(236),
            progress_filled: Color::Indexed(75),
            progress_empty: Color::DarkGray,
            success: Color::Green,
            error: Color::Red,
            warning: Color::Yellow,
        }
    }

    /// Green/hacker theme
    pub fn green() -> Self {
        Self {
            accent: Color::Indexed(41),     // bright green
            accent_dim: Color::Indexed(28), // darker green
            fg: Color::Indexed(157),        // light green text
            fg_dim: Color::Indexed(65),     // muted green
            bg: Color::Indexed(233),
            border: Color::Indexed(236),
            border_focus: Color::Indexed(41),
            selected_bg: Color::Indexed(236),
            progress_filled: Color::Indexed(41),
            progress_empty: Color::Indexed(236),
            success: Color::Indexed(46),
            error: Color::Red,
            warning: Color::Yellow,
        }
    }

    /// Pink/magenta theme
    pub fn pink() -> Self {
        Self {
            accent: Color::Indexed(205),     // pink
            accent_dim: Color::Indexed(132), // muted pink
            fg: Color::White,
            fg_dim: Color::Gray,
            bg: Color::Indexed(233),
            border: Color::DarkGray,
            border_focus: Color::Indexed(205),
            selected_bg: Color::Indexed(236),
            progress_filled: Color::Indexed(205),
            progress_empty: Color::DarkGray,
            success: Color::Green,
            error: Color::Red,
            warning: Color::Yellow,
        }
    }

    /// Nord-inspired muted theme
    pub fn nord() -> Self {
        Self {
            accent: Color::Indexed(110),    // nord frost
            accent_dim: Color::Indexed(67), // nord10
            fg: Color::Indexed(252),        // light gray
            fg_dim: Color::Indexed(245),
            bg: Color::Indexed(233),
            border: Color::Indexed(238), // nord3
            border_focus: Color::Indexed(110),
            selected_bg: Color::Indexed(235), // nord0
            progress_filled: Color::Indexed(110),
            progress_empty: Color::Indexed(238),
            success: Color::Indexed(108), // nord14
            error: Color::Indexed(131),   // nord11
            warning: Color::Indexed(180), // nord13
        }
    }

    pub fn title_style(&self) -> Style {
        Style::default()
            .fg(self.accent)
            .add_modifier(Modifier::BOLD)
    }

    pub fn border_style(&self, focused: bool) -> Style {
        if focused {
            Style::default().fg(self.border_focus)
        } else {
            Style::default().fg(self.border)
        }
    }

    pub fn selected_style(&self) -> Style {
        Style::default().fg(self.fg).bg(self.selected_bg)
    }

    pub fn dim_style(&self) -> Style {
        Style::default().fg(self.fg_dim)
    }

    pub fn accent_style(&self) -> Style {
        Style::default().fg(self.accent)
    }

    /// Return the ANSI escape code for the accent color (for headless mode).
    pub fn accent_ansi(&self) -> String {
        match self.accent {
            Color::Rgb(r, g, b) => format!("\x1b[38;2;{};{};{}m", r, g, b),
            Color::White => "\x1b[37m".to_string(),
            Color::Green => "\x1b[32m".to_string(),
            _ => "\x1b[38;5;208m".to_string(), // fallback orange
        }
    }

    /// Return the ANSI escape code for the success color.
    pub fn success_ansi(&self) -> String {
        match self.success {
            Color::Rgb(r, g, b) => format!("\x1b[38;2;{};{};{}m", r, g, b),
            Color::Green => "\x1b[32m".to_string(),
            _ => "\x1b[32m".to_string(),
        }
    }

    /// Return the ANSI escape code for the error color.
    pub fn error_ansi(&self) -> String {
        match self.error {
            Color::Rgb(r, g, b) => format!("\x1b[38;2;{};{};{}m", r, g, b),
            Color::Red => "\x1b[31m".to_string(),
            _ => "\x1b[31m".to_string(),
        }
    }
}

/// Set the active theme by name. Unknown names fall back to orange.
pub fn set_theme(name: &str) {
    let id = THEME_NAMES.iter().position(|&n| n == name).unwrap_or(0) as u8;
    ACTIVE_THEME.store(id, Ordering::Relaxed);
}

/// Get the current theme
pub fn current_theme() -> Theme {
    match ACTIVE_THEME.load(Ordering::Relaxed) {
        0 => Theme::orange(),
        1 => Theme::white(),
        2 => Theme::blue(),
        3 => Theme::green(),
        4 => Theme::pink(),
        5 => Theme::nord(),
        _ => Theme::orange(),
    }
}

/// Get the name of the currently active theme
pub fn current_theme_name() -> &'static str {
    let id = ACTIVE_THEME.load(Ordering::Relaxed) as usize;
    THEME_NAMES.get(id).unwrap_or(&"orange")
}

/// Cycle to the next theme, returns the new name
pub fn next_theme(current: &str) -> &'static str {
    let idx = THEME_NAMES.iter().position(|&n| n == current).unwrap_or(0);
    let next = (idx + 1) % THEME_NAMES.len();
    THEME_NAMES[next]
}
