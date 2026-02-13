pub mod code_input;
pub mod fetch_view;
pub mod file_browser;
pub mod help_overlay;
pub mod host_view;
pub mod limit_overlay;
pub mod main_menu;
pub mod settings_overlay;
pub mod theme;
pub mod widgets;

use ratatui::Frame;

use crate::app::{AppState, Overlay, Screen};

pub fn draw(f: &mut Frame, app: &AppState) {
    match app.screen {
        Screen::Dashboard => main_menu::draw_main_menu(f, app),
        Screen::Sending => host_view::draw_host(f, app),
        Screen::Receiving => fetch_view::draw_fetch(f, app),
    }

    match app.overlay {
        Overlay::Help => help_overlay::draw_help(f, app),
        Overlay::FileBrowser => file_browser::draw_file_browser(f, app),
        Overlay::CodeInput => code_input::draw_code_input(f, app),
        Overlay::LimitInput => limit_overlay::draw_limit_overlay(f, app),
        Overlay::Settings => settings_overlay::draw_settings(f, app),
        Overlay::None => {}
    }
}
