use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use crate::network;
use crate::protocol::catalog::{CatalogEntry, SharedCatalog};
use crate::share_code;
use crate::state::{HistoryEntry, PersistedState, TransferDirection, TransferResult};
use crate::transfer::manager::{TransferInfo, TransferManager};
use crate::ui;
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct PeerInfo {
    pub name: String,
    pub files_requested: Vec<String>,
    pub bytes_sent: u64,
}

/// Which screen we're on
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// Dashboard — the home screen, always the starting point
    Dashboard,
    /// Active sending session
    Sending,
    /// Active receiving session
    Receiving,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    FileList,
    History,
}

#[derive(Clone)]
pub enum ShareLimit {
    MaxDownloads(u32),
    Countdown { expires_at: std::time::Instant },
    Deadline { expires_at: chrono::NaiveDateTime },
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Overlay {
    None,
    Help,
    FileBrowser,
    CodeInput,
    LimitInput,
    Settings,
}

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

pub struct AppState {
    // Current screen
    pub screen: Screen,

    // Persisted state (shared files + history)
    pub persisted: PersistedState,

    // Session state
    pub share_code: String,
    pub catalog: SharedCatalog,
    pub transfers: Vec<TransferInfo>,
    pub peers: Vec<PeerInfo>,
    pub connected: bool,
    pub output_dir: PathBuf,

    // UI navigation
    pub selected_index: usize,
    pub focus: Focus,
    pub overlay: Overlay,
    pub should_quit: bool,
    pub status_message: Option<String>,

    // Transfer engine
    pub transfer_manager: TransferManager,

    // File browser
    pub browser_path: PathBuf,
    pub browser_entries: Vec<PathBuf>,
    pub browser_selected: usize,

    // Fetch selection checkboxes
    pub fetch_selected: Vec<bool>,

    // Code input buffer
    pub code_input: String,

    // Whether network is active
    pub network_started: bool,

    // Cancellation token for the active network task
    pub cancel_token: Option<CancellationToken>,

    // Pipe mode: stream received data to stdout instead of files
    pub pipe_mode: bool,

    // Share limits
    pub share_limit: Option<ShareLimit>,
    pub completed_downloads: u32,

    // Notification: true once we've fired the "all done" notification
    pub notified_complete: bool,
    // Whether to play audible bell on completion
    pub notification_bell: bool,
    // Whether to show desktop notification on completion
    pub notification_desktop: bool,

    // Limit input UI state
    pub limit_menu_selected: usize,
    pub limit_input_value: String,
    pub limit_input_step: u8,

    // Settings overlay
    pub config: crate::config::Config,
    pub settings_selected: usize,
    pub settings_editing: bool,
    pub settings_edit_buf: String,

    // History panel selection
    pub history_selected: usize,
}

impl AppState {
    pub fn new() -> Self {
        let mut persisted = PersistedState::load();
        persisted.refresh_missing();
        let cfg = crate::config::Config::load();

        crate::ui::theme::set_theme(&cfg.appearance.theme);

        Self {
            screen: Screen::Dashboard,
            persisted,
            share_code: String::new(),
            catalog: SharedCatalog::new(),
            transfers: Vec::new(),
            peers: Vec::new(),
            connected: false,
            output_dir: cfg.download_dir(),
            selected_index: 0,
            focus: Focus::FileList,
            overlay: Overlay::None,
            should_quit: false,
            status_message: None,
            transfer_manager: TransferManager::new(),
            browser_path: std::env::current_dir().unwrap_or_else(|_| crate::config::home_dir()),
            browser_entries: Vec::new(),
            browser_selected: 0,
            fetch_selected: Vec::new(),
            code_input: String::new(),
            network_started: false,
            cancel_token: None,
            pipe_mode: false,
            share_limit: None,
            completed_downloads: 0,
            notified_complete: false,
            notification_bell: cfg.notifications.bell,
            notification_desktop: cfg.notifications.desktop,
            limit_menu_selected: 0,
            limit_input_value: String::new(),
            limit_input_step: 0,
            config: cfg,
            settings_selected: 0,
            settings_editing: false,
            settings_edit_buf: String::new(),
            history_selected: 0,
        }
    }

    /// Create an AppState that persists to a custom path, for test isolation.
    /// This avoids touching the real ~/.local/share/snag/state.json.
    pub fn new_with_state_path(state_path: PathBuf) -> Self {
        let mut persisted = PersistedState::load_from(state_path);
        persisted.refresh_missing();
        let cfg = crate::config::Config::load();

        crate::ui::theme::set_theme(&cfg.appearance.theme);

        Self {
            screen: Screen::Dashboard,
            persisted,
            share_code: String::new(),
            catalog: SharedCatalog::new(),
            transfers: Vec::new(),
            peers: Vec::new(),
            connected: false,
            output_dir: cfg.download_dir(),
            selected_index: 0,
            focus: Focus::FileList,
            overlay: Overlay::None,
            should_quit: false,
            status_message: None,
            transfer_manager: TransferManager::new(),
            browser_path: std::env::current_dir().unwrap_or_else(|_| crate::config::home_dir()),
            browser_entries: Vec::new(),
            browser_selected: 0,
            fetch_selected: Vec::new(),
            code_input: String::new(),
            network_started: false,
            cancel_token: None,
            pipe_mode: false,
            share_limit: None,
            completed_downloads: 0,
            notified_complete: false,
            notification_bell: cfg.notifications.bell,
            notification_desktop: cfg.notifications.desktop,
            limit_menu_selected: 0,
            limit_input_value: String::new(),
            limit_input_step: 0,
            config: cfg,
            settings_selected: 0,
            settings_editing: false,
            settings_edit_buf: String::new(),
            history_selected: 0,
        }
    }

    pub fn display_name(&self) -> String {
        let name = &self.config.identity.display_name;
        if name.is_empty() {
            let hostname = crate::discovery::get_hostname();
            if hostname.is_empty() || hostname == "unknown" {
                "snag-user".into()
            } else {
                hostname
            }
        } else {
            name.clone()
        }
    }

    /// Build a catalog from the persisted shared files (skips missing)
    pub fn build_catalog_from_persisted(&mut self) {
        self.catalog = SharedCatalog::new();
        for f in &self.persisted.shared_files {
            if !f.missing {
                self.catalog.add_path(&f.path);
            }
        }
    }

    /// Save persisted state to disk (call after any mutation)
    pub fn save(&self) {
        if let Err(e) = self.persisted.save() {
            tracing::warn!("Failed to save state: {}", e);
        }
    }

    /// Add a file to the persisted list and save
    pub fn add_shared_file(&mut self, path: &std::path::Path) {
        self.persisted.add_file(path);
        self.save();
    }

    /// Remove a file from the persisted list by index
    pub fn remove_shared_file(&mut self) {
        if self.selected_index < self.persisted.shared_files.len() {
            let removed = self.persisted.remove_file(self.selected_index);
            if let Some(f) = removed {
                self.status_message = Some(format!("Removed: {}", f.name));
            }
            if self.selected_index >= self.persisted.shared_files.len() && self.selected_index > 0 {
                self.selected_index -= 1;
            }
            self.save();
        }
    }

    pub fn record_transfer(
        &mut self,
        file_name: &str,
        direction: TransferDirection,
        peer: &str,
        bytes: u64,
        status: TransferResult,
    ) {
        if !self.config.privacy.history {
            return;
        }
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M").to_string();
        self.persisted.add_history(
            HistoryEntry {
                file_name: file_name.to_string(),
                direction,
                peer: peer.to_string(),
                timestamp,
                bytes,
                status,
                path: None,
            },
            self.config.privacy.history_limit,
        );
        self.save();
    }

    /// Called when a share session ends (manual stop, limit reached, etc).
    /// Moves shared files into history so the user can re-add them later.
    pub fn end_share_session(&mut self) {
        if self.persisted.shared_files.is_empty() {
            return;
        }
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M").to_string();
        if self.config.privacy.history {
            // collect first to avoid borrowing shared_files while mutating history
            let entries: Vec<HistoryEntry> = self
                .persisted
                .shared_files
                .iter()
                .map(|file| HistoryEntry {
                    file_name: file.name.clone(),
                    direction: TransferDirection::Upload,
                    peer: String::new(),
                    timestamp: timestamp.clone(),
                    bytes: file.size,
                    status: TransferResult::Complete,
                    path: Some(file.path.clone()),
                })
                .collect();
            let limit = self.config.privacy.history_limit;
            for entry in entries {
                self.persisted.add_history(entry, limit);
            }
        }
        self.persisted.shared_files.clear();
        self.selected_index = 0;
        self.save();
    }

    /// Re-add a file from history back to shared files
    pub fn re_add_from_history(&mut self) {
        if self.history_selected >= self.persisted.history.len() {
            return;
        }
        // clone what we need to avoid borrow conflicts
        let file_name = self.persisted.history[self.history_selected]
            .file_name
            .clone();
        let path = self.persisted.history[self.history_selected].path.clone();
        if let Some(path) = path {
            if path.exists() {
                self.persisted.add_file(&path);
                self.status_message = Some(format!("Re-added: {}", file_name));
                self.save();
            } else {
                self.status_message = Some(format!("File not found: {}", file_name));
            }
        } else {
            self.status_message = Some("No path stored for this entry".to_string());
        }
    }

    /// Remove a history entry by the current selection index
    pub fn remove_history_entry(&mut self) {
        if self.history_selected < self.persisted.history.len() {
            let removed = self.persisted.history.remove(self.history_selected);
            self.status_message = Some(format!("Removed: {}", removed.file_name));
            if self.history_selected >= self.persisted.history.len() && self.history_selected > 0 {
                self.history_selected -= 1;
            }
            self.save();
        }
    }

    // --- navigation ---

    pub fn move_up(&mut self) {
        match self.overlay {
            Overlay::FileBrowser => {
                if self.browser_selected > 0 {
                    self.browser_selected -= 1;
                }
            }
            Overlay::None => {
                if self.screen == Screen::Dashboard && self.focus == Focus::History {
                    if self.history_selected > 0 {
                        self.history_selected -= 1;
                    }
                } else if self.selected_index > 0 {
                    self.selected_index -= 1;
                }
            }
            _ => {}
        }
    }

    pub fn move_down(&mut self) {
        match self.overlay {
            Overlay::FileBrowser => {
                if !self.browser_entries.is_empty()
                    && self.browser_selected < self.browser_entries.len() - 1
                {
                    self.browser_selected += 1;
                }
            }
            Overlay::None => {
                if self.screen == Screen::Dashboard && self.focus == Focus::History {
                    let max = self.persisted.history.len();
                    if max > 0 && self.history_selected < max - 1 {
                        self.history_selected += 1;
                    }
                } else {
                    let max = match self.screen {
                        Screen::Dashboard => self.persisted.shared_files.len(),
                        Screen::Sending => self.catalog.entries.len(),
                        Screen::Receiving => self.catalog.entries.len(),
                    };
                    if max > 0 && self.selected_index < max - 1 {
                        self.selected_index += 1;
                    }
                }
            }
            _ => {}
        }
    }

    /// Ensure fetch_selected is in sync with catalog entries
    pub fn sync_fetch_selected(&mut self) {
        let expected = self.catalog.entries.len();
        if self.fetch_selected.len() != expected {
            self.fetch_selected.resize(expected, false);
        }
    }

    pub fn toggle_selection(&mut self) {
        if self.screen == Screen::Receiving {
            self.sync_fetch_selected();
            if !self.fetch_selected.is_empty() && self.selected_index < self.fetch_selected.len() {
                self.fetch_selected[self.selected_index] =
                    !self.fetch_selected[self.selected_index];
            }
        }
    }

    pub fn select_all(&mut self) {
        if self.screen == Screen::Receiving {
            self.sync_fetch_selected();
            let all = self.fetch_selected.iter().all(|&s| s);
            for s in self.fetch_selected.iter_mut() {
                *s = !all;
            }
        }
    }

    // --- file browser ---

    pub fn refresh_browser(&mut self) {
        self.browser_entries.clear();
        self.browser_selected = 0;
        if let Ok(entries) = std::fs::read_dir(&self.browser_path) {
            let mut paths: Vec<PathBuf> = entries
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .map(|n| !n.to_string_lossy().starts_with('.'))
                        .unwrap_or(false)
                })
                .collect();
            paths.sort_by(|a, b| b.is_dir().cmp(&a.is_dir()).then_with(|| a.cmp(b)));
            self.browser_entries = paths;
        }
    }

    pub fn open_file_browser(&mut self) {
        self.overlay = Overlay::FileBrowser;
        self.refresh_browser();
    }

    pub fn browser_enter(&mut self) {
        if self.browser_entries.is_empty() || self.browser_selected >= self.browser_entries.len() {
            return;
        }
        let selected = self.browser_entries[self.browser_selected].clone();
        if selected.is_dir() {
            self.browser_path = selected;
            self.refresh_browser();
        } else {
            // Add file
            self.add_shared_file(&selected);
            self.overlay = Overlay::None;
            self.status_message = Some(format!(
                "Added: {}",
                selected.file_name().unwrap_or_default().to_string_lossy()
            ));
        }
    }

    pub fn browser_add_selected(&mut self) {
        if self.browser_entries.is_empty() || self.browser_selected >= self.browser_entries.len() {
            return;
        }
        let selected = self.browser_entries[self.browser_selected].clone();
        self.add_shared_file(&selected);
        self.overlay = Overlay::None;
        self.status_message = Some(format!(
            "Added: {}",
            selected.file_name().unwrap_or_default().to_string_lossy()
        ));
    }

    pub fn browser_go_up(&mut self) {
        if let Some(parent) = self.browser_path.parent() {
            self.browser_path = parent.to_path_buf();
            self.refresh_browser();
        }
    }

    // --- clipboard ---

    pub fn copy_code_to_clipboard(&mut self) {
        if self.share_code.is_empty() {
            return;
        }
        let code = self.share_code.clone();
        let result = try_clipboard_copy(&code);
        match result {
            Ok(_) => self.status_message = Some("Copied to clipboard!".to_string()),
            Err(_) => {
                if cfg!(target_os = "macos") {
                    self.status_message = Some("Copy failed — pbcopy not found".to_string());
                } else if cfg!(target_os = "windows") {
                    self.status_message = Some("Copy failed — clip.exe not found".to_string());
                } else {
                    self.status_message = Some("Copy failed — install xclip or xsel".to_string());
                }
            }
        }
    }
}

fn try_clipboard_copy(text: &str) -> Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    // Platform-specific clipboard tools, tried in order
    let tools: &[&[&str]] = &[
        // macOS
        &["pbcopy"],
        // Linux / Wayland / X11
        &["xclip", "-selection", "clipboard"],
        &["xsel", "--clipboard", "--input"],
        &["wl-copy"],
        // Windows
        &["clip"],
    ];

    for tool in tools {
        if let Ok(mut child) = Command::new(tool[0])
            .args(&tool[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(text.as_bytes())?;
            }
            // stdin is dropped here, sending EOF to the clipboard tool
            child.wait()?;
            return Ok(());
        }
    }
    anyhow::bail!("no clipboard tool found")
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Default: open the dashboard
pub async fn run_main_menu() -> Result<()> {
    let state = Arc::new(Mutex::new(AppState::new()));
    run_tui(state).await
}

/// Direct send from CLI: `snag send <paths>`
pub async fn run_host(paths: Vec<PathBuf>, port: u16) -> Result<()> {
    let mut app = AppState::new();

    // Add CLI paths to persisted list
    for p in &paths {
        app.add_shared_file(p);
    }

    // Go directly to sending
    app.screen = Screen::Sending;
    app.build_catalog_from_persisted();

    let bind_addr = &app.config.network.bind_address;
    let effective_port = if port == 0 {
        app.config.network.port
    } else {
        port
    };
    let stun_servers = &app.config.network.stun_servers;
    let traversal =
        network::traversal::prepare_sender(effective_port, bind_addr, stun_servers).await?;
    let code = if traversal.needs_hole_punch {
        share_code::generate_share_code_with_flags(
            &traversal.external_addr,
            app.config.security.code_words,
            true,
        )
    } else {
        share_code::generate_share_code(&traversal.external_addr, app.config.security.code_words)
    };
    let cancel = CancellationToken::new();
    app.share_code = code.clone();
    app.network_started = true;
    app.cancel_token = Some(cancel.clone());

    let state = Arc::new(Mutex::new(app));
    let endpoint = network::connection::create_server_endpoint_from_socket(traversal.socket)?;

    let net_state = state.clone();
    let err_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) =
            network::listener::run_listener_with_endpoint(endpoint, code, net_state, cancel).await
        {
            tracing::error!("Listener error: {}", e);
            let mut app = err_state.lock().await;
            app.status_message = Some(format!("Listener error: {}", e));
        }
    });

    run_tui(state).await
}

/// Direct receive from CLI: `snag receive <code>`
pub async fn run_fetch(code: String, output: PathBuf) -> Result<()> {
    let mut app = AppState::new();
    app.screen = Screen::Receiving;
    app.share_code = code.clone();
    // CLI --output flag takes priority; if the user left it at the default ".",
    // use the configured download directory instead.
    if output == Path::new(".") {
        app.output_dir = app.config.download_dir();
    } else {
        app.output_dir = output;
    }
    app.network_started = true;

    let state = Arc::new(Mutex::new(app));

    let net_state = state.clone();
    let err_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = network::connection::connect_to_host(code, net_state).await {
            tracing::error!("Connection error: {}", e);
            let mut app = err_state.lock().await;
            app.status_message = Some(format!("Connection error: {}", e));
        }
    });

    run_tui(state).await
}

// ---------------------------------------------------------------------------
// TUI loop
// ---------------------------------------------------------------------------

async fn run_tui(state: Arc<Mutex<AppState>>) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let tick_rate = Duration::from_millis(100);
    let mut last_tick = Instant::now();

    loop {
        {
            let app = state.lock().await;
            terminal.draw(|f| ui::draw(f, &app))?;
        }

        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                let mut app = state.lock().await;
                let action = handle_key(&mut app, key);
                drop(app);
                if let Some(a) = action {
                    handle_action(a, &state).await?;
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            let mut app = state.lock().await;
            app.transfer_manager.tick();
            app.transfers = app.transfer_manager.get_all_transfers();

            // Check share limits
            if app.screen == Screen::Sending {
                let limit_expired = match &app.share_limit {
                    Some(ShareLimit::MaxDownloads(max)) => app.completed_downloads >= *max,
                    Some(ShareLimit::Countdown { expires_at }) => {
                        std::time::Instant::now() >= *expires_at
                    }
                    Some(ShareLimit::Deadline { expires_at }) => {
                        chrono::Local::now().naive_local() >= *expires_at
                    }
                    None => false,
                };
                if limit_expired {
                    if let Some(cancel) = app.cancel_token.take() {
                        cancel.cancel();
                    }
                    app.end_share_session();
                    app.screen = Screen::Dashboard;
                    app.network_started = false;
                    app.share_code.clear();
                    app.peers.clear();
                    app.share_limit = None;
                    app.completed_downloads = 0;
                    app.status_message = Some("Share limit reached — session ended".to_string());
                }
            }

            // Check if all downloads just finished (notify once)
            if app.screen == Screen::Receiving
                && !app.notified_complete
                && app.transfer_manager.all_downloads_done()
            {
                app.notified_complete = true;
                let bell = app.notification_bell;
                let desktop = app.notification_desktop;
                // Drop lock before notification (spawns a thread)
                drop(app);
                crate::network::connection::notify_completion(bell, desktop);
            }

            last_tick = Instant::now();
        }

        {
            let app = state.lock().await;
            if app.should_quit {
                break;
            }
        }
    }

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Deferred actions (spawns network tasks outside the mutex)
// ---------------------------------------------------------------------------

enum Action {
    StartSending,
    StartReceiving(String),
}

async fn handle_action(action: Action, state: &Arc<Mutex<AppState>>) -> Result<()> {
    match action {
        Action::StartSending => {
            let (bind_addr, port, code_words, stun_servers) = {
                let app = state.lock().await;
                (
                    app.config.network.bind_address.clone(),
                    app.config.network.port,
                    app.config.security.code_words,
                    app.config.network.stun_servers.clone(),
                )
            };
            let traversal =
                network::traversal::prepare_sender(port, &bind_addr, &stun_servers).await?;
            let code = if traversal.needs_hole_punch {
                share_code::generate_share_code_with_flags(
                    &traversal.external_addr,
                    code_words,
                    true,
                )
            } else {
                share_code::generate_share_code(&traversal.external_addr, code_words)
            };
            let cancel = CancellationToken::new();

            {
                let mut app = state.lock().await;
                // Cancel any previous network task
                if let Some(old) = app.cancel_token.take() {
                    old.cancel();
                }
                app.share_code = code.clone();
                app.screen = Screen::Sending;
                app.persisted.refresh_missing();
                app.build_catalog_from_persisted();
                app.network_started = true;
                app.cancel_token = Some(cancel.clone());
                app.status_message = Some(format!(
                    "Sharing via {} — give the code to the receiver",
                    traversal.method
                ));
            }

            let endpoint =
                network::connection::create_server_endpoint_from_socket(traversal.socket)?;
            let net_state = state.clone();
            let err_state = state.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    network::listener::run_listener_with_endpoint(endpoint, code, net_state, cancel)
                        .await
                {
                    tracing::error!("Listener error: {}", e);
                    let mut app = err_state.lock().await;
                    app.status_message = Some(format!("Listener error: {}", e));
                }
            });
        }
        Action::StartReceiving(code) => {
            {
                let mut app = state.lock().await;
                // Cancel any previous network task
                if let Some(old) = app.cancel_token.take() {
                    old.cancel();
                }
                app.share_code = code.clone();
                app.screen = Screen::Receiving;
                app.network_started = true;
                app.status_message = Some("Connecting...".to_string());
            }

            let net_state = state.clone();
            let err_state = state.clone();
            tokio::spawn(async move {
                if let Err(e) = network::connection::connect_to_host(code, net_state).await {
                    tracing::error!("Connection error: {}", e);
                    let mut app = err_state.lock().await;
                    app.status_message = Some(format!("Connection error: {}", e));
                }
            });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Key handling
// ---------------------------------------------------------------------------

fn handle_key(app: &mut AppState, key: event::KeyEvent) -> Option<Action> {
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        app.should_quit = true;
        return None;
    }

    match app.screen {
        Screen::Dashboard => handle_dashboard_keys(app, key),
        Screen::Sending => handle_sending_keys(app, key),
        Screen::Receiving => handle_receiving_keys(app, key),
    }
}

fn handle_dashboard_keys(app: &mut AppState, key: event::KeyEvent) -> Option<Action> {
    match app.overlay {
        Overlay::Help => {
            match key.code {
                KeyCode::Char('?') | KeyCode::Esc | KeyCode::Char('q') => {
                    app.overlay = Overlay::None
                }
                _ => {}
            }
            None
        }
        Overlay::FileBrowser => {
            match key.code {
                KeyCode::Esc | KeyCode::Char('q') => app.overlay = Overlay::None,
                KeyCode::Up | KeyCode::Char('k') => app.move_up(),
                KeyCode::Down | KeyCode::Char('j') => app.move_down(),
                KeyCode::Right | KeyCode::Enter => app.browser_enter(),
                KeyCode::Char(' ') => app.browser_add_selected(),
                KeyCode::Left | KeyCode::Backspace | KeyCode::Char('h') => app.browser_go_up(),
                _ => {}
            }
            None
        }
        Overlay::CodeInput => {
            match key.code {
                KeyCode::Esc => app.overlay = Overlay::None,
                KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    app.code_input.push(c);
                }
                KeyCode::Backspace => {
                    app.code_input.pop();
                }
                KeyCode::Enter if !app.code_input.is_empty() => {
                    let code = app.code_input.clone();
                    app.overlay = Overlay::None;
                    return Some(Action::StartReceiving(code));
                }
                _ => {}
            }
            None
        }
        Overlay::None => {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
                KeyCode::Char('?') => app.overlay = Overlay::Help,
                KeyCode::Up | KeyCode::Char('k') => app.move_up(),
                KeyCode::Down | KeyCode::Char('j') => app.move_down(),
                KeyCode::Tab => {
                    app.focus = match app.focus {
                        Focus::FileList => Focus::History,
                        Focus::History => Focus::FileList,
                    };
                }
                KeyCode::Char('a') => app.open_file_browser(),
                KeyCode::Char('d') | KeyCode::Char('x') => {
                    if app.focus == Focus::History {
                        app.remove_history_entry();
                    } else {
                        app.remove_shared_file();
                    }
                }
                KeyCode::Enter => {
                    if app.focus == Focus::History {
                        app.re_add_from_history();
                    } else {
                        // same as 's' — start sharing
                        if app.persisted.shared_files.is_empty() {
                            app.status_message = Some("Add files first — press [a]".to_string());
                        } else if app.persisted.shared_files.iter().all(|f| f.missing) {
                            app.status_message =
                                Some("All files are missing — check paths".to_string());
                        } else {
                            return Some(Action::StartSending);
                        }
                    }
                }
                KeyCode::Char('s') => {
                    if app.persisted.shared_files.is_empty() {
                        app.status_message = Some("Add files first — press [a]".to_string());
                    } else if app.persisted.shared_files.iter().all(|f| f.missing) {
                        app.status_message =
                            Some("All files are missing — check paths".to_string());
                    } else {
                        return Some(Action::StartSending);
                    }
                }
                KeyCode::Char('r') => {
                    app.code_input.clear();
                    app.overlay = Overlay::CodeInput;
                }
                KeyCode::Char('S') => {
                    app.overlay = Overlay::Settings;
                    app.settings_selected = 0;
                    app.settings_editing = false;
                }
                _ => {}
            }
            None
        }
        Overlay::Settings => {
            if app.settings_editing {
                // Text/number edit mode
                match key.code {
                    KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                        app.settings_edit_buf.push(c);
                    }
                    KeyCode::Backspace => {
                        app.settings_edit_buf.pop();
                    }
                    KeyCode::Enter => {
                        apply_settings_edit(app);
                        app.settings_editing = false;
                    }
                    KeyCode::Esc => {
                        app.settings_editing = false;
                    }
                    _ => {}
                }
            } else {
                match key.code {
                    KeyCode::Esc | KeyCode::Char('q') => {
                        // Save cfg on close
                        if let Err(e) = app.config.save() {
                            tracing::warn!("Failed to save config: {}", e);
                        }
                        app.overlay = Overlay::None;
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        if app.settings_selected > 0 {
                            app.settings_selected -= 1;
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if app.settings_selected < 11 {
                            app.settings_selected += 1;
                        }
                    }
                    KeyCode::Enter | KeyCode::Char(' ') => {
                        toggle_or_edit_setting(app);
                    }
                    _ => {}
                }
            }
            None
        }
        _ => None,
    }
}

fn toggle_or_edit_setting(app: &mut AppState) {
    match app.settings_selected {
        // Booleans: toggle directly
        0 => {
            app.config.notifications.bell = !app.config.notifications.bell;
            app.notification_bell = app.config.notifications.bell;
        }
        1 => {
            app.config.notifications.desktop = !app.config.notifications.desktop;
            app.notification_desktop = app.config.notifications.desktop;
        }
        5 => app.config.transfers.compression = !app.config.transfers.compression,
        9 => app.config.privacy.history = !app.config.privacy.history,
        // Cycle values
        2 => {
            let next = crate::ui::theme::next_theme(&app.config.appearance.theme);
            app.config.appearance.theme = next.to_string();
            crate::ui::theme::set_theme(next);
        }
        4 => {
            app.config.transfers.overwrite = match app.config.transfers.overwrite.as_str() {
                "skip" => "rename".into(),
                "rename" => "overwrite".into(),
                _ => "skip".into(),
            };
        }
        // Text inputs: enter edit mode
        3 | 7 | 8 => {
            app.settings_editing = true;
            app.settings_edit_buf = match app.settings_selected {
                3 => app.config.transfers.download_dir.clone(),
                7 => app.config.network.bind_address.clone(),
                8 => app.config.identity.display_name.clone(),
                _ => String::new(),
            };
        }
        // Number inputs
        6 | 10 | 11 => {
            app.settings_editing = true;
            app.settings_edit_buf = match app.settings_selected {
                6 => app.config.network.port.to_string(),
                10 => app.config.privacy.history_limit.to_string(),
                11 => app.config.security.code_words.to_string(),
                _ => String::new(),
            };
        }
        _ => {}
    }
}

fn apply_settings_edit(app: &mut AppState) {
    match app.settings_selected {
        3 => app.config.transfers.download_dir = app.settings_edit_buf.clone(),
        7 => app.config.network.bind_address = app.settings_edit_buf.clone(),
        8 => app.config.identity.display_name = app.settings_edit_buf.clone(),
        6 => {
            if let Ok(p) = app.settings_edit_buf.parse::<u16>() {
                app.config.network.port = p;
            }
        }
        10 => {
            if let Ok(n) = app.settings_edit_buf.parse::<usize>() {
                app.config.privacy.history_limit = n.max(1);
            }
        }
        11 => {
            if let Ok(n) = app.settings_edit_buf.parse::<u8>() {
                app.config.security.code_words = n.clamp(3, 5);
            }
        }
        _ => {}
    }
}

fn handle_sending_keys(app: &mut AppState, key: event::KeyEvent) -> Option<Action> {
    match app.overlay {
        Overlay::Help => {
            match key.code {
                KeyCode::Char('?') | KeyCode::Esc | KeyCode::Char('q') => {
                    app.overlay = Overlay::None
                }
                _ => {}
            }
            None
        }
        Overlay::FileBrowser => {
            match key.code {
                KeyCode::Esc | KeyCode::Char('q') => app.overlay = Overlay::None,
                KeyCode::Up | KeyCode::Char('k') => app.move_up(),
                KeyCode::Down | KeyCode::Char('j') => app.move_down(),
                KeyCode::Right | KeyCode::Enter => app.browser_enter(),
                KeyCode::Char(' ') => app.browser_add_selected(),
                KeyCode::Left | KeyCode::Backspace | KeyCode::Char('h') => app.browser_go_up(),
                _ => {}
            }
            // Rebuild catalog if we added files
            if app.overlay == Overlay::None {
                app.build_catalog_from_persisted();
            }
            None
        }
        Overlay::LimitInput => {
            match app.limit_input_step {
                0 => {
                    // Choosing limit type
                    match key.code {
                        KeyCode::Up | KeyCode::Char('k') => {
                            if app.limit_menu_selected > 0 {
                                app.limit_menu_selected -= 1;
                            }
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            if app.limit_menu_selected < 3 {
                                app.limit_menu_selected += 1;
                            }
                        }
                        KeyCode::Enter => {
                            if app.limit_menu_selected == 3 {
                                // Clear limit
                                app.share_limit = None;
                                app.overlay = Overlay::None;
                                app.status_message = Some("Limit cleared".to_string());
                            } else {
                                app.limit_input_step = 1;
                                app.limit_input_value.clear();
                            }
                        }
                        KeyCode::Esc => app.overlay = Overlay::None,
                        _ => {}
                    }
                }
                _ => {
                    // Entering value
                    match key.code {
                        KeyCode::Char(c) if c.is_ascii_digit() => {
                            if app.limit_input_value.len() < 6 {
                                app.limit_input_value.push(c);
                            }
                        }
                        KeyCode::Backspace => {
                            app.limit_input_value.pop();
                        }
                        KeyCode::Enter if !app.limit_input_value.is_empty() => {
                            if let Ok(val) = app.limit_input_value.parse::<u32>() {
                                if val > 0 {
                                    match app.limit_menu_selected {
                                        0 => {
                                            app.share_limit = Some(ShareLimit::MaxDownloads(val));
                                            app.status_message =
                                                Some(format!("Limit: {} download(s)", val));
                                        }
                                        1 => {
                                            let expires_at = std::time::Instant::now()
                                                + std::time::Duration::from_secs(val as u64 * 60);
                                            app.share_limit =
                                                Some(ShareLimit::Countdown { expires_at });
                                            app.status_message =
                                                Some(format!("Limit: {} minute(s)", val));
                                        }
                                        2 => {
                                            let now = chrono::Local::now().naive_local();
                                            let expires_at =
                                                now + chrono::Duration::hours(val as i64);
                                            app.share_limit =
                                                Some(ShareLimit::Deadline { expires_at });
                                            app.status_message = Some(format!(
                                                "Limit: until {}",
                                                expires_at.format("%b %d %H:%M")
                                            ));
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            app.overlay = Overlay::None;
                        }
                        KeyCode::Esc => {
                            app.limit_input_step = 0;
                        }
                        _ => {}
                    }
                }
            }
            None
        }
        Overlay::None => {
            match key.code {
                KeyCode::Char('q') => app.should_quit = true,
                KeyCode::Char('?') => app.overlay = Overlay::Help,
                KeyCode::Up | KeyCode::Char('k') => app.move_up(),
                KeyCode::Down | KeyCode::Char('j') => app.move_down(),
                KeyCode::Tab => {
                    app.focus = match app.focus {
                        Focus::FileList => Focus::History,
                        Focus::History => Focus::FileList,
                    };
                }
                KeyCode::Char('a') => app.open_file_browser(),
                KeyCode::Char('d') | KeyCode::Char('x') => {
                    app.remove_shared_file();
                    app.build_catalog_from_persisted();
                }
                KeyCode::Char('c') => app.copy_code_to_clipboard(),
                KeyCode::Char('l') => {
                    app.limit_menu_selected = 0;
                    app.limit_input_value.clear();
                    app.limit_input_step = 0;
                    app.overlay = Overlay::LimitInput;
                }
                KeyCode::Backspace | KeyCode::Esc => {
                    // Stop listener and go back to dashboard
                    if let Some(cancel) = app.cancel_token.take() {
                        cancel.cancel();
                    }
                    app.end_share_session();
                    app.screen = Screen::Dashboard;
                    app.network_started = false;
                    app.share_code.clear();
                    app.peers.clear();
                    app.share_limit = None;
                    app.completed_downloads = 0;
                    app.status_message = Some("Stopped sharing".to_string());
                }
                _ => {}
            }
            None
        }
        _ => None,
    }
}

fn handle_receiving_keys(app: &mut AppState, key: event::KeyEvent) -> Option<Action> {
    match app.overlay {
        Overlay::Help => {
            match key.code {
                KeyCode::Char('?') | KeyCode::Esc | KeyCode::Char('q') => {
                    app.overlay = Overlay::None
                }
                _ => {}
            }
            None
        }
        Overlay::None => {
            match key.code {
                KeyCode::Char('q') => app.should_quit = true,
                KeyCode::Char('?') => app.overlay = Overlay::Help,
                KeyCode::Up | KeyCode::Char('k') => app.move_up(),
                KeyCode::Down | KeyCode::Char('j') => app.move_down(),
                KeyCode::Char(' ') => app.toggle_selection(),
                KeyCode::Char('a') => app.select_all(),
                KeyCode::Enter => request_downloads(app),
                KeyCode::Tab => {
                    app.focus = match app.focus {
                        Focus::FileList => Focus::History,
                        Focus::History => Focus::FileList,
                    };
                }
                KeyCode::Backspace | KeyCode::Esc => {
                    if let Some(cancel) = app.cancel_token.take() {
                        cancel.cancel();
                    }
                    app.screen = Screen::Dashboard;
                    app.network_started = false;
                    app.connected = false;
                    app.status_message = Some("Disconnected".to_string());
                }
                _ => {}
            }
            None
        }
        _ => None,
    }
}

fn request_downloads(app: &mut AppState) {
    let selected: Vec<CatalogEntry> = app
        .fetch_selected
        .iter()
        .enumerate()
        .filter(|(_, &sel)| sel)
        .filter_map(|(i, _)| app.catalog.entries.get(i).cloned())
        .collect();

    if selected.is_empty() {
        app.status_message = Some("No files selected".to_string());
        return;
    }

    // Reset notification flag so this batch triggers a new notification
    app.notified_complete = false;

    for entry in &selected {
        app.transfer_manager
            .start_download(entry.name.clone(), entry.size);
    }

    app.status_message = Some(format!("Downloading {} file(s)", selected.len()));
}
