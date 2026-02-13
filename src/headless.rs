use anyhow::{bail, Result};
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::collections::HashMap;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::app::{AppState, Screen, ShareLimit};
use crate::network;
use crate::share_code;
use crate::transfer::manager::TransferStatus;
use crate::ui::theme::current_theme;

// ANSI codes that dont chage with theme
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";
const DIM: &str = "\x1b[2m";

/// Accent color from user's theme config
fn accent() -> String {
    current_theme().accent_ansi()
}
fn success() -> String {
    current_theme().success_ansi()
}
fn error() -> String {
    current_theme().error_ansi()
}

fn use_color() -> bool {
    std::io::stderr().is_terminal()
}

fn print_banner(color: bool) {
    let lines = [
        r"  ███████╗███╗   ██╗ █████╗  ██████╗ ",
        r"  ██╔════╝████╗  ██║██╔══██╗██╔════╝ ",
        r"  ███████╗██╔██╗ ██║███████║██║  ███╗",
        r"  ╚════██║██║╚██╗██║██╔══██║██║   ██║",
        r"  ███████║██║ ╚████║██║  ██║╚██████╔╝",
        r"  ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ",
    ];
    let c = accent();
    for line in &lines {
        if color {
            eprintln!("{}{}{}{}", BOLD, c, line, RESET);
        } else {
            eprintln!("{}", line);
        }
    }
}

fn format_size(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

fn progress_style() -> ProgressStyle {
    ProgressStyle::default_bar()
        .template(
            "  {prefix} [{bar:30.green/dim}] {percent:>3}% {binary_bytes_per_sec:>10} ETA {eta}",
        )
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("██░")
}

// ─────────────────────────────────────────────────────────────────────────────
// Headless Send
// ─────────────────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub async fn headless_send(
    paths: Vec<PathBuf>,
    port: u16,
    pipe: bool,
    bind: Option<String>,
    no_compress: bool,
    timer: Option<String>,
    until: Option<String>,
    downloads: Option<u32>,
    verbose: bool,
) -> Result<()> {
    crate::network::traversal::set_verbose(verbose);
    let mut cfg = crate::config::Config::load();
    if let Some(bind) = bind {
        cfg.network.bind_address = bind;
    }
    if no_compress {
        cfg.transfers.compression = false;
    }
    if port != 0 {
        cfg.network.port = port;
    }

    // Parse share limits
    let share_limit = if let Some(ref t) = timer {
        let dur = parse_duration(t)?;
        Some(ShareLimit::Countdown {
            expires_at: std::time::Instant::now() + dur,
        })
    } else if let Some(ref u) = until {
        let deadline = parse_time(u)?;
        Some(ShareLimit::Deadline {
            expires_at: deadline,
        })
    } else {
        None
    };
    let download_limit = downloads.map(ShareLimit::MaxDownloads);
    // Merge: download limit can combine with a time limit, but we store
    // only one ShareLimit in AppState. Prefer time-based if set, check
    // downloads separately in the loop.
    let time_limit = share_limit;

    // apply theme from config
    crate::ui::theme::set_theme(&cfg.appearance.theme);

    let color = use_color();

    // Handlle pipe: read stdin to temp file
    let effective_paths = if pipe {
        let path = read_stdin_to_temp()?;
        vec![path]
    } else {
        if paths.is_empty() {
            bail!("No files specified. Usage: snag send <files...>");
        }
        paths
    };

    // Build state
    let mut app = AppState::new();
    for p in &effective_paths {
        app.add_shared_file(p);
    }
    app.build_catalog_from_persisted();

    if app.catalog.entries.is_empty() {
        bail!("No valid files to share");
    }

    // Print header
    eprintln!();
    print_banner(color);
    if color {
        eprintln!(
            "  {}Sharing {} item(s) ({}){}\n",
            DIM,
            app.catalog.entries.len(),
            format_size(app.catalog.total_size()),
            RESET,
        );
    } else {
        eprintln!(
            "  Sharing {} item(s) ({})\n",
            app.catalog.entries.len(),
            format_size(app.catalog.total_size())
        );
    }

    for entry in &app.catalog.entries {
        let size = format_size(entry.size);
        if color {
            eprintln!("  {}  {}{}{}", entry.name, DIM, size, RESET);
        } else {
            eprintln!("  {}  {}", entry.name, size);
        }
    }

    // NAT traversal: try UPnP → NAT-PMP → STUN → local fallback
    let traversal = network::traversal::prepare_sender(
        cfg.network.port,
        &cfg.network.bind_address,
        &cfg.network.stun_servers,
    )
    .await?;

    let traversal_method = traversal.method;

    if verbose {
        eprintln!("  [verbose] External address: {}", traversal.external_addr);
        eprintln!("  [verbose] NAT type: {:?}", traversal.nat_type);
        eprintln!(
            "  [verbose] Needs hole punch: {}",
            traversal.needs_hole_punch
        );
    }

    let code = if traversal.needs_hole_punch {
        share_code::generate_share_code_with_flags(
            &traversal.external_addr,
            cfg.security.code_words,
            true,
        )
    } else {
        share_code::generate_share_code(&traversal.external_addr, cfg.security.code_words)
    };

    let cancel = CancellationToken::new();
    app.share_code = code.clone();
    app.screen = Screen::Sending;
    app.network_started = true;
    app.cancel_token = Some(cancel.clone());
    app.share_limit = time_limit;

    let state = Arc::new(Mutex::new(app));

    // Capture the local port before moving the socket into the endpoint
    let local_quic_port = traversal.socket.local_addr().map(|a| a.port()).unwrap_or(0);

    // Create QUIC endpoint from the pre-bound socket (same port used for STUN/UPnP)
    let endpoint = network::connection::create_server_endpoint_from_socket(traversal.socket)?;

    // Spawn listener on the pre-bound endpoint
    let net_state = state.clone();
    let net_cancel = cancel.clone();
    tokio::spawn(async move {
        if let Err(e) = network::listener::run_listener_with_endpoint(
            endpoint,
            code.clone(),
            net_state,
            net_cancel,
        )
        .await
        {
            tracing::error!("Listener error: {}", e);
        }
    });

    // Spawn LAN broadcast (includes QUIC port for same-LAN discovery)
    let bc_code = state.lock().await.share_code.clone();
    let bc_info = {
        let app = state.lock().await;
        (app.catalog.entries.len(), app.catalog.total_size())
    };
    let bc_cancel = cancel.clone();
    tokio::spawn(async move {
        let _ = crate::discovery::broadcast_presence(
            &bc_code,
            bc_info.0,
            bc_info.1,
            local_quic_port,
            bc_cancel,
        )
        .await;
    });

    // Print NAT tarversal method
    if color {
        eprintln!("  {}NAT traversal: {}{}", DIM, traversal_method, RESET);
    } else {
        eprintln!("  NAT traversal: {}", traversal_method);
    }

    // Print share code
    eprintln!();
    if color {
        eprintln!(
            "  Share code: {}{}{}{}",
            BOLD,
            accent(),
            state.lock().await.share_code,
            RESET
        );
    } else {
        eprintln!("  Share code: {}", state.lock().await.share_code);
    }

    // Print QR code
    eprintln!();
    let qr = crate::qr::render_qr(&state.lock().await.share_code);
    eprint!("{}", qr);

    eprintln!();
    if color {
        eprintln!(
            "  {}Scan QR or share the code. Waiting for receivers...{}",
            DIM, RESET
        );
        eprintln!("  {}Press Ctrl+C to stop{}", DIM, RESET);
    } else {
        eprintln!("  Waiting for receivers... (Ctrl+C to stop)");
    }

    // Print active limits
    if let Some(ref t) = timer {
        if color {
            eprintln!("  {}Auto-stop: after {}{}", DIM, t, RESET);
        } else {
            eprintln!("  Auto-stop: after {}", t);
        }
    }
    if let Some(ref u) = until {
        if color {
            eprintln!("  {}Auto-stop: at {}{}", DIM, u, RESET);
        } else {
            eprintln!("  Auto-stop: at {}", u);
        }
    }
    if let Some(n) = downloads {
        if color {
            eprintln!("  {}Auto-stop: after {} download(s){}", DIM, n, RESET);
        } else {
            eprintln!("  Auto-stop: after {} download(s)", n);
        }
    }
    eprintln!();

    // Progress loop
    let multi = MultiProgress::with_draw_target(ProgressDrawTarget::stderr());
    let style = progress_style();
    let mut bars: HashMap<String, ProgressBar> = HashMap::new();
    let mut known_peers: Vec<String> = Vec::new();

    tokio::select! {
        _ = async {
            loop {
                {
                    let mut app = state.lock().await;
                    app.transfer_manager.tick();
                    app.transfers = app.transfer_manager.get_all_transfers();

                    // Announce new peers
                    for peer in &app.peers {
                        if !known_peers.contains(&peer.name) {
                            if color {
                                multi.println(format!(
                                    "  {}{} connected{}",
                                    success(), peer.name, RESET
                                )).ok();
                            } else {
                                multi.println(format!(
                                    "  {} connected",
                                    peer.name
                                )).ok();
                            }
                            known_peers.push(peer.name.clone());
                        }
                    }

                    // Check for fatal errors
                    if let Some(msg) = &app.status_message {
                        if msg.starts_with("Listener error") {
                            multi.println(format!("  Error: {}", msg)).ok();
                            break;
                        }
                    }

                    // Update transfer progress bars
                    for transfer in &app.transfers {
                        if !bars.contains_key(&transfer.file_name) {
                            let pb = multi.add(ProgressBar::new(transfer.total_bytes));
                            pb.set_style(style.clone());
                            let prefix = if let Some(peer) = &transfer.peer_name {
                                format!("↑ {} → {}", transfer.file_name, peer)
                            } else {
                                format!("↑ {}", transfer.file_name)
                            };
                            pb.set_prefix(prefix);
                            bars.insert(transfer.file_name.clone(), pb);
                        }
                        if let Some(pb) = bars.get(&transfer.file_name) {
                            pb.set_position(transfer.transferred_bytes);
                            if matches!(transfer.status, TransferStatus::Complete) {
                                pb.finish_with_message("✓");
                            }
                        }
                    }

                    // Check share limits
                    let limit_expired = match &app.share_limit {
                        Some(ShareLimit::Countdown { expires_at }) => {
                            std::time::Instant::now() >= *expires_at
                        }
                        Some(ShareLimit::Deadline { expires_at }) => {
                            chrono::Local::now().naive_local() >= *expires_at
                        }
                        Some(ShareLimit::MaxDownloads(max)) => {
                            app.completed_downloads >= *max
                        }
                        None => false,
                    };
                    let download_limit_hit = match &download_limit {
                        Some(ShareLimit::MaxDownloads(max)) => {
                            app.completed_downloads >= *max
                        }
                        _ => false,
                    };
                    if limit_expired || download_limit_hit {
                        multi.println("  Share limit reached -- stopping.").ok();
                        cancel.cancel();
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        } => {}
        _ = tokio::signal::ctrl_c() => {
            cancel.cancel();
        }
    }

    eprintln!("\n  Stopped.\n");

    // Clean up temp file for pipe mode
    if pipe {
        for p in &effective_paths {
            let _ = std::fs::remove_file(p);
            if let Some(parent) = p.parent() {
                let _ = std::fs::remove_dir(parent);
            }
        }
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Headless Receive
// ─────────────────────────────────────────────────────────────────────────────
pub async fn headless_receive(
    code: String,
    output: PathBuf,
    pipe: bool,
    overwrite: bool,
    yes: bool,
    verbose: bool,
) -> Result<()> {
    crate::network::traversal::set_verbose(verbose);

    let mut cfg = crate::config::Config::load();
    if overwrite {
        cfg.transfers.overwrite = "overwrite".into();
    }

    // apply theme from config
    crate::ui::theme::set_theme(&cfg.appearance.theme);

    let color = use_color();
    let auth_words = share_code::extract_auth_words(&code);

    if verbose {
        if let Some(info) = share_code::decode_share_code_full(&code) {
            eprintln!("  [verbose] Decoded share code:");
            eprintln!("  [verbose]   Target address: {}", info.addr);
            eprintln!("  [verbose]   Needs hole punch: {}", info.needs_hole_punch);
            eprintln!("  [verbose]   Relay: {:?}", info.relay_addr);
        } else {
            eprintln!("  [verbose] WARNING: Could not decode share code");
        }
    }

    let mut app = AppState::new();
    app.screen = Screen::Receiving;
    app.share_code = code.clone();
    if output == Path::new(".") {
        app.output_dir = cfg.download_dir();
    } else {
        app.output_dir = output.clone();
    }
    app.pipe_mode = pipe;
    app.network_started = true;

    let state = Arc::new(Mutex::new(app));

    // Print header
    eprintln!();
    print_banner(color);
    if color {
        eprintln!(
            "  {}Connecting to {}{}{}...{}\n",
            DIM, RESET, BOLD, auth_words, RESET
        );
    } else {
        eprintln!("  Connecting to {}...\n", auth_words);
    }

    // Spawn network connection
    let net_state = state.clone();
    let err_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = network::connection::connect_to_host(code, net_state).await {
            tracing::error!("Connection error: {}", e);
            let mut app = err_state.lock().await;
            app.status_message = Some(format!("Connection error: {}", e));
        }
    });

    // Wait for connection (with timeout)
    let connect_deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        {
            let app = state.lock().await;
            if app.connected {
                break;
            }
            if let Some(msg) = &app.status_message {
                if msg.starts_with("Connection error") || msg.starts_with("Connection closed") {
                    if color {
                        bail!("  {}{}Error:{} {}", BOLD, error(), RESET, msg);
                    } else {
                        bail!("  Error: {}", msg);
                    }
                }
            }
        }
        if tokio::time::Instant::now() >= connect_deadline {
            bail!("  Connection timed out");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Connected — print file list
    {
        let app = state.lock().await;
        let count = app.catalog.entries.len();
        let size = app.catalog.total_size();

        if color {
            eprintln!(
                "  {}Connected!{} {} file(s) available ({})\n",
                success(),
                RESET,
                count,
                format_size(size)
            );
        } else {
            eprintln!(
                "  Connected! {} file(s) available ({})\n",
                count,
                format_size(size)
            );
        }

        for entry in &app.catalog.entries {
            if color {
                eprintln!(
                    "  {}  {}{}{}",
                    entry.name,
                    DIM,
                    format_size(entry.size),
                    RESET
                );
            } else {
                eprintln!("  {}  {}", entry.name, format_size(entry.size));
            }
        }
        eprintln!();
    }

    // Prompt for acceptance (skip if --yes, --pipe, or non-interactive)
    let auto_accept = yes || pipe || !std::io::stdin().is_terminal();
    if !auto_accept {
        eprint!("  Accept? [y/N]: ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let answer = input.trim().to_lowercase();
        if answer != "y" && answer != "yes" {
            eprintln!("  Declined.\n");
            return Ok(());
        }
        eprintln!();
    }

    // Request all downloads
    {
        let mut app = state.lock().await;
        let entries: Vec<_> = app.catalog.entries.clone();
        for entry in entries {
            app.transfer_manager.start_download(entry.name, entry.size);
        }
    }

    // Progress bars (always on stderr so pipe mode works)
    let multi = MultiProgress::with_draw_target(ProgressDrawTarget::stderr());
    let style = progress_style();
    let mut bars: HashMap<String, ProgressBar> = HashMap::new();

    // Create bars for all files
    {
        let app = state.lock().await;
        for entry in &app.catalog.entries {
            let pb = multi.add(ProgressBar::new(entry.size));
            pb.set_style(style.clone());
            pb.set_prefix(format!("↓ {}", entry.name));
            bars.insert(entry.name.clone(), pb);
        }
    }

    // Progress loop
    loop {
        {
            let mut app = state.lock().await;
            app.transfer_manager.tick();
            app.transfers = app.transfer_manager.get_all_transfers();

            for transfer in &app.transfers {
                if let Some(pb) = bars.get(&transfer.file_name) {
                    pb.set_position(transfer.transferred_bytes);
                    if matches!(transfer.status, TransferStatus::Complete) {
                        pb.finish_with_message("✓");
                    } else if matches!(transfer.status, TransferStatus::Failed) {
                        pb.abandon_with_message("✗");
                    }
                }
            }

            // Check if all done
            let all_done = !app.transfers.is_empty()
                && app
                    .transfers
                    .iter()
                    .all(|t| matches!(t.status, TransferStatus::Complete | TransferStatus::Failed));

            if all_done {
                break;
            }

            // Check for connection loss while transfers are pending
            if let Some(msg) = &app.status_message {
                if msg.contains("Connection closed") || msg.contains("Connection error") {
                    let has_active = app.transfers.iter().any(|t| {
                        matches!(
                            t.status,
                            TransferStatus::Downloading | TransferStatus::Pending
                        )
                    });
                    if has_active {
                        // Finish all pending bars
                        for transfer in &app.transfers {
                            if matches!(
                                transfer.status,
                                TransferStatus::Downloading | TransferStatus::Pending
                            ) {
                                if let Some(pb) = bars.get(&transfer.file_name) {
                                    pb.abandon_with_message("connection lost");
                                }
                            }
                        }
                        eprintln!();
                        if color {
                            eprintln!("  {}{}Error:{} {}", BOLD, error(), RESET, msg);
                        } else {
                            eprintln!("  Error: {}", msg);
                        }
                        eprintln!();
                        return Ok(());
                    }
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Summary
    let app = state.lock().await;
    let completed = app
        .transfers
        .iter()
        .filter(|t| matches!(t.status, TransferStatus::Complete))
        .count();
    let failed = app
        .transfers
        .iter()
        .filter(|t| matches!(t.status, TransferStatus::Failed))
        .count();

    // Single notification at the end of all downloads
    crate::network::connection::notify_completion(
        cfg.notifications.bell,
        cfg.notifications.desktop,
    );

    eprintln!();
    if failed == 0 {
        if color {
            if pipe {
                eprintln!(
                    "  {}{}Done!{} {} file(s) streamed to stdout",
                    BOLD,
                    success(),
                    RESET,
                    completed
                );
            } else {
                eprintln!(
                    "  {}{}Done!{} {} file(s) saved to {}",
                    BOLD,
                    success(),
                    RESET,
                    completed,
                    output.display()
                );
            }
        } else if pipe {
            eprintln!("  Done! {} file(s) streamed to stdout", completed);
        } else {
            eprintln!(
                "  Done! {} file(s) saved to {}",
                completed,
                output.display()
            );
        }
    } else if color {
        eprintln!(
            "  {}{}{} completed{}, {}{}{} failed{}",
            success(),
            completed,
            RESET,
            RESET,
            error(),
            failed,
            RESET,
            RESET
        );
    } else {
        eprintln!("  {} completed, {} failed", completed, failed);
    }
    eprintln!();

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Discover
// ─────────────────────────────────────────────────────────────────────────────

pub async fn run_discover(timeout_secs: u64) -> Result<()> {
    // load theme for colored output
    let cfg = crate::config::Config::load();
    crate::ui::theme::set_theme(&cfg.appearance.theme);

    let color = use_color();

    eprintln!();
    print_banner(color);
    if color {
        eprintln!("  {}Scanning for peers on your network...{}\n", DIM, RESET);
    } else {
        eprintln!("  Scanning for peers on your network...\n");
    }

    let peers = crate::discovery::discover_peers(timeout_secs).await?;

    if peers.is_empty() {
        if color {
            eprintln!("  {}No peers found.{}", DIM, RESET);
            eprintln!(
                "  {}Make sure someone is running 'snag send' on this network.{}\n",
                DIM, RESET
            );
        } else {
            eprintln!("  No peers found.");
            eprintln!("  Make sure someone is running 'snag send' on this network.\n");
        }
        return Ok(());
    }

    // Print table header
    if color {
        eprintln!(
            "  {}{:#>3}  {:<20} {:<6} {:<10} Code{}",
            DIM, "#", "Host", "Files", "Size", RESET
        );
    } else {
        eprintln!(
            "  {:#>3}  {:<20} {:<6} {:<10} Code",
            "#", "Host", "Files", "Size"
        );
    }

    for (i, peer) in peers.iter().enumerate() {
        if color {
            eprintln!(
                "  {:<3}  {:<20} {:<6} {:<10} {}{}{}",
                i + 1,
                peer.hostname,
                peer.file_count,
                format_size(peer.total_size),
                accent(),
                peer.share_code,
                RESET
            );
        } else {
            eprintln!(
                "  {:<3}  {:<20} {:<6} {:<10} {}",
                i + 1,
                peer.hostname,
                peer.file_count,
                format_size(peer.total_size),
                peer.share_code
            );
        }
    }

    eprintln!();
    if color {
        eprintln!(
            "  {}Run 'snag receive <code>' to download from a peer.{}\n",
            DIM, RESET
        );
    } else {
        eprintln!("  Run 'snag receive <code>' to download from a peer.\n");
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Duration / time parsing for share limits
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a human duration string like "30m", "2h", "1h30m", "90s".
fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim().to_lowercase();
    if s.is_empty() {
        bail!("Empty duration string");
    }
    let mut total_secs: u64 = 0;
    let mut num_buf = String::new();
    let mut found_unit = false;

    for ch in s.chars() {
        if ch.is_ascii_digit() {
            num_buf.push(ch);
        } else {
            let n: u64 = num_buf
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid duration: '{}'", s))?;
            num_buf.clear();
            match ch {
                'h' => total_secs += n * 3600,
                'm' => total_secs += n * 60,
                's' => total_secs += n,
                _ => bail!("Unknown duration unit '{}' in '{}'", ch, s),
            }
            found_unit = true;
        }
    }
    // Bare number without unit → treat as minutes
    if !num_buf.is_empty() {
        if found_unit {
            bail!("Trailing digits without unit in '{}'", s);
        }
        let n: u64 = num_buf
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid duration: '{}'", s))?;
        total_secs += n * 60;
    }
    if total_secs == 0 {
        bail!("Duration must be greater than zero");
    }
    Ok(Duration::from_secs(total_secs))
}

/// Parse a clock time string "HH:MM" (24h). Must be in the future today.
fn parse_time(s: &str) -> Result<chrono::NaiveDateTime> {
    let s = s.trim();
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        bail!("Expected time in HH:MM format, got '{}'", s);
    }
    let hour: u32 = parts[0]
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid hour in '{}'", s))?;
    let minute: u32 = parts[1]
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid minute in '{}'", s))?;
    if hour >= 24 || minute >= 60 {
        bail!("Invalid time '{}' (expected 00:00-23:59)", s);
    }

    let today = chrono::Local::now().date_naive();
    let target = today
        .and_hms_opt(hour, minute, 0)
        .ok_or_else(|| anyhow::anyhow!("Invalid time '{}'", s))?;
    let now = chrono::Local::now().naive_local();
    if target <= now {
        bail!(
            "Time {} has already passed today (current time: {})",
            s,
            now.format("%H:%M")
        );
    }
    Ok(target)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn read_stdin_to_temp() -> Result<PathBuf> {
    use std::io::{Read, Write};

    eprintln!("  Reading from stdin...");

    let temp_dir = std::env::temp_dir().join(format!("snag-pipe-{}", std::process::id()));
    std::fs::create_dir_all(&temp_dir)?;
    let temp_file = temp_dir.join("stdin");

    let mut stdin = std::io::stdin().lock();
    let mut file = std::fs::File::create(&temp_file)?;
    let mut total = 0u64;
    let mut buf = vec![0u8; 65536];

    loop {
        let n = stdin.read(&mut buf)?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n])?;
        total += n as u64;
    }

    eprintln!("  Read {} from stdin\n", format_size(total));
    Ok(temp_file)
}
