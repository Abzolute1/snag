use anyhow::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

const DISCOVERY_PORT: u16 = 45_816;
const MAGIC: &[u8] = b"ZAP1";

/// A discovered peer on the LAN
#[derive(Debug, Clone)]
pub struct DiscoveredPeer {
    pub share_code: String,
    pub file_count: usize,
    pub total_size: u64,
    pub hostname: String,
    pub addr: SocketAddr,
    /// The QUIC server port the sender is listening on (if included in broadcast)
    pub quic_port: Option<u16>,
}

/// Broadcast presence on the LAN so `snag discover` can find us.
/// Runs until cancelled. `quic_port` is the local QUIC server port
/// so receivers on the same LAN can connect directly.
pub async fn broadcast_presence(
    share_code: &str,
    file_count: usize,
    total_size: u64,
    quic_port: u16,
    cancel: CancellationToken,
) -> Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.set_broadcast(true)?;

    let hostname = get_hostname();
    let msg = format!(
        "ZAP1|{}|{}|{}|{}|{}",
        share_code, file_count, total_size, hostname, quic_port
    );
    let broadcast_addr: SocketAddr = format!("255.255.255.255:{}", DISCOVERY_PORT).parse()?;

    loop {
        if cancel.is_cancelled() {
            break;
        }
        let _ = socket.send_to(msg.as_bytes(), broadcast_addr).await;
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(2)) => {}
            _ = cancel.cancelled() => break,
        }
    }

    Ok(())
}

/// Listen for LAN peers broadcasting their presence.
/// Returns discovered peers after the timeout.
pub async fn discover_peers(timeout_secs: u64) -> Result<Vec<DiscoveredPeer>> {
    let socket = UdpSocket::bind(format!("0.0.0.0:{}", DISCOVERY_PORT)).await?;
    socket.set_broadcast(true)?;

    let mut peers: HashMap<String, DiscoveredPeer> = HashMap::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);

    loop {
        let remaining = deadline - tokio::time::Instant::now();
        if remaining.is_zero() {
            break;
        }

        let mut buf = [0u8; 1024];
        match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, addr))) => {
                if let Some(peer) = parse_discovery_msg(&buf[..len], addr) {
                    peers.insert(peer.share_code.clone(), peer);
                }
            }
            Ok(Err(_)) => break,
            Err(_) => break, // timeout
        }
    }

    let mut result: Vec<_> = peers.into_values().collect();
    result.sort_by(|a, b| a.hostname.cmp(&b.hostname));
    Ok(result)
}

fn parse_discovery_msg(data: &[u8], addr: SocketAddr) -> Option<DiscoveredPeer> {
    let text = std::str::from_utf8(data).ok()?;
    let parts: Vec<&str> = text.split('|').collect();
    // Support both old (5 fields) and new (6 fields with quic_port) format
    if (parts.len() != 5 && parts.len() != 6) || parts[0] != "ZAP1" {
        return None;
    }

    let quic_port = if parts.len() >= 6 {
        parts[5].parse().ok()
    } else {
        None
    };

    Some(DiscoveredPeer {
        share_code: parts[1].to_string(),
        file_count: parts[2].parse().ok()?,
        total_size: parts[3].parse().ok()?,
        hostname: parts[4].to_string(),
        addr,
        quic_port,
    })
}

/// Quick LAN probe: listen for a broadcast matching the given share code.
/// Returns the sender's LAN address (IP from broadcast source + QUIC port).
/// Used as a cascade fallback when direct connect to the encoded address fails.
pub async fn probe_lan_for_sender(
    share_code: &str,
    fallback_port: u16,
    timeout_secs: u64,
) -> Option<SocketAddr> {
    let socket = UdpSocket::bind(format!("0.0.0.0:{}", DISCOVERY_PORT))
        .await
        .ok()?;
    socket.set_broadcast(true).ok()?;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        let mut buf = [0u8; 1024];
        match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, src_addr))) => {
                if let Some(peer) = parse_discovery_msg(&buf[..len], src_addr) {
                    if peer.share_code == share_code {
                        // Found the sender! Use their LAN IP + QUIC port
                        let port = peer.quic_port.unwrap_or(fallback_port);
                        return Some(SocketAddr::new(src_addr.ip(), port));
                    }
                }
            }
            Ok(Err(_)) => break,
            Err(_) => break,
        }
    }

    None
}

pub fn get_hostname() -> String {
    // On Linux, try /etc/hostname first (no subprocess needed)
    #[cfg(target_os = "linux")]
    if let Ok(name) = std::fs::read_to_string("/etc/hostname") {
        let name = name.trim().to_string();
        if !name.is_empty() {
            return name;
        }
    }

    // On Windows, try COMPUTERNAME env var (no subprocess needed)
    #[cfg(target_os = "windows")]
    if let Ok(name) = std::env::var("COMPUTERNAME") {
        if !name.is_empty() {
            return name;
        }
    }

    // Fallback: `hostname` command works on Linux, macOS, and Windows
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}
