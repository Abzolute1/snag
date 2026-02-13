//! Layered NAT traversal orchestrator.
//!
//! Tries methods in order of preference to maximize P2P success rate:
//!
//! **Sender side** (prepare_sender):
//! 1. UPnP IGD port mapping (makes sender directly reachable)
//! 2. NAT-PMP / PCP port mapping (Apple routers, etc.)
//! 3. STUN discovery + NAT type detection
//! 4. Local address fallback (LAN only)
//!
//! **Receiver side** (connect_with_cascade):
//! 1. Direct QUIC connect (5s timeout)
//! 2. STUN + hole punch + connect (for cone NATs)
//! 3. Port prediction + spray (for sequential symmetric NATs)
//! 4. Relay fallback (last resort, if relay address in share code)
//!
//! Goal: minimize relay usage so the project stays sustainable at scale.

use anyhow::{Context, Result};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::nat::{self, NatType};

// ─────────────────────────────────────────────────────────────────────────────
// Verbose logging for connection diagnostics (--verbose flag)
// ─────────────────────────────────────────────────────────────────────────────

static VERBOSE: AtomicBool = AtomicBool::new(false);

pub fn set_verbose(v: bool) {
    VERBOSE.store(v, Ordering::Relaxed);
}

fn vlog(msg: &str) {
    if VERBOSE.load(Ordering::Relaxed) {
        eprintln!("  [verbose] {}", msg);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Sender-side traversal
// ─────────────────────────────────────────────────────────────────────────────

/// Result of sender-side NAT traversal preparation.
pub struct SenderTraversal {
    /// The external address to encode in the share code
    pub external_addr: SocketAddr,
    /// The local socket to bind Quinn to (pre-used for STUN/UPnP)
    pub socket: std::net::UdpSocket,
    /// NAT traversal method that succeeded
    pub method: TraversalMethod,
    /// Whether the receiver needs to hole-punch
    pub needs_hole_punch: bool,
    /// Detected NAT type
    pub nat_type: NatType,
    /// UPnP lease handle for cleanup on shutdown
    upnp_lease: Option<UpnpLease>,
}

impl SenderTraversal {
    /// Clean up NAT traversal state (remove UPnP mapping, etc.)
    pub async fn cleanup(&mut self) {
        if let Some(lease) = self.upnp_lease.take() {
            lease.remove().await;
        }
    }
}

/// Which NAT traversal method succeeded on the sender side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraversalMethod {
    /// UPnP IGD port mapping — sender is directly reachable
    Upnp,
    /// NAT-PMP / PCP port mapping — sender is directly reachable
    NatPmp,
    /// STUN-discovered address (hole punch may be needed)
    Stun,
    /// Fallback to local address (LAN only)
    LocalOnly,
}

impl std::fmt::Display for TraversalMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Upnp => write!(f, "UPnP"),
            Self::NatPmp => write!(f, "NAT-PMP"),
            Self::Stun => write!(f, "STUN"),
            Self::LocalOnly => write!(f, "LAN"),
        }
    }
}

/// Handle for cleaning up a UPnP port mapping on shutdown.
/// Re-discovers the gateway for cleanup since Gateway<P> has a private generic.
struct UpnpLease {
    external_port: u16,
}

impl UpnpLease {
    async fn remove(self) {
        // Best-effort: re-discover gateway and remove the mapping.
        // If this fails, the mapping expires naturally after 1 hour.
        if let Ok(gw) = igd_next::aio::tokio::search_gateway(Default::default()).await {
            let _ = gw
                .remove_port(igd_next::PortMappingProtocol::UDP, self.external_port)
                .await;
        }
    }
}

/// Detect the local IPv4 address by connecting a UDP socket to a public endpoint.
fn get_local_ipv4() -> Result<Ipv4Addr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:80")?;
    match socket.local_addr()? {
        SocketAddr::V4(addr) => Ok(*addr.ip()),
        SocketAddr::V6(_) => anyhow::bail!("No IPv4 address found"),
    }
}

/// Try UPnP IGD port mapping. Returns external address + lease handle.
/// Timeout: 3 seconds for gateway discovery.
async fn try_upnp(local_port: u16) -> Option<(SocketAddr, UpnpLease)> {
    let search_opts = igd_next::SearchOptions {
        timeout: Some(Duration::from_secs(3)),
        ..Default::default()
    };

    let gateway = match tokio::time::timeout(
        Duration::from_secs(4),
        igd_next::aio::tokio::search_gateway(search_opts),
    )
    .await
    {
        Ok(Ok(gw)) => gw,
        _ => return None,
    };

    let local_ip = get_local_ipv4().ok()?;
    let local_addr = SocketAddr::V4(SocketAddrV4::new(local_ip, local_port));

    // Request same external port as local, 1-hour lease.
    // add_port returns () on success — the external port is what we requested.
    match tokio::time::timeout(
        Duration::from_secs(3),
        gateway.add_port(
            igd_next::PortMappingProtocol::UDP,
            local_port,
            local_addr,
            3600,
            "snag",
        ),
    )
    .await
    {
        Ok(Ok(())) => {}
        _ => return None,
    };

    // Get the gateway's external IP (returns IpAddr)
    let external_ip =
        match tokio::time::timeout(Duration::from_secs(3), gateway.get_external_ip()).await {
            Ok(Ok(ip)) => ip,
            _ => {
                // Got port mapping but can't get external IP — clean up and bail
                let _ = gateway
                    .remove_port(igd_next::PortMappingProtocol::UDP, local_port)
                    .await;
                return None;
            }
        };

    let external_addr = SocketAddr::new(external_ip, local_port);

    Some((
        external_addr,
        UpnpLease {
            external_port: local_port,
        },
    ))
}

/// Try NAT-PMP port mapping (RFC 6886).
/// NAT-PMP is simpler than UPnP: just 2 UDP packets to the default gateway.
async fn try_nat_pmp(local_port: u16) -> Option<(SocketAddr, u16)> {
    // Discover the default gateway (NAT-PMP server runs on port 5351)
    let gateway_ip = get_default_gateway()?;
    let gateway_addr = SocketAddr::V4(SocketAddrV4::new(gateway_ip, 5351));

    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;

    // 1. Get external IP address (opcode 0)
    let external_ip = nat_pmp_get_external_ip(&socket, gateway_addr).await?;

    // 2. Request UDP port mapping (opcode 1)
    let external_port =
        nat_pmp_map_port(&socket, gateway_addr, local_port, local_port, 3600).await?;

    let external_addr = SocketAddr::V4(SocketAddrV4::new(external_ip, external_port));
    Some((external_addr, external_port))
}

/// Get default gateway IP. Uses /proc/net/route on Linux,
/// `route -n get default` on macOS, and `ipconfig` on Windows.
fn get_default_gateway() -> Option<Ipv4Addr> {
    #[cfg(target_os = "linux")]
    {
        let data = std::fs::read_to_string("/proc/net/route").ok()?;
        for line in data.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 3 && fields[1] == "00000000" {
                // Default route — gateway is in hex (little-endian on x86)
                let gw_hex = u32::from_str_radix(fields[2], 16).ok()?;
                return Some(Ipv4Addr::from(gw_hex.to_be()));
            }
        }
        None
    }

    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .ok()?;
        let text = String::from_utf8(output.stdout).ok()?;
        for line in text.lines() {
            let line = line.trim();
            if let Some(gw) = line.strip_prefix("gateway:") {
                return gw.trim().parse().ok();
            }
        }
        None
    }

    #[cfg(target_os = "windows")]
    {
        // NAT-PMP is rare on Windows, but try ipconfig for completeness
        let output = std::process::Command::new("ipconfig").output().ok()?;
        let text = String::from_utf8(output.stdout).ok()?;
        for line in text.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("Default Gateway") {
                let rest = rest.trim_start_matches(|c: char| c == '.' || c == ' ' || c == ':');
                if let Ok(ip) = rest.trim().parse::<Ipv4Addr>() {
                    if !ip.is_unspecified() {
                        return Some(ip);
                    }
                }
            }
        }
        None
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

/// NAT-PMP: Get external IP address (opcode 0).
async fn nat_pmp_get_external_ip(
    socket: &tokio::net::UdpSocket,
    gateway: SocketAddr,
) -> Option<Ipv4Addr> {
    // Request: version(0) + opcode(0) = 2 bytes
    let request = [0u8, 0u8];
    socket.send_to(&request, gateway).await.ok()?;

    let mut buf = [0u8; 12];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?;

    if n < 12 {
        return None;
    }

    // Response: version(0) + opcode(128) + result(2 bytes) + epoch(4 bytes) + ip(4 bytes)
    if buf[1] != 128 {
        return None; // Not a response to opcode 0
    }
    let result_code = u16::from_be_bytes([buf[2], buf[3]]);
    if result_code != 0 {
        return None; // Error
    }

    Some(Ipv4Addr::new(buf[8], buf[9], buf[10], buf[11]))
}

/// NAT-PMP: Request UDP port mapping (opcode 1).
async fn nat_pmp_map_port(
    socket: &tokio::net::UdpSocket,
    gateway: SocketAddr,
    internal_port: u16,
    external_port: u16,
    lifetime: u32,
) -> Option<u16> {
    // Request: version(0) + opcode(1) + reserved(2) + internal_port(2) + external_port(2) + lifetime(4)
    let mut request = vec![0u8, 1u8, 0, 0];
    request.extend_from_slice(&internal_port.to_be_bytes());
    request.extend_from_slice(&external_port.to_be_bytes());
    request.extend_from_slice(&lifetime.to_be_bytes());

    socket.send_to(&request, gateway).await.ok()?;

    let mut buf = [0u8; 16];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?;

    if n < 16 {
        return None;
    }

    // Response: version + opcode(129) + result(2) + epoch(4) + internal_port(2) + mapped_port(2) + lifetime(4)
    if buf[1] != 129 {
        return None;
    }
    let result_code = u16::from_be_bytes([buf[2], buf[3]]);
    if result_code != 0 {
        return None;
    }

    let mapped_port = u16::from_be_bytes([buf[10], buf[11]]);
    Some(mapped_port)
}

/// Prepare sender-side NAT traversal.
/// Tries each layer in order, returns the best available method.
/// `stun_servers` is from config — empty list disables STUN.
pub async fn prepare_sender(
    local_port: u16,
    bind_addr: &str,
    stun_servers: &[String],
) -> Result<SenderTraversal> {
    // Step 1: Bind a reusable UDP socket
    let socket = if bind_addr == "0.0.0.0" {
        nat::bind_reusable_socket(local_port)?
    } else {
        let addr: SocketAddrV4 = format!("{}:{}", bind_addr, local_port)
            .parse()
            .context("Invalid bind address")?;
        let s = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        s.set_reuse_address(true)?;
        s.set_nonblocking(true)?;
        s.bind(&socket2::SockAddr::from(addr))?;
        s.into()
    };

    let local_addr = socket.local_addr()?;
    let effective_port = local_addr.port();
    let local_ip = get_local_ipv4().unwrap_or(Ipv4Addr::UNSPECIFIED);

    vlog(&format!(
        "Bound socket to {} (effective port {})",
        local_addr, effective_port
    ));
    vlog(&format!("Local LAN IP: {}", local_ip));

    // Step 2: Try UPnP port mapping
    vlog("Trying UPnP IGD port mapping...");
    if let Some((external_addr, lease)) = try_upnp(effective_port).await {
        vlog(&format!(
            "UPnP succeeded: external address = {}",
            external_addr
        ));
        return Ok(SenderTraversal {
            external_addr,
            socket,
            method: TraversalMethod::Upnp,
            needs_hole_punch: false,
            nat_type: NatType::FullCone,
            upnp_lease: Some(lease),
        });
    }
    vlog("UPnP failed (no gateway or port mapping denied)");

    // Step 3: Try NAT-PMP
    vlog("Trying NAT-PMP / PCP...");
    if let Some((external_addr, _mapped_port)) = try_nat_pmp(effective_port).await {
        vlog(&format!(
            "NAT-PMP succeeded: external address = {}",
            external_addr
        ));
        return Ok(SenderTraversal {
            external_addr,
            socket,
            method: TraversalMethod::NatPmp,
            needs_hole_punch: false,
            nat_type: NatType::FullCone,
            upnp_lease: None,
        });
    }
    vlog("NAT-PMP failed (not supported by router)");

    // Step 4: STUN discovery using the server's actual socket so the
    // NAT mapping matches the port QUIC will use.
    vlog("Trying STUN discovery (using server socket)...");
    match nat::discover_addr_from_socket(&socket, stun_servers).await {
        Ok(stun_addr) if !stun_addr.ip().is_unspecified() && !stun_addr.ip().is_loopback() => {
            vlog(&format!("STUN discovered: {}", stun_addr));
            let nat_type = nat::detect_nat_type(stun_servers).await;
            let needs_punch = nat_type.needs_hole_punch();
            vlog(&format!(
                "NAT type: {:?}, needs hole punch: {}",
                nat_type, needs_punch
            ));

            Ok(SenderTraversal {
                external_addr: stun_addr,
                socket,
                method: TraversalMethod::Stun,
                needs_hole_punch: needs_punch,
                nat_type,
                upnp_lease: None,
            })
        }
        Ok(stun_addr) => {
            vlog(&format!("STUN returned unusable address: {}", stun_addr));
            let lan_addr = SocketAddr::V4(SocketAddrV4::new(local_ip, effective_port));
            vlog(&format!("Falling back to LAN address: {}", lan_addr));
            Ok(SenderTraversal {
                external_addr: lan_addr,
                socket,
                method: TraversalMethod::LocalOnly,
                needs_hole_punch: false,
                nat_type: NatType::Unknown,
                upnp_lease: None,
            })
        }
        Err(e) => {
            vlog(&format!("STUN failed: {}", e));
            // Fallback to actual LAN IP (not 0.0.0.0)
            let lan_addr = SocketAddr::V4(SocketAddrV4::new(local_ip, effective_port));
            vlog(&format!("Falling back to LAN address: {}", lan_addr));
            Ok(SenderTraversal {
                external_addr: lan_addr,
                socket,
                method: TraversalMethod::LocalOnly,
                needs_hole_punch: false,
                nat_type: NatType::Unknown,
                upnp_lease: None,
            })
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Receiver-side connection cascade
// ─────────────────────────────────────────────────────────────────────────────

/// Which connection method succeeded on the receiver side.
#[derive(Debug, Clone, Copy)]
pub enum ConnectMethod {
    Direct,
    LanDiscovery,
    HolePunch,
    PortPredict,
    Relay,
}

impl std::fmt::Display for ConnectMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct => write!(f, "direct"),
            Self::LanDiscovery => write!(f, "LAN discovery"),
            Self::HolePunch => write!(f, "hole-punched"),
            Self::PortPredict => write!(f, "port-predicted"),
            Self::Relay => write!(f, "relayed"),
        }
    }
}

/// Result of a successful connection cascade.
pub struct CascadeResult {
    pub connection: quinn::Connection,
    pub method: ConnectMethod,
}

/// Try to connect to the sender using a cascade of methods.
/// Each layer is tried in order; first success wins.
/// `share_code` is the raw code string, used for LAN discovery matching.
pub async fn connect_with_cascade(
    info: &crate::share_code::ShareCodeInfo,
    client_config: quinn::ClientConfig,
    share_code: &str,
) -> Result<CascadeResult> {
    let addr = info.addr;

    vlog(&format!("Share code decoded: target address = {}", addr));
    vlog(&format!("  needs_hole_punch = {}", info.needs_hole_punch));
    vlog(&format!("  relay_addr = {:?}", info.relay_addr));

    // Layer 1: Direct QUIC connect (5s timeout)
    vlog(&format!(
        "Layer 1: Direct connect to {} (5s timeout)...",
        addr
    ));
    match try_direct_connect(addr, &client_config, Duration::from_secs(5)).await {
        Ok(conn) => {
            vlog("Layer 1: SUCCESS - direct connection established");
            return Ok(CascadeResult {
                connection: conn,
                method: ConnectMethod::Direct,
            });
        }
        Err(e) => {
            vlog(&format!("Layer 1: FAILED - {}", e));
        }
    }

    // Layer 2: LAN discovery — listen for the sender's broadcast on the local network.
    // If both machines are on the same LAN but the share code has a public/unreachable IP,
    // this finds the sender's actual LAN address.
    vlog("Layer 2: LAN discovery (listening for sender broadcast, 3s)...");
    if let Some(lan_addr) = crate::discovery::probe_lan_for_sender(share_code, addr.port(), 3).await
    {
        vlog(&format!(
            "Layer 2: Found sender at LAN address {}",
            lan_addr
        ));
        if lan_addr != addr {
            vlog(&format!(
                "Layer 2: Trying direct connect to {}...",
                lan_addr
            ));
            match try_direct_connect(lan_addr, &client_config, Duration::from_secs(5)).await {
                Ok(conn) => {
                    vlog("Layer 2: SUCCESS - connected via LAN discovery");
                    return Ok(CascadeResult {
                        connection: conn,
                        method: ConnectMethod::LanDiscovery,
                    });
                }
                Err(e) => {
                    vlog(&format!("Layer 2: Connect to LAN address failed - {}", e));
                }
            }
        } else {
            vlog("Layer 2: LAN address same as encoded address, skipping");
        }
    } else {
        vlog("Layer 2: No matching sender found on LAN");
    }

    // Layer 3: STUN + hole punch + connect
    if info.needs_hole_punch {
        vlog(&format!("Layer 3: Hole punch to {}...", addr));
        match try_hole_punch_connect(addr, &client_config).await {
            Ok(conn) => {
                vlog("Layer 3: SUCCESS - hole punch connection established");
                return Ok(CascadeResult {
                    connection: conn,
                    method: ConnectMethod::HolePunch,
                });
            }
            Err(e) => {
                vlog(&format!("Layer 3: FAILED - {}", e));
            }
        }

        // Layer 4: Port prediction for symmetric NATs
        vlog(&format!("Layer 4: Port prediction around {}...", addr));
        match try_port_predict_connect(addr, &client_config).await {
            Ok(conn) => {
                vlog("Layer 4: SUCCESS - port prediction connection established");
                return Ok(CascadeResult {
                    connection: conn,
                    method: ConnectMethod::PortPredict,
                });
            }
            Err(e) => {
                vlog(&format!("Layer 4: FAILED - {}", e));
            }
        }
    } else {
        vlog("Layer 3-4: Skipped (hole punch not flagged)");
    }

    // Layer 5: Relay (if available)
    if let Some(relay_addr) = &info.relay_addr {
        vlog(&format!("Layer 5: Relay at {} (not yet wired)", relay_addr));
    } else {
        vlog("Layer 5: Skipped (no relay address)");
    }

    // Final attempt: direct connection with longer timeout (10s)
    vlog(&format!(
        "Layer 6: Final direct connect to {} (10s timeout)...",
        addr
    ));
    match try_direct_connect(addr, &client_config, Duration::from_secs(10)).await {
        Ok(conn) => {
            vlog("Layer 6: SUCCESS");
            Ok(CascadeResult {
                connection: conn,
                method: ConnectMethod::Direct,
            })
        }
        Err(e) => {
            vlog(&format!("Layer 6: FAILED - {}", e));
            Err(e).context(
                "All connection methods failed. \
                 The sender may be behind a strict NAT. \
                 Try connecting on the same network, or ask the sender to enable UPnP on their router.",
            )
        }
    }
}

/// Try a direct QUIC connection.
async fn try_direct_connect(
    addr: SocketAddr,
    client_config: &quinn::ClientConfig,
    timeout: Duration,
) -> Result<quinn::Connection> {
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;
    endpoint.set_default_client_config(client_config.clone());

    let connecting = endpoint.connect(addr, "peershare.local")?;
    match tokio::time::timeout(timeout, connecting).await {
        Ok(Ok(conn)) => Ok(conn),
        Ok(Err(e)) => {
            anyhow::bail!("QUIC connect to {} failed: {}", addr, e)
        }
        Err(_) => {
            anyhow::bail!(
                "Connection to {} timed out after {}s",
                addr,
                timeout.as_secs()
            )
        }
    }
}

/// Try hole-punched QUIC connection.
///
/// 1. Bind a reusable UDP socket
/// 2. Send punch packets to open the NAT mapping
/// 3. Create Quinn endpoint on the same socket
/// 4. Connect through the punched hole
async fn try_hole_punch_connect(
    remote_addr: SocketAddr,
    client_config: &quinn::ClientConfig,
) -> Result<quinn::Connection> {
    let std_socket = nat::bind_reusable_socket(0)?;

    // Send punch packets (nonblocking socket, 1-byte sends succeed immediately)
    for _ in 0..5 {
        let _ = std_socket.send_to(&[0u8; 1], remote_addr);
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    // Create Quinn endpoint on the same socket
    let runtime = quinn::default_runtime().ok_or_else(|| anyhow::anyhow!("No async runtime"))?;

    let mut endpoint =
        quinn::Endpoint::new(quinn::EndpointConfig::default(), None, std_socket, runtime)?;
    endpoint.set_default_client_config(client_config.clone());

    let conn = tokio::time::timeout(
        Duration::from_secs(8),
        endpoint.connect(remote_addr, "peershare.local")?,
    )
    .await
    .map_err(|_| anyhow::anyhow!("Hole punch connection timed out"))??;

    Ok(conn)
}

/// Try port prediction for sequential symmetric NATs.
///
/// Many symmetric NATs allocate external ports sequentially (e.g., each new
/// mapping gets port N+1). The share code contains the sender's STUN-mapped
/// port, but the QUIC listener may have gotten a nearby port instead.
///
/// This tries a small window of ±4 ports around the STUN-reported port.
/// Each attempt is short (1.5s) to keep total time reasonable (~12s worst case).
/// Only 8 additional ports are tried — this is conservative enough to avoid
/// looking like a port scan while still catching sequential allocators.
async fn try_port_predict_connect(
    addr: SocketAddr,
    client_config: &quinn::ClientConfig,
) -> Result<quinn::Connection> {
    let base_port = addr.port();

    // Small, sequential offsets — covers the most common symmetric NAT behavior
    let offsets: &[i32] = &[1, 2, -1, 3, -2, 4, -3, -4];

    for &offset in offsets {
        let predicted_port = match (base_port as i32).checked_add(offset) {
            Some(p) if p > 0 && p <= 65535 => p as u16,
            _ => continue,
        };

        let predicted_addr = SocketAddr::new(addr.ip(), predicted_port);
        let std_socket = match nat::bind_reusable_socket(0) {
            Ok(s) => s,
            Err(_) => continue,
        };

        // Send a punch packet before connecting
        let _ = std_socket.send_to(&[0u8; 1], predicted_addr);

        let runtime = match quinn::default_runtime() {
            Some(r) => r,
            None => continue,
        };

        let mut endpoint =
            match quinn::Endpoint::new(quinn::EndpointConfig::default(), None, std_socket, runtime)
            {
                Ok(e) => e,
                Err(_) => continue,
            };
        endpoint.set_default_client_config(client_config.clone());

        if let Ok(connecting) = endpoint.connect(predicted_addr, "peershare.local") {
            if let Ok(Ok(conn)) =
                tokio::time::timeout(Duration::from_millis(1500), connecting).await
            {
                return Ok(conn);
            }
        }
    }

    anyhow::bail!("Port prediction failed")
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_traversal_method_display() {
        assert_eq!(format!("{}", TraversalMethod::Upnp), "UPnP");
        assert_eq!(format!("{}", TraversalMethod::NatPmp), "NAT-PMP");
        assert_eq!(format!("{}", TraversalMethod::Stun), "STUN");
        assert_eq!(format!("{}", TraversalMethod::LocalOnly), "LAN");
    }

    #[test]
    fn test_connect_method_display() {
        assert_eq!(format!("{}", ConnectMethod::Direct), "direct");
        assert_eq!(format!("{}", ConnectMethod::LanDiscovery), "LAN discovery");
        assert_eq!(format!("{}", ConnectMethod::HolePunch), "hole-punched");
        assert_eq!(format!("{}", ConnectMethod::PortPredict), "port-predicted");
        assert_eq!(format!("{}", ConnectMethod::Relay), "relayed");
    }

    #[test]
    fn test_get_local_ipv4() {
        // Should succeed on any machine with network access
        if let Ok(ip) = get_local_ipv4() {
            assert!(!ip.is_loopback());
            assert!(!ip.is_unspecified());
        }
    }

    #[test]
    fn test_get_default_gateway() {
        // On Linux, /proc/net/route should be readable
        if cfg!(target_os = "linux") {
            // Don't assert Some — CI may not have a default route
            let _ = get_default_gateway();
        }
    }
}
