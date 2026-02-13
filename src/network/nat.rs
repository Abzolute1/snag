use anyhow::Result;
use std::net::SocketAddr;

/// Default STUN servers (used when config has none).
const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
];

/// Detected NAT type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    /// No NAT — public IP directly reachable
    OpenInternet,
    /// Full cone NAT — any external host can send to the mapped address
    FullCone,
    /// Restricted cone — only hosts the client has sent to can reply
    Restricted,
    /// Port-restricted cone — reply must come from the exact port sent to
    PortRestricted,
    /// Symmetric NAT — each destination gets a different mapped address
    Symmetric,
    /// Could not determine NAT type
    Unknown,
}

impl NatType {
    /// Whether this NAT type may require hole punching for inbound connections
    pub fn needs_hole_punch(&self) -> bool {
        matches!(
            self,
            NatType::Restricted | NatType::PortRestricted | NatType::Symmetric
        )
    }
}

/// Resolve the STUN server list: use provided list, or fall back to defaults.
fn resolve_stun_servers(servers: &[String]) -> Vec<String> {
    if servers.is_empty() {
        DEFAULT_STUN_SERVERS.iter().map(|s| s.to_string()).collect()
    } else {
        servers.to_vec()
    }
}

/// Discover our public address using STUN.
/// Falls back to local address if STUN fails.
pub async fn discover_public_addr(local_port: u16, stun_servers: &[String]) -> Result<SocketAddr> {
    let servers = resolve_stun_servers(stun_servers);
    match stun_discover(local_port, &servers).await {
        Ok(addr) => Ok(addr),
        Err(_) => {
            // Fallback to local address for LAN use
            let addr: SocketAddr = format!("0.0.0.0:{}", local_port).parse()?;
            let socket = tokio::net::UdpSocket::bind(addr).await?;
            Ok(socket.local_addr()?)
        }
    }
}

/// Detect NAT type by comparing mapped addresses from two different STUN servers.
/// If both servers return the same mapped address, it's a cone NAT (hole-punchable).
/// If they differ, it's symmetric NAT (needs relay).
pub async fn detect_nat_type(stun_servers: &[String]) -> NatType {
    let servers = resolve_stun_servers(stun_servers);
    if servers.len() < 2 {
        return NatType::Unknown;
    }

    let request = build_stun_request();

    // Need results from at least two different servers
    let mut results = Vec::new();
    for server in &servers {
        if let Ok(addr) = try_stun_server_raw(server, &request).await {
            results.push(addr);
            if results.len() >= 2 {
                break;
            }
        }
    }

    if results.len() < 2 {
        return NatType::Unknown;
    }

    if results[0] == results[1] {
        // Same mapped address from two different servers — cone NAT or open
        // We can't distinguish full-cone vs restricted without extra tests,
        // but for hole-punching purposes they're equivalent.
        if results[0].ip().is_loopback() || results[0].ip().is_unspecified() {
            NatType::OpenInternet
        } else {
            NatType::FullCone
        }
    } else {
        NatType::Symmetric
    }
}

/// Send 3-5 empty UDP packets to open a NAT mapping for the remote peer.
/// Must be called on the same socket that quinn will later use.
pub async fn punch_hole(socket: &tokio::net::UdpSocket, remote_addr: SocketAddr) -> Result<()> {
    for _ in 0..4 {
        // Send a small UDP packet — doesn't matter if the peer receives it,
        // the point is to open the NAT mapping so their reply can reach us.
        let _ = socket.send_to(&[0u8; 1], remote_addr).await;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    Ok(())
}

/// Bind a UDP socket with SO_REUSEADDR so both STUN and quinn can use
/// the same local address.
pub fn bind_reusable_socket(port: u16) -> Result<std::net::UdpSocket> {
    use std::net::{Ipv4Addr, SocketAddrV4};

    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&socket2::SockAddr::from(addr))?;
    Ok(socket.into())
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal STUN implementation
// ─────────────────────────────────────────────────────────────────────────────

fn build_stun_request() -> Vec<u8> {
    let mut request = vec![0x00, 0x01, 0x00, 0x00]; // Binding Request, length 0
    request.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]); // Magic cookie
    let txn_id: Vec<u8> = (0..12).map(|_| rand::random::<u8>()).collect();
    request.extend_from_slice(&txn_id);
    request
}

/// Discover public address using the actual server socket.
/// This ensures the STUN-mapped port matches the port QUIC will use,
/// because the request goes through the same NAT mapping.
pub async fn discover_addr_from_socket(
    socket: &std::net::UdpSocket,
    stun_servers: &[String],
) -> Result<SocketAddr> {
    let servers = resolve_stun_servers(stun_servers);
    let cloned = socket.try_clone()?;
    let tokio_socket = tokio::net::UdpSocket::from_std(cloned)?;

    let request = build_stun_request();

    for server in &servers {
        match try_stun_with_socket(&tokio_socket, server, &request).await {
            Ok(addr) => return Ok(addr),
            Err(_) => continue,
        }
    }

    anyhow::bail!("All STUN servers failed")
}

/// Send a STUN request through a specific socket and parse the response.
/// Retries reading until a valid STUN response arrives or timeout.
async fn try_stun_with_socket(
    socket: &tokio::net::UdpSocket,
    server: &str,
    request: &[u8],
) -> Result<SocketAddr> {
    socket.send_to(request, server).await?;

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
    let mut buf = [0u8; 512];

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            anyhow::bail!("STUN timeout");
        }

        match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => {
                if let Ok(addr) = parse_stun_response(&buf[..n]) {
                    return Ok(addr);
                }
                // Not a valid STUN response, keep waiting
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => anyhow::bail!("STUN timeout"),
        }
    }
}

/// Simple STUN binding request to discover public IP:port
async fn stun_discover(_local_port: u16, servers: &[String]) -> Result<SocketAddr> {
    let request = build_stun_request();

    for server in servers {
        if let Ok(result) = try_stun_server(server, &request).await {
            return Ok(result);
        }
    }

    anyhow::bail!("All STUN servers failed")
}

async fn try_stun_server(server: &str, request: &[u8]) -> Result<SocketAddr> {
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    socket.send_to(request, server).await?;

    let mut buf = [0u8; 512];
    let timeout = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        socket.recv_from(&mut buf),
    );

    let (n, _) = timeout.await??;
    parse_stun_response(&buf[..n])
}

/// Like try_stun_server but returns the raw mapped address
async fn try_stun_server_raw(server: &str, request: &[u8]) -> Result<SocketAddr> {
    try_stun_server(server, request).await
}

/// Parse a STUN binding response to extract the XOR-MAPPED-ADDRESS
fn parse_stun_response(data: &[u8]) -> Result<SocketAddr> {
    if data.len() < 20 {
        anyhow::bail!("STUN response too short");
    }

    // Check it's a binding response (0x0101)
    if data[0] != 0x01 || data[1] != 0x01 {
        anyhow::bail!("Not a STUN binding response");
    }

    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() < 20 + msg_len {
        anyhow::bail!("STUN response truncated");
    }

    // Parse attributes looking for XOR-MAPPED-ADDRESS (0x0020) or MAPPED-ADDRESS (0x0001)
    let mut offset = 20;
    while offset + 4 <= data.len() {
        let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;

        if offset + attr_len > data.len() {
            break;
        }

        match attr_type {
            0x0020 => {
                // XOR-MAPPED-ADDRESS
                if attr_len >= 8 {
                    let family = data[offset + 1];
                    if family == 0x01 {
                        // IPv4
                        let port =
                            u16::from_be_bytes([data[offset + 2], data[offset + 3]]) ^ 0x2112; // XOR with magic cookie upper 16 bits
                        let ip = [
                            data[offset + 4] ^ 0x21,
                            data[offset + 5] ^ 0x12,
                            data[offset + 6] ^ 0xa4,
                            data[offset + 7] ^ 0x42,
                        ];
                        return Ok(SocketAddr::new(
                            std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                                ip[0], ip[1], ip[2], ip[3],
                            )),
                            port,
                        ));
                    }
                }
            }
            0x0001 => {
                // MAPPED-ADDRESS (fallback)
                if attr_len >= 8 {
                    let family = data[offset + 1];
                    if family == 0x01 {
                        let port = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
                        let ip = std::net::Ipv4Addr::new(
                            data[offset + 4],
                            data[offset + 5],
                            data[offset + 6],
                            data[offset + 7],
                        );
                        return Ok(SocketAddr::new(std::net::IpAddr::V4(ip), port));
                    }
                }
            }
            _ => {}
        }

        // Align to 4 bytes
        offset += (attr_len + 3) & !3;
    }

    anyhow::bail!("No mapped address in STUN response")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_type_needs_hole_punch() {
        assert!(!NatType::OpenInternet.needs_hole_punch());
        assert!(!NatType::FullCone.needs_hole_punch());
        assert!(NatType::Restricted.needs_hole_punch());
        assert!(NatType::PortRestricted.needs_hole_punch());
        assert!(NatType::Symmetric.needs_hole_punch());
        assert!(!NatType::Unknown.needs_hole_punch());
    }

    #[test]
    fn test_parse_stun_xor_mapped_address() {
        // Construct a minimal STUN binding response with XOR-MAPPED-ADDRESS
        let mut response = vec![
            0x01, 0x01, // Binding Response
            0x00, 0x0C, // Message Length: 12
            0x21, 0x12, 0xA4, 0x42, // Magic Cookie
        ];
        // Transaction ID (12 bytes)
        response.extend_from_slice(&[0x00; 12]);
        // XOR-MAPPED-ADDRESS attribute
        response.extend_from_slice(&[
            0x00, 0x20, // Attr Type: XOR-MAPPED-ADDRESS
            0x00, 0x08, // Attr Length: 8
            0x00, 0x01, // Family: IPv4
        ]);
        // Port: 8080 XOR 0x2112 = 0x1F92 XOR 0x2112 = 0x3E80
        // 8080 = 0x1F90, 0x1F90 XOR 0x2112 = 0x3E82
        let port_xor = 8080u16 ^ 0x2112;
        response.extend_from_slice(&port_xor.to_be_bytes());
        // IP: 203.0.113.1 XOR magic cookie bytes
        response.extend_from_slice(&[203 ^ 0x21, 0 ^ 0x12, 113 ^ 0xA4, 1 ^ 0x42]);

        let result = parse_stun_response(&response).unwrap();
        assert_eq!(result, "203.0.113.1:8080".parse::<SocketAddr>().unwrap());
    }
}
