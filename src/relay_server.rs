//! Zero-knowledge UDP relay server for NAT traversal.
//!
//! When both peers are behind symmetric NAT, direct hole punching fails.
//! This relay forwards opaque UDP packets between two clients in the same
//! "room" (derived from the share code hash). It never sees plaintext — all
//! traffic is QUIC-encrypted between the peers.
//!
//! Usage: `snag relay [--port 19816] [--max-rooms 1000]`

use anyhow::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

const DEFAULT_PORT: u16 = 19816;
const ROOM_TIMEOUT: Duration = Duration::from_secs(3600); // 1 hour
const MAX_PACKET_SIZE: usize = 65536;

/// A relay room: two clients that want to talk to each other.
struct Room {
    clients: Vec<SocketAddr>,
    last_activity: Instant,
}

impl Room {
    fn new() -> Self {
        Self {
            clients: Vec::with_capacity(2),
            last_activity: Instant::now(),
        }
    }

    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    fn is_expired(&self) -> bool {
        self.last_activity.elapsed() > ROOM_TIMEOUT
    }

    /// Add a client to the room. Returns true if this is a new client.
    fn add_client(&mut self, addr: SocketAddr) -> bool {
        if !self.clients.contains(&addr) && self.clients.len() < 2 {
            self.clients.push(addr);
            return true;
        }
        false
    }

    /// Get the other client's address (the peer to forward to).
    fn peer_of(&self, addr: &SocketAddr) -> Option<SocketAddr> {
        if self.clients.len() == 2 {
            if self.clients[0] == *addr {
                Some(self.clients[1])
            } else if self.clients[1] == *addr {
                Some(self.clients[0])
            } else {
                None
            }
        } else {
            None
        }
    }
}

/// Relay state: maps room IDs to rooms.
struct RelayState {
    rooms: HashMap<[u8; 32], Room>,
    max_rooms: usize,
}

impl RelayState {
    fn new(max_rooms: usize) -> Self {
        Self {
            rooms: HashMap::new(),
            max_rooms,
        }
    }

    fn evict_expired(&mut self) {
        self.rooms.retain(|_, room| !room.is_expired());
    }
}

/// Relay protocol: first 32 bytes of each packet are the room ID.
/// Remaining bytes are forwarded to the peer in the same room.
const ROOM_ID_LEN: usize = 32;

/// Run the relay server.
pub async fn run_relay(port: u16, max_rooms: usize) -> Result<()> {
    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;
    let socket = UdpSocket::bind(addr).await?;
    let state = Arc::new(Mutex::new(RelayState::new(max_rooms)));

    eprintln!("Relay server listening on {}", socket.local_addr()?);
    eprintln!("Max rooms: {}", max_rooms);
    eprintln!("Room timeout: {}s", ROOM_TIMEOUT.as_secs());

    let mut buf = vec![0u8; MAX_PACKET_SIZE];
    let mut last_eviction = Instant::now();

    loop {
        let (n, src_addr) = socket.recv_from(&mut buf).await?;

        if n < ROOM_ID_LEN {
            // Too short to contain a room ID — ignore
            continue;
        }

        let mut room_id = [0u8; ROOM_ID_LEN];
        room_id.copy_from_slice(&buf[..ROOM_ID_LEN]);
        let payload = &buf[ROOM_ID_LEN..n];

        let forward_to = {
            let mut relay = state.lock().await;

            // Periodic eviction (every 60 seconds)
            if last_eviction.elapsed() > Duration::from_secs(60) {
                relay.evict_expired();
                last_eviction = Instant::now();
            }

            // Evict if at capacity before inserting
            if !relay.rooms.contains_key(&room_id) && relay.rooms.len() >= relay.max_rooms {
                relay.evict_expired();
            }

            let room = relay.rooms.entry(room_id).or_insert_with(Room::new);

            room.add_client(src_addr);
            room.touch();

            room.peer_of(&src_addr)
        };

        // Forward the payload (without room ID prefix) to the peer
        if let Some(peer_addr) = forward_to {
            let _ = socket.send_to(payload, peer_addr).await;
        }
    }
}

/// Derive a room ID from a share code (deterministic, both peers compute the same).
pub fn room_id_from_code(share_code: &str) -> [u8; 32] {
    let hash = blake3::hash(share_code.as_bytes());
    *hash.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_room_lifecycle() {
        let mut room = Room::new();
        let addr1: SocketAddr = "1.2.3.4:1000".parse().unwrap();
        let addr2: SocketAddr = "5.6.7.8:2000".parse().unwrap();

        assert!(room.add_client(addr1));
        assert_eq!(room.peer_of(&addr1), None); // Only 1 client

        assert!(room.add_client(addr2));
        assert_eq!(room.peer_of(&addr1), Some(addr2));
        assert_eq!(room.peer_of(&addr2), Some(addr1));

        // Duplicate add is a no-op
        assert!(!room.add_client(addr1));
    }

    #[test]
    fn test_room_id_deterministic() {
        let id1 = room_id_from_code("fox-ram-log-K7XM9PR2");
        let id2 = room_id_from_code("fox-ram-log-K7XM9PR2");
        assert_eq!(id1, id2);

        let id3 = room_id_from_code("dog-hat-big-XXXXXXXX");
        assert_ne!(id1, id3);
    }
}
