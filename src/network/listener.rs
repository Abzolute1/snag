use anyhow::{anyhow, Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::app::{AppState, PeerInfo};
use crate::crypto::bulk::BulkCipher;
use crate::crypto::keys::DerivedKeys;
use crate::crypto::stream::EncryptedStream;
use crate::network::connection::{create_server_endpoint, recv_msg, send_msg};
use crate::protocol::handshake::{self, NoiseHandshaker};
use crate::protocol::messages::Message;
use crate::share_code;
use crate::transfer::sender;

/// Run the QUIC listener for hosting files
pub async fn run_listener(
    addr: SocketAddr,
    share_code: String,
    state: Arc<Mutex<AppState>>,
    cancel: CancellationToken,
) -> Result<()> {
    let endpoint = create_server_endpoint(addr)?;
    run_listener_with_endpoint(endpoint, share_code, state, cancel).await
}

/// Run the QUIC listener using a pre-created endpoint.
/// Used when NAT traversal has already bound the socket.
pub async fn run_listener_with_endpoint(
    endpoint: quinn::Endpoint,
    share_code: String,
    state: Arc<Mutex<AppState>>,
    cancel: CancellationToken,
) -> Result<()> {
    let auth_words = share_code::extract_auth_words(&share_code);

    loop {
        if cancel.is_cancelled() {
            break;
        }

        let should_quit = {
            let app = state.lock().await;
            app.should_quit
        };
        if should_quit {
            break;
        }

        let incoming = match tokio::time::timeout(
            std::time::Duration::from_secs(1),
            endpoint.accept(),
        )
        .await
        {
            Ok(Some(incoming)) => incoming,
            Ok(None) => break,
            Err(_) => continue,
        };

        let connection = match incoming.await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!("Failed to accept connection: {}", e);
                continue;
            }
        };

        let peer_state = state.clone();
        let peer_auth = auth_words.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_peer(connection, peer_auth, peer_state).await {
                tracing::warn!("Peer session error: {}", e);
            }
        });
    }

    endpoint.close(0u32.into(), b"shutting down");
    Ok(())
}

/// Handle a single peer connection
async fn handle_peer(
    connection: quinn::Connection,
    auth_words: String,
    state: Arc<Mutex<AppState>>,
) -> Result<()> {
    let peer_addr = connection.remote_address();
    let peer_name = format!("peer-{}", peer_addr.port());

    let (mut send_stream, mut recv_stream) = connection
        .accept_bi()
        .await
        .context("Failed to accept QUIC stream")?;

    // === SPAKE2 exchange ===
    let (spake_msg, spake_state) = handshake::spake2_start_host(&auth_words)?;

    // Receive peer's SPAKE2 message first
    let peer_msg = recv_msg(&mut recv_stream).await?;
    let peer_spake_bytes = match peer_msg {
        Message::Spake(bytes) => bytes,
        _ => return Err(anyhow!("Expected SPAKE2 message")),
    };

    // Send our SPAKE2 message
    send_msg(&mut send_stream, &Message::Spake(spake_msg)).await?;

    // Complete SPAKE2
    let shared_secret = handshake::spake2_finish(spake_state, &peer_spake_bytes)?;
    let psk = handshake::derive_noise_psk(&shared_secret)?;

    // Derive bulk encryption key from shared secret
    let derived = DerivedKeys::from_shared_secret(&shared_secret)?;
    let mut bulk_cipher = BulkCipher::new(&derived.data_key);

    // === Noise XX handshake (as initiator) ===
    let noise_state = handshake::noise_initiator(&psk)?;
    let mut noise = NoiseHandshaker::new(noise_state);

    // → e
    let msg1 = noise.write_message()?;
    send_msg(&mut send_stream, &Message::NoiseHandshake(msg1)).await?;

    // ← e, ee, s, es
    let msg2 = recv_msg(&mut recv_stream).await?;
    let msg2_bytes = match msg2 {
        Message::NoiseHandshake(b) => b,
        _ => return Err(anyhow!("Expected Noise handshake")),
    };
    noise.read_message(&msg2_bytes)?;

    // → s, se, psk
    let msg3 = noise.write_message()?;
    send_msg(&mut send_stream, &Message::NoiseHandshake(msg3)).await?;

    let transport = noise.into_transport()?;
    let mut encrypted = EncryptedStream::new(transport);

    // Capture a local snapshot of the catalog so the sender's file lookups
    // are never affected by the receiver overwriting app.catalog
    let catalog_snapshot = {
        let mut app = state.lock().await;
        app.peers.push(PeerInfo {
            name: peer_name.clone(),
            files_requested: Vec::new(),
            bytes_sent: 0,
        });
        app.status_message = Some(format!("{} connected", peer_name));
        app.catalog.clone()
    };

    // Send catalog (control message — uses Noise encryption)
    let catalog_msg = Message::Catalog(catalog_snapshot.to_wire());
    let frame = encrypted.encrypt_message(&catalog_msg)?;
    send_stream.write_all(&frame).await?;

    // === Handle requests loop ===
    loop {
        let should_quit = {
            let app = state.lock().await;
            app.should_quit
        };
        if should_quit {
            break;
        }

        // Read length-prefixed encrypted frames
        let mut len_buf = [0u8; 4];
        match tokio::time::timeout(
            std::time::Duration::from_millis(500),
            recv_stream.read_exact(&mut len_buf),
        )
        .await
        {
            Ok(Ok(())) => {
                let len = u32::from_be_bytes(len_buf) as usize;
                if len > crate::network::connection::MAX_FRAME_SIZE {
                    return Err(anyhow!("Frame too large: {} bytes", len));
                }
                let mut payload = vec![0u8; len];
                recv_stream.read_exact(&mut payload).await?;

                if let Ok(msg) = encrypted.decrypt_message(&payload) {
                    match msg {
                        Message::DownloadRequest(req) => {
                            // Track requested files for this peer
                            {
                                let mut app = state.lock().await;
                                if let Some(peer) =
                                    app.peers.iter_mut().find(|p| p.name == peer_name)
                                {
                                    peer.files_requested.extend(req.file_names.clone());
                                }
                            }

                            handle_download_request(
                                &req,
                                &peer_name,
                                &state,
                                &catalog_snapshot,
                                &mut encrypted,
                                &mut bulk_cipher,
                                &mut send_stream,
                            )
                            .await?;
                        }
                        Message::Ping => {
                            let pong = encrypted.encrypt_message(&Message::Pong)?;
                            send_stream.write_all(&pong).await?;
                        }
                        _ => {}
                    }
                }
            }
            Ok(Err(_)) => break,
            Err(_) => {} // timeout
        }
    }

    // Remove peer
    {
        let mut app = state.lock().await;
        app.peers.retain(|p| p.name != peer_name);
        app.status_message = Some(format!("{} disconnected", peer_name));
    }

    Ok(())
}

async fn handle_download_request(
    req: &crate::protocol::messages::DownloadRequestMessage,
    peer_name: &str,
    state: &Arc<Mutex<AppState>>,
    catalog: &crate::protocol::catalog::SharedCatalog,
    encrypted: &mut EncryptedStream,
    bulk: &mut BulkCipher,
    send_stream: &mut quinn::SendStream,
) -> Result<()> {
    // Build resume map from the request
    let mut resume_map = std::collections::HashMap::new();
    for entry in &req.resume_from {
        resume_map.insert(entry.file_name.clone(), entry.bytes_received);
    }

    for file_name in &req.file_names {
        let entry = catalog
            .entries
            .iter()
            .find(|e| e.name == *file_name)
            .cloned();

        if let Some(entry) = entry {
            let compress = {
                let mut app = state.lock().await;
                app.transfer_manager.start_upload(
                    file_name.clone(),
                    entry.size,
                    peer_name.to_string(),
                );
                app.config.transfers.compression
            };

            sender::send_file(
                &entry.path,
                file_name,
                peer_name,
                state,
                encrypted,
                bulk,
                send_stream,
                &resume_map,
                compress,
            )
            .await?;

            // Only increment completed_downloads once per (peer, file)
            {
                let mut app = state.lock().await;
                if app
                    .transfer_manager
                    .mark_transfer_complete(peer_name, file_name)
                {
                    app.completed_downloads += 1;
                }
                // Track bytes sent for this peer
                if let Some(peer) = app.peers.iter_mut().find(|p| p.name == *peer_name) {
                    peer.bytes_sent += entry.size;
                }
            }
        }
    }
    Ok(())
}
