use anyhow::{anyhow, Context, Result};
use quinn::Endpoint;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use crate::app::AppState;
use crate::crypto::bulk::{self, BulkCipher};
use crate::crypto::keys::{generate_self_signed_cert, DerivedKeys};
use crate::protocol::catalog::SharedCatalog;
use crate::protocol::handshake::{self, NoiseHandshaker};
use crate::protocol::messages::{self, Message};
use crate::share_code;

/// Build a shared QUIC transport config with keepalive and idle timeout.
fn make_transport_config() -> quinn::TransportConfig {
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.keep_alive_interval(Some(Duration::from_secs(5)));
    transport_config.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(30)).unwrap(),
    ));
    transport_config
}

/// Get the local address for hosting
pub async fn get_local_addr(port: u16, bind_addr: &str) -> Result<SocketAddr> {
    let addr: SocketAddr = format!("{}:{}", bind_addr, port).parse()?;
    let socket = tokio::net::UdpSocket::bind(addr).await?;
    let local_addr = socket.local_addr()?;
    let effective_addr = if local_addr.ip().is_unspecified() {
        SocketAddr::new("127.0.0.1".parse().unwrap(), local_addr.port())
    } else {
        local_addr
    };
    Ok(effective_addr)
}

/// Create a QUIC server endpoint
pub fn create_server_endpoint(addr: SocketAddr) -> Result<Endpoint> {
    let (cert, key) = generate_self_signed_cert()?;
    let mut server_config = quinn::ServerConfig::with_single_cert(vec![cert], key)
        .context("Failed to create QUIC server config")?;
    server_config.transport_config(Arc::new(make_transport_config()));
    let endpoint = Endpoint::server(server_config, addr).context("Failed to bind QUIC endpoint")?;
    Ok(endpoint)
}

/// Create a QUIC server endpoint from a pre-bound UDP socket.
/// Used when NAT traversal has already bound a socket (for STUN/UPnP).
pub fn create_server_endpoint_from_socket(socket: std::net::UdpSocket) -> Result<Endpoint> {
    let (cert, key) = generate_self_signed_cert()?;
    let mut server_config = quinn::ServerConfig::with_single_cert(vec![cert], key)
        .context("Failed to create QUIC server config")?;
    server_config.transport_config(Arc::new(make_transport_config()));
    let runtime = quinn::default_runtime().ok_or_else(|| anyhow!("No async runtime available"))?;
    let endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        runtime,
    )
    .context("Failed to create QUIC endpoint from socket")?;
    Ok(endpoint)
}

/// Build a reusable QUIC client config (shared across cascade attempts).
pub fn make_client_config() -> Result<quinn::ClientConfig> {
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .context("Failed to create QUIC client config")?,
    ));
    client_config.transport_config(Arc::new(make_transport_config()));
    Ok(client_config)
}

/// Create a QUIC client endpoint
pub fn create_client_endpoint() -> Result<Endpoint> {
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
        .context("Failed to create client endpoint")?;
    endpoint.set_default_client_config(make_client_config()?);
    Ok(endpoint)
}

/// Helper: send a framed message over QUIC
pub async fn send_msg(stream: &mut quinn::SendStream, msg: &Message) -> Result<()> {
    let data = messages::encode_message(msg)?;
    stream.write_all(&data).await?;
    Ok(())
}

/// Helper: receive a framed message over QUIC
pub async fn recv_msg(stream: &mut quinn::RecvStream) -> Result<Message> {
    // Read length prefix
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;

    let msg = messages::decode_message(&payload)?;
    Ok(msg)
}

/// Connect to a host using a share code.
/// Uses a layered connection cascade: direct → hole punch → port predict → relay.
pub async fn connect_to_host(code: String, state: Arc<Mutex<AppState>>) -> Result<()> {
    let auth_words = share_code::extract_auth_words(&code);
    let info =
        share_code::decode_share_code_full(&code).ok_or_else(|| anyhow!("Invalid share code"))?;

    let client_config = make_client_config()?;

    // Use the connection cascade — tries multiple methods in order
    let cascade_result =
        crate::network::traversal::connect_with_cascade(&info, client_config, &code).await?;

    tracing::info!("Connected via {}", cascade_result.method);
    let connection = cascade_result.connection;

    let (mut send_stream, mut recv_stream) = connection
        .open_bi()
        .await
        .context("Failed to open QUIC stream")?;

    // === SPAKE2 exchange ===
    let (spake_msg, spake_state) = handshake::spake2_start_fetch(&auth_words)?;
    send_msg(&mut send_stream, &Message::Spake(spake_msg)).await?;

    let host_msg = recv_msg(&mut recv_stream).await?;
    let host_spake_bytes = match host_msg {
        Message::Spake(bytes) => bytes,
        _ => return Err(anyhow!("Expected SPAKE2 message")),
    };

    let shared_secret = handshake::spake2_finish(spake_state, &host_spake_bytes)
        .map_err(|_| anyhow!("Wrong share code — check and try again"))?;
    let psk = handshake::derive_noise_psk(&shared_secret)?;

    // Derive bulk encryption key from shared secret (same derivation as sender)
    let derived = DerivedKeys::from_shared_secret(&shared_secret)?;
    let mut bulk_cipher = BulkCipher::new(&derived.data_key);

    // === Noise XX handshake (as responder) ===
    let noise_state = handshake::noise_responder(&psk)?;
    let mut noise = NoiseHandshaker::new(noise_state);

    // ← e (receive from initiator/host)
    let msg1 = recv_msg(&mut recv_stream).await?;
    let msg1_bytes = match msg1 {
        Message::NoiseHandshake(b) => b,
        _ => return Err(anyhow!("Expected Noise handshake")),
    };
    noise.read_message(&msg1_bytes)?;

    // → e, ee, s, es
    let msg2 = noise.write_message()?;
    send_msg(&mut send_stream, &Message::NoiseHandshake(msg2)).await?;

    // ← s, se, psk
    let msg3 = recv_msg(&mut recv_stream).await?;
    let msg3_bytes = match msg3 {
        Message::NoiseHandshake(b) => b,
        _ => return Err(anyhow!("Expected Noise handshake")),
    };
    noise.read_message(&msg3_bytes)?;

    let transport = noise.into_transport()?;
    let mut encrypted = crate::crypto::stream::EncryptedStream::new(transport);

    // === Receive catalog ===
    let mut enc_len_buf = [0u8; 4];
    recv_stream.read_exact(&mut enc_len_buf).await?;
    let enc_len = u32::from_be_bytes(enc_len_buf) as usize;
    if enc_len > MAX_FRAME_SIZE {
        return Err(anyhow!("Catalog frame too large: {} bytes", enc_len));
    }
    let mut enc_payload = vec![0u8; enc_len];
    recv_stream.read_exact(&mut enc_payload).await?;

    let catalog_msg = encrypted.decrypt_message(&enc_payload)?;

    if let Message::Catalog(catalog_wire) = catalog_msg {
        let catalog = SharedCatalog::from_wire(&catalog_wire);
        let num_entries = catalog.entries.len();

        let mut app = state.lock().await;
        app.catalog = catalog;
        app.fetch_selected = vec![false; num_entries];
        app.connected = true;
        app.status_message = Some(format!("Connected! {} files available", num_entries));
    }

    // === Main communication loop ===
    // Process frames as fast as possible. Only check quit/requests every
    // Nth iteration or when we hit a read timeout (no data flowing).
    let mut iter_count: u32 = 0;
    loop {
        iter_count = iter_count.wrapping_add(1);

        // Check quit and pending requests every 64 iterations or on timeout
        if iter_count.is_multiple_of(64) {
            let should_quit = {
                let app = state.lock().await;
                app.should_quit
            };
            if should_quit {
                break;
            }

            // Send download requests if any
            let download_requests = {
                let app = state.lock().await;
                app.transfer_manager.pending_requests.clone()
            };

            if !download_requests.is_empty() {
                // Check for existing .part files to build resume info
                let resume_from = {
                    let app = state.lock().await;
                    build_resume_entries(&download_requests, &app.output_dir)
                };

                let request_msg = Message::DownloadRequest(messages::DownloadRequestMessage {
                    file_names: download_requests.clone(),
                    resume_from,
                });
                let frame = encrypted.encrypt_message(&request_msg)?;
                send_stream.write_all(&frame).await?;
                // Only clear after successful send
                {
                    let mut app = state.lock().await;
                    let sent_count = download_requests.len();
                    if app.transfer_manager.pending_requests.len() >= sent_count {
                        app.transfer_manager.pending_requests.drain(..sent_count);
                    }
                }
            }
        }

        // Try to receive data (handles both Noise and bulk-encrypted frames)
        let mut len_buf = [0u8; 4];
        match tokio::time::timeout(
            std::time::Duration::from_millis(100),
            recv_stream.read_exact(&mut len_buf),
        )
        .await
        {
            Ok(Ok(())) => {
                if bulk::is_bulk_frame(len_buf) {
                    // Bulk-encrypted data frame (file chunks)
                    let payload_len = bulk::bulk_payload_len(len_buf);
                    if payload_len > MAX_FRAME_SIZE {
                        return Err(anyhow!("Frame too large: {} bytes", payload_len));
                    }
                    let mut payload = vec![0u8; payload_len];
                    recv_stream.read_exact(&mut payload).await?;

                    match bulk_cipher.decrypt_payload(&payload) {
                        Ok(plaintext) => {
                            if let Ok(msg) = bincode::deserialize::<Message>(&plaintext) {
                                handle_received_message(msg, &state).await?;
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Bulk decrypt failed: {}", e);
                        }
                    }
                } else {
                    // Noise-encrypted control frame
                    let len = u32::from_be_bytes(len_buf) as usize;
                    if len > MAX_FRAME_SIZE {
                        return Err(anyhow!("Frame too large: {} bytes", len));
                    }
                    let mut payload = vec![0u8; len];
                    recv_stream.read_exact(&mut payload).await?;

                    if let Ok(msg) = encrypted.decrypt_message(&payload) {
                        handle_received_message(msg, &state).await?;
                    }
                }
            }
            Ok(Err(_)) => {
                let mut app = state.lock().await;
                app.status_message = Some("Connection closed".to_string());
                break;
            }
            Err(_) => {
                // Timeout (no data) — good time to check quit + requests
                iter_count = 63; // force check on next iteration
            }
        }
    }

    Ok(())
}

async fn handle_received_message(msg: Message, state: &Arc<Mutex<AppState>>) -> Result<()> {
    match msg {
        Message::FileChunk(chunk) => {
            if chunk.total_chunks == 0 || chunk.chunk_index >= chunk.total_chunks {
                tracing::warn!(
                    "Invalid chunk index {}/{}",
                    chunk.chunk_index,
                    chunk.total_chunks
                );
                return Ok(());
            }

            // Decompress if needed
            let data = if chunk.compressed {
                zstd::bulk::decompress(&chunk.data, crate::transfer::chunker::CHUNK_SIZE * 2)
                    .map_err(|e| anyhow!("Decompression failed: {}", e))?
            } else {
                chunk.data
            };

            // Verify hash against the original (uncompressed) data
            crate::crypto::verify::verify_chunk(&data, &chunk.blake3_hash)?;

            let mut app = state.lock().await;

            if app.pipe_mode {
                use std::io::Write;
                // On Windows, stdout defaults to text mode which converts \n to \r\n.
                // This corrupts binary data, so we switch to binary mode.
                #[cfg(windows)]
                {
                    use std::os::windows::io::AsRawHandle;
                    extern "C" {
                        fn _setmode(fd: i32, mode: i32) -> i32;
                    }
                    unsafe {
                        _setmode(std::io::stdout().as_raw_handle() as i32, 0x8000);
                    }
                }
                let mut stdout = std::io::stdout().lock();
                stdout.write_all(&data)?;
            } else {
                // Sanitize file_name to prevent path traversal attacks
                let safe_name = sanitize_file_name(&chunk.file_name);
                let output_path = app.output_dir.join(&safe_name);

                // Verify the resolved path stays within output_dir
                if let Ok(canon_dir) = std::fs::canonicalize(&app.output_dir) {
                    if let Some(parent) = output_path.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    let part_path = output_path.with_extension("part");
                    if let Ok(canon_part) =
                        std::fs::canonicalize(part_path.parent().unwrap_or(&app.output_dir))
                    {
                        if !canon_part.starts_with(&canon_dir) {
                            return Err(anyhow!("Path traversal blocked: {}", chunk.file_name));
                        }
                    }

                    // Validate chunk index won't cause overflow
                    let offset = chunk
                        .chunk_index
                        .checked_mul(crate::transfer::chunker::CHUNK_SIZE as u64)
                        .ok_or_else(|| anyhow!("Chunk index overflow"))?;

                    use std::io::{Seek, Write};
                    let mut file = std::fs::OpenOptions::new()
                        .create(true)
                        .truncate(false)
                        .write(true)
                        .open(&part_path)?;

                    file.seek(std::io::SeekFrom::Start(offset))?;
                    file.write_all(&data)?;
                }
            }

            app.transfer_manager.update_chunk_received(
                &chunk.file_name,
                chunk.chunk_index,
                chunk.total_chunks,
                data.len() as u64,
            );
        }
        Message::TransferComplete(complete) => {
            let mut app = state.lock().await;
            let safe_name = sanitize_file_name(&complete.file_name);
            let output_path = app.output_dir.join(&safe_name);
            let part_path = output_path.with_extension("part");

            if !app.pipe_mode && !complete.blake3_hash.is_empty() && part_path.exists() {
                // Single file with hash — verify before finalizing
                match crate::crypto::verify::hash_file(&part_path) {
                    Ok(actual_hash) => {
                        if actual_hash == complete.blake3_hash {
                            if let Err(e) = std::fs::rename(&part_path, &output_path) {
                                app.transfer_manager.mark_failed(&complete.file_name);
                                app.status_message = Some(format!(
                                    "Download failed: could not finalize {}: {}",
                                    complete.file_name, e
                                ));
                                return Ok(());
                            }
                            app.transfer_manager.mark_complete(&complete.file_name);
                            app.status_message =
                                Some(format!("Download complete: {}", complete.file_name));
                        } else {
                            let _ = std::fs::remove_file(&part_path);
                            app.transfer_manager.mark_failed(&complete.file_name);
                            app.status_message = Some(format!(
                                "Download failed: file corrupted — {}",
                                complete.file_name
                            ));
                        }
                    }
                    Err(e) => {
                        let _ = std::fs::remove_file(&part_path);
                        app.transfer_manager.mark_failed(&complete.file_name);
                        app.status_message = Some(format!(
                            "Download failed: could not verify {}: {}",
                            complete.file_name, e
                        ));
                    }
                }
            } else {
                // Pipe mode, directory completion, or no .part file
                app.transfer_manager.mark_complete(&complete.file_name);
                app.status_message = Some(format!("Download complete: {}", complete.file_name));
            }
        }
        Message::Error(err) => {
            let mut app = state.lock().await;
            app.status_message = Some(format!("Error from host: {}", err.message));
        }
        _ => {}
    }
    Ok(())
}

/// Maximum frame size we'll accept (256 MB). Prevents memory exhaustion from
/// malicious peers sending huge length prefixes.
pub const MAX_FRAME_SIZE: usize = 256 * 1024 * 1024;

/// Sanitize a file name from a remote peer to prevent path traversal.
/// Strips leading slashes, ".." components, absolute path prefixes,
/// null bytes, and characters that are invalid on Windows.
fn sanitize_file_name(name: &str) -> String {
    // Strip null bytes which could trick path resolution
    let name = name.replace('\0', "");

    // Split on both / and \ so Windows-originated paths are handled
    let mut parts: Vec<String> = Vec::new();
    for component in name.split(&['/', '\\'][..]) {
        match component {
            "" | "." | ".." => continue,
            c => {
                // Strip Windows drive letter prefixes (e.g. "C:")
                let c = if c.len() >= 2
                    && c.as_bytes()[1] == b':'
                    && c.as_bytes()[0].is_ascii_alphabetic()
                {
                    &c[2..]
                } else {
                    c
                };
                if c.is_empty() {
                    continue;
                }
                // Strip characters that are invalid on Windows filesystems
                let cleaned: String = c
                    .chars()
                    .filter(|ch| !matches!(ch, ':' | '*' | '?' | '"' | '<' | '>' | '|'))
                    .collect();
                if !cleaned.is_empty() {
                    parts.push(cleaned);
                }
            }
        }
    }
    if parts.is_empty() {
        "unnamed".to_string()
    } else {
        // Always use forward slashes in output paths (OS-native join happens at write time)
        parts.join("/")
    }
}

/// Ring terminal bell and attempt desktop notification on transfer completion.
/// `bell` controls whether the audible BEL character is emitted.
/// `desktop` controls whether a desktop notification is sent.
pub fn notify_completion(bell: bool, desktop: bool) {
    if bell {
        eprint!("\x07");
    }

    if !desktop {
        return;
    }

    std::thread::spawn(|| {
        send_desktop_notification("Snag", "All downloads complete");
    });
}

/// Send a desktop notification using the platform's native mechanism.
fn send_desktop_notification(title: &str, body: &str) {
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("notify-send")
            .args([
                "--expire-time=5000",
                "--hint=string:x-dunst-stack-tag:snag",
                "--replace-id=99271",
                title,
                body,
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }

    #[cfg(target_os = "macos")]
    {
        // Escape AppleScript string characters
        let title = title.replace('\\', "\\\\").replace('"', "\\\"");
        let body = body.replace('\\', "\\\\").replace('"', "\\\"");
        let script = format!("display notification \"{}\" with title \"{}\"", body, title);
        let _ = std::process::Command::new("osascript")
            .args(["-e", &script])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }

    #[cfg(target_os = "windows")]
    {
        let script = format!(
            "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null; \
             $xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent(0); \
             $text = $xml.GetElementsByTagName('text'); \
             $text.Item(0).AppendChild($xml.CreateTextNode('{}: {}')) > $null; \
             $toast = [Windows.UI.Notifications.ToastNotification]::new($xml); \
             [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('snag').Show($toast)",
            title, body
        );
        let _ = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", &script])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

/// Check for existing .part files and return resume entries so the sender
/// can skip chunks the receiver already has.
fn build_resume_entries(
    file_names: &[String],
    output_dir: &std::path::Path,
) -> Vec<messages::ResumeEntry> {
    let mut entries = Vec::new();
    for name in file_names {
        let part_path = output_dir.join(name).with_extension("part");
        if let Ok(meta) = std::fs::metadata(&part_path) {
            let bytes = meta.len();
            if bytes > 0 {
                entries.push(messages::ResumeEntry {
                    file_name: name.clone(),
                    bytes_received: bytes,
                });
            }
        }
    }
    entries
}

/// Custom certificate verifier that skips TLS verification
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}
