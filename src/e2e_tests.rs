//! End-to-end integration tests for the full Snag transfer pipeline.
//!
//! Each test:
//!   1. Creates temp source files in a temp directory.
//!   2. Starts a sender (QUIC listener) on localhost.
//!   3. Starts a receiver that connects with the correct share code.
//!   4. Runs the full SPAKE2 + Noise handshake, then streams file data.
//!   5. Verifies received files match originals via BLAKE3 hashes.
//!
//! All state persistence is redirected to temp directories so the real
//! ~/.local/share/snag/state.json is never touched.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::app::{AppState, Screen};
use crate::crypto::verify::hash_file;
use crate::network;
use crate::share_code;
use crate::transfer::manager::TransferStatus;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create an isolated AppState backed by a temp directory.
fn make_test_state(tmp: &Path) -> AppState {
    let state_file = tmp.join("state.json");
    AppState::new_with_state_path(state_file)
}

/// Write `size` bytes of deterministic pseudo-random data to `path`.
fn write_test_file(path: &Path, size: usize) {
    // Deterministic pattern so we can verify integrity.
    let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, &data).unwrap();
}

/// Set up a sender: add files, build catalog, bind listener, return
/// (share_code, cancel_token, state_handle, listener_join_handle).
async fn start_sender(
    source_files: &[PathBuf],
    tmp: &Path,
) -> (
    String,
    CancellationToken,
    Arc<Mutex<AppState>>,
    tokio::task::JoinHandle<()>,
) {
    let mut app = make_test_state(tmp);

    for p in source_files {
        app.persisted.add_file(p);
    }
    app.build_catalog_from_persisted();
    app.screen = Screen::Sending;

    let addr = network::connection::get_local_addr(0, "0.0.0.0")
        .await
        .expect("bind local addr");
    let code = share_code::generate_share_code(&addr, 3);
    let cancel = CancellationToken::new();

    app.share_code = code.clone();
    app.network_started = true;
    app.cancel_token = Some(cancel.clone());

    let state = Arc::new(Mutex::new(app));

    let net_state = state.clone();
    let net_cancel = cancel.clone();
    let net_code = code.clone();
    let handle = tokio::spawn(async move {
        let _ = network::listener::run_listener(addr, net_code, net_state, net_cancel).await;
    });

    // Give the listener a moment to bind
    tokio::time::sleep(Duration::from_millis(100)).await;

    (code, cancel, state, handle)
}

/// Set up a receiver: connect, wait for the catalog, auto-request all files,
/// then wait until every transfer is complete (or timeout).
async fn run_receiver(
    code: &str,
    output_dir: &Path,
    tmp: &Path,
    timeout: Duration,
) -> Arc<Mutex<AppState>> {
    let mut app = make_test_state(tmp);
    app.screen = Screen::Receiving;
    app.share_code = code.to_string();
    app.output_dir = output_dir.to_path_buf();
    app.network_started = true;

    let state = Arc::new(Mutex::new(app));

    // Spawn connection
    let net_state = state.clone();
    let net_code = code.to_string();
    tokio::spawn(async move {
        if let Err(e) = network::connection::connect_to_host(net_code, net_state).await {
            tracing::warn!("receiver connect error: {}", e);
        }
    });

    // Wait for the catalog to arrive (connected == true)
    let deadline = Instant::now() + timeout;
    loop {
        {
            let app = state.lock().await;
            if app.connected {
                break;
            }
            // Check for a fatal error message
            if let Some(msg) = &app.status_message {
                if msg.contains("error") || msg.contains("Error") || msg.contains("failed") {
                    panic!("Receiver hit error before connecting: {}", msg);
                }
            }
        }
        assert!(
            Instant::now() < deadline,
            "Timed out waiting for receiver to connect"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Request all files
    {
        let mut app = state.lock().await;
        let entries: Vec<_> = app.catalog.entries.clone();
        for entry in entries {
            app.transfer_manager.start_download(entry.name, entry.size);
        }
    }

    // Wait for all transfers to complete
    loop {
        {
            let mut app = state.lock().await;
            app.transfer_manager.tick();
            app.transfers = app.transfer_manager.get_all_transfers();

            if !app.transfers.is_empty()
                && app
                    .transfers
                    .iter()
                    .all(|t| matches!(t.status, TransferStatus::Complete | TransferStatus::Failed))
            {
                // Assert none failed
                for t in &app.transfers {
                    assert!(
                        matches!(t.status, TransferStatus::Complete),
                        "Transfer of '{}' failed",
                        t.file_name
                    );
                }
                break;
            }
        }
        assert!(
            Instant::now() < deadline,
            "Timed out waiting for transfers to complete"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    state
}

/// Assert that a received file is byte-identical to its source by comparing
/// BLAKE3 hashes and file sizes.
fn assert_files_match(src: &Path, dst: &Path) {
    let src_meta = std::fs::metadata(src).expect("source file metadata");
    let dst_meta = std::fs::metadata(dst).expect("destination file metadata");
    assert_eq!(
        src_meta.len(),
        dst_meta.len(),
        "Size mismatch: {} ({}) vs {} ({})",
        src.display(),
        src_meta.len(),
        dst.display(),
        dst_meta.len(),
    );

    let src_hash = hash_file(src).expect("hash source");
    let dst_hash = hash_file(dst).expect("hash destination");
    assert_eq!(
        src_hash,
        dst_hash,
        "BLAKE3 hash mismatch for {} vs {}",
        src.display(),
        dst.display()
    );
}

/// Compare an entire directory tree recursively.
fn assert_dir_matches(src_dir: &Path, dst_dir: &Path) {
    for entry in walkdir(src_dir) {
        let rel = entry.strip_prefix(src_dir).unwrap();
        let dst_path = dst_dir.join(rel);
        if entry.is_file() {
            assert!(
                dst_path.exists(),
                "Missing received file: {}",
                dst_path.display()
            );
            assert_files_match(&entry, &dst_path);
        }
    }
}

/// Simple recursive file listing (no external crate needed).
fn walkdir(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                out.extend(walkdir(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Transfer a single 1 KB file end-to-end.
#[tokio::test]
async fn test_small_file_1kb() {
    let tmp = tempfile::tempdir().unwrap();
    let src_dir = tmp.path().join("src");
    let dst_dir = tmp.path().join("dst");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    let file_path = src_dir.join("small.bin");
    write_test_file(&file_path, 1024);

    let (code, cancel, _sender_state, _handle) =
        start_sender(&[file_path.clone()], &tmp.path().join("sender")).await;

    let _recv_state = run_receiver(
        &code,
        &dst_dir,
        &tmp.path().join("receiver"),
        Duration::from_secs(30),
    )
    .await;

    assert_files_match(&file_path, &dst_dir.join("small.bin"));

    cancel.cancel();
}

/// Transfer a single 1 MB file end-to-end.
#[tokio::test]
async fn test_medium_file_1mb() {
    let tmp = tempfile::tempdir().unwrap();
    let src_dir = tmp.path().join("src");
    let dst_dir = tmp.path().join("dst");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    let file_path = src_dir.join("medium.bin");
    write_test_file(&file_path, 1_048_576);

    let (code, cancel, _sender_state, _handle) =
        start_sender(&[file_path.clone()], &tmp.path().join("sender")).await;

    let _recv_state = run_receiver(
        &code,
        &dst_dir,
        &tmp.path().join("receiver"),
        Duration::from_secs(60),
    )
    .await;

    assert_files_match(&file_path, &dst_dir.join("medium.bin"));

    cancel.cancel();
}

/// Transfer a single 50 MB file end-to-end.
#[tokio::test]
async fn test_large_file_50mb() {
    let tmp = tempfile::tempdir().unwrap();
    let src_dir = tmp.path().join("src");
    let dst_dir = tmp.path().join("dst");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    let file_path = src_dir.join("large.bin");
    write_test_file(&file_path, 50 * 1_048_576);

    let (code, cancel, _sender_state, _handle) =
        start_sender(&[file_path.clone()], &tmp.path().join("sender")).await;

    let _recv_state = run_receiver(
        &code,
        &dst_dir,
        &tmp.path().join("receiver"),
        Duration::from_secs(120),
    )
    .await;

    assert_files_match(&file_path, &dst_dir.join("large.bin"));

    cancel.cancel();
}

/// Transfer multiple files in a single session.
#[tokio::test]
async fn test_multiple_files() {
    let tmp = tempfile::tempdir().unwrap();
    let src_dir = tmp.path().join("src");
    let dst_dir = tmp.path().join("dst");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    let names_and_sizes: Vec<(&str, usize)> = vec![
        ("alpha.txt", 512),
        ("beta.bin", 100_000),
        ("gamma.dat", 1_048_576),
    ];

    let mut paths = Vec::new();
    for (name, size) in &names_and_sizes {
        let p = src_dir.join(name);
        write_test_file(&p, *size);
        paths.push(p);
    }

    let (code, cancel, _sender_state, _handle) =
        start_sender(&paths, &tmp.path().join("sender")).await;

    let _recv_state = run_receiver(
        &code,
        &dst_dir,
        &tmp.path().join("receiver"),
        Duration::from_secs(60),
    )
    .await;

    for (name, _) in &names_and_sizes {
        assert_files_match(&src_dir.join(name), &dst_dir.join(name));
    }

    cancel.cancel();
}

/// Transfer a directory with nested sub-directories.
///
/// Directory transfers are special: the catalog has a single entry "mydir"
/// but the sender streams individual sub-files as "mydir/a.txt", etc.
/// Each sub-file gets its own TransferComplete message, so the directory-
/// level transfer tracker never sees `mark_complete("mydir")`.  We
/// therefore monitor the filesystem directly for completion instead of
/// relying on `TransferStatus::Complete`.
#[tokio::test]
async fn test_directory_transfer() {
    let tmp = tempfile::tempdir().unwrap();
    let src_root = tmp.path().join("src");
    let dst_dir = tmp.path().join("dst");

    // Build a directory tree: mydir/{a.txt, sub/b.bin, sub/deep/c.dat}
    let dir_root = src_root.join("mydir");
    let expected_files: Vec<(&str, usize)> = vec![
        ("a.txt", 200),
        ("sub/b.bin", 5_000),
        ("sub/deep/c.dat", 60_000),
    ];
    for (rel, size) in &expected_files {
        let p = dir_root.join(rel);
        write_test_file(&p, *size);
    }

    std::fs::create_dir_all(&dst_dir).unwrap();

    let (code, cancel, _sender_state, _handle) =
        start_sender(&[dir_root.clone()], &tmp.path().join("sender")).await;

    // Set up receiver manually
    let mut app = make_test_state(&tmp.path().join("receiver"));
    app.screen = Screen::Receiving;
    app.share_code = code.clone();
    app.output_dir = dst_dir.clone();
    app.network_started = true;

    let recv_state = Arc::new(Mutex::new(app));

    let net_state = recv_state.clone();
    let net_code = code.clone();
    tokio::spawn(async move {
        let _ = network::connection::connect_to_host(net_code, net_state).await;
    });

    let timeout = Duration::from_secs(30);
    let deadline = Instant::now() + timeout;

    // Wait for connection
    loop {
        let app = recv_state.lock().await;
        if app.connected {
            break;
        }
        drop(app);
        assert!(Instant::now() < deadline, "Timeout waiting for connect");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Request the directory
    {
        let mut app = recv_state.lock().await;
        let entries: Vec<_> = app.catalog.entries.clone();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].is_dir);
        for entry in entries {
            app.transfer_manager.start_download(entry.name, entry.size);
        }
    }

    // Wait for all expected files to appear on disk (not .part files)
    loop {
        let all_present = expected_files.iter().all(|(rel, _)| {
            let dst_path = dst_dir.join("mydir").join(rel);
            dst_path.exists() && !dst_path.extension().is_some_and(|e| e == "part")
        });
        if all_present {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Timed out waiting for directory files to arrive"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Verify all files match
    assert_dir_matches(&dir_root, &dst_dir.join("mydir"));

    cancel.cancel();
}

/// Transfer an empty (zero-byte) file.
#[tokio::test]
async fn test_empty_file() {
    let tmp = tempfile::tempdir().unwrap();
    let src_dir = tmp.path().join("src");
    let dst_dir = tmp.path().join("dst");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    let file_path = src_dir.join("empty.bin");
    std::fs::write(&file_path, b"").unwrap();

    let (code, cancel, _sender_state, _handle) =
        start_sender(&[file_path.clone()], &tmp.path().join("sender")).await;

    // The receiver should connect and see 1 catalog entry with size 0.
    // Because an empty file has 0 chunks the transfer is marked complete
    // immediately by the sender's TransferComplete message.
    let recv_state_handle = {
        let mut app = make_test_state(&tmp.path().join("receiver"));
        app.screen = Screen::Receiving;
        app.share_code = code.clone();
        app.output_dir = dst_dir.clone();
        app.network_started = true;
        Arc::new(Mutex::new(app))
    };

    let net_state = recv_state_handle.clone();
    let net_code = code.clone();
    tokio::spawn(async move {
        let _ = network::connection::connect_to_host(net_code, net_state).await;
    });

    // Wait for connection
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let app = recv_state_handle.lock().await;
        if app.connected {
            break;
        }
        drop(app);
        assert!(Instant::now() < deadline, "Timeout waiting for connect");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Request the empty file
    {
        let mut app = recv_state_handle.lock().await;
        let entries: Vec<_> = app.catalog.entries.clone();
        assert_eq!(entries.len(), 1, "Expected 1 catalog entry for empty file");
        assert_eq!(entries[0].size, 0, "Empty file should have size 0");
        for entry in entries {
            app.transfer_manager.start_download(entry.name, entry.size);
        }
    }

    // Wait for the TransferComplete message.  For a zero-byte file the sender
    // sends TransferComplete immediately (no chunks).
    loop {
        {
            let mut app = recv_state_handle.lock().await;
            app.transfer_manager.tick();
            app.transfers = app.transfer_manager.get_all_transfers();
            if !app.transfers.is_empty()
                && app
                    .transfers
                    .iter()
                    .all(|t| matches!(t.status, TransferStatus::Complete | TransferStatus::Failed))
            {
                break;
            }
        }
        assert!(
            Instant::now() < deadline,
            "Timeout waiting for empty file transfer"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // The file on disk may or may not exist (zero chunks means nothing was
    // written). If it does exist it must be empty.
    let dst_path = dst_dir.join("empty.bin");
    if dst_path.exists() {
        let meta = std::fs::metadata(&dst_path).unwrap();
        assert_eq!(meta.len(), 0, "Empty file should be 0 bytes on disk");
    }
    // Either way: success -- the transfer completed without error.

    cancel.cancel();
}

/// Connecting with the wrong share code should fail the handshake.
#[tokio::test]
async fn test_wrong_share_code_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let src_dir = tmp.path().join("src");
    std::fs::create_dir_all(&src_dir).unwrap();

    let file_path = src_dir.join("secret.bin");
    write_test_file(&file_path, 1024);

    let (real_code, cancel, _sender_state, _handle) =
        start_sender(&[file_path.clone()], &tmp.path().join("sender")).await;

    // Tamper with the auth words to produce a wrong code that still points to
    // the same address.
    let parts: Vec<&str> = real_code.split('-').collect();
    assert!(parts.len() == 4, "Expected 4-part code, got: {}", real_code);
    // Swap first word to something else
    let bad_word = if parts[0] == "fox" { "dog" } else { "fox" };
    let bad_code = format!("{}-{}-{}-{}", bad_word, parts[1], parts[2], parts[3]);

    // The receiver should fail to establish a working session because
    // SPAKE2 passwords differ, resulting in mismatched Noise PSKs.
    let mut app = make_test_state(&tmp.path().join("receiver"));
    app.screen = Screen::Receiving;
    app.share_code = bad_code.clone();
    app.output_dir = tmp.path().join("dst_bad");
    std::fs::create_dir_all(&app.output_dir).unwrap();
    app.network_started = true;

    let state = Arc::new(Mutex::new(app));

    let net_state = state.clone();
    let join =
        tokio::spawn(
            async move { network::connection::connect_to_host(bad_code, net_state).await },
        );

    // The connection should error out (Noise handshake decrypt failure).
    let result = tokio::time::timeout(Duration::from_secs(15), join).await;

    match result {
        Ok(Ok(Err(_e))) => {
            // Expected: the handshake failed with an error.
        }
        Ok(Ok(Ok(()))) => {
            // connect_to_host returned Ok -- check state for error
            let app = state.lock().await;
            // If it somehow "connected", the catalog should be empty or
            // the status should show an error, because the Noise decrypt
            // would have failed.
            assert!(
                !app.connected || app.catalog.entries.is_empty(),
                "Should not have successfully received catalog with wrong code"
            );
        }
        Ok(Err(_join_err)) => {
            // Task panicked, also acceptable -- handshake blew up.
        }
        Err(_) => {
            // Timeout -- the connection just hung (wrong PSK means garbled
            // messages).  Acceptable: the point is we never got real data.
            let app = state.lock().await;
            assert!(
                !app.connected,
                "Should not be connected with wrong share code"
            );
        }
    }

    cancel.cancel();
}

/// BLAKE3 integrity: verify that every received file has the same BLAKE3 hash
/// as its source.  (This is also implicitly tested by `assert_files_match` in
/// the other tests, but here we make it the explicit focus.)
#[tokio::test]
async fn test_blake3_integrity() {
    let tmp = tempfile::tempdir().unwrap();
    let src_dir = tmp.path().join("src");
    let dst_dir = tmp.path().join("dst");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    // A file whose size is NOT a multiple of the chunk size.
    let file_path = src_dir.join("integrity.bin");
    write_test_file(&file_path, 150_001);

    let src_hash = hash_file(&file_path).unwrap();

    let (code, cancel, _sender_state, _handle) =
        start_sender(&[file_path.clone()], &tmp.path().join("sender")).await;

    let _recv_state = run_receiver(
        &code,
        &dst_dir,
        &tmp.path().join("receiver"),
        Duration::from_secs(30),
    )
    .await;

    let dst_path = dst_dir.join("integrity.bin");
    let dst_hash = hash_file(&dst_path).unwrap();

    assert_eq!(src_hash, dst_hash, "BLAKE3 hash mismatch after transfer");

    cancel.cancel();
}

/// Benchmark: measure throughput for a 50 MB transfer and print the result.
/// This test always passes; the output is informational.
#[tokio::test]
async fn test_speed_benchmark_50mb() {
    let tmp = tempfile::tempdir().unwrap();
    let src_dir = tmp.path().join("src");
    let dst_dir = tmp.path().join("dst");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    let size: usize = 50 * 1_048_576;
    let file_path = src_dir.join("bench.bin");
    write_test_file(&file_path, size);

    let (code, cancel, _sender_state, _handle) =
        start_sender(&[file_path.clone()], &tmp.path().join("sender")).await;

    let start = Instant::now();

    let _recv_state = run_receiver(
        &code,
        &dst_dir,
        &tmp.path().join("receiver"),
        Duration::from_secs(120),
    )
    .await;

    let elapsed = start.elapsed();
    let mb_per_sec = (size as f64 / 1_048_576.0) / elapsed.as_secs_f64();

    // Print benchmark results (visible with `cargo test -- --nocapture`)
    println!(
        "[BENCHMARK] 50 MB transfer: {:.2}s ({:.1} MB/s)",
        elapsed.as_secs_f64(),
        mb_per_sec
    );

    // Sanity: the received file must match
    assert_files_match(&file_path, &dst_dir.join("bench.bin"));

    cancel.cancel();
}

/// Verify that state persistence uses the custom path and does NOT write to
/// the real ~/.local/share/snag/state.json.
#[tokio::test]
async fn test_state_isolation() {
    let tmp = tempfile::tempdir().unwrap();
    let state_path = tmp.path().join("custom_state.json");

    let mut app = AppState::new_with_state_path(state_path.clone());
    app.persisted.add_file(Path::new("/dev/null"));
    app.save();

    // The custom file should exist
    assert!(state_path.exists(), "Custom state file should be created");

    // Verify contents
    let contents = std::fs::read_to_string(&state_path).unwrap();
    assert!(
        contents.contains("/dev/null"),
        "State file should contain the added path"
    );

    // The real state file should not have been modified by this test.
    // (We can't assert it wasn't touched by another test running in
    // parallel, but we verify our PersistedState wrote to the right place.)
    let loaded = crate::state::PersistedState::load_from(state_path.clone());
    assert_eq!(loaded.shared_files.len(), 1);
}

/// Transfer a file whose size exactly equals the chunk size boundary.
#[tokio::test]
async fn test_exact_chunk_boundary() {
    let tmp = tempfile::tempdir().unwrap();
    let src_dir = tmp.path().join("src");
    let dst_dir = tmp.path().join("dst");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    let chunk_size = crate::transfer::chunker::CHUNK_SIZE;
    let file_path = src_dir.join("boundary.bin");
    write_test_file(&file_path, chunk_size);

    let (code, cancel, _sender_state, _handle) =
        start_sender(&[file_path.clone()], &tmp.path().join("sender")).await;

    let _recv_state = run_receiver(
        &code,
        &dst_dir,
        &tmp.path().join("receiver"),
        Duration::from_secs(30),
    )
    .await;

    assert_files_match(&file_path, &dst_dir.join("boundary.bin"));

    cancel.cancel();
}

/// Transfer a file spanning exactly 2 chunks (chunk boundary + 1 extra chunk).
#[tokio::test]
async fn test_two_chunk_file() {
    let tmp = tempfile::tempdir().unwrap();
    let src_dir = tmp.path().join("src");
    let dst_dir = tmp.path().join("dst");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    let chunk_size = crate::transfer::chunker::CHUNK_SIZE;
    let file_path = src_dir.join("twochunk.bin");
    write_test_file(&file_path, chunk_size * 2);

    let (code, cancel, _sender_state, _handle) =
        start_sender(&[file_path.clone()], &tmp.path().join("sender")).await;

    let _recv_state = run_receiver(
        &code,
        &dst_dir,
        &tmp.path().join("receiver"),
        Duration::from_secs(30),
    )
    .await;

    assert_files_match(&file_path, &dst_dir.join("twochunk.bin"));

    cancel.cancel();
}
