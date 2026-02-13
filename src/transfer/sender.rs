use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::app::AppState;
use crate::crypto::bulk::BulkCipher;
use crate::crypto::stream::EncryptedStream;
use crate::protocol::messages::{FileChunkMessage, Message, TransferCompleteMessage};
use crate::transfer::chunker::{self, FileChunker, CHUNK_SIZE};

/// Send a file to a peer in chunks.
/// `resume_map` contains per-file byte offsets to resume from (skip chunks before that point).
/// `compress` controls whether zstd compression is attempted on each chunk.
#[allow(clippy::too_many_arguments)]
pub async fn send_file(
    path: &Path,
    file_name: &str,
    peer_name: &str,
    state: &Arc<Mutex<AppState>>,
    encrypted: &mut EncryptedStream,
    bulk: &mut BulkCipher,
    send_stream: &mut quinn::SendStream,
    resume_map: &HashMap<String, u64>,
    compress: bool,
) -> Result<()> {
    if path.is_dir() {
        send_directory(
            path,
            file_name,
            peer_name,
            state,
            encrypted,
            bulk,
            send_stream,
            resume_map,
            compress,
        )
        .await
    } else {
        let resume_from = resume_map.get(file_name).copied().unwrap_or(0);
        send_single_file(
            path,
            file_name,
            peer_name,
            resume_from,
            state,
            encrypted,
            bulk,
            send_stream,
            compress,
        )
        .await
    }
}

#[allow(clippy::too_many_arguments)]
async fn send_single_file(
    path: &Path,
    file_name: &str,
    peer_name: &str,
    resume_from_bytes: u64,
    state: &Arc<Mutex<AppState>>,
    _encrypted: &mut EncryptedStream,
    bulk: &mut BulkCipher,
    send_stream: &mut quinn::SendStream,
    compress: bool,
) -> Result<()> {
    let mut chunker = FileChunker::new(path)?;
    // Clamp resume_from_bytes to actual file size
    let resume_from_bytes = resume_from_bytes.min(chunker.file_size());
    let total_chunks = chunker.total_chunks();
    let file_hash = crate::crypto::verify::hash_file(path)?;

    // Calculate which chunk to start from for resume
    let skip_chunks = if resume_from_bytes > 0 {
        resume_from_bytes / CHUNK_SIZE as u64
    } else {
        0
    };

    let mut chunks_since_update = 0u32;
    let mut total_sent_bytes = 0u64;

    while let Some(chunk) = chunker.next_chunk()? {
        // Skip chunks the receiver already has
        if chunk.index < skip_chunks {
            continue;
        }

        let (data, compressed) = if compress {
            compress_if_smaller(&chunk.data)
        } else {
            (chunk.data.clone(), false)
        };

        let chunk_msg = Message::FileChunk(FileChunkMessage {
            file_name: file_name.to_string(),
            chunk_index: chunk.index,
            total_chunks,
            data,
            blake3_hash: chunk.blake3_hash,
            compressed,
        });

        let plaintext = bincode::serialize(&chunk_msg)?;
        let frame = bulk.encrypt_frame(&plaintext)?;
        send_stream.write_all(&frame).await?;

        chunks_since_update += 1;
        total_sent_bytes += chunk.data.len() as u64;

        // Batch state updates: every 4 chunks or on last chunk
        if chunks_since_update >= 4 || chunk.index + 1 == total_chunks {
            let mut app = state.lock().await;
            app.transfer_manager
                .update_chunk_sent(peer_name, file_name, total_sent_bytes);
            total_sent_bytes = 0;
            chunks_since_update = 0;
        }
    }

    // TransferComplete — use bulk encryption too (it's just metadata)
    let complete_msg = Message::TransferComplete(TransferCompleteMessage {
        file_name: file_name.to_string(),
        total_bytes: std::fs::metadata(path)?.len(),
        blake3_hash: file_hash,
    });
    let plaintext = bincode::serialize(&complete_msg)?;
    let frame = bulk.encrypt_frame(&plaintext)?;
    send_stream.write_all(&frame).await?;

    {
        let mut app = state.lock().await;
        app.transfer_manager
            .mark_upload_complete(peer_name, file_name);
    }

    Ok(())
}

/// Compress data with zstd. Returns (data, true) if compression saved space,
/// or (original_data, false) if it didn't.
fn compress_if_smaller(data: &[u8]) -> (Vec<u8>, bool) {
    // Don't bother compressing tiny chunks
    if data.len() < 128 {
        return (data.to_vec(), false);
    }

    match zstd::bulk::compress(data, 3) {
        Ok(compressed) if compressed.len() < data.len() => (compressed, true),
        _ => (data.to_vec(), false),
    }
}

#[allow(clippy::too_many_arguments)]
async fn send_directory(
    dir: &Path,
    dir_name: &str,
    peer_name: &str,
    state: &Arc<Mutex<AppState>>,
    encrypted: &mut EncryptedStream,
    bulk: &mut BulkCipher,
    send_stream: &mut quinn::SendStream,
    resume_map: &HashMap<String, u64>,
    compress: bool,
) -> Result<()> {
    let files = chunker::collect_dir_files(dir)?;
    let mut total_bytes = 0u64;

    for (relative_path, full_path) in &files {
        let name = format!("{}/{}", dir_name, relative_path);
        total_bytes += std::fs::metadata(full_path).map(|m| m.len()).unwrap_or(0);
        let resume_from = resume_map.get(&name).copied().unwrap_or(0);
        send_single_file(
            full_path,
            &name,
            peer_name,
            resume_from,
            state,
            encrypted,
            bulk,
            send_stream,
            compress,
        )
        .await?;
    }

    // Directory-level TransferComplete
    let complete_msg = Message::TransferComplete(TransferCompleteMessage {
        file_name: dir_name.to_string(),
        total_bytes,
        blake3_hash: Vec::new(),
    });
    let plaintext = bincode::serialize(&complete_msg)?;
    let frame = bulk.encrypt_frame(&plaintext)?;
    send_stream.write_all(&frame).await?;

    {
        let mut app = state.lock().await;
        app.transfer_manager
            .mark_upload_complete(peer_name, dir_name);
    }

    Ok(())
}
