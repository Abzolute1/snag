use anyhow::Result;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Track state for receiving a file
pub struct FileReceiver {
    pub file_name: String,
    pub output_path: PathBuf,
    pub total_chunks: u64,
    pub received_chunks: HashMap<u64, bool>,
    pub total_bytes_received: u64,
}

impl FileReceiver {
    pub fn new(file_name: String, output_dir: &Path, total_chunks: u64) -> Self {
        let output_path = output_dir.join(&file_name);
        Self {
            file_name,
            output_path,
            total_chunks,
            received_chunks: HashMap::new(),
            total_bytes_received: 0,
        }
    }

    /// Record that a chunk was received
    pub fn mark_chunk_received(&mut self, chunk_index: u64, bytes: u64) {
        self.received_chunks.insert(chunk_index, true);
        self.total_bytes_received += bytes;
    }

    /// Check if all chunks have been received
    pub fn is_complete(&self) -> bool {
        self.received_chunks.len() as u64 >= self.total_chunks
    }

    /// Get the progress as a fraction [0, 1]
    pub fn progress(&self) -> f64 {
        if self.total_chunks == 0 {
            return 1.0;
        }
        self.received_chunks.len() as f64 / self.total_chunks as f64
    }

    /// Get missing chunk indices for resume support
    pub fn missing_chunks(&self) -> Vec<u64> {
        (0..self.total_chunks)
            .filter(|i| !self.received_chunks.contains_key(i))
            .collect()
    }
}

/// Manage multiple file receivers
pub struct ReceiveManager {
    receivers: HashMap<String, FileReceiver>,
    output_dir: PathBuf,
}

impl ReceiveManager {
    pub fn new(output_dir: PathBuf) -> Self {
        Self {
            receivers: HashMap::new(),
            output_dir,
        }
    }

    /// Get or create a receiver for a file
    pub fn get_or_create(&mut self, file_name: &str, total_chunks: u64) -> &mut FileReceiver {
        self.receivers
            .entry(file_name.to_string())
            .or_insert_with(|| {
                FileReceiver::new(file_name.to_string(), &self.output_dir, total_chunks)
            })
    }

    /// Write a chunk to disk
    pub fn write_chunk(
        &mut self,
        file_name: &str,
        chunk_index: u64,
        total_chunks: u64,
        data: &[u8],
    ) -> Result<()> {
        let receiver = self.get_or_create(file_name, total_chunks);

        // Ensure parent directories exist
        if let Some(parent) = receiver.output_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Write chunk at correct offset
        use std::io::{Seek, Write};
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&receiver.output_path)?;

        let offset = chunk_index * crate::transfer::chunker::CHUNK_SIZE as u64;
        file.seek(std::io::SeekFrom::Start(offset))?;
        file.write_all(data)?;

        receiver.mark_chunk_received(chunk_index, data.len() as u64);
        Ok(())
    }

    /// Check if a file transfer is complete
    pub fn is_complete(&self, file_name: &str) -> bool {
        self.receivers
            .get(file_name)
            .map(|r| r.is_complete())
            .unwrap_or(false)
    }
}
