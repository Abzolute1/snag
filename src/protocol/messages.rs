use serde::{Deserialize, Serialize};

/// Wire protocol message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    /// SPAKE2 key exchange message
    Spake(Vec<u8>),

    /// Noise handshake message
    NoiseHandshake(Vec<u8>),

    /// File catalog from host
    Catalog(CatalogMessage),

    /// Request to download specific files
    DownloadRequest(DownloadRequestMessage),

    /// A chunk of file data
    FileChunk(FileChunkMessage),

    /// Acknowledgement of received chunk
    ChunkAck(ChunkAckMessage),

    /// Transfer complete notification
    TransferComplete(TransferCompleteMessage),

    /// Error message
    Error(ErrorMessage),

    /// Ping/keepalive
    Ping,

    /// Pong response
    Pong,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogMessage {
    pub entries: Vec<CatalogEntryWire>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogEntryWire {
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
    pub blake3_hash: Option<Vec<u8>>,
    /// Child entries for directories (file listing for preview)
    #[serde(default)]
    pub children: Vec<CatalogChildWire>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogChildWire {
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadRequestMessage {
    pub file_names: Vec<String>,
    /// Byte offset to resume from (0 = start from beginning).
    /// The sender skips all chunks whose end offset <= this value.
    #[serde(default)]
    pub resume_from: Vec<ResumeEntry>,
}

/// Per-file resume information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResumeEntry {
    pub file_name: String,
    pub bytes_received: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChunkMessage {
    pub file_name: String,
    pub chunk_index: u64,
    pub total_chunks: u64,
    pub data: Vec<u8>,
    pub blake3_hash: Vec<u8>,
    /// Whether the data is zstd-compressed
    #[serde(default)]
    pub compressed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkAckMessage {
    pub file_name: String,
    pub chunk_index: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferCompleteMessage {
    pub file_name: String,
    pub total_bytes: u64,
    pub blake3_hash: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorMessage {
    pub code: u32,
    pub message: String,
}

/// Serialize a message to bytes with length prefix
pub fn encode_message(msg: &Message) -> anyhow::Result<Vec<u8>> {
    let payload = bincode::serialize(msg)?;
    let len = (payload.len() as u32).to_be_bytes();
    let mut buf = Vec::with_capacity(4 + payload.len());
    buf.extend_from_slice(&len);
    buf.extend_from_slice(&payload);
    Ok(buf)
}

/// Deserialize a message from bytes (without length prefix)
pub fn decode_message(data: &[u8]) -> anyhow::Result<Message> {
    Ok(bincode::deserialize(data)?)
}

/// Read a length-prefixed message from a buffer.
/// Returns (message, bytes_consumed) or None if buffer is incomplete.
pub fn try_decode_message(buf: &[u8]) -> Option<(Message, usize)> {
    if buf.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if buf.len() < 4 + len {
        return None;
    }
    let msg = bincode::deserialize(&buf[4..4 + len]).ok()?;
    Some((msg, 4 + len))
}
