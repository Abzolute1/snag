use anyhow::{anyhow, Result};

use crate::protocol::messages::{self, Message};

/// Encrypted message stream wrapping a Noise TransportState
pub struct EncryptedStream {
    transport: snow::TransportState,
    read_buf: Vec<u8>,
}

impl EncryptedStream {
    pub fn new(transport: snow::TransportState) -> Self {
        Self {
            transport,
            read_buf: vec![0u8; 65535],
        }
    }

    /// Encrypt and frame a message for sending
    pub fn encrypt_message(&mut self, msg: &Message) -> Result<Vec<u8>> {
        let plaintext = bincode::serialize(msg)?;

        let mut ciphertext = vec![0u8; plaintext.len() + 16]; // 16 bytes for AEAD tag
        let len = self
            .transport
            .write_message(&plaintext, &mut ciphertext)
            .map_err(|e| anyhow!("Noise encrypt failed: {}", e))?;
        ciphertext.truncate(len);

        // Frame with length prefix
        let frame_len = (len as u32).to_be_bytes();
        let mut frame = Vec::with_capacity(4 + len);
        frame.extend_from_slice(&frame_len);
        frame.extend_from_slice(&ciphertext[..len]);

        Ok(frame)
    }

    /// Decrypt a received frame
    pub fn decrypt_message(&mut self, ciphertext: &[u8]) -> Result<Message> {
        let len = self
            .transport
            .read_message(ciphertext, &mut self.read_buf)
            .map_err(|e| anyhow!("Noise decrypt failed: {}", e))?;

        let msg: Message = bincode::deserialize(&self.read_buf[..len])?;
        Ok(msg)
    }

    /// Try to decrypt a length-prefixed frame from a buffer.
    /// Returns (message, bytes_consumed) or None if incomplete.
    pub fn try_decrypt_frame(&mut self, buf: &[u8]) -> Result<Option<(Message, usize)>> {
        if buf.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if buf.len() < 4 + len {
            return Ok(None);
        }

        let msg = self.decrypt_message(&buf[4..4 + len])?;
        Ok(Some((msg, 4 + len)))
    }
}

/// Unencrypted stream for pre-handshake communication (SPAKE2 exchange)
pub struct PlaintextStream;

impl PlaintextStream {
    /// Frame a message with length prefix (no encryption)
    pub fn frame_message(msg: &Message) -> Result<Vec<u8>> {
        messages::encode_message(msg)
    }

    /// Try to read a framed message from buffer
    pub fn try_read_frame(buf: &[u8]) -> Option<(Message, usize)> {
        messages::try_decode_message(buf)
    }
}
