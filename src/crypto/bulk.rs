use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};

/// High-throughput bulk encryption using ChaCha20-Poly1305 directly.
///
/// Bypasses the Noise protocol's 65535-byte message limit for file data.
/// Keys are derived from the SPAKE2 shared secret (same root of trust as Noise).
/// Nonces increment monotonically to prevent reuse.
pub struct BulkCipher {
    cipher: ChaCha20Poly1305,
    nonce_counter: u64,
}

/// Frame type tag — the MSB of the 4-byte length prefix distinguishes
/// Noise-encrypted control frames from bulk-encrypted data frames.
pub const BULK_FLAG: u32 = 0x8000_0000;
pub const LENGTH_MASK: u32 = 0x7FFF_FFFF;

impl BulkCipher {
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        Self {
            cipher,
            nonce_counter: 0,
        }
    }

    /// Encrypt plaintext and return a framed message.
    /// Frame format: [4-byte length | BULK_FLAG][12-byte nonce][ciphertext + 16-byte tag]
    pub fn encrypt_frame(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.next_nonce();
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| anyhow!("Bulk encrypt failed: {}", e))?;

        let payload_len = 12 + ciphertext.len(); // nonce + ciphertext
        let tagged_len = (payload_len as u32) | BULK_FLAG;

        let mut frame = Vec::with_capacity(4 + payload_len);
        frame.extend_from_slice(&tagged_len.to_be_bytes());
        frame.extend_from_slice(nonce.as_slice());
        frame.extend_from_slice(&ciphertext);

        Ok(frame)
    }

    /// Decrypt a bulk payload (everything after the 4-byte length prefix).
    /// Input: [12-byte nonce][ciphertext + tag]
    pub fn decrypt_payload(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        if payload.len() < 12 {
            return Err(anyhow!("Bulk frame too short"));
        }
        let nonce = Nonce::from_slice(&payload[..12]);
        let plaintext = self
            .cipher
            .decrypt(nonce, &payload[12..])
            .map_err(|e| anyhow!("Bulk decrypt failed: {}", e))?;
        Ok(plaintext)
    }

    fn next_nonce(&mut self) -> Nonce {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&self.nonce_counter.to_be_bytes());
        self.nonce_counter += 1;
        *Nonce::from_slice(&nonce_bytes)
    }
}

/// Check if a length prefix indicates a bulk-encrypted frame
pub fn is_bulk_frame(len_bytes: [u8; 4]) -> bool {
    (u32::from_be_bytes(len_bytes) & BULK_FLAG) != 0
}

/// Extract the actual payload length from a bulk frame's length prefix
pub fn bulk_payload_len(len_bytes: [u8; 4]) -> usize {
    (u32::from_be_bytes(len_bytes) & LENGTH_MASK) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bulk_roundtrip() {
        let key = [42u8; 32];
        let mut enc = BulkCipher::new(&key);
        let mut dec = BulkCipher::new(&key);

        let plaintext = b"hello, this is a test of bulk encryption";
        let frame = enc.encrypt_frame(plaintext).unwrap();

        // Verify frame header has bulk flag
        let len_bytes = [frame[0], frame[1], frame[2], frame[3]];
        assert!(is_bulk_frame(len_bytes));

        let payload_len = bulk_payload_len(len_bytes);
        let decrypted = dec.decrypt_payload(&frame[4..4 + payload_len]).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_bulk_large_data() {
        let key = [99u8; 32];
        let mut enc = BulkCipher::new(&key);
        let mut dec = BulkCipher::new(&key);

        // 256KB of data — well beyond Noise's 65535 limit
        let data = vec![0xAB; 256 * 1024];
        let frame = enc.encrypt_frame(&data).unwrap();

        let len_bytes = [frame[0], frame[1], frame[2], frame[3]];
        let payload_len = bulk_payload_len(len_bytes);
        let decrypted = dec.decrypt_payload(&frame[4..4 + payload_len]).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_bulk_sequential_nonces() {
        let key = [7u8; 32];
        let mut enc = BulkCipher::new(&key);
        let mut dec = BulkCipher::new(&key);

        for i in 0..100u8 {
            let data = vec![i; 1000];
            let frame = enc.encrypt_frame(&data).unwrap();
            let len_bytes = [frame[0], frame[1], frame[2], frame[3]];
            let payload_len = bulk_payload_len(len_bytes);
            let decrypted = dec.decrypt_payload(&frame[4..4 + payload_len]).unwrap();
            assert_eq!(decrypted, data);
        }
    }

    #[test]
    fn test_wrong_key_fails() {
        let mut enc = BulkCipher::new(&[1u8; 32]);
        let mut dec = BulkCipher::new(&[2u8; 32]);

        let frame = enc.encrypt_frame(b"secret").unwrap();
        let len_bytes = [frame[0], frame[1], frame[2], frame[3]];
        let payload_len = bulk_payload_len(len_bytes);
        assert!(dec.decrypt_payload(&frame[4..4 + payload_len]).is_err());
    }
}
