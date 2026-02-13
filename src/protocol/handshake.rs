use anyhow::{anyhow, Result};
use hkdf::Hkdf;
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};

/// Perform the SPAKE2 key exchange (initiator side - host)
pub fn spake2_start_host(password: &str) -> Result<(Vec<u8>, spake2::Spake2<Ed25519Group>)> {
    let (state, outbound) = Spake2::<Ed25519Group>::start_a(
        &Password::new(password.as_bytes()),
        &Identity::new(b"peershare-host"),
        &Identity::new(b"peershare-fetch"),
    );
    Ok((outbound.to_vec(), state))
}

/// Perform the SPAKE2 key exchange (responder side - fetcher)
pub fn spake2_start_fetch(password: &str) -> Result<(Vec<u8>, spake2::Spake2<Ed25519Group>)> {
    let (state, outbound) = Spake2::<Ed25519Group>::start_b(
        &Password::new(password.as_bytes()),
        &Identity::new(b"peershare-host"),
        &Identity::new(b"peershare-fetch"),
    );
    Ok((outbound.to_vec(), state))
}

/// Complete the SPAKE2 exchange and derive the shared secret
pub fn spake2_finish(state: spake2::Spake2<Ed25519Group>, inbound_msg: &[u8]) -> Result<Vec<u8>> {
    let shared_key = state
        .finish(inbound_msg)
        .map_err(|_| anyhow!("SPAKE2 key exchange failed - wrong share code?"))?;
    Ok(shared_key.to_vec())
}

/// Derive a Noise PSK from the SPAKE2 shared secret using HKDF
pub fn derive_noise_psk(spake_secret: &[u8]) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(Some(b"peershare-noise-psk"), spake_secret);
    let mut psk = [0u8; 32];
    hkdf.expand(b"noise-psk", &mut psk)
        .map_err(|_| anyhow!("HKDF expand failed"))?;
    Ok(psk)
}

/// Build a Noise initiator (host) with the PSK
pub fn noise_initiator(psk: &[u8; 32]) -> Result<snow::HandshakeState> {
    let params: snow::params::NoiseParams = "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s".parse()?;
    let keypair = snow::Builder::new(params.clone())
        .generate_keypair()
        .map_err(|e| anyhow!("Failed to generate Noise keypair: {}", e))?;
    let state = snow::Builder::new(params)
        .local_private_key(&keypair.private)
        .psk(3, psk)
        .build_initiator()
        .map_err(|e| anyhow!("Failed to build Noise initiator: {}", e))?;
    Ok(state)
}

/// Build a Noise responder (fetcher) with the PSK
pub fn noise_responder(psk: &[u8; 32]) -> Result<snow::HandshakeState> {
    let params: snow::params::NoiseParams = "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s".parse()?;
    let keypair = snow::Builder::new(params.clone())
        .generate_keypair()
        .map_err(|e| anyhow!("Failed to generate Noise keypair: {}", e))?;
    let state = snow::Builder::new(params)
        .local_private_key(&keypair.private)
        .psk(3, psk)
        .build_responder()
        .map_err(|e| anyhow!("Failed to build Noise responder: {}", e))?;
    Ok(state)
}

/// Perform the Noise XX handshake as initiator using raw message buffers.
/// Returns a list of messages to send and expects messages from the peer.
///
/// Initiator pattern:
///   → e
///   ← e, ee, s, es
///   → s, se, psk
pub struct NoiseHandshaker {
    state: snow::HandshakeState,
    buf: Vec<u8>,
}

impl NoiseHandshaker {
    pub fn new(state: snow::HandshakeState) -> Self {
        Self {
            state,
            buf: vec![0u8; 65535],
        }
    }

    /// Write the next handshake message (our turn to send)
    pub fn write_message(&mut self) -> Result<Vec<u8>> {
        let len = self
            .state
            .write_message(&[], &mut self.buf)
            .map_err(|e| anyhow!("Noise write_message failed: {}", e))?;
        Ok(self.buf[..len].to_vec())
    }

    /// Read a handshake message from the peer
    pub fn read_message(&mut self, msg: &[u8]) -> Result<()> {
        self.state
            .read_message(msg, &mut self.buf)
            .map_err(|e| anyhow!("Noise read_message failed: {}", e))?;
        Ok(())
    }

    /// Check if the handshake is complete
    pub fn is_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// Convert to transport mode after handshake completes
    pub fn into_transport(self) -> Result<snow::TransportState> {
        self.state
            .into_transport_mode()
            .map_err(|e| anyhow!("Failed to enter transport mode: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spake2_roundtrip() {
        let password = "fox-rain-lamp";

        let (msg_a, state_a) = spake2_start_host(password).unwrap();
        let (msg_b, state_b) = spake2_start_fetch(password).unwrap();

        let key_a = spake2_finish(state_a, &msg_b).unwrap();
        let key_b = spake2_finish(state_b, &msg_a).unwrap();

        assert_eq!(key_a, key_b);
    }

    #[test]
    fn test_spake2_wrong_password() {
        let (msg_a, state_a) = spake2_start_host("correct-password").unwrap();
        let (msg_b, state_b) = spake2_start_fetch("wrong-password").unwrap();

        let key_a = spake2_finish(state_a, &msg_b).unwrap();
        let key_b = spake2_finish(state_b, &msg_a).unwrap();

        // Keys should NOT match with wrong passwords
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn test_derive_noise_psk() {
        let secret = vec![0u8; 32];
        let psk = derive_noise_psk(&secret).unwrap();
        assert_eq!(psk.len(), 32);

        let psk2 = derive_noise_psk(&secret).unwrap();
        assert_eq!(psk, psk2);
    }

    #[test]
    fn test_noise_handshake_full() {
        let psk = [42u8; 32];
        let initiator = noise_initiator(&psk).unwrap();
        let responder = noise_responder(&psk).unwrap();

        let mut init = NoiseHandshaker::new(initiator);
        let mut resp = NoiseHandshaker::new(responder);

        // → e
        let msg1 = init.write_message().unwrap();
        resp.read_message(&msg1).unwrap();

        // ← e, ee, s, es
        let msg2 = resp.write_message().unwrap();
        init.read_message(&msg2).unwrap();

        // → s, se, psk
        let msg3 = init.write_message().unwrap();
        resp.read_message(&msg3).unwrap();

        assert!(init.is_finished());
        assert!(resp.is_finished());

        let mut init_transport = init.into_transport().unwrap();
        let mut resp_transport = resp.into_transport().unwrap();

        // Test encrypted communication
        let mut buf = vec![0u8; 1024];
        let len = init_transport.write_message(b"hello", &mut buf).unwrap();
        let mut dec_buf = vec![0u8; 1024];
        let dec_len = resp_transport
            .read_message(&buf[..len], &mut dec_buf)
            .unwrap();
        assert_eq!(&dec_buf[..dec_len], b"hello");
    }
}
