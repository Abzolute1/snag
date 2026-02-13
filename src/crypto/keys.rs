use anyhow::{anyhow, Result};
use hkdf::Hkdf;
use sha2::Sha256;

/// Derive multiple keys from a master secret using HKDF
pub struct DerivedKeys {
    /// Key for encrypting data in transit
    pub data_key: [u8; 32],
}

impl DerivedKeys {
    /// Derive keys from a SPAKE2 shared secret
    pub fn from_shared_secret(secret: &[u8]) -> Result<Self> {
        let hkdf = Hkdf::<Sha256>::new(Some(b"peershare-keys-v1"), secret);

        let mut data_key = [0u8; 32];

        hkdf.expand(b"data-encryption", &mut data_key)
            .map_err(|_| anyhow!("Failed to derive data key"))?;

        Ok(Self { data_key })
    }
}

/// Generate a self-signed certificate for QUIC
pub fn generate_self_signed_cert() -> Result<(
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    let cert = rcgen::generate_simple_self_signed(vec!["peershare.local".to_string()])
        .map_err(|e| anyhow!("Failed to generate certificate: {}", e))?;

    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()),
    );

    Ok((cert_der, key_der))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation() {
        let secret = vec![42u8; 32];
        let keys = DerivedKeys::from_shared_secret(&secret).unwrap();
        assert_eq!(keys.data_key.len(), 32);
    }

    #[test]
    fn test_deterministic_derivation() {
        let secret = vec![42u8; 32];
        let keys1 = DerivedKeys::from_shared_secret(&secret).unwrap();
        let keys2 = DerivedKeys::from_shared_secret(&secret).unwrap();
        assert_eq!(keys1.data_key, keys2.data_key);
    }

    #[test]
    fn test_self_signed_cert() {
        let (cert, key) = generate_self_signed_cert().unwrap();
        assert!(!cert.is_empty());
        match &key {
            rustls::pki_types::PrivateKeyDer::Pkcs8(k) => {
                assert!(!k.secret_pkcs8_der().is_empty())
            }
            _ => panic!("Expected PKCS8 key"),
        }
    }
}
