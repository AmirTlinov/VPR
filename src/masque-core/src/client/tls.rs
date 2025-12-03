//! TLS/QUIC configuration for VPN client.
//!
//! # Security Design
//! - **NO INSECURE MODE**: All connections require valid certificate verification
//! - TLS 1.3 only for forward secrecy and modern cipher suites
//! - Support for custom CA certificates or system roots
//! - Certificate pinning via TOFU (Trust On First Use) optional
//!
//! # Certificate Validation
//! By default, certificates are validated against webpki system roots.
//! For self-hosted servers, provide a custom CA certificate via `ca_cert` parameter.

use anyhow::{bail, Context, Result};
use quinn::{ClientConfig as QuinnClientConfig, TransportConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use x509_parser::prelude::*;

use crate::tls_fingerprint::TlsProfile;

/// Certificate validation mode
#[derive(Debug, Clone)]
pub enum CertValidation {
    /// Use system CA roots (webpki-roots)
    SystemRoots,
    /// Use custom CA certificate file
    CustomCa(PathBuf),
    /// Pin to specific public key (TOFU - Trust On First Use)
    /// The bytes are the expected public key in DER format
    PublicKeyPin(Vec<u8>),
}

impl Default for CertValidation {
    fn default() -> Self {
        Self::SystemRoots
    }
}

/// Build QUIC client configuration with TLS fingerprinting support
///
/// # Security
/// All connections require valid certificate verification. There is no insecure mode.
/// Use `CertValidation::CustomCa` for self-signed server certificates or
/// `CertValidation::PublicKeyPin` for TOFU-style pinning.
///
/// # Arguments
/// * `idle_timeout` - QUIC idle timeout in seconds
/// * `tls_profile` - TLS fingerprint profile for anti-DPI
/// * `cert_validation` - Certificate validation mode
///
/// # Errors
/// Returns error if certificate cannot be loaded or validated
pub fn build_quic_config(
    idle_timeout: u64,
    tls_profile: TlsProfile,
    cert_validation: CertValidation,
) -> Result<QuinnClientConfig> {
    tracing::debug!(profile = %tls_profile, validation = ?cert_validation, "Building QUIC client config");

    let mut transport_config = TransportConfig::default();
    transport_config.max_idle_timeout(Some(Duration::from_secs(idle_timeout).try_into()?));

    // Enable QUIC datagrams for VPN traffic with conservative limits
    // 16KB buffer to prevent memory exhaustion from malicious datagrams
    transport_config.datagram_receive_buffer_size(Some(16384));
    transport_config.datagram_send_buffer_size(16384);

    // Configure MTU for VPN traffic - set initial MTU high enough for typical networks
    // TUN MTU 1400 + QUIC overhead (~60 bytes) requires UDP payload of ~1460
    // We set initial_mtu to 1500 (standard Ethernet MTU) and enable MTU discovery
    transport_config.initial_mtu(1500);
    transport_config.min_mtu(1280); // IPv6 minimum, safe fallback
    transport_config.mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()));

    // Apply TLS profile cipher suites and key exchange groups
    let cipher_suites = tls_profile.rustls_cipher_suites();
    let kx_groups = tls_profile.rustls_kx_groups();

    tracing::info!(
        profile = %tls_profile,
        cipher_count = cipher_suites.len(),
        kx_count = kx_groups.len(),
        "Applying TLS profile cipher suites"
    );

    // Build custom crypto provider with profile-specific ciphers
    let provider = rustls::crypto::CryptoProvider {
        cipher_suites,
        kx_groups,
        ..rustls::crypto::ring::default_provider()
    };

    let crypto_config = match cert_validation {
        CertValidation::SystemRoots => {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            rustls::ClientConfig::builder_with_provider(Arc::new(provider))
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .with_root_certificates(roots)
                .with_no_client_auth()
        }
        CertValidation::CustomCa(ca_cert_path) => {
            let mut roots = rustls::RootCertStore::empty();

            let cert_pem = std::fs::read_to_string(&ca_cert_path).context(format!(
                "Failed to read CA certificate from {:?}",
                ca_cert_path
            ))?;
            let certs = rustls_pemfile::certs(&mut cert_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .context("Failed to parse PEM certificate")?;

            if certs.is_empty() {
                bail!("CA certificate file contains no valid certificates");
            }

            // Validate certificate is not expired before adding
            for cert in &certs {
                validate_certificate_basic(cert)?;
            }

            for cert in certs {
                roots
                    .add(cert)
                    .context("Failed to add CA certificate to root store")?;
            }

            tracing::info!(
                ca_path = ?ca_cert_path,
                cert_count = roots.len(),
                "Loaded custom CA certificates"
            );

            rustls::ClientConfig::builder_with_provider(Arc::new(provider))
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .with_root_certificates(roots)
                .with_no_client_auth()
        }
        CertValidation::PublicKeyPin(expected_pubkey) => {
            // Use custom verifier that pins to specific public key
            let verifier = PublicKeyPinVerifier::new(expected_pubkey);

            rustls::ClientConfig::builder_with_provider(Arc::new(provider))
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_no_client_auth()
        }
    };

    let mut crypto_config = crypto_config;
    crypto_config.alpn_protocols = vec![b"h3".to_vec(), b"masque".to_vec()];

    let mut client_config = QuinnClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto_config)?,
    ));
    client_config.transport_config(Arc::new(transport_config));

    Ok(client_config)
}

/// Legacy API - deprecated, use build_quic_config with CertValidation instead
#[deprecated(since = "2.0.0", note = "Use build_quic_config with CertValidation enum")]
pub fn build_quic_config_legacy(
    insecure: bool,
    idle_timeout: u64,
    tls_profile: TlsProfile,
    ca_cert: Option<PathBuf>,
) -> Result<QuinnClientConfig> {
    if insecure {
        bail!(
            "Insecure mode has been removed for security. \
             Use CertValidation::CustomCa with your server's CA certificate, \
             or CertValidation::PublicKeyPin for TOFU-style pinning."
        );
    }

    let validation = match ca_cert {
        Some(path) => CertValidation::CustomCa(path),
        None => CertValidation::SystemRoots,
    };

    build_quic_config(idle_timeout, tls_profile, validation)
}

/// Validate basic certificate properties (expiration, structure)
fn validate_certificate_basic(cert: &CertificateDer<'_>) -> Result<()> {
    let (_, parsed) = X509Certificate::from_der(cert.as_ref())
        .context("Failed to parse X.509 certificate")?;

    // Check not expired
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let not_before = parsed.validity().not_before.timestamp();
    let not_after = parsed.validity().not_after.timestamp();

    if now < not_before {
        bail!(
            "Certificate is not yet valid (valid from {:?})",
            parsed.validity().not_before
        );
    }

    if now > not_after {
        bail!(
            "Certificate has expired (expired {:?})",
            parsed.validity().not_after
        );
    }

    // Warn if expiring soon (30 days)
    let days_until_expiry = (not_after - now) / 86400;
    if days_until_expiry < 30 {
        tracing::warn!(
            days_remaining = days_until_expiry,
            "Certificate expires soon"
        );
    }

    Ok(())
}

/// Public key pinning certificate verifier (TOFU - Trust On First Use)
///
/// This verifier pins to a specific public key, rejecting any certificate
/// that doesn't contain the expected key. This provides strong security
/// even without a CA infrastructure.
///
/// # Security
/// - Validates certificate structure and expiration
/// - Verifies signatures using standard TLS 1.3 schemes
/// - Pins to specific public key (not full certificate, allowing rotation)
///
/// # Usage
/// ```rust
/// // Get the server's public key on first connection (TOFU)
/// let pubkey = get_server_pubkey_from_cert(cert)?;
/// // Store pubkey securely, use for future connections
/// let verifier = PublicKeyPinVerifier::new(pubkey);
/// ```
#[derive(Debug)]
pub struct PublicKeyPinVerifier {
    /// Expected public key in DER format (SPKI - Subject Public Key Info)
    expected_pubkey: Vec<u8>,
}

impl PublicKeyPinVerifier {
    /// Create a new verifier that pins to the given public key
    pub fn new(expected_pubkey: Vec<u8>) -> Self {
        Self { expected_pubkey }
    }

    /// Extract public key from certificate
    fn extract_pubkey(cert: &CertificateDer<'_>) -> Result<Vec<u8>, rustls::Error> {
        let (_, parsed) = X509Certificate::from_der(cert.as_ref())
            .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;

        Ok(parsed.public_key().raw.to_vec())
    }

    /// Verify certificate structure and expiration
    fn verify_cert_valid(cert: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        let (_, parsed) = X509Certificate::from_der(cert.as_ref())
            .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;

        // Check expiration
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let not_before = parsed.validity().not_before.timestamp();
        let not_after = parsed.validity().not_after.timestamp();

        if now < not_before || now > not_after {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::Expired,
            ));
        }

        Ok(())
    }
}

impl ServerCertVerifier for PublicKeyPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // Verify certificate is valid (not expired)
        Self::verify_cert_valid(end_entity)?;

        // Extract and compare public key
        let actual_pubkey = Self::extract_pubkey(end_entity)?;

        // Constant-time comparison to prevent timing attacks
        if actual_pubkey.len() != self.expected_pubkey.len() {
            tracing::warn!(
                expected_len = self.expected_pubkey.len(),
                actual_len = actual_pubkey.len(),
                "Public key length mismatch"
            );
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadSignature,
            ));
        }

        // Use subtle crate for constant-time comparison if available
        // For now, use byte-by-byte XOR to avoid early exit
        let mut diff = 0u8;
        for (a, b) in actual_pubkey.iter().zip(self.expected_pubkey.iter()) {
            diff |= a ^ b;
        }

        if diff != 0 {
            tracing::warn!("Public key does not match pinned key");
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadSignature,
            ));
        }

        tracing::debug!("Public key pin verification successful");
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // Use webpki for signature verification
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // Use webpki for signature verification
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            // TLS 1.3 required schemes
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            // Legacy (for compatibility)
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

/// Extract public key from a PEM-encoded certificate file for pinning
///
/// Use this to get the public key from a trusted certificate for TOFU setup.
pub fn extract_pubkey_from_pem(cert_path: &std::path::Path) -> Result<Vec<u8>> {
    let cert_pem = std::fs::read_to_string(cert_path)
        .context("Failed to read certificate file")?;

    let certs = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse PEM certificate")?;

    if certs.is_empty() {
        bail!("No certificates found in PEM file");
    }

    let (_, parsed) = X509Certificate::from_der(certs[0].as_ref())
        .context("Failed to parse X.509 certificate")?;

    Ok(parsed.public_key().raw.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cert_validation_default_is_system_roots() {
        let validation = CertValidation::default();
        assert!(matches!(validation, CertValidation::SystemRoots));
    }

    #[test]
    fn test_legacy_api_rejects_insecure() {
        #[allow(deprecated)]
        let result = build_quic_config_legacy(
            true, // insecure = true
            30,
            TlsProfile::Chrome,
            None,
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Insecure mode has been removed"));
    }
}
