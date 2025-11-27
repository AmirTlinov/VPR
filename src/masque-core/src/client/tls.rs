//! TLS/QUIC configuration and insecure verifier for VPN client.

use anyhow::{Context, Result};
use quinn::{ClientConfig as QuinnClientConfig, TransportConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::tls_fingerprint::TlsProfile;

/// Build QUIC client configuration with TLS fingerprinting support
pub fn build_quic_config(
    insecure: bool,
    idle_timeout: u64,
    tls_profile: TlsProfile,
    ca_cert: Option<PathBuf>,
) -> Result<QuinnClientConfig> {
    tracing::debug!(profile = %tls_profile, "Building QUIC client config");

    let mut transport_config = TransportConfig::default();
    transport_config.max_idle_timeout(Some(Duration::from_secs(idle_timeout).try_into()?));

    // Enable QUIC datagrams for VPN traffic
    transport_config.datagram_receive_buffer_size(Some(65536));
    transport_config.datagram_send_buffer_size(65536);

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

    let crypto_config = if insecure {
        rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();

        // Load custom CA cert if provided, otherwise use webpki roots
        if let Some(ca_cert_path) = &ca_cert {
            let cert_pem = std::fs::read_to_string(ca_cert_path).context(format!(
                "Failed to read CA certificate from {:?}",
                ca_cert_path
            ))?;
            let certs = rustls_pemfile::certs(&mut cert_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .context("Failed to parse PEM certificate")?;

            for cert in certs {
                roots
                    .add(cert)
                    .context("Failed to add CA certificate to root store")?;
            }
        } else {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }

        rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth()
    };

    let mut crypto_config = crypto_config;
    crypto_config.alpn_protocols = vec![b"h3".to_vec(), b"masque".to_vec()];

    let mut client_config = QuinnClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto_config)?,
    ));
    client_config.transport_config(Arc::new(transport_config));

    Ok(client_config)
}

/// Insecure certificate verifier for testing (bypasses all verification)
#[derive(Debug)]
pub struct InsecureVerifier;

impl ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}
