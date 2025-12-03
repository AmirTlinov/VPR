//! TLS/QUIC configuration for VPN server.

use anyhow::{Context, Result};
use quinn::{ServerConfig, TransportConfig};
use rustls::crypto::SupportedKxGroup;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::SupportedCipherSuite;
use rustls_pemfile::{certs, private_key};
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::tls_fingerprint::{
    GreaseMode, Ja3Fingerprint, Ja3sFingerprint, Ja4Fingerprint, TlsProfile,
};
use crate::vpn_common::preferred_tls13_cipher;

/// Load TLS certificates from PEM file
pub fn load_certs(path: &PathBuf) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path).with_context(|| format!("opening cert file {:?}", path))?;
    let mut reader = BufReader::new(file);
    certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .context("parsing certificates")
}

/// Load private key from PEM file
pub fn load_key(path: &PathBuf) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path).with_context(|| format!("opening key file {:?}", path))?;
    let mut reader = BufReader::new(file);
    private_key(&mut reader)
        .context("parsing private key")?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {:?}", path))
}

/// Build QUIC server configuration with TLS fingerprint mimicry
pub fn build_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    idle_timeout: u64,
    cipher_suites: Vec<SupportedCipherSuite>,
    kx_groups: Vec<&'static dyn SupportedKxGroup>,
) -> Result<ServerConfig> {
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

    let provider = rustls::crypto::CryptoProvider {
        cipher_suites,
        kx_groups,
        ..rustls::crypto::ring::default_provider()
    };

    let mut rustls_config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    rustls_config.alpn_protocols = vec![b"h3".to_vec(), b"masque".to_vec()];
    rustls_config.max_early_data_size = u32::MAX;

    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(rustls_config))
        .context("building rustls QUIC server config")?;

    let mut server_config = ServerConfig::with_crypto(Arc::new(crypto));
    server_config.transport_config(Arc::new(transport_config));

    Ok(server_config)
}

/// Build TLS fingerprints (JA3/JA3S/JA4) for the given profile
pub fn build_tls_fingerprint(
    profile: &TlsProfile,
    grease_mode: GreaseMode,
) -> (Ja3Fingerprint, Ja3sFingerprint, Ja4Fingerprint, u16) {
    let ja3 = Ja3Fingerprint::from_profile_with_grease(profile, grease_mode);
    let selected_cipher = preferred_tls13_cipher(profile);
    let ja3s = Ja3sFingerprint::from_profile_with_grease(profile, selected_cipher, grease_mode);
    let ja4 = Ja4Fingerprint::from_profile(profile);
    (ja3, ja3s, ja4, selected_cipher)
}
