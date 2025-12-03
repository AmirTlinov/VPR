//! # MASQUE Core
//!
//! Core VPN implementation using the MASQUE protocol (RFC 9298) over HTTP/3.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                       VPN Client                            │
//! │  ┌─────────┐  ┌──────────┐  ┌───────────────┐              │
//! │  │   TUN   │──│  Tunnel  │──│ Hybrid Noise  │              │
//! │  └─────────┘  └──────────┘  │  + ML-KEM768  │              │
//! │                             └───────┬───────┘              │
//! │                                     │                      │
//! │  ┌────────────────────────────────────────────────┐       │
//! │  │              MASQUE CONNECT-UDP                │       │
//! │  │                 (RFC 9298)                     │       │
//! │  └────────────────────┬───────────────────────────┘       │
//! │                       │                                    │
//! │  ┌────────────────────────────────────────────────┐       │
//! │  │          HTTP/3 over QUIC (h3-quinn)           │       │
//! │  └────────────────────┬───────────────────────────┘       │
//! └───────────────────────┼───────────────────────────────────┘
//!                         │ TLS 1.3 (Chrome fingerprint)
//!                         ↓
//! ┌───────────────────────────────────────────────────────────┐
//! │                       VPN Server                          │
//! │  ┌─────────┐  ┌──────────┐  ┌──────────────────────┐     │
//! │  │   NAT   │──│ IP Pool  │──│ Noise + Key Rotation │     │
//! │  └─────────┘  └──────────┘  └──────────────────────┘     │
//! └───────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Stealth Features
//!
//! - **TLS fingerprint**: Mimics Chrome browser (JA3/JA4)
//! - **Cover traffic**: Background noise generation
//! - **Adaptive padding**: Packet size normalization
//! - **Domain fronting**: Optional CDN-based hiding
//! - **Probe protection**: Active probing defense
//!
//! ## Security Features
//!
//! - **Post-quantum**: ML-KEM768 hybrid handshake
//! - **Key rotation**: 60s or 1GB threshold
//! - **Replay protection**: 5-minute window
//! - **Kill switch**: WAL-based network guard

/// ACME client for automatic TLS certificate management
pub mod acme_client;
/// Bootstrap manifest handling and server discovery
pub mod bootstrap;
/// Canary rollout for gradual server updates
pub mod canary_rollout;
/// TLS certificate manager with auto-renewal
pub mod cert_manager;
/// Cover traffic generator for traffic analysis resistance
pub mod cover_traffic;
/// Diagnostic and troubleshooting tools
pub mod diagnostics;
/// DNS record updater for dynamic server IPs
pub mod dns_updater;
/// Domain fronting support for censorship resistance
pub mod domain_fronting;
/// DPI (Deep Packet Inspection) feedback system
pub mod dpi_feedback;
/// HTTP/3 server implementation
pub mod h3_server;
/// Hybrid Noise + ML-KEM768 handshake
pub mod hybrid_handshake;
/// Automatic key rotation (time/data thresholds)
pub mod key_rotation;
/// Server manifest rotation and signing
pub mod manifest_rotator;
/// MASQUE CONNECT-UDP protocol implementation
pub mod masque;
/// Network state guard (kill switch)
pub mod network_guard;
/// Noise protocol key management
pub mod noise_keys;
/// Traffic padding for fingerprint resistance
pub mod padding;
/// Active probing protection
pub mod probe_protection;
/// QUIC stream handling
pub mod quic_stream;
/// Replay attack protection
pub mod replay_protection;
/// Cryptographically secure RNG wrapper
pub mod rng;
/// Steganographic RSS feed distribution
pub mod stego_rss;
/// DPI suspicion score calculation
pub mod suspicion;
/// TLS fingerprint customization (JA3/JA4)
pub mod tls_fingerprint;
/// Traffic monitoring and statistics
pub mod traffic_monitor;
/// Low-level transport abstraction
pub mod transport;
/// TUN device management
pub mod tun;
/// Encrypted tunnel implementation
pub mod tunnel;
/// Common VPN utilities for client and server
pub mod vpn_common;
/// VPN configuration structures
pub mod vpn_config;
/// High-level VPN tunnel API
pub mod vpn_tunnel;
/// VPN server components (decomposed binary support)
pub mod server;
/// VPN client components (decomposed binary support)
pub mod client;
