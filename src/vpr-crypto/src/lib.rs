//! # VPR Crypto
//!
//! Cryptographic primitives for the VPR VPN protocol.
//!
//! This crate provides a complete cryptographic toolkit for building
//! censorship-resistant, post-quantum secure VPN systems.
//!
//! ## Features
//!
//! - **Post-quantum hybrid encryption**: ML-KEM768 + X25519 (NIST standard)
//! - **Noise protocol**: IK/NK patterns with ChaCha20-Poly1305
//! - **Key management**: Generation, storage, rotation with zeroization
//! - **PKI**: Three-tier X.509 hierarchy (Root CA → Intermediate → Service)
//! - **Age encryption**: File sealing for secrets management
//! - **Signed manifests**: Ed25519-signed server bootstrap lists
//! - **Constant-time operations**: Timing attack resistance
//! - **Secret hygiene**: All secrets zeroized on drop
//!
//! ## Modules Overview
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`keys`] | X25519/Ed25519 keypair generation, storage, metadata |
//! | [`noise`] | Hybrid Noise + ML-KEM768 post-quantum handshake |
//! | [`manifest`] | Ed25519-signed bootstrap manifests with versioning |
//! | [`pki`] | X.509 certificate generation (ECDSA P-384/P-256) |
//! | [`seal`] | Age-based file encryption for secrets |
//! | [`constant_time`] | Timing-safe comparisons and selections |
//! | [`rng`] | OS CSPRNG wrapper with test instrumentation |
//! | [`error`] | Unified error types for all operations |
//!
//! ## Quick Start: Key Generation
//!
//! ```
//! use vpr_crypto::{NoiseKeypair, SigningKeypair};
//!
//! // Generate X25519 keypair for Noise protocol
//! let noise_keys = NoiseKeypair::generate();
//! println!("Noise public key: {} bytes", noise_keys.public_bytes().len());
//!
//! // Generate Ed25519 keypair for signing
//! let signing_keys = SigningKeypair::generate();
//! let message = b"important data";
//! let signature = signing_keys.sign(message);
//! assert!(signing_keys.verify(message, &signature).is_ok());
//! ```
//!
//! ## Post-Quantum Handshake Example
//!
//! The hybrid handshake combines classical X25519 with post-quantum ML-KEM768,
//! providing security even against quantum computers.
//!
//! ```
//! use vpr_crypto::{NoiseInitiator, NoiseResponder};
//!
//! // === Server setup ===
//! let mut server_secret = [0u8; 32];
//! vpr_crypto::rng::fill(&mut server_secret);
//! let server_public = x25519_dalek::x25519(
//!     server_secret,
//!     x25519_dalek::X25519_BASEPOINT_BYTES
//! );
//!
//! // === Client initiates (IK pattern: knows server public key) ===
//! let mut client_secret = [0u8; 32];
//! vpr_crypto::rng::fill(&mut client_secret);
//! let mut initiator = NoiseInitiator::new_ik(&client_secret, &server_public)
//!     .expect("failed to create initiator");
//!
//! // === Server responds ===
//! let mut responder = NoiseResponder::new_ik(&server_secret)
//!     .expect("failed to create responder");
//!
//! // Message 1: Client → Server (e, es, s, ss + HybridPublic)
//! let msg1 = initiator.write_message(b"hello").unwrap();
//!
//! // Server reads and responds
//! let (payload, peer_hybrid) = responder.read_message(&msg1).unwrap();
//! assert_eq!(payload, b"hello");
//!
//! // Message 2: Server → Client (e, ee, se + ServerHybrid + ML-KEM CT)
//! let (msg2, server_secret) = responder.write_message(b"world", &peer_hybrid).unwrap();
//!
//! // Client completes handshake
//! let (payload, client_secret) = initiator.read_message(&msg2).unwrap();
//! assert_eq!(payload, b"world");
//!
//! // Both sides now have matching hybrid secrets!
//! assert_eq!(server_secret.combined, client_secret.combined);
//! ```
//!
//! ## PKI: Certificate Hierarchy
//!
//! Generate a complete TLS certificate chain:
//!
//! ```
//! use vpr_crypto::{PkiConfig, generate_root_ca, generate_intermediate_ca, generate_service_cert};
//!
//! let config = PkiConfig::default();
//!
//! // 1. Generate offline Root CA (ECDSA P-384, 10 years)
//! let root = generate_root_ca(&config).unwrap();
//!
//! // 2. Generate Intermediate CA signed by Root (1 year)
//! let intermediate = generate_intermediate_ca(
//!     &config,
//!     "datacenter-1",
//!     &root.cert_pem,
//!     &root.key_pem
//! ).unwrap();
//!
//! // 3. Generate Service cert signed by Intermediate (90 days)
//! let service = generate_service_cert(
//!     &config,
//!     "masque-proxy",
//!     &["vpn.example.com".to_string(), "api.example.com".to_string()],
//!     &intermediate.cert_pem,
//!     &intermediate.key_pem
//! ).unwrap();
//!
//! // service.chain_pem contains full chain for TLS server
//! assert!(service.chain_pem.contains("BEGIN CERTIFICATE"));
//! ```
//!
//! ## Seal: Encrypt Secrets with Age
//!
//! ```
//! use vpr_crypto::{SealIdentity, SealRecipient};
//!
//! // Generate identity (private key)
//! let identity = SealIdentity::generate();
//! let recipient = identity.recipient();
//!
//! // Encrypt data
//! let secret = b"database_password=hunter2";
//! let encrypted = recipient.encrypt(secret).unwrap();
//!
//! // Decrypt with identity
//! let decrypted = identity.decrypt(&encrypted).unwrap();
//! assert_eq!(decrypted, secret);
//! ```
//!
//! ## Signed Manifests for Server Discovery
//!
//! ```
//! use vpr_crypto::{SigningKeypair, SignedManifest, ManifestPayload, ServerEndpoint};
//!
//! // Create manifest with server list
//! let servers = vec![
//!     ServerEndpoint::new("srv1", "vpn1.example.com", 443, "aabb...")
//!         .with_region("us-east")
//!         .with_capabilities(vec!["masque".into(), "doh".into()]),
//!     ServerEndpoint::new("srv2", "vpn2.example.com", 443, "ccdd...")
//!         .with_region("eu-west"),
//! ];
//! let payload = ManifestPayload::new(servers);
//!
//! // Sign with operator's key
//! let signing_key = SigningKeypair::generate();
//! let signed = SignedManifest::sign(&payload, &signing_key).unwrap();
//!
//! // Clients verify with public key
//! let verified = signed.verify(&signing_key.public_bytes()).unwrap();
//! assert_eq!(verified.servers.len(), 2);
//! ```
//!
//! ## Constant-Time Operations
//!
//! For comparing secrets without timing leaks:
//!
//! ```
//! use vpr_crypto::{ct_eq_32, ct_is_zero, SecretBytes};
//!
//! let key1 = [1u8; 32];
//! let key2 = [1u8; 32];
//! let key3 = [2u8; 32];
//!
//! // Constant-time comparison (same time regardless of where difference is)
//! assert!(ct_eq_32(&key1, &key2));
//! assert!(!ct_eq_32(&key1, &key3));
//!
//! // Check if buffer is zeroed
//! let zeros = [0u8; 32];
//! assert!(ct_is_zero(&zeros));
//!
//! // SecretBytes wrapper with constant-time equality
//! let secret: SecretBytes<32> = key1.into();
//! let other: SecretBytes<32> = key2.into();
//! assert_eq!(secret, other); // Uses constant-time comparison
//! ```
//!
//! ## Security Considerations
//!
//! ### Entropy Source
//! All keys are generated via OS CSPRNG ([`rng::secure_rng`]), which uses:
//! - Linux: `getrandom()` syscall
//! - macOS: `SecRandomCopyBytes`
//! - Windows: `BCryptGenRandom`
//!
//! ### Secret Hygiene
//! - Secret keys implement `Zeroize` and are cleared on drop
//! - [`SecretBytes`] wrapper ensures constant-time comparison
//! - Private key files are saved with mode 0o600 (Unix only)
//!
//! ### Cryptographic Choices
//! - **X25519**: 128-bit security, fast, constant-time
//! - **Ed25519**: Deterministic signatures, no nonce reuse risk
//! - **ML-KEM768**: NIST post-quantum standard (192-bit quantum security)
//! - **ChaCha20-Poly1305**: AEAD with 256-bit key, constant-time
//! - **ECDSA P-384**: TLS certificates (required for browser compatibility)
//!
//! ## Feature Flags
//!
//! This crate has no optional features; all functionality is always available.

pub mod constant_time;
pub mod error;
pub mod keys;
pub mod manifest;
pub mod noise;
pub mod pki;
pub mod rng;
pub mod seal;

// Core types - most commonly used
pub use constant_time::{ct_eq, ct_eq_32, ct_eq_64, ct_is_zero, SecretBytes};
pub use error::{CryptoError, Result};
pub use keys::{KeyMetadata, KeyRole, NoiseKeypair, SignatureVerifier, SigningKeypair};
pub use manifest::{ManifestPayload, ServerEndpoint, SignedManifest};
pub use noise::{HybridKeypair, HybridPublic, NoiseInitiator, NoiseResponder, NoiseTransport};

// PKI types
pub use pki::{
    generate_intermediate_ca, generate_root_ca, generate_service_cert, CaBundle, PkiConfig,
    ServiceCert,
};

// Seal/encryption types
pub use seal::{seal_file, unseal_file, SealIdentity, SealRecipient};
