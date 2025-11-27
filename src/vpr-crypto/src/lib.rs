//! # VPR Crypto
//!
//! Cryptographic primitives for the VPR VPN protocol.
//!
//! ## Features
//!
//! - **Post-quantum hybrid encryption**: ML-KEM768 + X25519
//! - **Noise protocol**: IK/NK pattern with hybrid KEM
//! - **Key management**: Generation, storage, rotation
//! - **PKI**: X.509 certificate hierarchy (Root CA → Intermediate → Service)
//! - **Age encryption**: File sealing for secrets management
//! - **Constant-time operations**: For timing attack resistance
//! - **Secret hygiene**: Zeroizing memory on drop
//!
//! ## Modules
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`keys`] | X25519/Ed25519 keypair generation & storage |
//! | [`noise`] | Hybrid Noise + ML-KEM768 handshake |
//! | [`manifest`] | Ed25519-signed bootstrap manifests |
//! | [`pki`] | X.509 certificate generation |
//! | [`seal`] | Age-based file encryption |
//! | [`constant_time`] | Timing-safe comparisons |
//! | [`rng`] | Cryptographically secure RNG |
//!
//! ## Quick Start
//!
//! ```no_run
//! use vpr_crypto::{NoiseKeypair, SigningKeypair};
//! use std::path::Path;
//!
//! // Generate Noise keypair for VPN tunnel
//! let noise_keys = NoiseKeypair::generate();
//! noise_keys.save(Path::new("secrets"), "client").unwrap();
//!
//! // Generate signing keypair for manifests
//! let signing_keys = SigningKeypair::generate();
//! let signature = signing_keys.sign(b"message");
//! assert!(signing_keys.verify(b"message", &signature).is_ok());
//! ```
//!
//! ## Post-Quantum Handshake
//!
//! ```no_run
//! use vpr_crypto::{NoiseInitiator, NoiseResponder};
//!
//! // Server generates static key
//! let server_secret = [0u8; 32]; // In production: from NoiseKeypair
//! let server_public = x25519_dalek::x25519(
//!     server_secret,
//!     x25519_dalek::X25519_BASEPOINT_BYTES
//! );
//!
//! // Client initiates IK handshake (knows server public key)
//! let client_secret = [0u8; 32]; // In production: from NoiseKeypair
//! let mut initiator = NoiseInitiator::new_ik(&client_secret, &server_public)
//!     .expect("failed to create initiator");
//! ```
//!
//! ## Security Considerations
//!
//! - All keys are generated via OS CSPRNG ([`rng::secure_rng`])
//! - Secret keys are zeroized on drop
//! - Private key files are saved with mode 0o600 (Unix)
//! - Constant-time comparison for all secret data

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
