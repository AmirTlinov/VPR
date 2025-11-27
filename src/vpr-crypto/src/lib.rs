//! # VPR Crypto
//!
//! Cryptographic primitives for the VPR VPN protocol.
//!
//! ## Features
//!
//! - **Post-quantum hybrid encryption**: ML-KEM768 + X25519
//! - **Noise protocol**: IK/NK pattern with hybrid KEM
//! - **Key management**: Generation, storage, rotation
//! - **Constant-time operations**: For timing attack resistance
//! - **Secret hygiene**: Zeroizing memory on drop
//!
//! ## Example
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
//! ```

pub mod constant_time;
pub mod error;
pub mod keys;
pub mod manifest;
pub mod noise;
pub mod pki;
pub mod rng;
pub mod seal;

pub use constant_time::{ct_eq, ct_eq_32, ct_eq_64, ct_is_zero, SecretBytes};
pub use error::{CryptoError, Result};
pub use keys::{NoiseKeypair, SignatureVerifier, SigningKeypair};
pub use manifest::{ManifestPayload, ServerEndpoint, SignedManifest};
pub use noise::{HybridKeypair, HybridPublic, NoiseInitiator, NoiseResponder, NoiseTransport};
