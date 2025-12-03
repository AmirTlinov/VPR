//! Error types for cryptographic operations.
//!
//! All crypto operations return [`Result<T>`] which wraps [`CryptoError`].

use thiserror::Error;

/// Error type for all cryptographic operations.
///
/// Each variant includes a human-readable description of what went wrong.
/// Use pattern matching to handle specific error types.
///
/// # Example
///
/// ```no_run
/// use vpr_crypto::{CryptoError, NoiseKeypair};
/// use std::path::Path;
///
/// match NoiseKeypair::load(Path::new("keys"), "missing") {
///     Ok(kp) => println!("Loaded key"),
///     Err(CryptoError::Io(e)) => println!("File not found: {e}"),
///     Err(CryptoError::InvalidKey(msg)) => println!("Bad key: {msg}"),
///     Err(e) => println!("Other error: {e}"),
/// }
/// ```
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Key generation failed (e.g., insufficient entropy)
    #[error("key generation failed: {0}")]
    KeyGen(String),

    /// Invalid key material (wrong size, bad format, verification failed)
    #[error("invalid key material: {0}")]
    InvalidKey(String),

    /// Public Key Infrastructure error (certificate generation/validation)
    #[error("PKI error: {0}")]
    Pki(String),

    /// Encryption operation failed
    #[error("encryption failed: {0}")]
    Encrypt(String),

    /// Decryption operation failed (wrong key, corrupted data, auth failed)
    #[error("decryption failed: {0}")]
    Decrypt(String),

    /// Noise protocol handshake error
    #[error("Noise handshake failed: {0}")]
    Noise(String),

    /// X.509 certificate error
    #[error("certificate error: {0}")]
    Certificate(String),

    /// File system I/O error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON/binary serialization error
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Result type alias for cryptographic operations.
pub type Result<T> = std::result::Result<T, CryptoError>;

impl From<rcgen::Error> for CryptoError {
    fn from(e: rcgen::Error) -> Self {
        CryptoError::Pki(e.to_string())
    }
}

impl From<snow::Error> for CryptoError {
    fn from(e: snow::Error) -> Self {
        CryptoError::Noise(e.to_string())
    }
}

impl From<serde_json::Error> for CryptoError {
    fn from(e: serde_json::Error) -> Self {
        CryptoError::Serialization(e.to_string())
    }
}
