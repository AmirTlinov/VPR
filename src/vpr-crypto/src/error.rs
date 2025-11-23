use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("key generation failed: {0}")]
    KeyGen(String),

    #[error("invalid key material: {0}")]
    InvalidKey(String),

    #[error("PKI error: {0}")]
    Pki(String),

    #[error("encryption failed: {0}")]
    Encrypt(String),

    #[error("decryption failed: {0}")]
    Decrypt(String),

    #[error("Noise handshake failed: {0}")]
    Noise(String),

    #[error("certificate error: {0}")]
    Certificate(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(String),
}

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
