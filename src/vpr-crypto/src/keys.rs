use crate::{rng, CryptoError, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::Path;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use zeroize::Zeroize;

/// X25519 keypair for Noise protocol
#[derive(Clone)]
pub struct NoiseKeypair {
    pub secret: X25519Secret,
    pub public: X25519Public,
}

impl NoiseKeypair {
    pub fn generate() -> Self {
        let secret = X25519Secret::random_from_rng(rng::secure_rng());
        let public = X25519Public::from(&secret);
        Self { secret, public }
    }

    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        let secret = X25519Secret::from(*bytes);
        let public = X25519Public::from(&secret);
        Self { secret, public }
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    pub fn save(&self, dir: &Path, name: &str) -> Result<()> {
        std::fs::create_dir_all(dir)?;
        let sk_path = dir.join(format!("{name}.noise.key"));
        let pk_path = dir.join(format!("{name}.noise.pub"));
        std::fs::write(&sk_path, self.secret_bytes())?;
        std::fs::write(&pk_path, self.public_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&sk_path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    pub fn load(dir: &Path, name: &str) -> Result<Self> {
        let sk_path = dir.join(format!("{name}.noise.key"));
        let sk_bytes = std::fs::read(&sk_path)?;
        if sk_bytes.len() != 32 {
            return Err(CryptoError::InvalidKey("noise key must be 32 bytes".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&sk_bytes);
        Ok(Self::from_secret_bytes(&arr))
    }

    pub fn load_public(path: &Path) -> Result<[u8; 32]> {
        let pk_bytes = std::fs::read(path)?;
        if pk_bytes.len() != 32 {
            return Err(CryptoError::InvalidKey("noise pub must be 32 bytes".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&pk_bytes);
        Ok(arr)
    }
}

/// Ed25519 keypair for signing
pub struct SigningKeypair {
    pub signing: SigningKey,
    pub verifying: VerifyingKey,
}

impl SigningKeypair {
    pub fn generate() -> Self {
        let mut rng = rng::secure_rng();
        let signing = SigningKey::generate(&mut rng);
        let verifying = signing.verifying_key();
        Self { signing, verifying }
    }

    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let signing = SigningKey::from_bytes(bytes);
        let verifying = signing.verifying_key();
        Ok(Self { signing, verifying })
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.verifying.to_bytes()
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        self.signing.sign(message).to_bytes()
    }

    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<()> {
        use ed25519_dalek::{Signature, Verifier};
        let sig = Signature::from_bytes(signature);
        self.verifying
            .verify(message, &sig)
            .map_err(|e| CryptoError::InvalidKey(format!("signature verification failed: {e}")))
    }

    pub fn save(&self, dir: &Path, name: &str) -> Result<()> {
        std::fs::create_dir_all(dir)?;
        let sk_path = dir.join(format!("{name}.sign.key"));
        let pk_path = dir.join(format!("{name}.sign.pub"));
        std::fs::write(&sk_path, self.secret_bytes())?;
        std::fs::write(&pk_path, self.public_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&sk_path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    pub fn load(dir: &Path, name: &str) -> Result<Self> {
        let sk_path = dir.join(format!("{name}.sign.key"));
        let sk_bytes = std::fs::read(&sk_path)?;
        if sk_bytes.len() != 32 {
            return Err(CryptoError::InvalidKey(
                "signing key must be 32 bytes".into(),
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&sk_bytes);
        Self::from_secret_bytes(&arr)
    }
}

/// Signature verifier (public key only, for verification without signing capability)
#[derive(Clone)]
pub struct SignatureVerifier {
    verifying: VerifyingKey,
}

impl SignatureVerifier {
    /// Create verifier from public key bytes
    pub fn from_public_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let verifying = VerifyingKey::from_bytes(bytes)
            .map_err(|e| CryptoError::InvalidKey(format!("invalid public key: {e}")))?;
        Ok(Self { verifying })
    }

    /// Get public key bytes
    pub fn public_bytes(&self) -> [u8; 32] {
        self.verifying.to_bytes()
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<()> {
        use ed25519_dalek::{Signature, Verifier};
        let sig = Signature::from_bytes(signature);
        self.verifying
            .verify(message, &sig)
            .map_err(|e| CryptoError::InvalidKey(format!("signature verification failed: {e}")))
    }

    /// Load public key from file
    pub fn load(path: &Path) -> Result<Self> {
        let pk_bytes = std::fs::read(path)?;
        if pk_bytes.len() != 32 {
            return Err(CryptoError::InvalidKey(
                "public key must be 32 bytes".into(),
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&pk_bytes);
        Self::from_public_bytes(&arr)
    }
}

/// Key metadata stored alongside keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub name: String,
    pub role: KeyRole,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyRole {
    RootCa,
    IntermediateCa,
    Service,
    Noise,
    Signing,
}

impl KeyMetadata {
    pub fn new(name: &str, role: KeyRole, public_key: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(public_key);
        let fingerprint = hex::encode(&hash[..16]);
        let now = time::OffsetDateTime::now_utc();
        Self {
            name: name.to_string(),
            role,
            created_at: now
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
            expires_at: None,
            fingerprint,
        }
    }

    pub fn save(&self, dir: &Path) -> Result<()> {
        let path = dir.join(format!("{}.meta.json", self.name));
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn load(dir: &Path, name: &str) -> Result<Self> {
        let path = dir.join(format!("{name}.meta.json"));
        let json = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&json)?)
    }
}

/// Securely zeroize key material on drop
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecretBytes(pub Vec<u8>);

impl SecretBytes {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn noise_keypair_generation_uses_osrng() {
        rng::reset_osrng_calls();
        let _ = NoiseKeypair::generate();
        assert!(
            rng::osrng_call_count() >= 1,
            "NoiseKeypair must draw from OsRng"
        );
    }

    #[test]
    fn signing_keypair_generation_uses_osrng() {
        rng::reset_osrng_calls();
        let _ = SigningKeypair::generate();
        assert!(
            rng::osrng_call_count() >= 1,
            "SigningKeypair must draw from OsRng"
        );
    }

    #[test]
    fn noise_keypair_roundtrip() {
        let dir = tempdir().unwrap();
        let kp = NoiseKeypair::generate();
        kp.save(dir.path(), "test").unwrap();
        let loaded = NoiseKeypair::load(dir.path(), "test").unwrap();
        assert_eq!(kp.public_bytes(), loaded.public_bytes());
    }

    #[test]
    fn signing_keypair_sign_verify() {
        let kp = SigningKeypair::generate();
        let msg = b"hello world";
        let sig = kp.sign(msg);
        kp.verify(msg, &sig).unwrap();
    }
}
