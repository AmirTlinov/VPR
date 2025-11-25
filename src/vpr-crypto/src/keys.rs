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
            .map_err(|_| CryptoError::InvalidKey("signature verification failed".into()))
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
            .map_err(|_| CryptoError::InvalidKey("invalid public key".into()))?;
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
            .map_err(|_| CryptoError::InvalidKey("signature verification failed".into()))
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
                .expect("RFC3339 format should always succeed"),
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
        let dir = tempdir().expect("test: failed to create temp directory");
        let kp = NoiseKeypair::generate();
        kp.save(dir.path(), "test")
            .expect("test: failed to save keypair");
        let loaded = NoiseKeypair::load(dir.path(), "test").expect("test: failed to load keypair");
        assert_eq!(kp.public_bytes(), loaded.public_bytes());
    }

    #[test]
    fn signing_keypair_sign_verify() {
        let kp = SigningKeypair::generate();
        let msg = b"hello world";
        let sig = kp.sign(msg);
        kp.verify(msg, &sig)
            .expect("test: signature verification failed");
    }

    #[test]
    fn noise_keypair_from_secret_bytes() {
        let original = NoiseKeypair::generate();
        let secret = original.secret_bytes();
        let restored = NoiseKeypair::from_secret_bytes(&secret);
        assert_eq!(original.public_bytes(), restored.public_bytes());
        assert_eq!(original.secret_bytes(), restored.secret_bytes());
    }

    #[test]
    fn noise_keypair_load_public() {
        let dir = tempdir().unwrap();
        let kp = NoiseKeypair::generate();
        kp.save(dir.path(), "test").unwrap();

        let pk_path = dir.path().join("test.noise.pub");
        let loaded_pub = NoiseKeypair::load_public(&pk_path).unwrap();
        assert_eq!(kp.public_bytes(), loaded_pub);
    }

    #[test]
    fn noise_keypair_load_invalid_size() {
        let dir = tempdir().unwrap();
        let sk_path = dir.path().join("bad.noise.key");
        std::fs::write(&sk_path, vec![0u8; 16]).unwrap(); // Wrong size

        let result = NoiseKeypair::load(dir.path(), "bad");
        assert!(result.is_err());
    }

    #[test]
    fn noise_keypair_load_public_invalid_size() {
        let dir = tempdir().unwrap();
        let pk_path = dir.path().join("bad.noise.pub");
        std::fs::write(&pk_path, vec![0u8; 64]).unwrap(); // Wrong size

        let result = NoiseKeypair::load_public(&pk_path);
        assert!(result.is_err());
    }

    #[test]
    fn signing_keypair_roundtrip() {
        let dir = tempdir().unwrap();
        let kp = SigningKeypair::generate();
        kp.save(dir.path(), "test").unwrap();

        let loaded = SigningKeypair::load(dir.path(), "test").unwrap();
        assert_eq!(kp.public_bytes(), loaded.public_bytes());
        assert_eq!(kp.secret_bytes(), loaded.secret_bytes());
    }

    #[test]
    fn signing_keypair_from_secret_bytes() {
        let original = SigningKeypair::generate();
        let secret = original.secret_bytes();
        let restored = SigningKeypair::from_secret_bytes(&secret).unwrap();
        assert_eq!(original.public_bytes(), restored.public_bytes());
    }

    #[test]
    fn signing_keypair_load_invalid_size() {
        let dir = tempdir().unwrap();
        let sk_path = dir.path().join("bad.sign.key");
        std::fs::write(&sk_path, vec![0u8; 48]).unwrap(); // Wrong size

        let result = SigningKeypair::load(dir.path(), "bad");
        assert!(result.is_err());
    }

    #[test]
    fn signing_keypair_verify_wrong_signature() {
        let kp = SigningKeypair::generate();
        let msg = b"hello";
        let mut bad_sig = kp.sign(msg);
        bad_sig[0] ^= 0xFF; // Corrupt signature

        let result = kp.verify(msg, &bad_sig);
        assert!(result.is_err());
    }

    #[test]
    fn signing_keypair_verify_wrong_message() {
        let kp = SigningKeypair::generate();
        let msg = b"hello";
        let sig = kp.sign(msg);

        let result = kp.verify(b"goodbye", &sig);
        assert!(result.is_err());
    }

    #[test]
    fn signature_verifier_from_public_bytes() {
        let kp = SigningKeypair::generate();
        let verifier = SignatureVerifier::from_public_bytes(&kp.public_bytes()).unwrap();
        assert_eq!(verifier.public_bytes(), kp.public_bytes());

        let msg = b"test message";
        let sig = kp.sign(msg);
        verifier.verify(msg, &sig).unwrap();
    }

    #[test]
    fn signature_verifier_load() {
        let dir = tempdir().unwrap();
        let kp = SigningKeypair::generate();
        kp.save(dir.path(), "test").unwrap();

        let pk_path = dir.path().join("test.sign.pub");
        let verifier = SignatureVerifier::load(&pk_path).unwrap();
        assert_eq!(verifier.public_bytes(), kp.public_bytes());
    }

    #[test]
    fn signature_verifier_load_invalid_size() {
        let dir = tempdir().unwrap();
        let pk_path = dir.path().join("bad.sign.pub");
        std::fs::write(&pk_path, vec![0u8; 20]).unwrap();

        let result = SignatureVerifier::load(&pk_path);
        assert!(result.is_err());
    }

    #[test]
    fn signature_verifier_verify_fails_bad_sig() {
        let kp = SigningKeypair::generate();
        let verifier = SignatureVerifier::from_public_bytes(&kp.public_bytes()).unwrap();

        let bad_sig = [0u8; 64];
        let result = verifier.verify(b"test", &bad_sig);
        assert!(result.is_err());
    }

    #[test]
    fn key_metadata_new_and_fingerprint() {
        let kp = NoiseKeypair::generate();
        let meta = KeyMetadata::new("mykey", KeyRole::Noise, &kp.public_bytes());

        assert_eq!(meta.name, "mykey");
        assert_eq!(meta.role, KeyRole::Noise);
        assert!(!meta.fingerprint.is_empty());
        assert_eq!(meta.fingerprint.len(), 32); // 16 bytes hex = 32 chars
        assert!(meta.expires_at.is_none());
    }

    #[test]
    fn key_metadata_roundtrip() {
        let dir = tempdir().unwrap();
        let kp = NoiseKeypair::generate();
        let meta = KeyMetadata::new("testkey", KeyRole::Signing, &kp.public_bytes());
        meta.save(dir.path()).unwrap();

        let loaded = KeyMetadata::load(dir.path(), "testkey").unwrap();
        assert_eq!(loaded.name, meta.name);
        assert_eq!(loaded.role, meta.role);
        assert_eq!(loaded.fingerprint, meta.fingerprint);
        assert_eq!(loaded.created_at, meta.created_at);
    }

    #[test]
    fn key_role_variants() {
        // Ensure all variants are serializable
        let roles = [
            KeyRole::RootCa,
            KeyRole::IntermediateCa,
            KeyRole::Service,
            KeyRole::Noise,
            KeyRole::Signing,
        ];
        for role in roles {
            let json = serde_json::to_string(&role).unwrap();
            let restored: KeyRole = serde_json::from_str(&json).unwrap();
            assert_eq!(role, restored);
        }
    }

    #[test]
    fn secret_bytes_zeroize() {
        let mut sb = SecretBytes::new(vec![1, 2, 3, 4, 5]);
        assert_eq!(sb.as_slice(), &[1, 2, 3, 4, 5]);

        // Manually zeroize - Vec<u8> zeroize clears the vector
        sb.0.zeroize();
        assert!(sb.as_slice().is_empty());
    }

    #[test]
    fn secret_bytes_drop_clears_memory() {
        // Create SecretBytes with known data
        let data = vec![0xAB; 32];
        let sb = SecretBytes::new(data);
        assert_eq!(sb.as_slice().len(), 32);
        assert_eq!(sb.as_slice()[0], 0xAB);
        // Drop will zeroize (can't directly verify without unsafe, but exercise the path)
        drop(sb);
    }
}
