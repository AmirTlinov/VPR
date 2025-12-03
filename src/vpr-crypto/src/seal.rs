//! File Encryption using Age
//!
//! Provides [age](https://age-encryption.org/) encryption for secrets management.
//! Age uses X25519 key agreement with ChaCha20-Poly1305 authenticated encryption.
//!
//! # Use Cases
//!
//! - Encrypting deployment secrets
//! - Sealing configuration files for distribution
//! - Secure key storage
//!
//! # Example
//!
//! ```no_run
//! use vpr_crypto::seal::{SealIdentity, seal_file};
//! use std::path::Path;
//!
//! // Generate identity (private key)
//! let identity = SealIdentity::generate();
//! identity.save(Path::new("secret.key")).unwrap();
//!
//! // Encrypt file for this recipient
//! let recipient = identity.recipient();
//! seal_file(
//!     Path::new("config.toml"),
//!     Path::new("config.toml.age"),
//!     &recipient
//! ).unwrap();
//! ```

use crate::{CryptoError, Result};
use age::{
    armor::{ArmoredReader, ArmoredWriter, Format},
    secrecy::ExposeSecret,
    x25519, Decryptor, Encryptor,
};
use std::io::{Read, Write};
use std::path::Path;

/// Age identity (private key) for decryption.
///
/// Wraps an X25519 private key used for age encryption.
/// The identity can decrypt data encrypted for its corresponding [`SealRecipient`].
///
/// # Security
///
/// - Private key is stored in memory; use [`zeroize`] for sensitive contexts
/// - Save with [`save`](Self::save) which sets 0600 permissions on Unix
///
/// # Key Format
///
/// - Secret key: `AGE-SECRET-KEY-1...` (Bech32-encoded)
/// - Derived public key: `age1...` (Bech32-encoded)
pub struct SealIdentity {
    identity: x25519::Identity,
}

impl SealIdentity {
    /// Generate new age identity
    pub fn generate() -> Self {
        Self {
            identity: x25519::Identity::generate(),
        }
    }

    /// Load from secret key string (age secret key format)
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self> {
        let identity = s
            .parse::<x25519::Identity>()
            .map_err(|_| CryptoError::InvalidKey("invalid age identity".into()))?;
        Ok(Self { identity })
    }

    /// Get public recipient for encryption
    pub fn recipient(&self) -> SealRecipient {
        SealRecipient {
            recipient: self.identity.to_public(),
        }
    }

    /// Export secret key in age format
    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        self.identity.to_string().expose_secret().to_string()
    }

    /// Decrypt data encrypted for this identity
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let decryptor = match Decryptor::new(ArmoredReader::new(ciphertext))
            .map_err(|e| CryptoError::Decrypt(e.to_string()))?
        {
            Decryptor::Recipients(d) => d,
            Decryptor::Passphrase(_) => {
                return Err(CryptoError::Decrypt(
                    "passphrase decryption not supported".into(),
                ))
            }
        };

        let mut reader = decryptor
            .decrypt(std::iter::once(&self.identity as &dyn age::Identity))
            .map_err(|e| CryptoError::Decrypt(e.to_string()))?;

        let mut plaintext = Vec::new();
        reader.read_to_end(&mut plaintext)?;
        Ok(plaintext)
    }

    /// Save identity to file (secret key)
    pub fn save(&self, path: &Path) -> Result<()> {
        std::fs::write(path, self.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// Load identity from file
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Self::from_str(content.trim())
    }
}

/// Age recipient (public key) for encryption.
///
/// Wraps an X25519 public key used for age encryption.
/// Anyone with the recipient can encrypt data that only
/// the corresponding [`SealIdentity`] can decrypt.
///
/// # Key Format
///
/// Public key: `age1...` (Bech32-encoded, ~62 characters)
///
/// # Example
///
/// ```
/// use vpr_crypto::seal::SealIdentity;
///
/// let identity = SealIdentity::generate();
/// let recipient = identity.recipient();
///
/// // Share recipient.to_string() publicly
/// println!("Public key: {}", recipient.to_string());
///
/// // Anyone can encrypt for this recipient
/// let ciphertext = recipient.encrypt(b"secret message").unwrap();
/// ```
#[derive(Clone)]
pub struct SealRecipient {
    recipient: x25519::Recipient,
}

impl SealRecipient {
    /// Parse from public key string
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self> {
        let recipient = s
            .parse::<x25519::Recipient>()
            .map_err(|_| CryptoError::InvalidKey("invalid age recipient".into()))?;
        Ok(Self { recipient })
    }

    /// Export public key in age format
    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        self.recipient.to_string()
    }

    /// Encrypt data for this recipient
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let encryptor = Encryptor::with_recipients(vec![Box::new(self.recipient.clone())])
            .ok_or_else(|| {
                CryptoError::Encrypt("failed to create encryptor: recipients list is empty".into())
            })?;

        let mut ciphertext = Vec::new();
        let armored_writer = ArmoredWriter::wrap_output(&mut ciphertext, Format::AsciiArmor)
            .map_err(|e| CryptoError::Encrypt(format!("failed to create armored writer: {}", e)))?;
        let mut writer = encryptor
            .wrap_output(armored_writer)
            .map_err(|e| CryptoError::Encrypt(e.to_string()))?;

        writer.write_all(plaintext)?;
        writer
            .finish()
            .and_then(|w| w.finish())
            .map_err(|e| CryptoError::Encrypt(e.to_string()))?;

        Ok(ciphertext)
    }

    /// Save public key to file
    pub fn save(&self, path: &Path) -> Result<()> {
        std::fs::write(path, self.to_string())?;
        Ok(())
    }

    /// Load public key from file
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Self::from_str(content.trim())
    }
}

/// Convenience: encrypt file for recipient
pub fn seal_file(input: &Path, output: &Path, recipient: &SealRecipient) -> Result<()> {
    let plaintext = std::fs::read(input)?;
    let ciphertext = recipient.encrypt(&plaintext)?;
    std::fs::write(output, ciphertext)?;
    Ok(())
}

/// Convenience: decrypt file with identity
pub fn unseal_file(input: &Path, output: &Path, identity: &SealIdentity) -> Result<()> {
    let ciphertext = std::fs::read(input)?;
    let plaintext = identity.decrypt(&ciphertext)?;
    std::fs::write(output, plaintext)?;
    Ok(())
}

/// Encrypt all files in a directory for deployment.
///
/// Iterates over files in `secrets_dir`, encrypting each to `output_dir`
/// with `.age` extension. Skips files already ending in `.age`.
///
/// # Arguments
///
/// * `secrets_dir` - Directory containing plaintext secrets
/// * `output_dir` - Directory for encrypted files (created if needed)
/// * `recipient` - Public key for encryption
///
/// # Returns
///
/// List of encrypted filenames (original names, without `.age` suffix).
///
/// # Behavior
///
/// - Only processes regular files (not directories)
/// - Skips files already ending in `.age`
/// - Output files named `{original}.age`
///
/// # Example
///
/// ```no_run
/// use vpr_crypto::seal::{SealIdentity, seal_secrets_dir};
/// use std::path::Path;
///
/// let identity = SealIdentity::generate();
/// let recipient = identity.recipient();
///
/// // Encrypt all secrets for deployment
/// let sealed = seal_secrets_dir(
///     Path::new("./secrets"),
///     Path::new("./deploy/secrets"),
///     &recipient
/// ).unwrap();
///
/// println!("Sealed {} files", sealed.len());
/// ```
///
/// # Errors
///
/// Returns error if directory read fails or any file encryption fails.
pub fn seal_secrets_dir(
    secrets_dir: &Path,
    output_dir: &Path,
    recipient: &SealRecipient,
) -> Result<Vec<String>> {
    std::fs::create_dir_all(output_dir)?;
    let mut sealed_files = Vec::new();

    for entry in std::fs::read_dir(secrets_dir)? {
        let entry = entry?;
        let path = entry.path();
        // NOTE: avoid `.is_none_or` to stay within MSRV 1.70 (clippy::incompatible-msrv)
        let extension_is_age = path.extension().map(|e| e == "age").unwrap_or(false);
        if path.is_file() && !extension_is_age {
            let name = path
                .file_name()
                .ok_or_else(|| {
                    CryptoError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "path has no filename",
                    ))
                })?
                .to_string_lossy();
            let output_path = output_dir.join(format!("{name}.age"));
            seal_file(&path, &output_path, recipient)?;
            sealed_files.push(name.to_string());
        }
    }

    Ok(sealed_files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let id = SealIdentity::generate();
        let recipient = id.recipient();

        let plaintext = b"super secret data";
        let ciphertext = recipient.encrypt(plaintext).unwrap();
        let decrypted = id.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn file_seal_unseal() {
        let dir = tempdir().unwrap();
        let id = SealIdentity::generate();
        let recipient = id.recipient();

        let input = dir.path().join("secret.txt");
        let sealed = dir.path().join("secret.txt.age");
        let output = dir.path().join("decrypted.txt");

        std::fs::write(&input, "hello secrets").unwrap();
        seal_file(&input, &sealed, &recipient).unwrap();
        unseal_file(&sealed, &output, &id).unwrap();

        assert_eq!(
            std::fs::read_to_string(&input).unwrap(),
            std::fs::read_to_string(&output).unwrap()
        );
    }

    #[test]
    fn identity_to_string_from_string_roundtrip() {
        let id = SealIdentity::generate();
        let key_str = id.to_string();

        // age secret keys start with AGE-SECRET-KEY-
        assert!(key_str.starts_with("AGE-SECRET-KEY-"));

        let restored = SealIdentity::from_str(&key_str).unwrap();
        // The public key (recipient) should match
        assert_eq!(id.recipient().to_string(), restored.recipient().to_string());
    }

    #[test]
    fn identity_save_load() {
        let dir = tempdir().unwrap();
        let id = SealIdentity::generate();
        let path = dir.path().join("test.age.key");

        id.save(&path).unwrap();
        let loaded = SealIdentity::load(&path).unwrap();

        assert_eq!(id.recipient().to_string(), loaded.recipient().to_string());
    }

    #[test]
    fn recipient_to_string_from_string_roundtrip() {
        let id = SealIdentity::generate();
        let recipient = id.recipient();
        let key_str = recipient.to_string();

        // age public keys start with age1
        assert!(key_str.starts_with("age1"));

        let restored = SealRecipient::from_str(&key_str).unwrap();
        assert_eq!(recipient.to_string(), restored.to_string());
    }

    #[test]
    fn recipient_save_load() {
        let dir = tempdir().unwrap();
        let id = SealIdentity::generate();
        let recipient = id.recipient();
        let path = dir.path().join("test.age.pub");

        recipient.save(&path).unwrap();
        let loaded = SealRecipient::load(&path).unwrap();

        assert_eq!(recipient.to_string(), loaded.to_string());
    }

    #[test]
    fn encrypt_empty_data() {
        let id = SealIdentity::generate();
        let recipient = id.recipient();

        let ciphertext = recipient.encrypt(&[]).unwrap();
        let decrypted = id.decrypt(&ciphertext).unwrap();

        assert!(decrypted.is_empty());
    }

    #[test]
    fn encrypt_large_data() {
        let id = SealIdentity::generate();
        let recipient = id.recipient();

        let plaintext: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let ciphertext = recipient.encrypt(&plaintext).unwrap();
        let decrypted = id.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn decrypt_wrong_identity_fails() {
        let id1 = SealIdentity::generate();
        let id2 = SealIdentity::generate();

        let ciphertext = id1.recipient().encrypt(b"secret").unwrap();

        // Trying to decrypt with wrong identity should fail
        let result = id2.decrypt(&ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_corrupted_ciphertext_fails() {
        let id = SealIdentity::generate();

        // Random garbage is not valid ciphertext
        let result = id.decrypt(b"not valid age encrypted data");
        assert!(result.is_err());
    }

    #[test]
    fn identity_from_str_invalid() {
        let result = SealIdentity::from_str("not-a-valid-age-key");
        assert!(result.is_err());
    }

    #[test]
    fn recipient_from_str_invalid() {
        let result = SealRecipient::from_str("not-a-valid-age-pubkey");
        assert!(result.is_err());
    }

    #[test]
    fn seal_secrets_dir_encrypts_files() {
        let dir = tempdir().unwrap();
        let secrets = dir.path().join("secrets");
        let sealed = dir.path().join("sealed");
        std::fs::create_dir_all(&secrets).unwrap();

        // Create some secret files
        std::fs::write(secrets.join("key1.txt"), "secret1").unwrap();
        std::fs::write(secrets.join("key2.bin"), "secret2").unwrap();
        // Skip .age files
        std::fs::write(secrets.join("already.age"), "already encrypted").unwrap();

        let id = SealIdentity::generate();
        let recipient = id.recipient();

        let result = seal_secrets_dir(&secrets, &sealed, &recipient).unwrap();

        // Should have sealed key1.txt and key2.bin, but not already.age
        assert_eq!(result.len(), 2);
        assert!(result.contains(&"key1.txt".to_string()));
        assert!(result.contains(&"key2.bin".to_string()));

        // Verify files were created
        assert!(sealed.join("key1.txt.age").exists());
        assert!(sealed.join("key2.bin.age").exists());
        assert!(!sealed.join("already.age.age").exists());

        // Verify can decrypt
        let ciphertext = std::fs::read(sealed.join("key1.txt.age")).unwrap();
        let decrypted = id.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, b"secret1");
    }

    #[test]
    fn seal_secrets_dir_creates_output() {
        let dir = tempdir().unwrap();
        let secrets = dir.path().join("secrets");
        let sealed = dir.path().join("nonexistent/nested/sealed");
        std::fs::create_dir_all(&secrets).unwrap();
        std::fs::write(secrets.join("test.key"), "test data").unwrap();

        let id = SealIdentity::generate();
        let result = seal_secrets_dir(&secrets, &sealed, &id.recipient()).unwrap();

        assert_eq!(result.len(), 1);
        assert!(sealed.exists());
    }

    #[test]
    fn recipient_clone() {
        let id = SealIdentity::generate();
        let recipient = id.recipient();
        let cloned = recipient.clone();

        assert_eq!(recipient.to_string(), cloned.to_string());

        // Both can encrypt
        let ct1 = recipient.encrypt(b"test").unwrap();
        let ct2 = cloned.encrypt(b"test").unwrap();
        // Ciphertexts differ (random IV), but both decrypt
        assert_eq!(id.decrypt(&ct1).unwrap(), b"test");
        assert_eq!(id.decrypt(&ct2).unwrap(), b"test");
    }
}
