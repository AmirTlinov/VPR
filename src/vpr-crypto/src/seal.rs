use crate::{CryptoError, Result};
use age::{
    armor::{ArmoredReader, ArmoredWriter, Format},
    secrecy::ExposeSecret,
    x25519, Decryptor, Encryptor,
};
use std::io::{Read, Write};
use std::path::Path;

/// Age identity (private key) for decryption
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

/// Age recipient (public key) for encryption
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
            .expect("recipients should not be empty");

        let mut ciphertext = Vec::new();
        let mut writer = encryptor
            .wrap_output(ArmoredWriter::wrap_output(&mut ciphertext, Format::AsciiArmor).unwrap())
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

/// Seal a directory of secret files
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
        if path.is_file() && path.extension().is_none_or(|e| e != "age") {
            let name = path.file_name().unwrap().to_string_lossy();
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
}
