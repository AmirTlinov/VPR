use anyhow::{bail, Context, Result};
use snow::Keypair;
use std::{fs, path::Path};

pub fn load_keypair(priv_path: &Path) -> Result<Keypair> {
    let sk = fs::read(priv_path).with_context(|| format!("reading noise key {priv_path:?}"))?;
    if sk.len() != 32 {
        bail!("noise key must be 32 bytes");
    }
    let pk = x25519_public(&sk)?;
    Ok(Keypair {
        private: sk,
        public: pk,
    })
}

pub fn load_public(pub_path: &Path) -> Result<Vec<u8>> {
    let pk = fs::read(pub_path).with_context(|| format!("reading noise pub {pub_path:?}"))?;
    if pk.len() != 32 {
        bail!("noise pub must be 32 bytes");
    }
    Ok(pk)
}

pub fn x25519_public(sk: &[u8]) -> Result<Vec<u8>> {
    if sk.len() != 32 {
        bail!("private key must be 32 bytes");
    }
    let mut pk = [0u8; 32];
    // Safety: length validated above, try_into guaranteed to succeed
    let sk_array: [u8; 32] = sk.try_into().expect("length checked above");
    let out = x25519_dalek::x25519(sk_array, x25519_dalek::X25519_BASEPOINT_BYTES);
    pk.copy_from_slice(&out);
    Ok(pk.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_x25519_public_valid_key() {
        let sk = [1u8; 32]; // Valid 32-byte key
        let result = x25519_public(&sk);
        assert!(result.is_ok());
        let pk = result.unwrap();
        assert_eq!(pk.len(), 32);
    }

    #[test]
    fn test_x25519_public_wrong_length() {
        let short_key = [1u8; 16];
        let result = x25519_public(&short_key);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("32 bytes"));

        let long_key = [1u8; 64];
        let result = x25519_public(&long_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_x25519_public_deterministic() {
        let sk = [42u8; 32];
        let pk1 = x25519_public(&sk).unwrap();
        let pk2 = x25519_public(&sk).unwrap();
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn test_x25519_public_different_keys() {
        let sk1 = [1u8; 32];
        let sk2 = [2u8; 32];
        let pk1 = x25519_public(&sk1).unwrap();
        let pk2 = x25519_public(&sk2).unwrap();
        assert_ne!(pk1, pk2);
    }

    #[test]
    fn test_load_keypair_valid() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("noise.key");
        let sk = [42u8; 32];
        std::fs::write(&key_path, sk).unwrap();

        let result = load_keypair(&key_path);
        assert!(result.is_ok());
        let keypair = result.unwrap();
        assert_eq!(keypair.private.len(), 32);
        assert_eq!(keypair.public.len(), 32);
        assert_eq!(keypair.private, sk.to_vec());
    }

    #[test]
    fn test_load_keypair_wrong_size() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("noise.key");
        let short_key = [1u8; 16];
        std::fs::write(&key_path, short_key).unwrap();

        let result = load_keypair(&key_path);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.to_string().contains("32 bytes"));
    }

    #[test]
    fn test_load_keypair_file_not_found() {
        let result = load_keypair(Path::new("/nonexistent/path/noise.key"));
        assert!(result.is_err());
    }

    #[test]
    fn test_load_public_valid() {
        let dir = tempdir().unwrap();
        let pub_path = dir.path().join("noise.pub");
        let pk = [99u8; 32];
        std::fs::write(&pub_path, pk).unwrap();

        let result = load_public(&pub_path);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), pk.to_vec());
    }

    #[test]
    fn test_load_public_wrong_size() {
        let dir = tempdir().unwrap();
        let pub_path = dir.path().join("noise.pub");
        let bad_pk = [1u8; 48];
        std::fs::write(&pub_path, bad_pk).unwrap();

        let result = load_public(&pub_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("32 bytes"));
    }

    #[test]
    fn test_load_public_file_not_found() {
        let result = load_public(Path::new("/nonexistent/path/noise.pub"));
        assert!(result.is_err());
    }

    #[test]
    fn test_load_keypair_generates_matching_public() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("noise.key");
        let sk = [123u8; 32];
        std::fs::write(&key_path, sk).unwrap();

        let keypair = load_keypair(&key_path).unwrap();
        let expected_pk = x25519_public(&sk).unwrap();
        assert_eq!(keypair.public, expected_pk);
    }

    #[test]
    fn test_x25519_public_empty_slice() {
        let result = x25519_public(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_keypair_empty_file() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("empty.key");
        std::fs::File::create(&key_path).unwrap();

        let result = load_keypair(&key_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_public_empty_file() {
        let dir = tempdir().unwrap();
        let pub_path = dir.path().join("empty.pub");
        std::fs::File::create(&pub_path).unwrap();

        let result = load_public(&pub_path);
        assert!(result.is_err());
    }
}
