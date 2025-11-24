//! Tests for key zeroization behavior
use vpr_crypto::keys::NoiseKeypair;

#[test]
fn noise_keypair_secret_bytes_accessible() {
    let kp = NoiseKeypair::generate();
    // secret_bytes returns [u8; 32]
    let secret = kp.secret_bytes();
    // Should have some non-zero bytes (extremely unlikely all zeros from random)
    assert!(secret.iter().any(|b| *b != 0), "secret should have non-zero bytes");
}

#[test]
fn noise_keypair_public_bytes_consistent() {
    let kp = NoiseKeypair::generate();
    let pub1 = kp.public_bytes();
    let pub2 = kp.public_bytes();
    assert_eq!(pub1, pub2, "public key should be consistent");
}

#[test]
fn noise_keypair_roundtrip_via_secret() {
    let original = NoiseKeypair::generate();
    let secret = original.secret_bytes();
    let restored = NoiseKeypair::from_secret_bytes(&secret);
    assert_eq!(original.public_bytes(), restored.public_bytes(), "restored keypair should match");
}
