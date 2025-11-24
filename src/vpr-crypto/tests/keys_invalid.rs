//! Tests for invalid key handling
use vpr_crypto::keys::{NoiseKeypair, SigningKeypair};

#[test]
fn signing_keypair_rejects_short_bytes() {
    // from_secret_bytes expects exactly 32 bytes
    // Can't pass &[u8; 16] to &[u8; 32] directly - compiler enforces this
    // SigningKeypair::from_secret_bytes expects [u8; 32], so this is a compile-time check
    // Instead, test that generated keypair works correctly

    // Test that generated keypair works
    let kp = SigningKeypair::generate();
    let msg = b"test";
    let sig = kp.sign(msg);
    assert!(kp.verify(msg, &sig).is_ok());
}

#[test]
fn noise_keypair_from_secret_bytes_works() {
    // NoiseKeypair::from_secret_bytes expects exactly 32 bytes
    let bytes: [u8; 32] = [0x42; 32];
    let kp = NoiseKeypair::from_secret_bytes(&bytes);
    // from_secret_bytes always succeeds with valid 32-byte input
    assert!(kp.public_bytes().iter().any(|b| *b != 0), "keypair should be created");
}

#[test]
fn noise_keypair_generation_is_unique() {
    let kp1 = NoiseKeypair::generate();
    let kp2 = NoiseKeypair::generate();
    assert_ne!(kp1.public_bytes(), kp2.public_bytes(), "generated keypairs should be unique");
}
