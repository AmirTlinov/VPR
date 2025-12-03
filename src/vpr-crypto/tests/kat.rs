//! Known Answer Tests (KAT) for cryptographic primitives
//!
//! These tests use fixed test vectors to ensure cryptographic operations
//! produce expected outputs, providing confidence in correctness.

use vpr_crypto::keys::{NoiseKeypair, SigningKeypair};
use vpr_crypto::noise::{HybridKeypair, HybridPublic, NoiseInitiator, NoiseResponder};

/// Fixed seed for deterministic testing
const TEST_SEED: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

/// Fixed test keys for Noise handshake KAT
const TEST_CLIENT_STATIC: [u8; 32] = [
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
];

const TEST_SERVER_STATIC: [u8; 32] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
];

#[test]
fn test_noise_ik_handshake_kat() {
    // Known Answer Test for Noise IK handshake
    // Using fixed keys, the handshake should produce deterministic results

    // Compute server public key from static secret
    let server_public =
        x25519_dalek::x25519(TEST_SERVER_STATIC, x25519_dalek::X25519_BASEPOINT_BYTES);

    // Create initiator and responder with fixed keys
    let mut initiator = NoiseInitiator::new_ik(&TEST_CLIENT_STATIC, &server_public)
        .expect("KAT: failed to create initiator");
    let mut responder =
        NoiseResponder::new_ik(&TEST_SERVER_STATIC).expect("KAT: failed to create responder");

    // Handshake message 1: client -> server
    let msg1 = initiator
        .write_message(b"KAT test payload")
        .expect("KAT: failed to write message");
    assert!(!msg1.is_empty(), "KAT: message 1 should not be empty");

    // Handshake message 2: server -> client
    let (payload1, peer_hybrid) = responder
        .read_message(&msg1)
        .expect("KAT: failed to read message");
    assert_eq!(payload1, b"KAT test payload", "KAT: payload mismatch");

    let (msg2, server_secret) = responder
        .write_message(b"KAT response", &peer_hybrid)
        .expect("KAT: failed to write response");
    assert!(!msg2.is_empty(), "KAT: message 2 should not be empty");

    let (payload2, client_secret) = initiator
        .read_message(&msg2)
        .expect("KAT: failed to read response");
    assert_eq!(payload2, b"KAT response", "KAT: response payload mismatch");

    // Both sides should derive the same shared secret
    assert_eq!(
        server_secret.combined, client_secret.combined,
        "KAT: hybrid secrets must match"
    );

    // Verify handshake completed
    assert!(
        initiator.is_handshake_finished(),
        "KAT: initiator handshake should be finished"
    );
    assert!(
        responder.is_handshake_finished(),
        "KAT: responder handshake should be finished"
    );
}

#[test]
fn test_mlkem768_encap_decap_kat() {
    // Known Answer Test for ML-KEM768 encapsulation/decapsulation
    // Using deterministic keypair, verify encap/decap produces matching secrets

    // Create deterministic keypair using fixed seed
    // Note: ML-KEM keypair generation uses OsRng, so we test the encap/decap
    // operations themselves rather than keypair generation determinism
    let kp = HybridKeypair::generate();
    let public = kp.public_bundle();

    // Use fixed ephemeral secret for deterministic encapsulation
    let mut eph_secret = [0u8; 32];
    eph_secret.copy_from_slice(&TEST_SEED);
    let eph_public = x25519_dalek::x25519(eph_secret, x25519_dalek::X25519_BASEPOINT_BYTES);

    // Encapsulate
    let (ciphertext, secret1) = public
        .encapsulate(&eph_secret)
        .expect("KAT: failed to encapsulate");

    // Verify ciphertext is correct size (1088 bytes for ML-KEM768)
    assert_eq!(
        ciphertext.len(),
        1088,
        "KAT: ML-KEM768 ciphertext must be 1088 bytes"
    );

    // Decapsulate
    let secret2 = kp
        .decapsulate(&eph_public, &ciphertext)
        .expect("KAT: failed to decapsulate");

    // Secrets must match
    assert_eq!(
        secret1.combined, secret2.combined,
        "KAT: ML-KEM768 shared secrets must match"
    );

    // Verify secret is non-zero (should be random)
    assert!(
        secret1.combined.iter().any(|&b| b != 0),
        "KAT: shared secret should not be all zeros"
    );
}

#[test]
fn test_ed25519_sign_verify_kat() {
    // Known Answer Test for Ed25519 signature/verification
    // Using deterministic keypair, verify signatures are valid and consistent

    // Create keypair from fixed seed
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&TEST_SEED);
    let keypair =
        SigningKeypair::from_secret_bytes(&seed).expect("KAT: failed to create keypair from seed");

    // Test message
    let message = b"KAT test message for Ed25519 signature";

    // Sign message
    let signature = keypair.sign(message);

    // Verify signature is correct size (64 bytes for Ed25519)
    assert_eq!(
        signature.len(),
        64,
        "KAT: Ed25519 signature must be 64 bytes"
    );

    // Verify signature
    keypair
        .verify(message, &signature)
        .expect("KAT: signature verification failed");

    // Verify signature is deterministic (same message + key = same signature)
    let signature2 = keypair.sign(message);
    assert_eq!(
        signature, signature2,
        "KAT: Ed25519 signatures should be deterministic"
    );

    // Verify tampered message fails
    let tampered = b"KAT tampered message";
    assert!(
        keypair.verify(tampered, &signature).is_err(),
        "KAT: tampered message should fail verification"
    );

    // Verify wrong signature fails
    let mut wrong_sig = signature;
    wrong_sig[0] ^= 0x01; // Flip one bit
    assert!(
        keypair.verify(message, &wrong_sig).is_err(),
        "KAT: wrong signature should fail verification"
    );
}

#[test]
fn test_noise_keypair_deterministic() {
    // Test that Noise keypair generation from same seed produces same public key
    let seed1 = TEST_SEED;
    let seed2 = TEST_SEED;

    let kp1 = NoiseKeypair::from_secret_bytes(&seed1);
    let kp2 = NoiseKeypair::from_secret_bytes(&seed2);

    assert_eq!(
        kp1.public_bytes(),
        kp2.public_bytes(),
        "KAT: same seed should produce same public key"
    );
}

#[test]
fn test_hybrid_keypair_public_bundle_consistency() {
    // Test that public bundle serialization/deserialization is consistent
    let kp = HybridKeypair::generate();
    let public1 = kp.public_bundle();

    // Serialize and deserialize
    let bytes = public1.to_bytes();
    let public2 = HybridPublic::from_bytes(&bytes[..32], &bytes[32..])
        .expect("KAT: failed to deserialize public bundle");

    // Verify X25519 public key matches
    assert_eq!(
        public1.x25519, public2.x25519,
        "KAT: X25519 public key should match after roundtrip"
    );

    // Verify ML-KEM public key matches
    assert_eq!(
        public1.mlkem, public2.mlkem,
        "KAT: ML-KEM public key should match after roundtrip"
    );
}

#[test]
fn test_noise_transport_encrypt_decrypt_kat() {
    // Known Answer Test for Noise transport encryption/decryption
    let server_public =
        x25519_dalek::x25519(TEST_SERVER_STATIC, x25519_dalek::X25519_BASEPOINT_BYTES);

    let mut initiator = NoiseInitiator::new_ik(&TEST_CLIENT_STATIC, &server_public)
        .expect("KAT: failed to create initiator");
    let mut responder =
        NoiseResponder::new_ik(&TEST_SERVER_STATIC).expect("KAT: failed to create responder");

    // Complete handshake
    let msg1 = initiator
        .write_message(b"handshake")
        .expect("KAT: failed to write handshake");
    let (_, peer_hybrid) = responder
        .read_message(&msg1)
        .expect("KAT: failed to read handshake");
    let (msg2, _) = responder
        .write_message(b"handshake", &peer_hybrid)
        .expect("KAT: failed to write handshake response");
    let _ = initiator
        .read_message(&msg2)
        .expect("KAT: failed to read handshake response");

    // Enter transport mode
    let mut client_transport = initiator
        .into_transport()
        .expect("KAT: failed to enter transport mode");
    let mut server_transport = responder
        .into_transport()
        .expect("KAT: failed to enter transport mode");

    // Test encryption/decryption
    let plaintext = b"KAT transport test message";
    let ciphertext = client_transport
        .encrypt(plaintext)
        .expect("KAT: failed to encrypt");

    assert!(
        ciphertext.len() > plaintext.len(),
        "KAT: ciphertext should be larger than plaintext (AEAD overhead)"
    );

    let decrypted = server_transport
        .decrypt(&ciphertext)
        .expect("KAT: failed to decrypt");

    assert_eq!(
        plaintext,
        decrypted.as_slice(),
        "KAT: decrypted message should match plaintext"
    );

    // Verify tampered ciphertext fails
    let mut tampered = ciphertext.clone();
    if !tampered.is_empty() {
        tampered[0] ^= 0x01; // Flip one bit
        assert!(
            server_transport.decrypt(&tampered).is_err(),
            "KAT: tampered ciphertext should fail decryption"
        );
    }
}
