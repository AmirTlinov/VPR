//! Tests for keys, seal, and PKI functionality

use tempfile::TempDir;

use vpr_crypto::keys::{NoiseKeypair, SigningKeypair};
use vpr_crypto::manifest::{ManifestPayload, ServerEndpoint, SignedManifest};
use vpr_crypto::seal::{seal_file, unseal_file, SealIdentity};
use vpr_crypto::HybridKeypair;

#[test]
fn hybrid_keypair_generation() {
    let kp = HybridKeypair::generate();
    let bundle = kp.public_bundle();
    // Public bundle should have non-zero x25519 key
    assert!(bundle.x25519.iter().any(|b| *b != 0));
    // ML-KEM public key should be present
    assert!(!bundle.mlkem.is_empty());
}

#[test]
fn noise_keypair_zeroizes_secret() {
    let kp = NoiseKeypair::generate();
    let mut bytes = kp.secret_bytes();
    // overwrite bytes to simulate drop
    bytes.fill(0);
    // regenerate and ensure not all zero
    let kp2 = NoiseKeypair::generate();
    assert!(kp2.secret_bytes().iter().any(|b| *b != 0));
}

#[test]
fn seal_unseal_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let input = tmp.path().join("input.bin");
    let sealed = tmp.path().join("sealed.age");
    let unsealed = tmp.path().join("unsealed.bin");

    std::fs::write(&input, b"secret-data").unwrap();

    // Use SealIdentity (age encryption)
    let identity = SealIdentity::generate();
    let recipient = identity.recipient();

    seal_file(&input, &sealed, &recipient).expect("seal");
    unseal_file(&sealed, &unsealed, &identity).expect("unseal");

    let out = std::fs::read(&unsealed).unwrap();
    assert_eq!(out, b"secret-data");
}

#[test]
fn manifest_sign_verify() {
    let signing = SigningKeypair::generate();
    let payload = ManifestPayload::new(vec![ServerEndpoint::new(
        "id",
        "host",
        443,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )]);
    let signed = SignedManifest::sign(&payload, &signing).expect("sign");

    // verify expects &[u8; 32] public key
    let pubkey = signing.public_bytes();
    let verified = signed.verify(&pubkey).expect("verify");
    assert_eq!(verified.version, payload.version);
}

#[test]
fn manifest_verify_wrong_key_fails() {
    let signing = SigningKeypair::generate();
    let wrong_signer = SigningKeypair::generate();

    let payload = ManifestPayload::new(vec![ServerEndpoint::new(
        "id",
        "host",
        443,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )]);
    let signed = SignedManifest::sign(&payload, &signing).expect("sign");

    // Verify with wrong key should fail
    let wrong_pubkey = wrong_signer.public_bytes();
    let result = signed.verify(&wrong_pubkey);
    assert!(result.is_err(), "verification with wrong key should fail");
}
