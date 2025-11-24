//! Tests for seal/unseal tampering detection
use tempfile::tempdir;
use vpr_crypto::seal::{seal_file, unseal_file, SealIdentity};

#[test]
fn tampered_ciphertext_fails_unseal() {
    let dir = tempdir().unwrap();
    let plain = dir.path().join("plain.txt");
    let sealed = dir.path().join("sealed.age");
    let output = dir.path().join("output.txt");

    // Create identity and recipient
    let identity = SealIdentity::generate();
    let recipient = identity.to_recipient();

    // Write plaintext and seal it
    std::fs::write(&plain, b"secret data").unwrap();
    seal_file(&plain, &sealed, &recipient).expect("seal should succeed");

    // Tamper with sealed file (flip some bytes in the middle)
    let mut data = std::fs::read(&sealed).unwrap();
    if data.len() > 50 {
        data[50] ^= 0xFF;
        std::fs::write(&sealed, &data).unwrap();
    }

    // Unseal should fail due to tampering
    let res = unseal_file(&sealed, &output, &identity);
    assert!(res.is_err(), "tampered ciphertext should fail to decrypt");
}

#[test]
fn wrong_identity_fails_unseal() {
    let dir = tempdir().unwrap();
    let plain = dir.path().join("plain.txt");
    let sealed = dir.path().join("sealed.age");
    let output = dir.path().join("output.txt");

    // Create two different identities
    let identity1 = SealIdentity::generate();
    let identity2 = SealIdentity::generate();
    let recipient1 = identity1.to_recipient();

    // Seal with identity1's recipient
    std::fs::write(&plain, b"secret").unwrap();
    seal_file(&plain, &sealed, &recipient1).expect("seal should succeed");

    // Try to unseal with identity2 (wrong key)
    let res = unseal_file(&sealed, &output, &identity2);
    assert!(res.is_err(), "wrong identity should fail to decrypt");
}
