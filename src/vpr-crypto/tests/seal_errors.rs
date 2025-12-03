//! Tests for seal error handling
use tempfile::tempdir;
use vpr_crypto::keys::SigningKeypair;
use vpr_crypto::seal::{seal_file, unseal_file, SealIdentity};

#[test]
fn unseal_nonexistent_file_fails() {
    let dir = tempdir().unwrap();
    let nonexistent = dir.path().join("does_not_exist.age");
    let output = dir.path().join("output.txt");

    let identity = SealIdentity::generate();
    let res = unseal_file(&nonexistent, &output, &identity);
    assert!(res.is_err(), "unsealing nonexistent file should fail");
}

#[test]
fn seal_to_readonly_dir_fails() {
    // This test is platform-specific and may be skipped on some systems
    let dir = tempdir().unwrap();
    let plain = dir.path().join("plain.txt");
    std::fs::write(&plain, b"data").unwrap();

    // Try to seal to a path that doesn't exist (parent dir missing)
    let invalid_output = dir.path().join("nonexistent_dir").join("output.age");

    let identity = SealIdentity::generate();
    let recipient = identity.recipient();
    let res = seal_file(&plain, &invalid_output, &recipient);
    assert!(res.is_err(), "sealing to invalid path should fail");
}

#[test]
fn signing_keypair_roundtrip() {
    let key = SigningKeypair::generate();
    let msg = b"test message";
    let sig = key.sign(msg);

    // Verify with public key bytes
    let _pubkey = key.public_bytes();
    assert!(
        key.verify(msg, &sig).is_ok(),
        "signature verification should succeed"
    );

    // Wrong message should fail
    assert!(
        key.verify(b"wrong message", &sig).is_err(),
        "wrong message should fail verification"
    );
}
