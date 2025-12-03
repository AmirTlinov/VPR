//! Property-based tests for cryptography
//!
//! Uses proptest to generate test vectors and verify properties

use masque_core::hybrid_handshake::{HybridClient, HybridServer};
use proptest::prelude::*;
use tokio::io::duplex;
use vpr_crypto::keys::NoiseKeypair;

proptest! {
    #[test]
    fn test_noise_handshake_ik_properties(
        client_secret in prop::array::uniform32(0u8..),
        server_secret in prop::array::uniform32(0u8..),
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let server = HybridServer::from_secret(&server_secret);
            let client = HybridClient::new_ik(&client_secret, &server.public_key());

            let (mut client_stream, mut server_stream) = duplex(8192);

            let server_handle = tokio::spawn(async move {
                server.handshake_ik(&mut server_stream).await
            });

            let client_result = client.handshake_ik(&mut client_stream).await;
            let server_result = server_handle.await.expect("server task should complete");

            let (mut client_transport, client_hybrid) = client_result.expect("client handshake should succeed");
            let (mut server_transport, server_hybrid) = server_result.expect("server handshake should succeed");

            // Hybrid secrets should match
            prop_assert_eq!(client_hybrid.combined, server_hybrid.combined);

            // Test encryption/decryption roundtrip
            let test_msg = b"test message";
            let encrypted = client_transport.encrypt(test_msg).expect("encryption should succeed");
            let decrypted = server_transport.decrypt(&encrypted).expect("decryption should succeed");
            prop_assert_eq!(decrypted.clone(), test_msg.to_vec());
            Ok(())
        })?;
    }

    #[test]
    fn test_noise_handshake_nk_properties(
        server_secret in prop::array::uniform32(0u8..),
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let server = HybridServer::from_secret(&server_secret);
            let client = HybridClient::new_nk(&server.public_key());

            let (mut client_stream, mut server_stream) = duplex(8192);

            let server_handle = tokio::spawn(async move {
                server.handshake_nk(&mut server_stream).await
            });

            let client_result = client.handshake_nk(&mut client_stream).await;
            let server_result = server_handle.await.expect("server task should complete");

            let (mut client_transport, client_hybrid) = client_result.expect("client NK handshake should succeed");
            let (mut server_transport, server_hybrid) = server_result.expect("server NK handshake should succeed");

            // Hybrid secrets should match
            prop_assert_eq!(client_hybrid.combined, server_hybrid.combined);

            // Test encryption/decryption
            let test_msg = b"anonymous test";
            let encrypted = client_transport.encrypt(test_msg).expect("encryption should succeed");
            let decrypted = server_transport.decrypt(&encrypted).expect("decryption should succeed");
            prop_assert_eq!(decrypted.clone(), test_msg.to_vec());
            Ok(())
        })?;
    }

    #[test]
    fn test_encryption_decryption_properties(
        message in prop::collection::vec(any::<u8>(), 0..1024),
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let server_kp = NoiseKeypair::generate();
            let client_kp = NoiseKeypair::generate();

            let server = HybridServer::from_secret(&server_kp.secret_bytes());
            let client = HybridClient::new_ik(&client_kp.secret_bytes(), &server.public_key());

            let (mut client_stream, mut server_stream) = duplex(8192);

            let server_handle = tokio::spawn(async move {
                server.handshake_ik(&mut server_stream).await
            });

            let (mut client_transport, _) = client
                .handshake_ik(&mut client_stream)
                .await
                .expect("client handshake should succeed");

            let (mut server_transport, _) = server_handle
                .await
                .expect("server task should complete")
                .expect("server handshake should succeed");

            // Encrypt message
            let encrypted = client_transport
                .encrypt(&message)
                .expect("encryption should succeed");

            // Encrypted should be different from plaintext (unless empty)
            if !message.is_empty() {
                prop_assert_ne!(encrypted.clone(), message.clone());
            }

            // Decrypt
            let decrypted = server_transport
                .decrypt(&encrypted)
                .expect("decryption should succeed");

            // Should match original
            prop_assert_eq!(decrypted.clone(), message.clone());
            Ok(())
        })?;
    }
}

// Non-property tests (no input parameters) - outside proptest! macro
#[cfg(test)]
mod deterministic_tests {
    use vpr_crypto::keys::NoiseKeypair;
    use vpr_crypto::noise::HybridKeypair;

    #[test]
    fn test_noise_keypair_generation_uniqueness() {
        // Generate multiple keypairs and verify they're different
        let kp1 = NoiseKeypair::generate();
        let kp2 = NoiseKeypair::generate();
        let kp3 = NoiseKeypair::generate();

        assert_ne!(kp1.public_bytes(), kp2.public_bytes());
        assert_ne!(kp2.public_bytes(), kp3.public_bytes());
        assert_ne!(kp1.public_bytes(), kp3.public_bytes());

        assert_ne!(kp1.secret_bytes(), kp2.secret_bytes());
        assert_ne!(kp2.secret_bytes(), kp3.secret_bytes());
        assert_ne!(kp1.secret_bytes(), kp3.secret_bytes());
    }

    #[test]
    fn test_mlkem768_keypair_properties() {
        // Generate multiple hybrid keypairs
        let kp1 = HybridKeypair::generate();
        let kp2 = HybridKeypair::generate();
        let kp3 = HybridKeypair::generate();

        let pub1 = kp1.public_bundle();
        let pub2 = kp2.public_bundle();
        let pub3 = kp3.public_bundle();

        // Public keys should be different
        assert_ne!(pub1.x25519, pub2.x25519);
        assert_ne!(pub2.x25519, pub3.x25519);
        assert_ne!(pub1.mlkem, pub2.mlkem);
        assert_ne!(pub2.mlkem, pub3.mlkem);

        // ML-KEM public keys should be correct size (1184 bytes for ML-KEM768)
        assert_eq!(pub1.mlkem.len(), 1184);
        assert_eq!(pub2.mlkem.len(), 1184);
        assert_eq!(pub3.mlkem.len(), 1184);

        // X25519 public keys should be 32 bytes
        assert_eq!(pub1.x25519.len(), 32);
        assert_eq!(pub2.x25519.len(), 32);
        assert_eq!(pub3.x25519.len(), 32);
    }

    #[test]
    fn test_mlkem768_encapsulation_properties() {
        // Generate keypair
        let kp = HybridKeypair::generate();
        let public = kp.public_bundle();

        // Encapsulate to public key
        let (ciphertext, shared_secret1) = public
            .encapsulate(&kp.x25519_secret)
            .expect("encapsulation should succeed");

        // Ciphertext should be correct size (1088 bytes for ML-KEM768)
        assert_eq!(ciphertext.len(), 1088);

        // Decapsulate
        let shared_secret2 = kp
            .decapsulate(&public.x25519, &ciphertext)
            .expect("decapsulation should succeed");

        // Shared secrets should match
        assert_eq!(shared_secret1.combined, shared_secret2.combined);
    }
}
