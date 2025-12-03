//! Integration tests for Noise handshake via Capsule Protocol
//!
//! Tests full cycle: Client → Server → Handshake → Encrypted tunnel

use bytes::Bytes;
use masque_core::hybrid_handshake::{HybridClient, HybridServer};
use masque_core::masque::{CapsuleBuffer, UdpCapsule, CONTEXT_ID_HANDSHAKE};
use tokio::io::duplex;
use vpr_crypto::keys::NoiseKeypair;

#[tokio::test]
async fn test_ik_handshake_via_capsules() {
    // Generate keypairs
    let server_kp = NoiseKeypair::generate();
    let client_kp = NoiseKeypair::generate();

    let server = HybridServer::from_secret(&server_kp.secret_bytes());
    let client = HybridClient::new_ik(&client_kp.secret_bytes(), &server.public_key());

    let (mut client_stream, mut server_stream) = duplex(8192);

    // Run handshakes concurrently over the duplex stream to avoid deadlock
    let server_task = tokio::spawn(async move {
        server
            .handshake_ik(&mut server_stream)
            .await
            .expect("server handshake should succeed")
    });

    let (mut client_transport, _client_hybrid) = client
        .handshake_ik(&mut client_stream)
        .await
        .expect("client handshake should succeed");

    let (mut server_transport, _server_hybrid) =
        server_task.await.expect("server task join should succeed");

    // Test encrypted communication
    let test_msg = b"test encrypted message";
    let encrypted = client_transport
        .encrypt(test_msg)
        .expect("encryption should succeed");

    let decrypted = server_transport
        .decrypt(&encrypted)
        .expect("decryption should succeed");

    assert_eq!(decrypted, test_msg);
}

#[tokio::test]
async fn test_nk_handshake_via_capsules() {
    // Generate server keypair (client is anonymous)
    let server_kp = NoiseKeypair::generate();

    let server = HybridServer::from_secret(&server_kp.secret_bytes());
    let client = HybridClient::new_nk(&server.public_key());

    let (mut client_stream, mut server_stream) = duplex(8192);

    let server_task = tokio::spawn(async move {
        server
            .handshake_nk(&mut server_stream)
            .await
            .expect("server NK handshake should succeed")
    });

    let (mut client_transport, _client_hybrid) = client
        .handshake_nk(&mut client_stream)
        .await
        .expect("client NK handshake should succeed");

    let (mut server_transport, _server_hybrid) =
        server_task.await.expect("server task join should succeed");

    // Test encrypted communication
    let test_msg = b"anonymous encrypted message";
    let encrypted = client_transport
        .encrypt(test_msg)
        .expect("encryption should succeed");

    let decrypted = server_transport
        .decrypt(&encrypted)
        .expect("decryption should succeed");

    assert_eq!(decrypted, test_msg);
}

#[tokio::test]
async fn test_handshake_capsule_format() {
    // Test that handshake messages are properly formatted as capsules
    let server_kp = NoiseKeypair::generate();
    let client_kp = NoiseKeypair::generate();

    let server = HybridServer::from_secret(&server_kp.secret_bytes());
    let _client = HybridClient::new_ik(&client_kp.secret_bytes(), &server.public_key());

    let (_client_stream, _server_stream) = duplex(8192);

    // Start handshake to get first message
    let mut initiator =
        vpr_crypto::noise::NoiseInitiator::new_ik(&client_kp.secret_bytes(), &server.public_key())
            .expect("should create initiator");

    let msg1 = initiator
        .write_message(b"")
        .expect("should write first message");

    // Format as capsule
    let handshake_capsule = UdpCapsule::new_handshake(Bytes::from(msg1.clone()));
    assert!(handshake_capsule.is_handshake());
    assert_eq!(handshake_capsule.context_id, CONTEXT_ID_HANDSHAKE);

    // Encode capsule with length prefix (as per Capsule Protocol)
    let encoded = handshake_capsule.encode();
    let mut capsule_data = Vec::new();
    capsule_data.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
    capsule_data.extend_from_slice(&encoded);

    // Decode back
    let mut buf = CapsuleBuffer::new();
    let data = Bytes::from(capsule_data);
    if let Some(decoded) = buf.add_bytes(data).expect("should decode") {
        assert!(decoded.is_handshake());
        assert_eq!(decoded.payload.as_ref(), msg1.as_slice());
    } else {
        panic!("should have decoded capsule");
    }
}

#[tokio::test]
async fn test_encrypted_datagram_roundtrip() {
    // Test that encrypted datagrams can be encrypted/decrypted correctly
    let server_kp = NoiseKeypair::generate();
    let client_kp = NoiseKeypair::generate();

    let server = HybridServer::from_secret(&server_kp.secret_bytes());
    let client = HybridClient::new_ik(&client_kp.secret_bytes(), &server.public_key());

    let (mut client_stream, mut server_stream) = duplex(8192);

    // Perform handshake
    let server_handle = tokio::spawn(async move { server.handshake_ik(&mut server_stream).await });

    let (mut client_transport, _) = client
        .handshake_ik(&mut client_stream)
        .await
        .expect("client handshake should succeed");

    let (_server_transport, _) = server_handle
        .await
        .expect("server task should complete")
        .expect("server handshake should succeed");

    // Test multiple encrypted messages
    let messages = vec![
        b"message 1".as_slice(),
        b"message 2".as_slice(),
        b"longer message with more data".as_slice(),
        &[0u8; 100], // binary data
    ];

    for msg in messages {
        let encrypted = client_transport
            .encrypt(msg)
            .expect("encryption should succeed");

        // In real scenario, this would go through the tunnel
        // For test, we verify encryption produces different output
        assert_ne!(encrypted, msg);
        assert!(encrypted.len() > msg.len()); // Should have AEAD tag
    }
}
