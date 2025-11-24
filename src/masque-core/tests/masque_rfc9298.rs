//! RFC 9298 MASQUE CONNECT-UDP compliance tests
//!
//! Tests for full cycle: CONNECT-UDP → Handshake → Encrypted datagrams

use bytes::Bytes;
use masque_core::masque::{CapsuleBuffer, UdpCapsule, CONTEXT_ID_HANDSHAKE, CONTEXT_ID_UDP};

#[tokio::test]
async fn test_handshake_capsule_roundtrip() {
    let payload = Bytes::from_static(b"handshake message");
    let capsule = UdpCapsule::new_handshake(payload.clone());

    assert!(capsule.is_handshake());
    assert!(!capsule.is_udp());
    assert_eq!(capsule.context_id, CONTEXT_ID_HANDSHAKE);

    let encoded = capsule.encode();
    let decoded = UdpCapsule::decode(encoded).expect("failed to decode handshake capsule");

    assert_eq!(decoded.context_id, CONTEXT_ID_HANDSHAKE);
    assert_eq!(decoded.payload, payload);
    assert!(decoded.is_handshake());
}

#[tokio::test]
async fn test_udp_capsule_roundtrip() {
    let payload = Bytes::from_static(b"udp payload data");
    let capsule = UdpCapsule::new(payload.clone());

    assert!(capsule.is_udp());
    assert!(!capsule.is_handshake());
    assert_eq!(capsule.context_id, CONTEXT_ID_UDP);

    let encoded = capsule.encode();
    let decoded = UdpCapsule::decode(encoded).expect("failed to decode UDP capsule");

    assert_eq!(decoded.context_id, CONTEXT_ID_UDP);
    assert_eq!(decoded.payload, payload);
    assert!(decoded.is_udp());
}

#[tokio::test]
async fn test_capsule_buffer_multiple_capsules() {
    let mut buf = CapsuleBuffer::new();

    // Create two capsules
    let cap1 = UdpCapsule::new_handshake(Bytes::from_static(b"handshake1"));
    let cap2 = UdpCapsule::new(Bytes::from_static(b"udp1"));

    // Encode with length prefix
    let mut data = Vec::new();
    let enc1 = cap1.encode();
    data.extend_from_slice(&(enc1.len() as u32).to_be_bytes());
    data.extend_from_slice(&enc1);

    let enc2 = cap2.encode();
    data.extend_from_slice(&(enc2.len() as u32).to_be_bytes());
    data.extend_from_slice(&enc2);

    // Add data in chunks to test buffering
    let split_point = data.len() / 2;
    let chunk1 = Bytes::copy_from_slice(&data[..split_point]);
    let chunk2 = Bytes::copy_from_slice(&data[split_point..]);

    // First chunk - should not yield complete capsule yet
    let result1 = buf.add_bytes(chunk1).expect("failed to add first chunk");
    assert!(result1.is_none(), "should not have complete capsule yet");

    // Second chunk - should yield first capsule
    let result2 = buf.add_bytes(chunk2).expect("failed to add second chunk");
    let cap1_decoded = result2.expect("should have first capsule");
    assert!(cap1_decoded.is_handshake());
    assert_eq!(cap1_decoded.payload.as_ref(), b"handshake1");

    // Should have second capsule available
    let result3 = buf.add_bytes(Bytes::new()).expect("failed to check buffer");
    let cap2_decoded = result3.expect("should have second capsule");
    assert!(cap2_decoded.is_udp());
    assert_eq!(cap2_decoded.payload.as_ref(), b"udp1");
}

#[tokio::test]
async fn test_capsule_buffer_partial_length() {
    let mut buf = CapsuleBuffer::new();

    let cap = UdpCapsule::new(Bytes::from_static(b"test"));
    let enc = cap.encode();
    let mut data = Vec::new();
    data.extend_from_slice(&(enc.len() as u32).to_be_bytes());
    data.extend_from_slice(&enc);

    // Add only first 2 bytes of length prefix
    let partial = Bytes::copy_from_slice(&data[..2]);
    let result = buf.add_bytes(partial).expect("failed to add partial data");
    assert!(result.is_none(), "should not have complete capsule");

    // Add remaining data
    let remaining = Bytes::copy_from_slice(&data[2..]);
    let result = buf
        .add_bytes(remaining)
        .expect("failed to add remaining data");
    let decoded = result.expect("should have complete capsule");
    assert_eq!(decoded.payload.as_ref(), b"test");
}

#[tokio::test]
async fn test_different_context_ids() {
    // Test UDP context ID
    let udp_cap = UdpCapsule::new(Bytes::from_static(b"udp"));
    assert_eq!(udp_cap.context_id, CONTEXT_ID_UDP);
    assert!(udp_cap.is_udp());

    // Test handshake context ID
    let hs_cap = UdpCapsule::new_handshake(Bytes::from_static(b"handshake"));
    assert_eq!(hs_cap.context_id, CONTEXT_ID_HANDSHAKE);
    assert!(hs_cap.is_handshake());

    // Test custom context ID (should decode but not match standard IDs)
    let mut custom_data = Vec::new();
    custom_data.push(0x02); // varint for 2
    custom_data.extend_from_slice(b"custom");
    let custom_cap = UdpCapsule::decode(Bytes::from(custom_data)).expect("failed to decode");
    assert_eq!(custom_cap.context_id, 2);
    assert!(!custom_cap.is_udp());
    assert!(!custom_cap.is_handshake());
    assert_eq!(
        custom_cap.capsule_type(),
        masque_core::masque::CapsuleType::AddressRequest
    );
}

#[tokio::test]
async fn test_capsule_buffer_empty() {
    let buf = CapsuleBuffer::new();
    assert!(buf.is_empty());

    let mut buf2 = CapsuleBuffer::new();
    // Add partial length prefix (only 2 bytes of 4-byte length)
    let partial_len = Bytes::from_static(&[0x00, 0x00]);
    let result = buf2.add_bytes(partial_len).expect("failed to add");
    assert!(result.is_none());
    // Buffer is not empty because it has partial data
    assert!(!buf2.is_empty());
}

#[tokio::test]
async fn test_capsule_size_limit() {
    // Test that oversized capsules are rejected
    let mut buf = CapsuleBuffer::new();

    // Create a length prefix for oversized capsule (65KB + 1)
    let oversized_len = 65537u32;
    let mut data = Vec::new();
    data.extend_from_slice(&oversized_len.to_be_bytes());

    let result = buf.add_bytes(Bytes::from(data));
    assert!(result.is_err(), "should reject oversized capsule");
    assert!(result.unwrap_err().to_string().contains("too large"));
}

#[tokio::test]
async fn test_multiple_capsules_sequence() {
    let mut buf = CapsuleBuffer::new();

    // Create sequence of capsules
    let capsules = vec![
        UdpCapsule::new_handshake(Bytes::from_static(b"hs1")),
        UdpCapsule::new(Bytes::from_static(b"udp1")),
        UdpCapsule::new_handshake(Bytes::from_static(b"hs2")),
        UdpCapsule::new(Bytes::from_static(b"udp2")),
    ];

    // Encode all capsules
    let mut all_data = Vec::new();
    for cap in &capsules {
        let enc = cap.encode();
        all_data.extend_from_slice(&(enc.len() as u32).to_be_bytes());
        all_data.extend_from_slice(&enc);
    }

    // Add data and extract capsules one by one
    let data = Bytes::from(all_data);
    let mut offset = 0;
    for expected_cap in &capsules {
        // Calculate how much data we need for this capsule
        let enc = expected_cap.encode();
        let needed = 4 + enc.len(); // length prefix + capsule

        if offset + needed <= data.len() {
            let chunk = data.slice(offset..offset + needed);
            let result = buf.add_bytes(chunk).expect("failed to add data");
            let decoded = result.expect("should have capsule");
            assert_eq!(decoded.context_id, expected_cap.context_id);
            assert_eq!(decoded.payload, expected_cap.payload);
            offset += needed;
        }
    }
}

#[tokio::test]
async fn test_capsule_encoding_consistency() {
    // Test that encoding is consistent and can be decoded correctly
    let payloads = vec![
        Bytes::from_static(b""),
        Bytes::from_static(b"a"),
        Bytes::from_static(b"hello world"),
        Bytes::from_static(&[0u8; 100]),
        Bytes::from_static(&[255u8; 1000]),
    ];

    for payload in payloads {
        // Test UDP capsule
        let udp_cap = UdpCapsule::new(payload.clone());
        let encoded = udp_cap.encode();
        let decoded = UdpCapsule::decode(encoded).expect("failed to decode UDP capsule");
        assert_eq!(decoded.payload, payload);
        assert!(decoded.is_udp());

        // Test handshake capsule
        let hs_cap = UdpCapsule::new_handshake(payload.clone());
        let encoded = hs_cap.encode();
        let decoded = UdpCapsule::decode(encoded).expect("failed to decode handshake capsule");
        assert_eq!(decoded.payload, payload);
        assert!(decoded.is_handshake());
    }
}
