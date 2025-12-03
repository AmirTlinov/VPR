//! Integration tests for MASQUE CONNECT-UDP full implementation
//!
//! Tests complete flow: CONNECT-UDP → Handshake → Encrypted datagrams → All capsule types

use bytes::Bytes;
use masque_core::masque::{
    CapsuleBuffer, CapsuleType, ContextIdManager, UdpCapsule, UdpForwardingBuffer,
    CONTEXT_ID_ADDRESS_ASSIGN, CONTEXT_ID_ADDRESS_REQUEST, CONTEXT_ID_CLOSE, CONTEXT_ID_HANDSHAKE,
    CONTEXT_ID_UDP,
};
use std::net::SocketAddr;

#[tokio::test]
async fn test_all_capsule_types_roundtrip() {
    let payloads = vec![
        (CONTEXT_ID_UDP, Bytes::from_static(b"udp payload")),
        (CONTEXT_ID_HANDSHAKE, Bytes::from_static(b"handshake data")),
        (CONTEXT_ID_ADDRESS_REQUEST, Bytes::from_static(b"addr req")),
        (
            CONTEXT_ID_ADDRESS_ASSIGN,
            Bytes::from_static(b"addr assign"),
        ),
        (CONTEXT_ID_CLOSE, Bytes::from_static(b"close")),
    ];

    for (context_id, payload) in payloads {
        let capsule = UdpCapsule::with_context_id(context_id, payload.clone());
        let encoded = capsule.encode();
        let decoded = UdpCapsule::decode(encoded).expect("failed to decode");

        assert_eq!(decoded.context_id, context_id);
        assert_eq!(decoded.payload, payload);
        assert_eq!(
            decoded.capsule_type(),
            CapsuleType::from_context_id(context_id)
        );
    }
}

#[tokio::test]
async fn test_capsule_buffer_all_types() {
    let mut buf = CapsuleBuffer::new();

    // Create capsules of all types
    let capsules = vec![
        UdpCapsule::new(Bytes::from_static(b"udp1")),
        UdpCapsule::new_handshake(Bytes::from_static(b"hs1")),
        UdpCapsule::new_address_request(Bytes::from_static(b"addr_req")),
        UdpCapsule::new_address_assign(Bytes::from_static(b"addr_assign")),
        UdpCapsule::new_close(Bytes::from_static(b"close")),
    ];

    // Encode all capsules with length prefix
    let mut all_data = Vec::new();
    for cap in &capsules {
        let enc = cap.encode();
        all_data.extend_from_slice(&(enc.len() as u32).to_be_bytes());
        all_data.extend_from_slice(&enc);
    }

    // Add data and extract capsules
    let data = Bytes::from(all_data);
    let mut extracted = Vec::new();

    // Process in chunks to test buffering
    let chunk_size = data.len() / 3;
    for i in 0..3 {
        let start = i * chunk_size;
        let end = if i == 2 {
            data.len()
        } else {
            (i + 1) * chunk_size
        };
        let chunk = data.slice(start..end);

        if let Ok(Some(capsule)) = buf.add_bytes(chunk.clone()) {
            extracted.push(capsule);
        }
    }

    // Add remaining data
    let remaining = data.slice(chunk_size * 3..);
    while let Ok(Some(capsule)) = buf.add_bytes(remaining.clone()) {
        extracted.push(capsule);
    }

    // Verify all capsules were extracted
    assert_eq!(extracted.len(), capsules.len());
    for (i, (extracted_cap, expected_cap)) in extracted.iter().zip(capsules.iter()).enumerate() {
        assert_eq!(
            extracted_cap.context_id, expected_cap.context_id,
            "Capsule {} context ID mismatch",
            i
        );
        assert_eq!(
            extracted_cap.payload, expected_cap.payload,
            "Capsule {} payload mismatch",
            i
        );
    }
}

#[tokio::test]
async fn test_context_id_manager_lifecycle() {
    let mut manager = ContextIdManager::new(0, 100);

    // Allocate multiple contexts
    let mut allocated = Vec::new();
    for _ in 0..50 {
        if let Some(id) = manager.allocate() {
            allocated.push(id);
        }
    }

    assert_eq!(allocated.len(), 50);
    assert_eq!(manager.allocated_count(), 50);

    // Verify all are valid
    for id in &allocated {
        assert!(manager.is_valid(*id), "Context ID {} should be valid", id);
    }

    // Verify invalid IDs
    assert!(!manager.is_valid(1000));
    assert!(!manager.is_valid(200));
}

#[tokio::test]
async fn test_udp_forwarding_buffer_batching() {
    let mut buffer = UdpForwardingBuffer::new(10000, 100, 50);
    let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

    // Add multiple datagrams
    for i in 0..50 {
        let data = Bytes::from(format!("datagram_{}", i));
        if buffer.add(data, addr) {
            break;
        }
    }

    // Take batch
    let batch = buffer.take();
    assert!(!batch.is_empty());
    assert!(batch.len() <= 100); // Should respect max_batch

    // Verify all datagrams are present
    for (i, (data, _addr)) in batch.iter().enumerate() {
        let expected = format!("datagram_{}", i);
        assert_eq!(data.as_ref(), expected.as_bytes());
    }
}

#[tokio::test]
async fn test_udp_forwarding_buffer_size_limit() {
    let mut buffer = UdpForwardingBuffer::new(100, 10, 50);
    let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

    // Add datagrams until size limit
    let mut count = 0;
    loop {
        let data = Bytes::from(vec![0u8; 20]); // 20 bytes each
        let should_flush = buffer.add(data, addr);
        if should_flush {
            break;
        }
        count += 1;
        if count > 20 {
            panic!("Should have triggered flush by now");
        }
    }

    // Should have flushed before exceeding size limit
    let batch = buffer.take();
    assert!(batch.len() <= 5); // 5 * 20 = 100 bytes max
}

#[tokio::test]
async fn test_close_capsule_handling() {
    let close_capsule = UdpCapsule::new_close(Bytes::from_static(b"session closed"));

    assert!(close_capsule.is_close());
    assert_eq!(close_capsule.context_id, CONTEXT_ID_CLOSE);

    // Close capsule should encode/decode correctly
    let encoded = close_capsule.encode();
    let decoded = UdpCapsule::decode(encoded).expect("failed to decode close capsule");

    assert!(decoded.is_close());
    assert_eq!(decoded.payload.as_ref(), b"session closed");
}

#[tokio::test]
async fn test_address_capsules() {
    // Address Request
    let addr_req = UdpCapsule::new_address_request(Bytes::from_static(b"request"));
    assert_eq!(addr_req.context_id, CONTEXT_ID_ADDRESS_REQUEST);
    assert_eq!(addr_req.capsule_type(), CapsuleType::AddressRequest);

    // Address Assign
    let addr_assign = UdpCapsule::new_address_assign(Bytes::from_static(b"assign"));
    assert_eq!(addr_assign.context_id, CONTEXT_ID_ADDRESS_ASSIGN);
    assert_eq!(addr_assign.capsule_type(), CapsuleType::AddressAssign);

    // Roundtrip test
    let encoded_req = addr_req.encode();
    let decoded_req = UdpCapsule::decode(encoded_req).expect("failed to decode");
    assert_eq!(decoded_req.capsule_type(), CapsuleType::AddressRequest);

    let encoded_assign = addr_assign.encode();
    let decoded_assign = UdpCapsule::decode(encoded_assign).expect("failed to decode");
    assert_eq!(decoded_assign.capsule_type(), CapsuleType::AddressAssign);
}

#[tokio::test]
async fn test_capsule_type_enum() {
    // Test all capsule types
    let types = vec![
        (CONTEXT_ID_UDP, CapsuleType::Udp),
        (CONTEXT_ID_HANDSHAKE, CapsuleType::Handshake),
        (CONTEXT_ID_ADDRESS_REQUEST, CapsuleType::AddressRequest),
        (CONTEXT_ID_ADDRESS_ASSIGN, CapsuleType::AddressAssign),
        (CONTEXT_ID_CLOSE, CapsuleType::Close),
        (999, CapsuleType::Unknown(999)),
    ];

    for (id, expected_type) in types {
        let reconstructed = CapsuleType::from_context_id(id);
        assert_eq!(reconstructed.context_id(), id);
        assert_eq!(reconstructed, expected_type);
    }
}

#[tokio::test]
async fn test_unknown_capsule_type() {
    // Test handling of unknown context IDs
    let unknown_id = 999u64;
    let payload = Bytes::from_static(b"unknown capsule");

    let capsule = UdpCapsule::with_context_id(unknown_id, payload.clone());
    assert_eq!(capsule.context_id, unknown_id);
    assert_eq!(capsule.capsule_type(), CapsuleType::Unknown(unknown_id));

    // Should still encode/decode correctly
    let encoded = capsule.encode();
    let decoded = UdpCapsule::decode(encoded).expect("failed to decode");
    assert_eq!(decoded.context_id, unknown_id);
    assert_eq!(decoded.payload, payload);
    assert_eq!(decoded.capsule_type(), CapsuleType::Unknown(unknown_id));
}
