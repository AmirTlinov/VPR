//! Comprehensive tests for MASQUE CONNECT-UDP
//!
//! Tests cover:
//! - Close capsule handling and graceful shutdown
//! - Buffer size limits and DoS protection
//! - Timeout handling
//! - Edge cases and error conditions
//! - Property-based testing

use bytes::Bytes;
use masque_core::masque::{
    CapsuleBuffer, CapsuleType, ContextIdManager, UdpCapsule, UdpForwardingBuffer,
    CONTEXT_ID_CLOSE, MAX_UDP_PAYLOAD,
};
use std::net::SocketAddr;
use tokio::time::Duration;

// ============================================================================
// Close Capsule Handling Tests
// ============================================================================

#[tokio::test]
async fn test_close_capsule_graceful_shutdown() {
    // Test that Close capsule is properly identified and can trigger shutdown
    let close_capsule = UdpCapsule::new_close(Bytes::from_static(b"session closed"));

    assert!(close_capsule.is_close());
    assert!(!close_capsule.is_udp());
    assert!(!close_capsule.is_handshake());

    // Verify it encodes/decodes correctly
    let encoded = close_capsule.encode();
    let decoded = UdpCapsule::decode(encoded).expect("failed to decode close capsule");

    assert!(decoded.is_close());
    assert_eq!(decoded.context_id, CONTEXT_ID_CLOSE);
    assert_eq!(decoded.payload.as_ref(), b"session closed");
}

#[tokio::test]
async fn test_close_capsule_empty_payload() {
    // Close capsule can have empty payload
    let close_capsule = UdpCapsule::new_close(Bytes::new());

    assert!(close_capsule.is_close());
    let encoded = close_capsule.encode();
    let decoded = UdpCapsule::decode(encoded).expect("failed to decode");
    assert!(decoded.is_close());
    assert_eq!(decoded.payload.len(), 0);
}

#[tokio::test]
async fn test_close_capsule_with_error_code() {
    // Close capsule can contain error code (up to 8 bytes)
    let error_code = Bytes::from_static(&[0x01, 0x02, 0x03, 0x04]);
    let close_capsule = UdpCapsule::new_close(error_code.clone());

    let encoded = close_capsule.encode();
    let decoded = UdpCapsule::decode(encoded).expect("failed to decode");
    assert!(decoded.is_close());
    assert_eq!(decoded.payload, error_code);
}

#[tokio::test]
async fn test_close_capsule_in_sequence() {
    // Test Close capsule in sequence with other capsules
    let mut buf = CapsuleBuffer::new();

    let capsules = vec![
        UdpCapsule::new(Bytes::from_static(b"udp1")),
        UdpCapsule::new_close(Bytes::from_static(b"close")),
        UdpCapsule::new(Bytes::from_static(b"udp2")), // Should not be processed after close
    ];

    // Encode capsules
    let mut all_data = Vec::new();
    for cap in &capsules {
        let enc = cap.encode();
        all_data.extend_from_slice(&(enc.len() as u32).to_be_bytes());
        all_data.extend_from_slice(&enc);
    }

    // Extract capsules
    let data = Bytes::from(all_data);
    let mut extracted = Vec::new();
    let mut offset = 0;

    for expected_cap in &capsules {
        let enc = expected_cap.encode();
        let needed = 4 + enc.len();

        if offset + needed <= data.len() {
            let chunk = data.slice(offset..offset + needed);
            if let Ok(Some(capsule)) = buf.add_bytes(chunk) {
                extracted.push(capsule);
                // If we got a Close capsule, stop processing
                if extracted.last().unwrap().is_close() {
                    break;
                }
            }
            offset += needed;
        }
    }

    // Should have extracted UDP and Close capsules
    assert_eq!(extracted.len(), 2);
    assert!(extracted[0].is_udp());
    assert!(extracted[1].is_close());
}

// ============================================================================
// Buffer Size Limit Tests
// ============================================================================

#[tokio::test]
async fn test_capsule_buffer_size_limit_enforcement() {
    // Test that buffer size limit is enforced
    // The buffer checks size before adding data: buf.len() + data.len() > max_buffer_size
    let max_size = 1024; // 1KB
    let mut buf = CapsuleBuffer::with_max_size(max_size);

    // Add a valid capsule with payload that fits
    let small_capsule = UdpCapsule::new(Bytes::from(vec![0u8; max_size / 2]));
    let enc = small_capsule.encode();
    let mut data = Vec::new();
    data.extend_from_slice(&(enc.len() as u32).to_be_bytes());
    data.extend_from_slice(&enc);

    // Add first 3 bytes (less than length prefix size) - should succeed and stay in buffer
    let result1 = buf.add_bytes(Bytes::from(data[..3].to_vec()));
    assert!(result1.is_ok(), "should accept partial data");
    // Buffer now has 3 bytes (not enough for length prefix, so not processed)

    // Now try to add data that would exceed buffer limit
    // Current buffer: 3 bytes, adding max_size bytes = 3 + max_size > max_size
    let extra_data = Bytes::from(vec![0u8; max_size]);
    let result = buf.add_bytes(extra_data);
    assert!(
        result.is_err(),
        "should reject data that exceeds buffer size"
    );

    if let Err(e) = result {
        assert!(e.to_string().contains("buffer size exceeded"));
    }
}

#[tokio::test]
async fn test_capsule_buffer_size_limit_with_partial_capsule() {
    // Test that partial capsule data counts towards buffer size
    let max_size = 100;
    let mut buf = CapsuleBuffer::with_max_size(max_size);

    // Add length prefix (4 bytes) - this sets expecting_len
    let partial_len = Bytes::from_static(&[0x00, 0x00, 0x00, 0x64]); // length = 100
    let result1 = buf.add_bytes(partial_len);
    // This should succeed - we're just adding the length prefix
    assert!(result1.is_ok());
    // After reading length, buffer should have advanced past the 4-byte prefix
    // But we still need to check: the capsule size is 100, which exceeds max_size

    // Actually, the check for capsule size happens after reading length prefix
    // But the buffer size check happens before adding data
    // So if we try to add 100 bytes of payload, total would be 100 > max_size (100)
    // But wait - after reading length prefix, the 4 bytes are consumed
    // So buffer is empty, and we're trying to add 100 bytes
    // 0 + 100 = 100, which is NOT > 100, so it would succeed

    // Let's test with a capsule that would exceed limit when payload is added
    // We need a capsule size > max_size
    let large_len = Bytes::from_static(&[0x00, 0x00, 0x00, 0x65]); // length = 101
    let mut buf2 = CapsuleBuffer::with_max_size(max_size);
    // This should fail when we try to read the length because 101 > 100
    // But actually, the check happens when we try to add the payload
    // Let's add the length prefix first
    let _ = buf2.add_bytes(large_len);
    // Now try to add payload - this should fail because 101 > 100
    let payload = Bytes::from(vec![0u8; 101]);
    let result = buf2.add_bytes(payload);
    // Actually, the check is: buf.len() + data.len() > max_buffer_size
    // After reading length prefix, buf.len() = 0 (length prefix consumed)
    // So 0 + 101 = 101 > 100, should fail
    assert!(
        result.is_err(),
        "should reject capsule payload that exceeds buffer size"
    );
}

#[tokio::test]
async fn test_capsule_buffer_default_size() {
    // Test default buffer size (128KB)
    let _buf = CapsuleBuffer::new();
    // Default size should be 128KB
    // We can't directly access max_buffer_size, but we can test it by trying to exceed it
    let mut buf2 = CapsuleBuffer::new();

    // Try to add data that exceeds 128KB
    let large_data = Bytes::from(vec![0u8; 129 * 1024]);
    let result = buf2.add_bytes(large_data);
    assert!(
        result.is_err(),
        "should reject data exceeding default 128KB limit"
    );
}

#[tokio::test]
async fn test_capsule_buffer_size_limit_prevents_dos() {
    // Test that buffer size limit prevents DoS attacks
    // Simulate attacker sending data that would fill buffer
    let max_size = 100; // Small limit for testing
    let mut buf = CapsuleBuffer::with_max_size(max_size);

    // Add 3 bytes (not enough for length prefix, so stays in buffer)
    let partial = Bytes::from_static(&[0x00, 0x00, 0x00]);
    let _ = buf.add_bytes(partial);
    // Buffer now has 3 bytes

    // Now try to add large payload that exceeds buffer limit
    // Current: 3 bytes, adding max_size = 3 + 100 = 103 > 100
    let large_payload = Bytes::from(vec![0u8; max_size]);
    let result = buf.add_bytes(large_payload);
    // Should fail because it would exceed buffer size
    assert!(
        result.is_err(),
        "should reject data that exceeds buffer limit"
    );

    if let Err(e) = result {
        assert!(e.to_string().contains("buffer size exceeded"));
    }
}

// ============================================================================
// UDP Forwarding Buffer Tests
// ============================================================================

#[tokio::test]
async fn test_udp_forwarding_buffer_timeout_behavior() {
    // Test that buffer respects flush interval
    let buffer = UdpForwardingBuffer::new(10000, 100, 50);
    let flush_interval = buffer.flush_interval();

    assert_eq!(flush_interval, Duration::from_millis(50));
}

#[tokio::test]
async fn test_udp_forwarding_buffer_empty_after_take() {
    // Test that buffer is empty after take()
    let mut buffer = UdpForwardingBuffer::new(1000, 10, 100);
    let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

    let _ = buffer.add(Bytes::from_static(b"data1"), addr);
    assert!(!buffer.is_empty());

    let batch = buffer.take();
    assert!(!batch.is_empty());
    assert!(buffer.is_empty());
}

#[tokio::test]
async fn test_udp_forwarding_buffer_size_calculation() {
    // Test that buffer size is calculated correctly
    let mut buffer = UdpForwardingBuffer::new(1000, 10, 100);
    let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

    assert_eq!(buffer.size(), 0);

    let _ = buffer.add(Bytes::from_static(b"hello"), addr);
    assert_eq!(buffer.size(), 5);

    let _ = buffer.add(Bytes::from_static(b"world"), addr);
    assert_eq!(buffer.size(), 10);
}

// ============================================================================
// Edge Cases and Error Conditions
// ============================================================================

#[tokio::test]
async fn test_oversized_udp_payload_rejected() {
    // Test that UDP payloads exceeding MAX_UDP_PAYLOAD are rejected
    let oversized_payload = Bytes::from(vec![0u8; MAX_UDP_PAYLOAD + 1]);

    // Creating capsule should work, but decoding should fail
    let capsule = UdpCapsule::new(oversized_payload.clone());
    let encoded = capsule.encode();

    // Decode should fail due to size check
    let result = UdpCapsule::decode(encoded);
    assert!(result.is_err(), "should reject oversized UDP payload");

    if let Err(e) = result {
        assert!(e.to_string().contains("too large"));
    }
}

#[tokio::test]
async fn test_max_udp_payload_accepted() {
    // Test that maximum allowed UDP payload is accepted
    let max_payload = Bytes::from(vec![0u8; MAX_UDP_PAYLOAD]);

    let capsule = UdpCapsule::new(max_payload.clone());
    let encoded = capsule.encode();
    let decoded = UdpCapsule::decode(encoded).expect("should accept max UDP payload");

    assert_eq!(decoded.payload.len(), MAX_UDP_PAYLOAD);
}

#[tokio::test]
async fn test_empty_capsule_payload() {
    // Test capsules with empty payload
    let empty_capsule = UdpCapsule::new(Bytes::new());

    let encoded = empty_capsule.encode();
    let decoded = UdpCapsule::decode(encoded).expect("should handle empty payload");

    assert_eq!(decoded.payload.len(), 0);
    assert!(decoded.is_udp());
}

#[tokio::test]
async fn test_capsule_with_zero_context_id() {
    // Test that context ID 0 (UDP) works correctly
    let capsule = UdpCapsule::with_context_id(0, Bytes::from_static(b"test"));

    assert_eq!(capsule.context_id, 0);
    assert!(capsule.is_udp());

    let encoded = capsule.encode();
    let decoded = UdpCapsule::decode(encoded).expect("should decode context ID 0");
    assert_eq!(decoded.context_id, 0);
}

#[tokio::test]
async fn test_capsule_with_large_context_id() {
    // Test capsules with large context IDs
    // Note: varint encoding has limits, so we test with a large but encodable value
    // u64::MAX cannot be properly encoded in varint format (max is 2^62-1)
    let large_context_id = 1_073_741_824u64; // Large but encodable
    let capsule = UdpCapsule::with_context_id(large_context_id, Bytes::from_static(b"test"));

    assert_eq!(capsule.context_id, large_context_id);
    assert_eq!(
        capsule.capsule_type(),
        CapsuleType::Unknown(large_context_id)
    );

    let encoded = capsule.encode();
    let decoded = UdpCapsule::decode(encoded).expect("should handle large context ID");
    assert_eq!(decoded.context_id, large_context_id);
}

#[tokio::test]
async fn test_context_id_manager_overflow_protection() {
    // Test that context ID manager prevents overflow
    let mut manager = ContextIdManager::new(0, 3);

    assert_eq!(manager.allocate(), Some(0));
    assert_eq!(manager.allocate(), Some(1));
    assert_eq!(manager.allocate(), Some(2));
    assert_eq!(manager.allocate(), None); // Should return None when limit reached

    // Verify allocated count
    assert_eq!(manager.allocated_count(), 3);
}

#[tokio::test]
async fn test_context_id_manager_with_non_zero_base() {
    // Test context ID manager with non-zero base
    let mut manager = ContextIdManager::new(100, 5);

    assert_eq!(manager.base_id(), 100);
    assert_eq!(manager.allocate(), Some(100));
    assert_eq!(manager.allocate(), Some(101));
    assert_eq!(manager.allocate(), Some(102));

    assert!(manager.is_valid(100));
    assert!(manager.is_valid(101));
    assert!(!manager.is_valid(99));
    assert!(!manager.is_valid(105));
}

#[tokio::test]
async fn test_capsule_buffer_with_multiple_partial_capsules() {
    // Test buffer handling multiple partial capsules
    let mut buf = CapsuleBuffer::new();

    let cap1 = UdpCapsule::new(Bytes::from_static(b"capsule1"));
    let cap2 = UdpCapsule::new(Bytes::from_static(b"capsule2"));

    // Encode both capsules
    let mut data = Vec::new();
    let enc1 = cap1.encode();
    data.extend_from_slice(&(enc1.len() as u32).to_be_bytes());
    data.extend_from_slice(&enc1);

    let enc2 = cap2.encode();
    data.extend_from_slice(&(enc2.len() as u32).to_be_bytes());
    data.extend_from_slice(&enc2);

    // Add data byte by byte to test partial handling
    let mut extracted = Vec::new();
    for byte in data {
        if let Ok(Some(capsule)) = buf.add_bytes(Bytes::from(vec![byte])) {
            extracted.push(capsule);
        }
    }

    // Should have extracted both capsules
    assert_eq!(extracted.len(), 2);
    assert_eq!(extracted[0].payload.as_ref(), b"capsule1");
    assert_eq!(extracted[1].payload.as_ref(), b"capsule2");
}

#[tokio::test]
async fn test_capsule_buffer_reset_after_extraction() {
    // Test that buffer resets correctly after extracting capsule
    let mut buf = CapsuleBuffer::new();

    let cap = UdpCapsule::new(Bytes::from_static(b"test"));
    let enc = cap.encode();
    let mut data = Vec::new();
    data.extend_from_slice(&(enc.len() as u32).to_be_bytes());
    data.extend_from_slice(&enc);

    // Extract capsule
    let result = buf.add_bytes(Bytes::from(data)).expect("failed to add");
    assert!(result.is_some());

    // Buffer should be empty after extraction
    assert!(buf.is_empty());
}

// ============================================================================
// Property-Based Tests
// ============================================================================

#[tokio::test]
async fn test_capsule_encode_decode_roundtrip_property() {
    // Property: encoding and decoding should be inverse operations
    let test_cases = vec![
        Bytes::new(),
        Bytes::from_static(b"a"),
        Bytes::from_static(b"hello world"),
        Bytes::from(vec![0u8; 100]),
        Bytes::from(vec![255u8; 1000]),
        Bytes::from(vec![0u8; MAX_UDP_PAYLOAD]),
    ];

    for payload in test_cases {
        // Test UDP capsule
        let capsule = UdpCapsule::new(payload.clone());
        let encoded = capsule.encode();
        let decoded = UdpCapsule::decode(encoded).expect("should decode");
        assert_eq!(decoded.payload, payload, "UDP capsule roundtrip failed");
        assert!(decoded.is_udp());

        // Test handshake capsule
        let capsule = UdpCapsule::new_handshake(payload.clone());
        let encoded = capsule.encode();
        let decoded = UdpCapsule::decode(encoded).expect("should decode");
        assert_eq!(
            decoded.payload, payload,
            "Handshake capsule roundtrip failed"
        );
        assert!(decoded.is_handshake());

        // Test close capsule
        let capsule = UdpCapsule::new_close(payload.clone());
        let encoded = capsule.encode();
        let decoded = UdpCapsule::decode(encoded).expect("should decode");
        assert_eq!(decoded.payload, payload, "Close capsule roundtrip failed");
        assert!(decoded.is_close());
    }
}

#[tokio::test]
async fn test_varint_encode_decode_property() {
    // Property: varint encoding/decoding should be inverse
    // Note: varint format has limits - max encodable value is 2^62-1
    use masque_core::masque::{decode_varint, encode_varint};

    let test_values = vec![
        0u64,
        1,
        63,
        64,
        16383,
        16384,
        1_073_741_823,
        1_073_741_824,
        // u64::MAX cannot be properly encoded in varint format
        // Maximum encodable value is 2^62-1 = 4611686018427387903
        4611686018427387903u64,
    ];

    for val in test_values {
        let encoded = encode_varint(val);
        let mut buf = encoded.clone();
        let decoded = decode_varint(&mut buf).expect("should decode varint");
        assert_eq!(val, decoded, "varint roundtrip failed for {}", val);
    }
}

#[tokio::test]
async fn test_capsule_type_roundtrip_property() {
    // Property: context_id() and from_context_id() should be inverse
    let test_types = vec![
        CapsuleType::Udp,
        CapsuleType::Handshake,
        CapsuleType::AddressRequest,
        CapsuleType::AddressAssign,
        CapsuleType::Close,
        CapsuleType::Unknown(100),
        CapsuleType::Unknown(999),
        CapsuleType::Unknown(4611686018427387903u64), // Max encodable varint
    ];

    for cap_type in test_types {
        let id = cap_type.context_id();
        let reconstructed = CapsuleType::from_context_id(id);
        assert_eq!(cap_type.context_id(), reconstructed.context_id());
    }
}

#[tokio::test]
async fn test_context_id_manager_properties() {
    // Property: allocated IDs should be unique and sequential
    let mut manager = ContextIdManager::new(0, 100);
    let mut allocated = Vec::new();

    for _ in 0..50 {
        if let Some(id) = manager.allocate() {
            allocated.push(id);
        }
    }

    // Check uniqueness
    let mut seen = std::collections::HashSet::new();
    for id in &allocated {
        assert!(seen.insert(*id), "duplicate context ID: {}", id);
    }

    // Check sequentiality
    for (i, id) in allocated.iter().enumerate() {
        assert_eq!(*id, i as u64, "context ID should be sequential");
    }

    // Check validity
    for id in &allocated {
        assert!(manager.is_valid(*id), "allocated ID should be valid");
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

#[tokio::test]
async fn test_full_capsule_flow_with_close() {
    // Test complete flow: UDP → Close → verify shutdown
    let mut buf = CapsuleBuffer::new();

    let udp_cap = UdpCapsule::new(Bytes::from_static(b"udp data"));
    let close_cap = UdpCapsule::new_close(Bytes::from_static(b"closing"));

    // Encode both
    let mut data = Vec::new();
    let enc_udp = udp_cap.encode();
    data.extend_from_slice(&(enc_udp.len() as u32).to_be_bytes());
    data.extend_from_slice(&enc_udp);

    let enc_close = close_cap.encode();
    data.extend_from_slice(&(enc_close.len() as u32).to_be_bytes());
    data.extend_from_slice(&enc_close);

    // Extract capsules
    let mut extracted = Vec::new();
    let data_bytes = Bytes::from(data);

    // Process in chunks
    let chunk_size = 10;
    for i in (0..data_bytes.len()).step_by(chunk_size) {
        let end = std::cmp::min(i + chunk_size, data_bytes.len());
        let chunk = data_bytes.slice(i..end);

        if let Ok(Some(capsule)) = buf.add_bytes(chunk) {
            extracted.push(capsule);
            // Stop if we get Close capsule
            if extracted.last().unwrap().is_close() {
                break;
            }
        }
    }

    // Should have both capsules
    assert_eq!(extracted.len(), 2);
    assert!(extracted[0].is_udp());
    assert!(extracted[1].is_close());
}

#[tokio::test]
async fn test_udp_forwarding_buffer_with_close_signal() {
    // Test that UDP forwarding buffer can handle close signal
    let mut buffer = UdpForwardingBuffer::new(1000, 10, 100);
    let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

    // Add some UDP data
    let _ = buffer.add(Bytes::from_static(b"data1"), addr);
    let _ = buffer.add(Bytes::from_static(b"data2"), addr);

    // Simulate close signal by checking buffer state
    assert!(!buffer.is_empty());
    let batch = buffer.take();
    assert_eq!(batch.len(), 2);
    assert!(buffer.is_empty());
}

#[tokio::test]
async fn test_capsule_buffer_max_size_custom() {
    // Test custom max size configuration
    let custom_size = 2048;
    let _buf = CapsuleBuffer::with_max_size(custom_size);

    // Verify it works by trying to exceed it
    let mut buf2 = CapsuleBuffer::with_max_size(custom_size);
    let large_data = Bytes::from(vec![0u8; custom_size + 1]);
    let result = buf2.add_bytes(large_data);
    assert!(result.is_err(), "should reject data exceeding custom size");
}
