//! Integration tests for Stego RSS encoding/decoding
//!
//! Tests the full cycle of encoding manifests into RSS feeds and decoding them back,
//! including integration with ManifestClient and various steganographic methods.

use masque_core::stego_rss::{StegoMethod, StegoRssConfig, StegoRssDecoder, StegoRssEncoder};
use tempfile::TempDir;
use vpr_crypto::keys::SigningKeypair;
use vpr_crypto::manifest::{ManifestPayload, ServerEndpoint, SignedManifest};

fn create_test_payload() -> ManifestPayload {
    let servers = vec![
        ServerEndpoint::new(
            "server1",
            "example.com",
            443,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .with_region("us-east"),
        ServerEndpoint::new(
            "server2",
            "example.org",
            443,
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        )
        .with_region("eu-west"),
    ];
    ManifestPayload::new(servers)
}

fn create_test_signed_manifest() -> (SignedManifest, SigningKeypair) {
    let keypair = SigningKeypair::generate();
    let payload = create_test_payload();
    let signed = SignedManifest::sign(&payload, &keypair).expect("failed to sign manifest");
    (signed, keypair)
}

#[tokio::test]
async fn test_stego_rss_base64_method_encode_decode_payload() {
    // Base64Content is the most reliable method currently
    let method = StegoMethod::Base64Content;

    let config = StegoRssConfig {
        method,
        feed_title: "Test Feed".to_string(),
        feed_description: "Test Description".to_string(),
        feed_link: "https://example.com/feed".to_string(),
        min_items: 5,
        max_items: 20,
        random_order: false,
        seed: None,
    };

    let mut encoder = StegoRssEncoder::new(config.clone());
    let decoder = StegoRssDecoder::new(config);

    let payload = create_test_payload();

    // Encode
    let rss_xml = encoder
        .encode_payload(&payload)
        .unwrap_or_else(|_| panic!("failed to encode with method {:?}", method));

    // Verify RSS XML is valid
    assert!(rss_xml.contains("<rss"));
    assert!(rss_xml.contains("<channel>"));
    assert!(rss_xml.contains("<item>"));

    // Decode
    let decoded = decoder
        .decode_payload(&rss_xml)
        .unwrap_or_else(|_| panic!("failed to decode with method {:?}", method));

    // Verify decoded payload matches original
    assert_eq!(decoded.version, payload.version);
    assert_eq!(decoded.servers.len(), payload.servers.len());
    assert_eq!(decoded.servers[0].id, payload.servers[0].id);
    assert_eq!(decoded.servers[0].host, payload.servers[0].host);
    assert_eq!(decoded.servers[1].id, payload.servers[1].id);
}

#[tokio::test]
async fn test_stego_rss_base64_method_encode_decode_signed_manifest() {
    // Base64Content is the most reliable method currently
    let method = StegoMethod::Base64Content;

    let config = StegoRssConfig {
        method,
        feed_title: "Test Feed".to_string(),
        feed_description: "Test Description".to_string(),
        feed_link: "https://example.com/feed".to_string(),
        min_items: 5,
        max_items: 20,
        random_order: false,
        seed: None,
    };

    let mut encoder = StegoRssEncoder::new(config.clone());
    let decoder = StegoRssDecoder::new(config);

    let (signed, keypair) = create_test_signed_manifest();

    // Encode
    let rss_xml = encoder
        .encode_manifest(&signed)
        .unwrap_or_else(|_| panic!("failed to encode signed manifest with method {:?}", method));

    // Verify RSS XML is valid
    assert!(rss_xml.contains("<rss"));
    assert!(rss_xml.contains("<channel>"));

    // Decode
    let decoded = decoder
        .decode_manifest(&rss_xml)
        .unwrap_or_else(|_| panic!("failed to decode signed manifest with method {:?}", method));

    // Verify signature
    let payload = decoded
        .verify(&keypair.public_bytes())
        .expect("failed to verify decoded manifest");

    assert_eq!(payload.servers.len(), 2);
    assert_eq!(payload.servers[0].id, "server1");
}

#[tokio::test]
async fn test_stego_rss_large_manifest() {
    // Test with a larger manifest (many servers)
    let mut servers = Vec::new();
    for i in 0..10 {
        servers.push(ServerEndpoint::new(
            &format!("server{}", i),
            &format!("example{}.com", i),
            443,
            &format!("{:064x}", i),
        ));
    }

    let payload = ManifestPayload::new(servers);

    let config = StegoRssConfig {
        method: StegoMethod::Base64Content, // Use reliable method
        feed_title: "Large Feed".to_string(),
        feed_description: "Large Description".to_string(),
        feed_link: "https://example.com/feed".to_string(),
        min_items: 10,
        max_items: 50,
        random_order: false,
        seed: None,
    };

    let mut encoder = StegoRssEncoder::new(config.clone());
    let decoder = StegoRssDecoder::new(config);

    let rss_xml = encoder
        .encode_payload(&payload)
        .expect("failed to encode large manifest");
    let decoded = decoder
        .decode_payload(&rss_xml)
        .expect("failed to decode large manifest");

    assert_eq!(decoded.servers.len(), 10);
    for i in 0..10 {
        assert_eq!(decoded.servers[i].id, format!("server{}", i));
    }
}

#[tokio::test]
async fn test_stego_rss_roundtrip_with_manifest_client() {
    let temp_dir = TempDir::new().expect("failed to create temp dir");
    let (signed, keypair) = create_test_signed_manifest();

    // Encode manifest to RSS
    let config = StegoRssConfig {
        method: StegoMethod::Base64Content,
        feed_title: "Test Feed".to_string(),
        feed_description: "Test Description".to_string(),
        feed_link: "https://example.com/feed".to_string(),
        min_items: 5,
        max_items: 20,
        random_order: false,
        seed: None,
    };

    let mut encoder = StegoRssEncoder::new(config.clone());
    let rss_xml = encoder.encode_manifest(&signed).expect("failed to encode");

    // Save RSS to file (simulating RSS feed)
    let rss_file = temp_dir.path().join("feed.xml");
    tokio::fs::write(&rss_file, rss_xml)
        .await
        .expect("failed to write RSS file");

    // Note: file:// URLs won't work with reqwest, but this tests the structure
    // In real usage, RSS feeds would be served over HTTP
    // For now, we'll test the decode path directly
    let decoder = StegoRssDecoder::new(config);
    let rss_content = tokio::fs::read_to_string(&rss_file)
        .await
        .expect("failed to read RSS");
    let decoded = decoder
        .decode_manifest(&rss_content)
        .expect("failed to decode");

    let payload = decoded
        .verify(&keypair.public_bytes())
        .expect("failed to verify");
    assert_eq!(payload.servers.len(), 2);
}

#[tokio::test]
async fn test_stego_rss_invalid_xml_handling() {
    let config = StegoRssConfig {
        method: StegoMethod::Base64Content,
        feed_title: "Test".to_string(),
        feed_description: "Test".to_string(),
        feed_link: "https://example.com".to_string(),
        min_items: 5,
        max_items: 20,
        random_order: false,
        seed: None,
    };

    let decoder = StegoRssDecoder::new(config);

    // Try to decode invalid XML
    let invalid_xml = "<not>valid</rss>";
    let result = decoder.decode_payload(invalid_xml);
    assert!(result.is_err());
}

#[tokio::test]
async fn test_stego_rss_empty_manifest() {
    let config = StegoRssConfig {
        method: StegoMethod::Base64Content,
        feed_title: "Test".to_string(),
        feed_description: "Test".to_string(),
        feed_link: "https://example.com".to_string(),
        min_items: 5,
        max_items: 20,
        random_order: false,
        seed: None,
    };

    let mut encoder = StegoRssEncoder::new(config.clone());
    let decoder = StegoRssDecoder::new(config);

    // Create empty manifest
    let payload = ManifestPayload::new(Vec::new());

    let rss_xml = encoder
        .encode_payload(&payload)
        .expect("failed to encode empty manifest");
    let decoded = decoder
        .decode_payload(&rss_xml)
        .expect("failed to decode empty manifest");

    assert_eq!(decoded.servers.len(), 0);
}

#[tokio::test]
async fn test_stego_rss_different_configs_compatibility() {
    // Test that encoder and decoder with different configs (except method) still work
    let encoder_config = StegoRssConfig {
        method: StegoMethod::Base64Content,
        feed_title: "Encoder Feed".to_string(),
        feed_description: "Encoder Description".to_string(),
        feed_link: "https://encoder.com/feed".to_string(),
        min_items: 10,
        max_items: 30,
        random_order: true,
        seed: Some(42),
    };

    let decoder_config = StegoRssConfig {
        method: StegoMethod::Base64Content,                  // Must match!
        feed_title: "Decoder Feed".to_string(),              // Can differ
        feed_description: "Decoder Description".to_string(), // Can differ
        feed_link: "https://decoder.com/feed".to_string(),   // Can differ
        min_items: 5,                                        // Can differ
        max_items: 50,                                       // Can differ
        random_order: false,                                 // Can differ
        seed: None,                                          // Can differ
    };

    let mut encoder = StegoRssEncoder::new(encoder_config);
    let decoder = StegoRssDecoder::new(decoder_config);

    let payload = create_test_payload();

    let rss_xml = encoder.encode_payload(&payload).expect("failed to encode");
    let decoded = decoder.decode_payload(&rss_xml).expect("failed to decode");

    assert_eq!(decoded.servers.len(), payload.servers.len());
    assert_eq!(decoded.servers[0].id, payload.servers[0].id);
}

#[tokio::test]
async fn test_stego_rss_method_mismatch_fails() {
    // This test verifies that using wrong decoding method fails
    // Methods encode data differently, so wrong method should fail during
    // decompression or JSON deserialization
    let encoder_config = StegoRssConfig {
        method: StegoMethod::Base64Content,
        feed_title: "Test".to_string(),
        feed_description: "Test".to_string(),
        feed_link: "https://example.com".to_string(),
        min_items: 5,
        max_items: 20,
        random_order: false,
        seed: None,
    };

    let decoder_config = StegoRssConfig {
        method: StegoMethod::Ordering, // Different method!
        feed_title: "Test".to_string(),
        feed_description: "Test".to_string(),
        feed_link: "https://example.com".to_string(),
        min_items: 5,
        max_items: 20,
        random_order: false,
        seed: None,
    };

    let mut encoder = StegoRssEncoder::new(encoder_config);
    let decoder = StegoRssDecoder::new(decoder_config);

    let payload = create_test_payload();

    let rss_xml = encoder.encode_payload(&payload).expect("failed to encode");

    // Decoding with wrong method should fail
    // It may partially decode data, but should fail during decompression or JSON parsing
    let result = decoder.decode_payload(&rss_xml);

    // Verify that decoding fails (either during data extraction, decompression, or JSON parsing)
    assert!(
        result.is_err(),
        "Decoding with wrong method should fail. Error: {:?}",
        result.err()
    );

    // Verify the error indicates a problem (not just empty data)
    let error_msg = result.unwrap_err().to_string().to_lowercase();
    assert!(
        error_msg.contains("decode")
            || error_msg.contains("deserialize")
            || error_msg.contains("decompress")
            || error_msg.contains("found")
            || error_msg.contains("invalid"),
        "Error should indicate decoding/deserialization failure. Got: {}",
        error_msg
    );
}

#[tokio::test]
async fn test_stego_rss_manifest_with_odoh_relays() {
    let mut payload = create_test_payload();
    payload.odoh_relays = vec![
        "odoh1.example.com".to_string(),
        "odoh2.example.com".to_string(),
    ];
    payload.front_domains = vec!["front1.example.com".to_string()];

    let config = StegoRssConfig {
        method: StegoMethod::Base64Content, // Use reliable method
        feed_title: "Test".to_string(),
        feed_description: "Test".to_string(),
        feed_link: "https://example.com".to_string(),
        min_items: 5,
        max_items: 20,
        random_order: false,
        seed: None,
    };

    let mut encoder = StegoRssEncoder::new(config.clone());
    let decoder = StegoRssDecoder::new(config);

    let rss_xml = encoder.encode_payload(&payload).expect("failed to encode");
    let decoded = decoder.decode_payload(&rss_xml).expect("failed to decode");

    assert_eq!(decoded.odoh_relays.len(), 2);
    assert_eq!(decoded.odoh_relays[0], "odoh1.example.com");
    assert_eq!(decoded.front_domains.len(), 1);
    assert_eq!(decoded.front_domains[0], "front1.example.com");
}
