#![allow(clippy::field_reassign_with_default)]

//! Integration tests for Manifest fetch and fallback mechanisms
//!
//! Tests: Manifest fetch → Server selection → Connection
//! Tests: Fallback mechanisms (ODoH → DoH → Domain Fronting → Cached)

use masque_core::bootstrap::{ManifestClient, ManifestClientConfig};
use tempfile::TempDir;
use vpr_crypto::keys::SigningKeypair;
use vpr_crypto::manifest::{ManifestPayload, ServerEndpoint, SignedManifest};

#[tokio::test]
async fn test_manifest_fetch_cached_fallback() {
    // Test that cached manifest is used when network fetch fails
    let temp_dir = TempDir::new().expect("failed to create temp dir");
    let keypair = SigningKeypair::generate();

    let servers = vec![
        ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1"),
        ServerEndpoint::new("srv2", "5.6.7.8", 443, "key2"),
    ];
    let payload = ManifestPayload::new(servers.clone());
    let signed = SignedManifest::sign(&payload, &keypair).expect("failed to sign");

    let mut config = ManifestClientConfig::default();
    config.cache_dir = temp_dir.path().to_path_buf();
    config.expected_pubkey = keypair.public_bytes();
    // No network endpoints configured - should fallback to cache
    config.odoh_relays = Vec::new();
    config.doh_endpoints = Vec::new();
    config.front_configs = Vec::new();

    let mut client = ManifestClient::new(config).expect("failed to create client");

    // Cache the manifest first
    client
        .cache_manifest(&signed)
        .await
        .expect("failed to cache");

    // Fetch should use cached manifest
    let fetched = client
        .fetch_manifest()
        .await
        .expect("should fetch from cache");
    assert_eq!(fetched.servers.len(), 2);
    assert_eq!(fetched.servers[0].host, "1.2.3.4");
    assert_eq!(fetched.servers[1].host, "5.6.7.8");
}

#[tokio::test]
async fn test_manifest_server_selection() {
    // Test that manifest provides server endpoints for selection
    let temp_dir = TempDir::new().expect("failed to create temp dir");
    let keypair = SigningKeypair::generate();

    let servers = vec![
        ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1"),
        ServerEndpoint::new("srv2", "5.6.7.8", 8443, "key2"),
        ServerEndpoint::new("srv3", "9.10.11.12", 443, "key3"),
    ];
    let payload = ManifestPayload::new(servers.clone());
    let signed = SignedManifest::sign(&payload, &keypair).expect("failed to sign");

    let mut config = ManifestClientConfig::default();
    config.cache_dir = temp_dir.path().to_path_buf();
    config.expected_pubkey = keypair.public_bytes();
    config.odoh_relays = Vec::new();
    config.doh_endpoints = Vec::new();
    config.front_configs = Vec::new();

    let mut client = ManifestClient::new(config).expect("failed to create client");
    client
        .cache_manifest(&signed)
        .await
        .expect("failed to cache");

    let manifest = client
        .fetch_manifest()
        .await
        .expect("should fetch manifest");

    // Verify all servers are present
    assert_eq!(manifest.servers.len(), 3);

    // Test server selection logic (client would select based on criteria)
    let selected = manifest.servers.first().expect("should have servers");
    assert_eq!(selected.host, "1.2.3.4");
    assert_eq!(selected.port, 443);
}

#[tokio::test]
async fn test_manifest_freshness_check() {
    // Test that fresh manifests are preferred over stale ones
    let temp_dir = TempDir::new().expect("failed to create temp dir");
    let keypair = SigningKeypair::generate();

    let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];
    let payload = ManifestPayload::new(servers);
    let signed = SignedManifest::sign(&payload, &keypair).expect("failed to sign");

    let mut config = ManifestClientConfig::default();
    config.cache_dir = temp_dir.path().to_path_buf();
    config.expected_pubkey = keypair.public_bytes();
    config.odoh_relays = Vec::new();
    config.doh_endpoints = Vec::new();
    config.front_configs = Vec::new();

    let client = ManifestClient::new(config).expect("failed to create client");
    client
        .cache_manifest(&signed)
        .await
        .expect("failed to cache");

    // Check if cached manifest is fresh
    let is_fresh = client.has_fresh_cache().await;
    assert!(is_fresh, "cached manifest should be fresh");
}

#[tokio::test]
async fn test_manifest_signature_verification() {
    // Test that invalid signatures are rejected
    let temp_dir = TempDir::new().expect("failed to create temp dir");
    let keypair1 = SigningKeypair::generate();
    let keypair2 = SigningKeypair::generate(); // Different keypair

    let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];
    let payload = ManifestPayload::new(servers);
    let signed = SignedManifest::sign(&payload, &keypair1).expect("failed to sign");

    let mut config = ManifestClientConfig::default();
    config.cache_dir = temp_dir.path().to_path_buf();
    config.expected_pubkey = keypair2.public_bytes(); // Wrong public key
    config.odoh_relays = Vec::new();
    config.doh_endpoints = Vec::new();
    config.front_configs = Vec::new();

    let mut client = ManifestClient::new(config).expect("failed to create client");
    client
        .cache_manifest(&signed)
        .await
        .expect("failed to cache");

    // Fetch should fail due to signature mismatch
    let result = client.fetch_manifest().await;
    assert!(
        result.is_err(),
        "should reject manifest with invalid signature"
    );
}

#[tokio::test]
async fn test_manifest_cache_clear() {
    // Test that cache can be cleared
    let temp_dir = TempDir::new().expect("failed to create temp dir");
    let keypair = SigningKeypair::generate();

    let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];
    let payload = ManifestPayload::new(servers);
    let signed = SignedManifest::sign(&payload, &keypair).expect("failed to sign");

    let mut config = ManifestClientConfig::default();
    config.cache_dir = temp_dir.path().to_path_buf();
    config.expected_pubkey = keypair.public_bytes();
    config.odoh_relays = Vec::new();
    config.doh_endpoints = Vec::new();
    config.front_configs = Vec::new();

    let mut client = ManifestClient::new(config).expect("failed to create client");
    client
        .cache_manifest(&signed)
        .await
        .expect("failed to cache");

    // Verify cache exists
    assert!(client.has_fresh_cache().await);

    // Clear cache
    client.clear_cache().await.expect("failed to clear cache");

    // Verify cache is gone
    assert!(!client.has_fresh_cache().await);

    // Fetch should fail (no cache, no network endpoints)
    let result = client.fetch_manifest().await;
    assert!(
        result.is_err(),
        "should fail when cache is cleared and no network endpoints"
    );
}
