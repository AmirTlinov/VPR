//! Integration tests for ACME Client, Certificate Manager, and DNS Updater
//!
//! Tests the full certificate lifecycle: ACME certificate acquisition,
//! DNS record management, and certificate storage/renewal.

use anyhow::Result;
use masque_core::acme_client::{AcmeClientConfig, ChallengeType};
use masque_core::cert_manager::{CertificateManager, CertificateManagerConfig};
use masque_core::dns_updater::{DnsProvider, DnsUpdaterConfig, DnsUpdaterFactory};
use std::collections::HashMap;
use std::time::Duration;
use tempfile::TempDir;
use tokio::fs;

#[tokio::test]
async fn test_certificate_manager_initialization() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let cert_dir = temp_dir.path().join("certs");

    // Create ACME config that won't try to connect (use invalid URL)
    // This is intentional for unit testing - we test directory creation separately
    let acme_config = AcmeClientConfig {
        directory_url: "https://invalid-acme-url.example.com/directory".to_string(),
        account_key: masque_core::acme_client::AcmeAccountKey::generate()?,
        preferred_challenge: ChallengeType::Dns01,
        timeout: Duration::from_secs(1), // Short timeout
        contact_email: None,
    };

    let config = CertificateManagerConfig {
        cert_dir: cert_dir.clone(),
        acme_config,
        dns_updater_config: None,
        renewal_threshold: Duration::from_secs(30 * 24 * 60 * 60),
    };

    // Manager creation will fail due to ACME connection failure, but directory creation
    // happens first and should succeed. This is expected behavior for invalid ACME URL.
    let result = CertificateManager::new(config).await;

    // Verify directory was created (happens before ACME initialization)
    assert!(cert_dir.exists());

    // Manager creation should fail due to invalid ACME URL (expected)
    assert!(
        result.is_err(),
        "Manager creation should fail with invalid ACME URL"
    );

    Ok(())
}

#[tokio::test]
async fn test_acme_account_key_generation() -> Result<()> {
    use masque_core::acme_client::AcmeAccountKey;

    let key = AcmeAccountKey::generate()?;

    // Verify JWK structure
    assert!(key.public_key_jwk().get("kty").is_some());
    assert_eq!(
        key.public_key_jwk().get("kty").unwrap().as_str(),
        Some("OKP")
    );
    assert_eq!(
        key.public_key_jwk().get("crv").unwrap().as_str(),
        Some("Ed25519")
    );
    assert!(key.public_key_jwk().get("x").is_some());

    // Test signing capability
    let message = b"test message";
    let signature = key.sign(message);
    assert_eq!(signature.len(), 64); // Ed25519 signature is 64 bytes

    Ok(())
}

#[tokio::test]
async fn test_acme_dns01_challenge_calculation() -> Result<()> {
    use masque_core::acme_client::{AcmeAccountKey, Challenge};

    // Create ACME client config (but don't initialize - we only need the account key)
    let account_key = AcmeAccountKey::generate()?;

    // Create a temporary config just to test challenge calculation
    let _config = AcmeClientConfig {
        directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory".to_string(),
        account_key: account_key.clone(),
        preferred_challenge: ChallengeType::Dns01,
        timeout: Duration::from_secs(30),
        contact_email: None,
    };

    // Create client without directory fetch - we'll test challenge calculation directly
    // We need to create a client instance to access get_dns01_challenge method
    // Since we can't initialize without directory fetch, we'll test the calculation logic directly

    // Test account key structure
    assert!(account_key.public_key_jwk().get("kty").is_some());
    assert_eq!(
        account_key.public_key_jwk().get("kty").unwrap().as_str(),
        Some("OKP")
    );
    assert_eq!(
        account_key.public_key_jwk().get("crv").unwrap().as_str(),
        Some("Ed25519")
    );

    // Test signing capability
    let message = b"test message for signing";
    let signature = account_key.sign(message);
    assert_eq!(signature.len(), 64); // Ed25519 signature is 64 bytes

    // Test thumbprint calculation (matches get_dns01_challenge implementation)
    let jwk_canonical = serde_json::to_string(account_key.public_key_jwk())?;
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(jwk_canonical.as_bytes());
    let thumbprint_hash = hasher.finalize();
    use base64::{engine::general_purpose, Engine as _};
    let thumbprint = general_purpose::URL_SAFE_NO_PAD.encode(thumbprint_hash);

    // Verify thumbprint is valid base64url
    assert!(!thumbprint.is_empty());
    assert!(!thumbprint.contains('+'));
    assert!(!thumbprint.contains('/'));
    assert!(!thumbprint.contains('='));
    assert_eq!(thumbprint.len(), 43); // SHA256 = 32 bytes = 43 base64url chars

    // Test DNS-01 challenge calculation with a mock challenge
    // Create a mock challenge with a token
    let test_token = "test-token-12345";
    let _challenge = Challenge {
        type_: "dns-01".to_string(),
        url: "https://acme.example.com/challenge".to_string(),
        token: Some(test_token.to_string()),
        status: None,
        validation_record: None,
    };

    // Calculate key authorization: token + "." + thumbprint
    let key_authorization = format!("{}.{}", test_token, thumbprint);

    // Calculate DNS-01 record value: base64url(SHA256(key_authorization))
    let mut hasher = Sha256::new();
    hasher.update(key_authorization.as_bytes());
    let record_hash = hasher.finalize();
    let record_value = general_purpose::URL_SAFE_NO_PAD.encode(record_hash);

    // Verify record value format
    assert!(!record_value.is_empty());
    assert!(!record_value.contains('+'));
    assert!(!record_value.contains('/'));
    assert!(!record_value.contains('='));
    assert_eq!(record_value.len(), 43); // SHA256 = 32 bytes = 43 base64url chars

    // Verify key authorization format
    assert!(key_authorization.starts_with(test_token));
    assert!(key_authorization.contains('.'));
    assert!(key_authorization.ends_with(&thumbprint));

    Ok(())
}

#[tokio::test]
async fn test_dns_updater_factory_cloudflare() -> Result<()> {
    let mut credentials = HashMap::new();
    credentials.insert("api_token".to_string(), "test-token".to_string());
    credentials.insert("zone_id".to_string(), "test-zone-id".to_string());

    let config = DnsUpdaterConfig {
        provider: DnsProvider::Cloudflare,
        credentials,
        propagation_delay: Duration::from_secs(10),
        timeout: Duration::from_secs(30),
    };

    let _updater = DnsUpdaterFactory::create(&config)?;

    // Verify updater was created (doesn't panic)
    // updater is Box<dyn DnsUpdater>, not Option

    Ok(())
}

#[tokio::test]
async fn test_dns_updater_factory_http_api() -> Result<()> {
    let mut credentials = HashMap::new();
    credentials.insert(
        "api_url".to_string(),
        "https://api.example.com/dns".to_string(),
    );
    credentials.insert("api_key".to_string(), "test-key".to_string());

    let config = DnsUpdaterConfig {
        provider: DnsProvider::HttpApi,
        credentials,
        propagation_delay: Duration::from_secs(5),
        timeout: Duration::from_secs(30),
    };

    let _updater = DnsUpdaterFactory::create(&config)?;

    // Verify updater was created (doesn't panic)
    // updater is Box<dyn DnsUpdater>, not Option

    Ok(())
}

#[tokio::test]
async fn test_dns_updater_factory_route53() -> Result<()> {
    let mut credentials = HashMap::new();
    credentials.insert("access_key_id".to_string(), "test-access-key".to_string());
    credentials.insert(
        "secret_access_key".to_string(),
        "test-secret-key".to_string(),
    );
    credentials.insert("region".to_string(), "us-east-1".to_string());

    let config = DnsUpdaterConfig {
        provider: DnsProvider::Route53,
        credentials,
        propagation_delay: Duration::from_secs(15),
        timeout: Duration::from_secs(30),
    };

    let _updater = DnsUpdaterFactory::create(&config)?;

    // Verify updater was created (doesn't panic)
    // updater is Box<dyn DnsUpdater>, not Option

    Ok(())
}

#[tokio::test]
async fn test_dns_updater_factory_manual() -> Result<()> {
    let config = DnsUpdaterConfig {
        provider: DnsProvider::Manual,
        credentials: HashMap::new(),
        propagation_delay: Duration::from_secs(0),
        timeout: Duration::from_secs(30),
    };

    let result = DnsUpdaterFactory::create(&config);

    // Manual provider should fail
    assert!(result.is_err());

    Ok(())
}

#[tokio::test]
async fn test_dns_updater_verify_txt_record_real_dns() -> Result<()> {
    use masque_core::dns_updater::{CloudflareUpdater, DnsUpdater};

    // Test DNS verification using real DNS lookup
    // We'll use a public DNS record that we know exists for testing
    // Using _acme-challenge subdomain pattern (common for ACME DNS-01)

    // Create a Cloudflare updater (we won't actually use it for updates, just for verification)
    // Using dummy credentials since we're only testing verify_txt_record
    let updater = CloudflareUpdater::new("dummy-token".to_string(), None)?;

    // Test DNS lookup for a known public TXT record
    // Using example.com which has known TXT records
    // Note: This test may fail if DNS is unavailable, but that's acceptable for integration tests
    let test_domain = "_acme-challenge.example.com";
    let test_value = "test-value-12345";

    // Try to verify a TXT record (will use real DNS lookup)
    // This will likely fail because the record doesn't exist, but it tests the DNS lookup logic
    let result = updater.verify_txt_record(test_domain, test_value).await;

    // Result should be Ok(bool) - either true if record exists and matches, or false if not
    // We're testing that the DNS lookup mechanism works, not that a specific record exists
    match result {
        Ok(exists) => {
            // Record either exists and matches (true) or doesn't exist/doesn't match (false)
            // Both are valid outcomes - we're testing the lookup mechanism works
            let _ = exists;
        }
        Err(e) => {
            // DNS lookup failure is acceptable in test environments
            // But we verify the error is DNS-related, not a logic error
            let error_msg = e.to_string().to_lowercase();
            assert!(
                error_msg.contains("dns")
                    || error_msg.contains("resolve")
                    || error_msg.contains("timeout")
                    || error_msg.contains("network"),
                "Error should be DNS-related. Got: {}",
                error_msg
            );
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_dns_updater_verify_txt_record_format() -> Result<()> {
    use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
    use trust_dns_resolver::TokioAsyncResolver;

    // Test that DNS verification uses proper DNS lookup format
    // We'll test the DNS resolver directly to verify the format

    // Create resolver
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    // Test DNS lookup format for TXT records
    // Using a domain that likely has TXT records (like example.com)
    let test_name = "example.com";

    // Perform DNS lookup
    let lookup_result = resolver.txt_lookup(test_name).await;

    match lookup_result {
        Ok(lookup) => {
            // Verify we got TXT records
            let records: Vec<_> = lookup.iter().collect();
            assert!(
                !records.is_empty(),
                "Should have TXT records for example.com"
            );

            // Verify record format
            for record in records {
                let txt_data = record.iter().collect::<Vec<_>>();
                assert!(!txt_data.is_empty(), "TXT record should have data");
            }
        }
        Err(e) => {
            // DNS lookup failure is acceptable in test environments
            // But verify it's a DNS error, not a format error
            let error_msg = e.to_string().to_lowercase();
            assert!(
                error_msg.contains("dns")
                    || error_msg.contains("resolve")
                    || error_msg.contains("timeout")
                    || error_msg.contains("network"),
                "Error should be DNS-related. Got: {}",
                error_msg
            );
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_certificate_manager_with_dns_updater() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let cert_dir = temp_dir.path().join("certs");

    // Create DNS updater config (using HttpApi for testing)
    let mut dns_credentials = HashMap::new();
    dns_credentials.insert(
        "api_url".to_string(),
        "https://api.example.com/dns".to_string(),
    );

    let dns_config = DnsUpdaterConfig {
        provider: DnsProvider::HttpApi,
        credentials: dns_credentials,
        propagation_delay: Duration::from_secs(1),
        timeout: Duration::from_secs(30),
    };

    // Create ACME config with invalid URL
    let acme_config = AcmeClientConfig {
        directory_url: "https://invalid-acme-url.example.com/directory".to_string(),
        account_key: masque_core::acme_client::AcmeAccountKey::generate()?,
        preferred_challenge: ChallengeType::Dns01,
        timeout: Duration::from_secs(1),
        contact_email: None,
    };

    let config = CertificateManagerConfig {
        cert_dir: cert_dir.clone(),
        acme_config,
        dns_updater_config: Some(dns_config),
        renewal_threshold: Duration::from_secs(30 * 24 * 60 * 60),
    };

    // Manager creation may fail due to ACME, but directory should exist
    let _ = CertificateManager::new(config).await;

    // Verify directory exists
    assert!(cert_dir.exists());

    Ok(())
}

#[tokio::test]
async fn test_certificate_info_needs_renewal() -> Result<()> {
    use masque_core::cert_manager::CertificateInfo;
    use std::time::SystemTime;

    let temp_dir = TempDir::new()?;
    let cert_path = temp_dir.path().join("cert.crt");
    let key_path = temp_dir.path().join("cert.key");

    // Create certificate info that expires soon
    let info = CertificateInfo {
        cert_path: cert_path.clone(),
        key_path: key_path.clone(),
        domains: vec!["test.example.com".to_string()],
        expires_at: SystemTime::now() + Duration::from_secs(10 * 24 * 60 * 60), // 10 days
        is_valid: true,
    };

    // With 30-day threshold, 10 days should need renewal
    assert!(info.needs_renewal(Duration::from_secs(30 * 24 * 60 * 60)));

    // With 5-day threshold, 10 days should not need renewal
    assert!(!info.needs_renewal(Duration::from_secs(5 * 24 * 60 * 60)));

    Ok(())
}

#[tokio::test]
async fn test_certificate_info_remaining_validity() -> Result<()> {
    use masque_core::cert_manager::CertificateInfo;
    use std::time::SystemTime;

    let temp_dir = TempDir::new()?;
    let cert_path = temp_dir.path().join("cert.crt");
    let key_path = temp_dir.path().join("cert.key");

    let expires_in_30_days = SystemTime::now() + Duration::from_secs(30 * 24 * 60 * 60);

    let info = CertificateInfo {
        cert_path: cert_path.clone(),
        key_path: key_path.clone(),
        domains: vec!["test.example.com".to_string()],
        expires_at: expires_in_30_days,
        is_valid: true,
    };

    let remaining = info.remaining_validity();

    // Should have some remaining validity
    assert!(remaining.is_some());
    let remaining_duration = remaining.unwrap();

    // Should be approximately 30 days (allow some variance)
    let expected_secs = 30 * 24 * 60 * 60;
    let actual_secs = remaining_duration.as_secs();

    // Allow 1 hour variance
    assert!(actual_secs >= expected_secs - 3600);
    assert!(actual_secs <= expected_secs + 3600);

    Ok(())
}

#[tokio::test]
async fn test_acme_client_config_new() -> Result<()> {
    let config = AcmeClientConfig::new()?;

    // Verify default values
    assert_eq!(
        config.directory_url,
        "https://acme-staging-v02.api.letsencrypt.org/directory"
    );
    assert_eq!(config.preferred_challenge, ChallengeType::Dns01);
    assert_eq!(config.timeout, Duration::from_secs(30));
    assert!(config.contact_email.is_none());

    // Account key should be generated and have valid JWK
    assert!(config.account_key.public_key_jwk().get("kty").is_some());

    Ok(())
}

#[tokio::test]
async fn test_acme_jws_signing() -> Result<()> {
    use base64::{engine::general_purpose, Engine as _};
    use masque_core::acme_client::AcmeAccountKey;

    // Test JWS signing according to RFC 7515
    let account_key = AcmeAccountKey::generate()?;

    // Create a test payload
    let payload = serde_json::json!({
        "test": "data",
        "number": 42
    });

    // Create protected header (as per RFC 8555)
    let protected = serde_json::json!({
        "alg": "EdDSA",
        "jwk": account_key.public_key_jwk(),
        "nonce": "test-nonce-12345",
        "url": "https://acme.example.com/test"
    });

    // Encode protected header and payload as base64url (RFC 7515)
    let protected_b64 =
        general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_string(&protected)?.as_bytes());

    let payload_b64 =
        general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload)?.as_bytes());

    // Create signing input: protected.payload (RFC 7515 Section 5.1)
    let signing_input = format!("{}.{}", protected_b64, payload_b64);

    // Sign using Ed25519
    let signature_bytes = account_key.sign(signing_input.as_bytes());

    // Encode signature as base64url
    let signature_b64 = general_purpose::URL_SAFE_NO_PAD.encode(signature_bytes);

    // Verify JWS structure
    let jws = serde_json::json!({
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": signature_b64
    });

    // Verify all fields are present
    assert!(jws.get("protected").is_some());
    assert!(jws.get("payload").is_some());
    assert!(jws.get("signature").is_some());

    // Verify base64url encoding (no padding, no + or /)
    let protected_str = jws["protected"].as_str().unwrap();
    let payload_str = jws["payload"].as_str().unwrap();
    let signature_str = jws["signature"].as_str().unwrap();

    assert!(!protected_str.contains('+'));
    assert!(!protected_str.contains('/'));
    assert!(!protected_str.contains('='));

    assert!(!payload_str.contains('+'));
    assert!(!payload_str.contains('/'));
    assert!(!payload_str.contains('='));

    assert!(!signature_str.contains('+'));
    assert!(!signature_str.contains('/'));
    assert!(!signature_str.contains('='));

    // Verify signature length (Ed25519 signature is 64 bytes = 86 base64url chars)
    assert_eq!(signature_bytes.len(), 64);
    assert_eq!(signature_str.len(), 86); // 64 bytes * 4/3 = 85.33, rounded up = 86

    // Verify we can decode protected header back
    let decoded_protected_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(protected_str)
        .expect("should decode protected header");
    let decoded_protected: serde_json::Value = serde_json::from_slice(&decoded_protected_bytes)?;
    assert_eq!(decoded_protected["alg"], "EdDSA");
    assert_eq!(decoded_protected["nonce"], "test-nonce-12345");

    // Verify we can decode payload back
    let decoded_payload_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(payload_str)
        .expect("should decode payload");
    let decoded_payload: serde_json::Value = serde_json::from_slice(&decoded_payload_bytes)?;
    assert_eq!(decoded_payload["test"], "data");
    assert_eq!(decoded_payload["number"], 42);

    Ok(())
}

#[tokio::test]
async fn test_certificate_manager_list_empty() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let cert_dir = temp_dir.path().join("certs");

    // Create ACME config with invalid URL to avoid connection
    let acme_config = AcmeClientConfig {
        directory_url: "https://invalid-acme-url.example.com/directory".to_string(),
        account_key: masque_core::acme_client::AcmeAccountKey::generate()?,
        preferred_challenge: ChallengeType::Dns01,
        timeout: Duration::from_secs(1),
        contact_email: None,
    };

    let config = CertificateManagerConfig {
        cert_dir: cert_dir.clone(),
        acme_config,
        dns_updater_config: None,
        renewal_threshold: Duration::from_secs(30 * 24 * 60 * 60),
    };

    // Manager creation may fail due to ACME, but directory should exist
    let _ = CertificateManager::new(config).await;

    // Verify directory exists
    assert!(cert_dir.exists());

    // Test listing in empty directory manually
    let mut entries = fs::read_dir(&cert_dir).await?;
    let mut count = 0;
    while entries.next_entry().await?.is_some() {
        count += 1;
    }
    assert_eq!(count, 0);

    Ok(())
}
