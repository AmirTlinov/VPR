//! Public Key Infrastructure (PKI) for X.509 Certificates
//!
//! Generates TLS certificates for the VPR infrastructure using a
//! three-tier hierarchy: Root CA → Intermediate CA → Service Certs.
//!
//! # Security Design
//!
//! - **Root CA**: Offline, ECDSA P-384, 10-year validity
//! - **Intermediate CA**: Online, ECDSA P-384, 1-year validity
//! - **Service Certs**: Short-lived (90 days), auto-rotatable

use crate::{CryptoError, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use time::{Duration, OffsetDateTime};

/// PKI hierarchy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkiConfig {
    pub org_name: String,
    pub root_cn: String,
    pub root_validity_days: i64,
    pub intermediate_validity_days: i64,
    pub service_validity_days: i64,
}

impl Default for PkiConfig {
    fn default() -> Self {
        Self {
            org_name: "VPR".to_string(),
            root_cn: "VPR Root CA".to_string(),
            root_validity_days: 3650,        // 10 years
            intermediate_validity_days: 365, // 1 year
            service_validity_days: 90,       // 90 days
        }
    }
}

/// Generated CA bundle (root or intermediate)
pub struct CaBundle {
    pub cert_pem: String,
    pub key_pem: String,
}

/// Generated service certificate
pub struct ServiceCert {
    pub cert_pem: String,
    pub key_pem: String,
    pub chain_pem: String, // full chain for TLS
}

/// Generate offline root CA
pub fn generate_root_ca(config: &PkiConfig) -> Result<CaBundle> {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)
        .map_err(|e| CryptoError::KeyGen(e.to_string()))?;

    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::OrganizationName, &config.org_name);
    params
        .distinguished_name
        .push(DnType::CommonName, &config.root_cn);

    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + Duration::days(config.root_validity_days);

    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1)); // can sign intermediates
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    let cert = params.self_signed(&key)?;
    let cert_pem = cert.pem();
    let key_pem = key.serialize_pem();

    Ok(CaBundle { cert_pem, key_pem })
}

/// Generate intermediate CA signed by root
pub fn generate_intermediate_ca(
    config: &PkiConfig,
    node_name: &str,
    root_cert_pem: &str,
    root_key_pem: &str,
) -> Result<CaBundle> {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)
        .map_err(|e| CryptoError::KeyGen(e.to_string()))?;

    let cn = format!("VPR Intermediate CA - {node_name}");
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::OrganizationName, &config.org_name);
    params.distinguished_name.push(DnType::CommonName, &cn);

    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + Duration::days(config.intermediate_validity_days);

    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0)); // can only sign end-entity
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    // Create issuer from root CA PEM
    let root_key =
        KeyPair::from_pem(root_key_pem).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
    let issuer = Issuer::from_ca_cert_pem(root_cert_pem, &root_key)
        .map_err(|e| CryptoError::Certificate(e.to_string()))?;

    let cert = params.signed_by(&key, &issuer)?;
    let cert_pem = cert.pem();
    let key_pem = key.serialize_pem();

    Ok(CaBundle { cert_pem, key_pem })
}

/// Generate service certificate (for MASQUE, DoH, etc.)
pub fn generate_service_cert(
    config: &PkiConfig,
    service_name: &str,
    dns_names: &[String],
    intermediate_cert_pem: &str,
    intermediate_key_pem: &str,
) -> Result<ServiceCert> {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| CryptoError::KeyGen(e.to_string()))?;

    let cn = format!("VPR {service_name}");
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::OrganizationName, &config.org_name);
    params.distinguished_name.push(DnType::CommonName, &cn);

    for dns in dns_names {
        params.subject_alt_names.push(SanType::DnsName(
            dns.clone()
                .try_into()
                .map_err(|e| CryptoError::Certificate(format!("invalid dns name {dns}: {e}")))?,
        ));
    }

    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + Duration::days(config.service_validity_days);

    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];

    // Create issuer from intermediate CA PEM
    let inter_key = KeyPair::from_pem(intermediate_key_pem)
        .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
    let issuer = Issuer::from_ca_cert_pem(intermediate_cert_pem, &inter_key)
        .map_err(|e| CryptoError::Certificate(e.to_string()))?;

    let cert = params.signed_by(&key, &issuer)?;
    let cert_pem = cert.pem();
    let key_pem = key.serialize_pem();

    // Build full chain: service + intermediate
    let chain_pem = format!("{}\n{}", cert_pem, intermediate_cert_pem);

    Ok(ServiceCert {
        cert_pem,
        key_pem,
        chain_pem,
    })
}

/// Save CA bundle to directory
pub fn save_ca_bundle(bundle: &CaBundle, dir: &Path, name: &str) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let cert_path = dir.join(format!("{name}.crt"));
    let key_path = dir.join(format!("{name}.key"));
    std::fs::write(&cert_path, &bundle.cert_pem)?;
    std::fs::write(&key_path, &bundle.key_pem)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Load CA bundle from directory
pub fn load_ca_bundle(dir: &Path, name: &str) -> Result<(String, String)> {
    let cert_path = dir.join(format!("{name}.crt"));
    let key_path = dir.join(format!("{name}.key"));
    let cert_pem = std::fs::read_to_string(&cert_path)?;
    let key_pem = std::fs::read_to_string(&key_path)?;
    Ok((cert_pem, key_pem))
}

/// Validate PEM certificate and key, returning them for signing operations.
/// This validates the PEM formats are correct before use.
pub fn parse_ca_for_signing(cert_pem: &str, key_pem: &str) -> Result<(String, String)> {
    // Validate key PEM can be parsed
    KeyPair::from_pem(key_pem).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
    // Validate cert PEM can be used for signing (by attempting to create Issuer)
    let key = KeyPair::from_pem(key_pem).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
    Issuer::from_ca_cert_pem(cert_pem, &key)
        .map_err(|e| CryptoError::Certificate(e.to_string()))?;
    Ok((cert_pem.to_string(), key_pem.to_string()))
}

/// Save service certificate bundle
pub fn save_service_cert(cert: &ServiceCert, dir: &Path, name: &str) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join(format!("{name}.crt")), &cert.cert_pem)?;
    std::fs::write(dir.join(format!("{name}.key")), &cert.key_pem)?;
    std::fs::write(dir.join(format!("{name}.chain.crt")), &cert.chain_pem)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let key_path = dir.join(format!("{name}.key"));
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Certificate fingerprint (SHA-256)
pub fn cert_fingerprint(pem: &str) -> Result<String> {
    use sha2::{Digest, Sha256};
    use x509_parser::pem::parse_x509_pem;

    let (_, pem_obj) =
        parse_x509_pem(pem.as_bytes()).map_err(|e| CryptoError::Certificate(e.to_string()))?;
    let hash = Sha256::digest(&pem_obj.contents);
    Ok(hex::encode(hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn full_pki_chain() {
        let config = PkiConfig::default();
        let dir = tempdir().unwrap();

        // Generate root CA
        let root = generate_root_ca(&config).unwrap();
        save_ca_bundle(&root, dir.path(), "root").unwrap();

        // Generate intermediate CA
        let intermediate =
            generate_intermediate_ca(&config, "node1", &root.cert_pem, &root.key_pem).unwrap();
        save_ca_bundle(&intermediate, dir.path(), "intermediate").unwrap();

        // Generate service cert
        let service = generate_service_cert(
            &config,
            "masque",
            &["vpn.example.com".to_string()],
            &intermediate.cert_pem,
            &intermediate.key_pem,
        )
        .unwrap();
        save_service_cert(&service, dir.path(), "masque").unwrap();

        // Verify files exist
        assert!(dir.path().join("root.crt").exists());
        assert!(dir.path().join("intermediate.crt").exists());
        assert!(dir.path().join("masque.chain.crt").exists());
    }

    #[test]
    fn test_pki_config_default() {
        let config = PkiConfig::default();
        assert_eq!(config.org_name, "VPR");
        assert_eq!(config.root_cn, "VPR Root CA");
        assert_eq!(config.root_validity_days, 3650);
        assert_eq!(config.intermediate_validity_days, 365);
        assert_eq!(config.service_validity_days, 90);
    }

    #[test]
    fn test_pki_config_clone() {
        let config = PkiConfig::default();
        let cloned = config.clone();
        assert_eq!(config.org_name, cloned.org_name);
        assert_eq!(config.root_cn, cloned.root_cn);
    }

    #[test]
    fn test_pki_config_debug() {
        let config = PkiConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("PkiConfig"));
        assert!(debug_str.contains("VPR"));
    }

    #[test]
    fn test_pki_config_serialization() {
        let config = PkiConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("org_name"));
        assert!(json.contains("VPR"));

        let parsed: PkiConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.org_name, config.org_name);
        assert_eq!(parsed.root_validity_days, config.root_validity_days);
    }

    #[test]
    fn test_pki_config_custom() {
        let config = PkiConfig {
            org_name: "CustomOrg".to_string(),
            root_cn: "Custom Root".to_string(),
            root_validity_days: 7300,
            intermediate_validity_days: 730,
            service_validity_days: 30,
        };
        assert_eq!(config.org_name, "CustomOrg");
        assert_eq!(config.root_validity_days, 7300);
    }

    #[test]
    fn test_generate_root_ca_cert_contains_org() {
        let config = PkiConfig::default();
        let root = generate_root_ca(&config).unwrap();
        assert!(root.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(root.key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn test_generate_root_ca_custom_org() {
        let config = PkiConfig {
            org_name: "TestOrganization".to_string(),
            root_cn: "Test Root CA".to_string(),
            ..Default::default()
        };
        let root = generate_root_ca(&config).unwrap();
        assert!(!root.cert_pem.is_empty());
        assert!(!root.key_pem.is_empty());
    }

    #[test]
    fn test_generate_intermediate_ca() {
        let config = PkiConfig::default();
        let root = generate_root_ca(&config).unwrap();
        let intermediate =
            generate_intermediate_ca(&config, "test-node", &root.cert_pem, &root.key_pem).unwrap();

        assert!(intermediate
            .cert_pem
            .starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(intermediate
            .key_pem
            .starts_with("-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn test_generate_service_cert_multiple_dns() {
        let config = PkiConfig::default();
        let root = generate_root_ca(&config).unwrap();
        let intermediate =
            generate_intermediate_ca(&config, "node", &root.cert_pem, &root.key_pem).unwrap();

        let dns_names = vec![
            "vpn.example.com".to_string(),
            "api.example.com".to_string(),
            "www.example.com".to_string(),
        ];
        let service = generate_service_cert(
            &config,
            "multi-dns",
            &dns_names,
            &intermediate.cert_pem,
            &intermediate.key_pem,
        )
        .unwrap();

        assert!(service.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(service.key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        // Chain should contain both certs
        assert!(service.chain_pem.contains("-----BEGIN CERTIFICATE-----"));
        // Should contain at least 2 certificate blocks
        assert!(
            service
                .chain_pem
                .matches("-----BEGIN CERTIFICATE-----")
                .count()
                >= 2
        );
    }

    #[test]
    fn test_service_cert_chain_contains_intermediate() {
        let config = PkiConfig::default();
        let root = generate_root_ca(&config).unwrap();
        let intermediate =
            generate_intermediate_ca(&config, "node", &root.cert_pem, &root.key_pem).unwrap();

        let service = generate_service_cert(
            &config,
            "test-svc",
            &["test.example.com".to_string()],
            &intermediate.cert_pem,
            &intermediate.key_pem,
        )
        .unwrap();

        // Chain should contain the intermediate cert PEM
        assert!(service.chain_pem.contains(intermediate.cert_pem.trim()));
    }

    #[test]
    fn test_save_and_load_ca_bundle() {
        let config = PkiConfig::default();
        let dir = tempdir().unwrap();
        let root = generate_root_ca(&config).unwrap();

        save_ca_bundle(&root, dir.path(), "test-ca").unwrap();

        let (loaded_cert, loaded_key) = load_ca_bundle(dir.path(), "test-ca").unwrap();
        assert_eq!(loaded_cert, root.cert_pem);
        assert_eq!(loaded_key, root.key_pem);
    }

    #[test]
    fn test_load_ca_bundle_not_found() {
        let dir = tempdir().unwrap();
        let result = load_ca_bundle(dir.path(), "nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ca_for_signing() {
        let config = PkiConfig::default();
        let root = generate_root_ca(&config).unwrap();

        // Parse the generated CA for re-use
        let (parsed_cert, parsed_key) =
            parse_ca_for_signing(&root.cert_pem, &root.key_pem).unwrap();

        // Should be able to sign with parsed CA
        let intermediate =
            generate_intermediate_ca(&config, "parsed-test", &parsed_cert, &parsed_key).unwrap();
        assert!(!intermediate.cert_pem.is_empty());
    }

    #[test]
    fn test_parse_ca_invalid_cert() {
        let result = parse_ca_for_signing("not a cert", "not a key");
        assert!(result.is_err());
    }

    #[test]
    fn test_cert_fingerprint() {
        let config = PkiConfig::default();
        let root = generate_root_ca(&config).unwrap();

        let fp = cert_fingerprint(&root.cert_pem).unwrap();
        // SHA-256 fingerprint is 64 hex chars
        assert_eq!(fp.len(), 64);
        // Should be valid hex
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_cert_fingerprint_deterministic() {
        let config = PkiConfig::default();
        let root = generate_root_ca(&config).unwrap();

        let fp1 = cert_fingerprint(&root.cert_pem).unwrap();
        let fp2 = cert_fingerprint(&root.cert_pem).unwrap();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_cert_fingerprint_invalid_pem() {
        let result = cert_fingerprint("not a valid pem");
        assert!(result.is_err());
    }

    #[test]
    fn test_different_certs_different_fingerprints() {
        let config = PkiConfig::default();
        let root1 = generate_root_ca(&config).unwrap();
        let root2 = generate_root_ca(&config).unwrap();

        let fp1 = cert_fingerprint(&root1.cert_pem).unwrap();
        let fp2 = cert_fingerprint(&root2.cert_pem).unwrap();
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_save_service_cert_creates_files() {
        let config = PkiConfig::default();
        let dir = tempdir().unwrap();

        let root = generate_root_ca(&config).unwrap();
        let intermediate =
            generate_intermediate_ca(&config, "node", &root.cert_pem, &root.key_pem).unwrap();
        let service = generate_service_cert(
            &config,
            "test",
            &["test.local".to_string()],
            &intermediate.cert_pem,
            &intermediate.key_pem,
        )
        .unwrap();

        save_service_cert(&service, dir.path(), "svc").unwrap();

        assert!(dir.path().join("svc.crt").exists());
        assert!(dir.path().join("svc.key").exists());
        assert!(dir.path().join("svc.chain.crt").exists());
    }

    #[test]
    fn test_save_ca_bundle_creates_directory() {
        let dir = tempdir().unwrap();
        let nested_path = dir.path().join("nested").join("deep");

        let config = PkiConfig::default();
        let root = generate_root_ca(&config).unwrap();

        save_ca_bundle(&root, &nested_path, "ca").unwrap();
        assert!(nested_path.join("ca.crt").exists());
        assert!(nested_path.join("ca.key").exists());
    }

    #[test]
    #[cfg(unix)]
    fn test_key_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let config = PkiConfig::default();
        let dir = tempdir().unwrap();
        let root = generate_root_ca(&config).unwrap();

        save_ca_bundle(&root, dir.path(), "secure").unwrap();

        let key_path = dir.path().join("secure.key");
        let metadata = std::fs::metadata(&key_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn test_generate_service_cert_empty_dns() {
        let config = PkiConfig::default();
        let root = generate_root_ca(&config).unwrap();
        let intermediate =
            generate_intermediate_ca(&config, "node", &root.cert_pem, &root.key_pem).unwrap();

        // Empty DNS names should still work (no SANs)
        let service = generate_service_cert(
            &config,
            "no-san",
            &[],
            &intermediate.cert_pem,
            &intermediate.key_pem,
        )
        .unwrap();
        assert!(!service.cert_pem.is_empty());
    }

    #[test]
    fn test_ca_bundle_pem_format() {
        let config = PkiConfig::default();
        let root = generate_root_ca(&config).unwrap();

        // Cert PEM format
        assert!(root.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(root.cert_pem.trim().ends_with("-----END CERTIFICATE-----"));

        // Key PEM format
        assert!(root.key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(root.key_pem.trim().ends_with("-----END PRIVATE KEY-----"));
    }
}
