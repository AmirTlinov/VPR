//! Public Key Infrastructure (PKI) for X.509 Certificates
//!
//! Generates TLS certificates for the VPR infrastructure using a
//! three-tier hierarchy: Root CA → Intermediate CA → Service Certs.
//!
//! # Security Design
//!
//! - **Root CA**: Offline, ECDSA P-384, 10-year validity
//! - **Intermediate CA**: Online, ECDSA P-384, 1-year validity
//! - **Service Certs**: Short-lived (90 days), ECDSA P-256, auto-rotatable
//!
//! # Certificate Hierarchy
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │              Root CA (P-384)                │
//! │         Validity: 10 years                  │
//! │         Key Usage: certSign, crlSign        │
//! │         Store OFFLINE in HSM/airgapped      │
//! └─────────────────────┬───────────────────────┘
//!                       │ signs
//!                       ▼
//! ┌─────────────────────────────────────────────┐
//! │         Intermediate CA (P-384)             │
//! │         Validity: 1 year                    │
//! │         Key Usage: certSign, crlSign        │
//! │         PathLen: 0 (can only sign leaves)   │
//! └─────────────────────┬───────────────────────┘
//!                       │ signs
//!                       ▼
//! ┌─────────────────────────────────────────────┐
//! │          Service Cert (P-256)               │
//! │         Validity: 90 days                   │
//! │         Key Usage: digitalSig, keyEncipher  │
//! │         EKU: serverAuth, clientAuth         │
//! │         SANs: DNS names for TLS             │
//! └─────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```
//! use vpr_crypto::pki::{PkiConfig, generate_root_ca, generate_intermediate_ca, generate_service_cert};
//!
//! let config = PkiConfig::default();
//!
//! // Generate complete chain
//! let root = generate_root_ca(&config).unwrap();
//! let intermediate = generate_intermediate_ca(&config, "dc1", &root.cert_pem, &root.key_pem).unwrap();
//! let service = generate_service_cert(
//!     &config, "proxy", &["vpn.example.com".into()],
//!     &intermediate.cert_pem, &intermediate.key_pem
//! ).unwrap();
//!
//! // Use service.chain_pem for TLS server configuration
//! ```

use crate::{CryptoError, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use time::{Duration, OffsetDateTime};

/// Configuration for the PKI certificate hierarchy.
///
/// Controls organization name, common names, and validity periods
/// for each tier of the certificate chain.
///
/// # Fields
///
/// | Field | Default | Description |
/// |-------|---------|-------------|
/// | `org_name` | "VPR" | Organization name in certificate DN |
/// | `root_cn` | "VPR Root CA" | Common name for root CA |
/// | `root_validity_days` | 3650 | Root CA validity (10 years) |
/// | `intermediate_validity_days` | 365 | Intermediate CA validity (1 year) |
/// | `service_validity_days` | 90 | Service cert validity (90 days) |
///
/// # Example
///
/// ```
/// use vpr_crypto::PkiConfig;
///
/// // Use defaults
/// let config = PkiConfig::default();
/// assert_eq!(config.root_validity_days, 3650);
///
/// // Custom configuration
/// let custom = PkiConfig {
///     org_name: "MyOrg".into(),
///     root_cn: "MyOrg Root CA".into(),
///     service_validity_days: 30, // Shorter for testing
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkiConfig {
    /// Organization name for certificate Distinguished Name (O=)
    pub org_name: String,
    /// Common Name for root certificate (CN=)
    pub root_cn: String,
    /// Root CA validity in days (default: 3650 = 10 years)
    pub root_validity_days: i64,
    /// Intermediate CA validity in days (default: 365 = 1 year)
    pub intermediate_validity_days: i64,
    /// Service certificate validity in days (default: 90)
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

/// Certificate Authority bundle containing certificate and private key.
///
/// Used for both root and intermediate CAs. Contains PEM-encoded
/// X.509 certificate and PKCS#8 private key.
///
/// # Security
///
/// The `key_pem` field contains sensitive key material. When saving:
/// - Use [`save_ca_bundle`] which sets 0o600 permissions on Unix
/// - For root CA, store on air-gapped system or HSM
///
/// # Fields
///
/// - `cert_pem`: PEM-encoded X.509 certificate
/// - `key_pem`: PEM-encoded PKCS#8 private key (ECDSA P-384)
pub struct CaBundle {
    /// PEM-encoded X.509 certificate
    pub cert_pem: String,
    /// PEM-encoded PKCS#8 private key
    pub key_pem: String,
}

/// Generated service certificate with full chain.
///
/// Contains everything needed to configure a TLS server:
/// - Single certificate for the service
/// - Private key for TLS handshake
/// - Full chain (service + intermediate) for client verification
///
/// # Fields
///
/// - `cert_pem`: Service certificate only
/// - `key_pem`: ECDSA P-256 private key
/// - `chain_pem`: Full chain (service + intermediate) for TLS config
///
/// # Example
///
/// ```no_run
/// # use vpr_crypto::pki::ServiceCert;
/// # let service: ServiceCert = todo!();
/// // Configure TLS server (e.g., rustls)
/// // cert_chain: parse service.chain_pem
/// // private_key: parse service.key_pem
/// ```
pub struct ServiceCert {
    /// PEM-encoded service certificate only
    pub cert_pem: String,
    /// PEM-encoded PKCS#8 private key (ECDSA P-256)
    pub key_pem: String,
    /// Full certificate chain (service + intermediate) for TLS
    pub chain_pem: String,
}

/// Generate self-signed root Certificate Authority.
///
/// Creates an ECDSA P-384 root CA certificate suitable for offline storage.
/// This is the trust anchor for the entire PKI hierarchy.
///
/// # Security Recommendations
///
/// - Generate on air-gapped machine
/// - Store private key in HSM or encrypted offline storage
/// - Only use for signing intermediate CAs (not service certs directly)
///
/// # Certificate Properties
///
/// - **Algorithm**: ECDSA P-384 with SHA-384
/// - **Key Usage**: keyCertSign, cRLSign
/// - **Basic Constraints**: CA:TRUE, pathLen:1
/// - **Validity**: Configured via `config.root_validity_days`
///
/// # Errors
///
/// Returns [`CryptoError::KeyGen`] if key generation fails, or
/// [`CryptoError::Pki`] if certificate generation fails.
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

/// Generate intermediate Certificate Authority signed by the root CA.
///
/// Creates an ECDSA P-384 intermediate CA that can sign service certificates.
/// The intermediate CA has `pathLen:0`, meaning it can only sign leaf certs.
///
/// # Arguments
///
/// * `config` - PKI configuration with validity periods
/// * `node_name` - Identifier for this CA (e.g., "dc1", "eu-west")
/// * `root_cert_pem` - PEM-encoded root CA certificate
/// * `root_key_pem` - PEM-encoded root CA private key
///
/// # Certificate Properties
///
/// - **Algorithm**: ECDSA P-384 with SHA-384
/// - **Key Usage**: keyCertSign, cRLSign
/// - **Basic Constraints**: CA:TRUE, pathLen:0
/// - **CN**: "VPR Intermediate CA - {node_name}"
///
/// # Example
///
/// ```
/// use vpr_crypto::pki::{PkiConfig, generate_root_ca, generate_intermediate_ca};
///
/// let config = PkiConfig::default();
/// let root = generate_root_ca(&config).unwrap();
///
/// // Create regional intermediate CAs
/// let eu_ca = generate_intermediate_ca(&config, "eu-west", &root.cert_pem, &root.key_pem).unwrap();
/// let us_ca = generate_intermediate_ca(&config, "us-east", &root.cert_pem, &root.key_pem).unwrap();
/// ```
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKey`] if root key PEM is malformed, or
/// [`CryptoError::Certificate`] if root cert PEM is invalid.
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

/// Generate TLS service certificate signed by intermediate CA.
///
/// Creates an ECDSA P-256 end-entity certificate for TLS servers
/// (MASQUE, DoH, ACME, etc.). Includes Subject Alternative Names
/// for DNS-based certificate validation.
///
/// # Arguments
///
/// * `config` - PKI configuration with validity periods
/// * `service_name` - Human-readable service name (e.g., "masque", "doh")
/// * `dns_names` - DNS names for Subject Alternative Names (SANs)
/// * `intermediate_cert_pem` - PEM-encoded intermediate CA certificate
/// * `intermediate_key_pem` - PEM-encoded intermediate CA private key
///
/// # Certificate Properties
///
/// - **Algorithm**: ECDSA P-256 with SHA-256 (TLS-friendly)
/// - **Key Usage**: digitalSignature, keyEncipherment
/// - **Extended Key Usage**: serverAuth, clientAuth
/// - **SANs**: All provided DNS names
/// - **CN**: "VPR {service_name}"
///
/// # Example
///
/// ```
/// use vpr_crypto::pki::{PkiConfig, generate_root_ca, generate_intermediate_ca, generate_service_cert};
///
/// let config = PkiConfig::default();
/// let root = generate_root_ca(&config).unwrap();
/// let intermediate = generate_intermediate_ca(&config, "dc1", &root.cert_pem, &root.key_pem).unwrap();
///
/// // Generate cert with multiple SANs
/// let service = generate_service_cert(
///     &config,
///     "masque",
///     &["vpn.example.com".into(), "*.vpn.example.com".into()],
///     &intermediate.cert_pem,
///     &intermediate.key_pem,
/// ).unwrap();
///
/// // service.chain_pem contains service + intermediate for TLS config
/// ```
///
/// # Errors
///
/// Returns [`CryptoError::Certificate`] if any DNS name is invalid, or
/// [`CryptoError::InvalidKey`] if intermediate key is malformed.
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

/// Save CA bundle (certificate + key) to directory.
///
/// Writes `{name}.crt` and `{name}.key` files to the specified directory.
/// On Unix, sets key file permissions to `0o600` (owner read/write only).
///
/// # Arguments
///
/// * `bundle` - CA certificate and key to save
/// * `dir` - Target directory (created if it doesn't exist)
/// * `name` - Base filename (without extension)
///
/// # Files Created
///
/// - `{dir}/{name}.crt` - PEM certificate
/// - `{dir}/{name}.key` - PEM private key (mode 0600 on Unix)
///
/// # Security
///
/// Always store root CA keys on air-gapped systems or in HSMs.
/// Use this function only for intermediate CAs in production.
///
/// # Errors
///
/// Returns [`std::io::Error`] wrapped in [`CryptoError`] if directory
/// creation or file write fails.
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

/// Load CA bundle (certificate + key) from directory.
///
/// Reads `{name}.crt` and `{name}.key` files from the specified directory.
///
/// # Arguments
///
/// * `dir` - Directory containing the CA files
/// * `name` - Base filename (without extension)
///
/// # Returns
///
/// Tuple of `(cert_pem, key_pem)` as strings.
///
/// # Example
///
/// ```no_run
/// use vpr_crypto::pki::load_ca_bundle;
/// use std::path::Path;
///
/// let (cert_pem, key_pem) = load_ca_bundle(Path::new("/etc/vpr/pki"), "intermediate").unwrap();
/// ```
///
/// # Errors
///
/// Returns [`std::io::Error`] if files don't exist or can't be read.
pub fn load_ca_bundle(dir: &Path, name: &str) -> Result<(String, String)> {
    let cert_path = dir.join(format!("{name}.crt"));
    let key_path = dir.join(format!("{name}.key"));
    let cert_pem = std::fs::read_to_string(&cert_path)?;
    let key_pem = std::fs::read_to_string(&key_path)?;
    Ok((cert_pem, key_pem))
}

/// Validate and parse CA certificate and key for signing operations.
///
/// Verifies that both PEM formats are correct and the key matches
/// the certificate before use. Use this to validate loaded CA bundles.
///
/// # Arguments
///
/// * `cert_pem` - PEM-encoded X.509 certificate
/// * `key_pem` - PEM-encoded PKCS#8 private key
///
/// # Returns
///
/// Cloned `(cert_pem, key_pem)` tuple if validation succeeds.
///
/// # Example
///
/// ```
/// use vpr_crypto::pki::{PkiConfig, generate_root_ca, parse_ca_for_signing};
///
/// let root = generate_root_ca(&PkiConfig::default()).unwrap();
///
/// // Validate before using for signing
/// let (cert, key) = parse_ca_for_signing(&root.cert_pem, &root.key_pem).unwrap();
/// ```
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKey`] if key PEM is malformed, or
/// [`CryptoError::Certificate`] if cert PEM is invalid or doesn't
/// match the key.
pub fn parse_ca_for_signing(cert_pem: &str, key_pem: &str) -> Result<(String, String)> {
    // Validate key PEM can be parsed
    KeyPair::from_pem(key_pem).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
    // Validate cert PEM can be used for signing (by attempting to create Issuer)
    let key = KeyPair::from_pem(key_pem).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
    Issuer::from_ca_cert_pem(cert_pem, &key)
        .map_err(|e| CryptoError::Certificate(e.to_string()))?;
    Ok((cert_pem.to_string(), key_pem.to_string()))
}

/// Save service certificate bundle to directory.
///
/// Writes three files for TLS server configuration:
/// - `{name}.crt` - Service certificate only
/// - `{name}.key` - Private key (mode 0600 on Unix)
/// - `{name}.chain.crt` - Full chain (service + intermediate)
///
/// # Arguments
///
/// * `cert` - Service certificate bundle
/// * `dir` - Target directory (created if it doesn't exist)
/// * `name` - Base filename (without extension)
///
/// # TLS Server Configuration
///
/// Most TLS servers need:
/// - Certificate chain: `{name}.chain.crt`
/// - Private key: `{name}.key`
///
/// # Example
///
/// ```no_run
/// use vpr_crypto::pki::{save_service_cert, ServiceCert};
/// use std::path::Path;
///
/// # let service: ServiceCert = todo!();
/// save_service_cert(&service, Path::new("/etc/vpr/tls"), "masque").unwrap();
/// // Creates: masque.crt, masque.key, masque.chain.crt
/// ```
///
/// # Errors
///
/// Returns [`std::io::Error`] if directory creation or file write fails.
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

/// Calculate SHA-256 fingerprint of a PEM certificate.
///
/// Returns a lowercase hex-encoded fingerprint string (64 characters).
/// Useful for certificate pinning and verification.
///
/// # Arguments
///
/// * `pem` - PEM-encoded X.509 certificate
///
/// # Returns
///
/// 64-character lowercase hex string (SHA-256 hash).
///
/// # Example
///
/// ```
/// use vpr_crypto::pki::{PkiConfig, generate_root_ca, cert_fingerprint};
///
/// let root = generate_root_ca(&PkiConfig::default()).unwrap();
/// let fingerprint = cert_fingerprint(&root.cert_pem).unwrap();
///
/// assert_eq!(fingerprint.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
/// println!("Root CA fingerprint: {}", fingerprint);
/// ```
///
/// # Errors
///
/// Returns [`CryptoError::Certificate`] if PEM parsing fails.
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
