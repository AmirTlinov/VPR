use crate::{CryptoError, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertifiedKey, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
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
    pub cert: Certificate,
    pub key: KeyPair,
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

    Ok(CaBundle {
        cert_pem,
        key_pem,
        cert,
        key,
    })
}

/// Generate intermediate CA signed by root
pub fn generate_intermediate_ca(
    config: &PkiConfig,
    node_name: &str,
    root_cert: &Certificate,
    root_key: &KeyPair,
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

    let cert = params.signed_by(&key, root_cert, root_key)?;
    let cert_pem = cert.pem();
    let key_pem = key.serialize_pem();

    Ok(CaBundle {
        cert_pem,
        key_pem,
        cert,
        key,
    })
}

/// Generate service certificate (for MASQUE, DoH, etc.)
pub fn generate_service_cert(
    config: &PkiConfig,
    service_name: &str,
    dns_names: &[String],
    intermediate_cert: &Certificate,
    intermediate_key: &KeyPair,
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

    let cert = params.signed_by(&key, intermediate_cert, intermediate_key)?;
    let cert_pem = cert.pem();
    let key_pem = key.serialize_pem();

    // Build full chain: service + intermediate
    let chain_pem = format!("{}\n{}", cert_pem, intermediate_cert.pem());

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

/// Parse PEM certificate and key for signing operations
pub fn parse_ca_for_signing(cert_pem: &str, key_pem: &str) -> Result<(Certificate, KeyPair)> {
    let key = KeyPair::from_pem(key_pem).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
    let params = CertificateParams::from_ca_cert_pem(cert_pem)
        .map_err(|e| CryptoError::Certificate(e.to_string()))?;
    let cert = params.self_signed(&key)?;
    Ok((cert, key))
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
            generate_intermediate_ca(&config, "node1", &root.cert, &root.key).unwrap();
        save_ca_bundle(&intermediate, dir.path(), "intermediate").unwrap();

        // Generate service cert
        let service = generate_service_cert(
            &config,
            "masque",
            &["vpn.example.com".to_string()],
            &intermediate.cert,
            &intermediate.key,
        )
        .unwrap();
        save_service_cert(&service, dir.path(), "masque").unwrap();

        // Verify files exist
        assert!(dir.path().join("root.crt").exists());
        assert!(dir.path().join("intermediate.crt").exists());
        assert!(dir.path().join("masque.chain.crt").exists());
    }
}
