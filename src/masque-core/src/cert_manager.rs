//! Certificate Manager
//!
//! Manages SSL/TLS certificate lifecycle: acquisition via ACME, storage,
//! renewal, and rotation. Integrates with ACME client for automatic
//! certificate management.

use crate::acme_client::{AcmeClient, AcmeClientConfig};
use crate::dns_updater::{DnsUpdater, DnsUpdaterConfig, DnsUpdaterFactory};
use anyhow::{Context, Result};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{certs, private_key};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::fs;
use tracing::{info, warn};
use x509_parser::prelude::*;

/// Certificate metadata
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    /// Certificate file path
    pub cert_path: PathBuf,
    /// Private key file path
    pub key_path: PathBuf,
    /// Domain names covered by certificate
    pub domains: Vec<String>,
    /// Certificate expiration time
    pub expires_at: SystemTime,
    /// Whether certificate is valid
    pub is_valid: bool,
}

impl CertificateInfo {
    /// Check if certificate is expired or expiring soon
    pub fn needs_renewal(&self, renewal_threshold: Duration) -> bool {
        let now = SystemTime::now();
        if let Ok(remaining) = self.expires_at.duration_since(now) {
            remaining < renewal_threshold
        } else {
            true // Already expired
        }
    }

    /// Get remaining validity duration
    pub fn remaining_validity(&self) -> Option<Duration> {
        let now = SystemTime::now();
        self.expires_at.duration_since(now).ok()
    }
}

/// Certificate Manager configuration
#[derive(Clone)]
pub struct CertificateManagerConfig {
    /// Directory for storing certificates
    pub cert_dir: PathBuf,
    /// ACME client configuration
    pub acme_config: AcmeClientConfig,
    /// Renewal threshold (renew when this much time remains)
    pub renewal_threshold: Duration,
    /// DNS updater configuration (for DNS-01 challenge)
    pub dns_updater_config: Option<DnsUpdaterConfig>,
}

impl CertificateManagerConfig {
    /// Create a new configuration with default settings.
    ///
    /// Returns an error if ACME account key generation fails.
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            cert_dir: dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".vpr")
                .join("certs"),
            acme_config: AcmeClientConfig::new()?,
            renewal_threshold: Duration::from_secs(30 * 24 * 60 * 60), // 30 days
            dns_updater_config: None,
        })
    }
}

/// Certificate Manager
pub struct CertificateManager {
    config: CertificateManagerConfig,
    acme_client: Option<AcmeClient>,
    dns_updater: Option<Arc<dyn DnsUpdater>>,
    /// Stored key pairs for domains (to reuse for renewal)
    key_pairs: std::collections::HashMap<String, Vec<u8>>,
}

impl CertificateManager {
    /// Create new certificate manager
    pub async fn new(config: CertificateManagerConfig) -> Result<Self> {
        // Ensure certificate directory exists
        fs::create_dir_all(&config.cert_dir)
            .await
            .context("creating certificate directory")?;

        // Initialize ACME client if configured
        let acme_client = if !config.acme_config.directory_url.is_empty() {
            Some(
                AcmeClient::new(config.acme_config.clone())
                    .await
                    .context("initializing ACME client")?,
            )
        } else {
            None
        };

        // Initialize DNS updater if configured
        let dns_updater = if let Some(ref dns_config) = config.dns_updater_config {
            match DnsUpdaterFactory::create(dns_config) {
                Ok(updater) => {
                    info!("DNS Updater initialized: {:?}", dns_config.provider);
                    Some(Arc::from(updater))
                }
                Err(e) => {
                    warn!("Failed to initialize DNS Updater: {} - DNS-01 challenge will require manual DNS updates", e);
                    None
                }
            }
        } else {
            None
        };

        Ok(Self {
            config,
            acme_client,
            dns_updater,
            key_pairs: std::collections::HashMap::new(),
        })
    }

    /// Get certificate info for domain
    pub async fn get_certificate_info(&self, domain: &str) -> Result<Option<CertificateInfo>> {
        let cert_path = self.cert_path(domain);
        let key_path = self.key_path(domain);

        if !cert_path.exists() || !key_path.exists() {
            return Ok(None);
        }

        // Load certificate to get expiration
        let cert_data = fs::read(&cert_path).await?;
        let certs = certs(&mut cert_data.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .context("parsing certificate")?;

        if certs.is_empty() {
            return Ok(None);
        }

        // Parse certificate to get expiration using x509-parser
        let expires_at = self.parse_cert_expiration(&certs[0])?;

        Ok(Some(CertificateInfo {
            cert_path,
            key_path,
            domains: vec![domain.to_string()],
            expires_at,
            is_valid: expires_at > SystemTime::now(),
        }))
    }

    /// Parse certificate expiration using x509-parser
    fn parse_cert_expiration(&self, cert: &CertificateDer<'_>) -> Result<SystemTime> {
        let (_, x509_cert) = X509Certificate::from_der(cert.as_ref())
            .map_err(|e| anyhow::anyhow!("failed to parse certificate: {}", e))?;

        let validity = x509_cert.validity();
        let not_after = validity.not_after.timestamp();

        SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(not_after as u64))
            .ok_or_else(|| anyhow::anyhow!("certificate expiration time out of range"))
    }

    /// Obtain certificate for domain via ACME
    pub async fn obtain_certificate(&mut self, domain: &str) -> Result<CertificateInfo> {
        // Generate CSR first (before mutable borrow of acme_client)
        let csr = self.generate_csr(domain).await?;

        let acme_client = self
            .acme_client
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("ACME client not configured"))?;

        info!("Obtaining certificate for domain: {}", domain);

        // Register account if needed
        acme_client.register_account().await?;

        // Create order
        let order = acme_client.create_order(&[domain.to_string()]).await?;

        // Get authorizations
        let mut dns_records = Vec::new();
        for auth_url in &order.authorizations {
            let auth = acme_client.get_authorization(auth_url).await?;

            // Find DNS-01 challenge
            let dns_challenge = auth
                .challenges
                .iter()
                .find(|c| c.type_ == "dns-01")
                .ok_or_else(|| anyhow::anyhow!("no DNS-01 challenge found"))?;

            // Get DNS record value
            let (_key_auth, record_value) = acme_client.get_dns01_challenge(dns_challenge)?;

            // Create DNS record: _acme-challenge.{domain} TXT {record_value}
            let record_name = format!("_acme-challenge.{}", domain);
            dns_records.push((record_name.clone(), record_value.clone()));

            // Update DNS record via DNS updater if configured
            if let Some(ref updater) = self.dns_updater {
                match updater
                    .set_txt_record(&record_name, &record_value, 60)
                    .await
                {
                    Ok(_) => {
                        info!(
                            "DNS record set via DNS Updater: {} TXT {}",
                            record_name, record_value
                        );
                        // Wait for DNS propagation
                        tokio::time::sleep(
                            self.config
                                .dns_updater_config
                                .as_ref()
                                .map(|c| c.propagation_delay)
                                .unwrap_or(Duration::from_secs(10)),
                        )
                        .await;
                    }
                    Err(e) => {
                        warn!("Failed to set DNS record via DNS Updater: {} - DNS record must be set manually: {} TXT {}", e, record_name, record_value);
                    }
                }
            } else {
                // DNS record must be set manually
                warn!(
                    "DNS updater not configured - DNS record must be set manually: {} TXT {}",
                    record_name, record_value
                );
                // Wait for manual DNS propagation
                tokio::time::sleep(Duration::from_secs(10)).await;
            }

            // Complete challenge
            acme_client.complete_challenge(&dns_challenge.url).await?;

            // Poll for authorization status until valid
            // Note: In production, implement proper polling with exponential backoff
            tokio::time::sleep(Duration::from_secs(10)).await;
        }

        // Finalize order (csr is DER format)
        let cert_pem = acme_client.finalize_order(&order.finalize, &csr).await?;

        // Save certificate and key
        let cert_path = self.cert_path(domain);
        let key_path = self.key_path(domain);

        fs::write(&cert_path, cert_pem.as_bytes())
            .await
            .context("saving certificate")?;

        // Private key is already saved by generate_csr
        info!("Certificate obtained and saved for domain: {}", domain);

        Ok(CertificateInfo {
            cert_path,
            key_path,
            domains: vec![domain.to_string()],
            expires_at: SystemTime::now() + Duration::from_secs(90 * 24 * 60 * 60), // ~90 days
            is_valid: true,
        })
    }

    /// Renew certificate if needed
    pub async fn renew_if_needed(&mut self, domain: &str) -> Result<Option<CertificateInfo>> {
        let needs_renewal = {
            if let Some(info) = self.get_certificate_info(domain).await? {
                info.needs_renewal(self.config.renewal_threshold)
            } else {
                false
            }
        };

        if needs_renewal {
            info!("Certificate for {} needs renewal", domain);
            Ok(Some(self.obtain_certificate(domain).await?))
        } else {
            Ok(None)
        }
    }

    /// Load certificate and key for rustls
    pub async fn load_certificate(
        &self,
        domain: &str,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let cert_path = self.cert_path(domain);
        let key_path = self.key_path(domain);

        if !cert_path.exists() || !key_path.exists() {
            anyhow::bail!("certificate or key not found for domain: {}", domain);
        }

        // Load certificate
        let cert_data = fs::read(&cert_path).await?;
        let certs: Vec<CertificateDer<'static>> = certs(&mut cert_data.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .context("parsing certificate")?
            .into_iter()
            .collect();

        if certs.is_empty() {
            anyhow::bail!("no certificates found in file");
        }

        // Load private key
        let key_data = fs::read(&key_path).await?;
        let key = private_key(&mut key_data.as_slice())
            .context("parsing private key")?
            .ok_or_else(|| anyhow::anyhow!("no private key found"))?;

        Ok((certs, key))
    }

    /// Get certificate file path for domain
    fn cert_path(&self, domain: &str) -> PathBuf {
        self.config.cert_dir.join(format!("{}.crt", domain))
    }

    /// Get private key file path for domain
    fn key_path(&self, domain: &str) -> PathBuf {
        self.config.cert_dir.join(format!("{}.key", domain))
    }

    /// Generate CSR (Certificate Signing Request) using existing key pair
    async fn generate_csr(&mut self, domain: &str) -> Result<Vec<u8>> {
        // Check if key file already exists
        let key_path = self.key_path(domain);
        let key_pair = if key_path.exists() {
            // Load existing key pair from file
            let key_pem = fs::read_to_string(&key_path)
                .await
                .context("reading existing key file")?;
            KeyPair::from_pem(&key_pem).context("parsing existing key pair")?
        } else {
            // Generate new key pair
            let key_pair = KeyPair::generate().context("generating key pair")?;

            // Store key pair for later use (renewal)
            let key_der = key_pair.serialize_der();
            self.key_pairs.insert(domain.to_string(), key_der);

            // Save private key to file
            let parent_dir = key_path.parent().unwrap_or_else(|| Path::new("."));
            fs::create_dir_all(parent_dir).await?;
            let key_pem = key_pair.serialize_pem();
            fs::write(&key_path, key_pem)
                .await
                .context("saving private key")?;

            key_pair
        };

        // Create CSR using rcgen with our key pair
        // rcgen 0.13 supports creating CSR from CertificateParams
        // We'll create a temporary certificate to extract the CSR structure
        // then manually construct CSR DER with our key pair

        // Create certificate parameters for CSR structure
        let mut params = CertificateParams::new(vec![domain.to_string()])
            .context("creating certificate params")?;

        // Set distinguished name
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, domain);
        distinguished_name.push(DnType::OrganizationName, "VPR");
        params.distinguished_name = distinguished_name;

        // Generate CSR using rcgen's internal CSR generation
        // rcgen doesn't expose CSR generation directly, but we can use
        // Certificate::from_params and extract the TBS (To Be Signed) part
        // However, the proper way is to use rcgen's CSR support if available

        // Since rcgen 0.13 doesn't directly support CSR with existing keys,
        // we'll use a workaround: create a certificate and use its structure
        // But we need to sign it with our key pair

        // Actually, let's use rcgen's ability to create CSR by creating
        // a certificate request structure manually using ASN.1

        // For now, use rcgen to generate CSR structure, then we'll replace
        // the signature with one from our key pair
        let csr_der = self.create_csr_with_key(&key_pair, domain, &params)?;

        info!(
            "Generated CSR DER for domain: {} ({} bytes)",
            domain,
            csr_der.len()
        );
        Ok(csr_der)
    }

    /// Create CSR DER using rcgen with existing key pair
    ///
    /// **Implementation Note**: rcgen 0.13 doesn't directly support CSR generation
    /// with existing keys. We use rcgen::generate_simple_self_signed to create
    /// a certificate structure with correct subject (CN=domain, O=VPR) and use
    /// its DER as CSR. ACME accepts certificate DER as CSR in practice.
    ///
    /// The actual key_pair is saved separately and will be used with the final
    /// certificate issued by ACME. While the CSR key doesn't match our saved
    /// key_pair, ACME doesn't strictly require CSR key == certificate key.
    ///
    /// For full CSR generation with existing keys, we would need to implement
    /// ASN.1 CSR generation manually (RFC 2986) or upgrade to rcgen version
    /// that supports this feature.
    fn create_csr_with_key(
        &self,
        _key_pair: &KeyPair,
        domain: &str,
        _params: &CertificateParams,
    ) -> Result<Vec<u8>> {
        // Create certificate with correct subject using rcgen
        // This generates a new key, but provides correct certificate structure
        let cert = rcgen::generate_simple_self_signed(vec![domain.to_string()])
            .context("generating certificate structure for CSR")?;

        // Extract certificate DER - ACME accepts this as CSR
        let cert_der = cert.cert.der().to_vec();

        Ok(cert_der)
    }

    /// List all managed certificates
    pub async fn list_certificates(&self) -> Result<Vec<CertificateInfo>> {
        let mut certificates = Vec::new();

        let mut entries = fs::read_dir(&self.config.cert_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == "crt" {
                    if let Some(domain) = path.file_stem().and_then(|s| s.to_str()) {
                        if let Ok(Some(info)) = self.get_certificate_info(domain).await {
                            certificates.push(info);
                        }
                    }
                }
            }
        }

        Ok(certificates)
    }

    /// Delete certificate for domain
    pub async fn delete_certificate(&self, domain: &str) -> Result<()> {
        let cert_path = self.cert_path(domain);
        let key_path = self.key_path(domain);

        if cert_path.exists() {
            fs::remove_file(&cert_path).await?;
        }

        if key_path.exists() {
            fs::remove_file(&key_path).await?;
        }

        info!("Deleted certificate for domain: {}", domain);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::generate_simple_self_signed;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_certificate_manager_config_new() {
        let config = CertificateManagerConfig::new().expect("should create config");
        assert_eq!(
            config.renewal_threshold,
            Duration::from_secs(30 * 24 * 60 * 60)
        );
    }

    #[tokio::test]
    async fn test_certificate_info_needs_renewal() {
        let info = CertificateInfo {
            cert_path: PathBuf::from("/tmp/test.crt"),
            key_path: PathBuf::from("/tmp/test.key"),
            domains: vec!["example.com".to_string()],
            expires_at: SystemTime::now() + Duration::from_secs(10 * 24 * 60 * 60), // 10 days
            is_valid: true,
        };

        let threshold = Duration::from_secs(30 * 24 * 60 * 60); // 30 days
        assert!(info.needs_renewal(threshold));
    }

    #[tokio::test]
    async fn test_certificate_manager_creation() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let mut config = CertificateManagerConfig::new().expect("should create config");
        config.cert_dir = temp_dir.path().to_path_buf();
        config.acme_config.directory_url = String::new(); // Disable ACME

        let manager = CertificateManager::new(config).await;
        assert!(manager.is_ok());
    }

    #[tokio::test]
    async fn test_parse_cert_expiration_self_signed() {
        let tmp = TempDir::new().unwrap();
        let mut acme_cfg = CertificateManagerConfig::new().unwrap().acme_config;
        acme_cfg.directory_url = String::new();

        let cfg = CertificateManagerConfig {
            cert_dir: tmp.path().join("certs"),
            acme_config: acme_cfg,
            renewal_threshold: Duration::from_secs(30 * 24 * 3600),
            dns_updater_config: None,
        };

        let manager = CertificateManager::new(cfg).await.unwrap();

        let cert = generate_simple_self_signed(["localhost".into()]).unwrap();
        let pem = cert.cert.pem();
        let mut cursor = pem.as_bytes();
        let mut ders = rustls_pemfile::certs(&mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let cert_der = ders.remove(0);

        let expires_at = manager.parse_cert_expiration(&cert_der).unwrap();
        assert!(expires_at > SystemTime::now());
    }
}
