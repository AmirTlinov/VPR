//! ACME (Automatic Certificate Management Environment) Client
//!
//! Provides automatic SSL/TLS certificate acquisition from ACME-compatible
//! certificate authorities (e.g., Let's Encrypt).
//!
//! Supports both HTTP-01 and DNS-01 challenges for domain validation.

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

/// ACME directory endpoints
pub mod endpoints {
    pub const LETS_ENCRYPT_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";
    pub const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
}

/// ACME challenge types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeType {
    Http01,
    Dns01,
}

impl ChallengeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChallengeType::Http01 => "http-01",
            ChallengeType::Dns01 => "dns-01",
        }
    }
}

/// ACME account key pair (for account registration)
///
/// Uses `Arc` internally to allow safe cloning without reconstructing the keypair.
#[derive(Clone)]
pub struct AcmeAccountKey {
    /// Signing keypair for Ed25519 signing (wrapped in Arc for safe cloning)
    signing_keypair: Arc<vpr_crypto::keys::SigningKeypair>,
    /// Public key JWK (JSON Web Key)
    public_key_jwk: serde_json::Value,
}

impl std::fmt::Debug for AcmeAccountKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcmeAccountKey")
            .field("public_key_jwk", &self.public_key_jwk)
            .field("signing_keypair", &"[SigningKeypair]")
            .finish()
    }
}

impl AcmeAccountKey {
    /// Generate new account key pair
    pub fn generate() -> Result<Self> {
        // Use Ed25519 for account key
        let signing_keypair = vpr_crypto::keys::SigningKeypair::generate();

        // Create JWK for public key
        let public_key_jwk = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signing_keypair.public_bytes())
        });

        Ok(Self {
            signing_keypair: Arc::new(signing_keypair),
            public_key_jwk,
        })
    }

    /// Sign message using Ed25519
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_keypair.sign(message)
    }

    /// Get public key JWK
    pub fn public_key_jwk(&self) -> &serde_json::Value {
        &self.public_key_jwk
    }
}

/// ACME client configuration
#[derive(Debug, Clone)]
pub struct AcmeClientConfig {
    /// ACME directory URL
    pub directory_url: String,
    /// Account key pair
    pub account_key: AcmeAccountKey,
    /// Preferred challenge type
    pub preferred_challenge: ChallengeType,
    /// HTTP client timeout
    pub timeout: Duration,
    /// Contact email (optional)
    pub contact_email: Option<String>,
}

impl AcmeClientConfig {
    /// Create a new ACME client configuration with default settings.
    ///
    /// Returns an error if account key generation fails (e.g., system RNG unavailable).
    pub fn new() -> Result<Self> {
        let account_key = AcmeAccountKey::generate()
            .context("failed to generate ACME account key - system RNG may be unavailable")?;

        Ok(Self {
            directory_url: endpoints::LETS_ENCRYPT_STAGING.to_string(),
            account_key,
            preferred_challenge: ChallengeType::Dns01,
            timeout: Duration::from_secs(30),
            contact_email: None,
        })
    }

    /// Create configuration with a specific account key.
    pub fn with_account_key(account_key: AcmeAccountKey) -> Self {
        Self {
            directory_url: endpoints::LETS_ENCRYPT_STAGING.to_string(),
            account_key,
            preferred_challenge: ChallengeType::Dns01,
            timeout: Duration::from_secs(30),
            contact_email: None,
        }
    }
}

/// ACME directory metadata
#[derive(Debug, Deserialize)]
struct AcmeDirectory {
    new_nonce: String,
    new_account: String,
    new_order: String,
    #[allow(dead_code)] // Будет использоваться для revocation операций
    revoke_cert: String,
}

/// ACME account information
#[derive(Debug, Deserialize)]
pub struct AcmeAccount {
    pub status: String,
    pub contact: Option<Vec<String>>,
    pub orders: Option<String>,
}

/// ACME order for certificate
#[derive(Debug, Deserialize, Serialize)]
pub struct AcmeOrder {
    pub status: String,
    pub expires: Option<String>,
    pub identifiers: Vec<Identifier>,
    pub authorizations: Vec<String>,
    pub finalize: String,
    pub certificate: Option<String>,
}

/// Domain identifier
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Identifier {
    #[serde(rename = "type")]
    pub type_: String,
    pub value: String,
}

/// ACME authorization
#[derive(Debug, Deserialize)]
pub struct AcmeAuthorization {
    pub status: String,
    pub expires: Option<String>,
    pub identifier: Identifier,
    pub challenges: Vec<Challenge>,
}

/// ACME challenge
#[derive(Debug, Deserialize, Clone)]
pub struct Challenge {
    #[serde(rename = "type")]
    pub type_: String,
    pub url: String,
    pub status: Option<String>,
    pub token: Option<String>,
    pub validation_record: Option<ValidationRecord>,
}

/// Validation record (for DNS-01 challenge)
#[derive(Debug, Deserialize, Clone)]
pub struct ValidationRecord {
    pub hostname: Option<String>,
    pub port: Option<u16>,
    pub addresses_resolved: Option<Vec<String>>,
    pub addresses_used: Option<Vec<String>>,
}

/// ACME Client for certificate management
pub struct AcmeClient {
    config: AcmeClientConfig,
    http_client: reqwest::Client,
    directory: AcmeDirectory,
    account_url: Option<String>,
    nonce: Option<String>,
}

impl AcmeClient {
    /// Create new ACME client
    pub async fn new(config: AcmeClientConfig) -> Result<Self> {
        let http_client = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .context("building HTTP client")?;

        // Fetch directory
        let directory: AcmeDirectory = http_client
            .get(&config.directory_url)
            .send()
            .await
            .context("fetching ACME directory")?
            .json()
            .await
            .context("parsing ACME directory")?;

        info!(
            "ACME client initialized with directory: {}",
            config.directory_url
        );

        Ok(Self {
            config,
            http_client,
            directory,
            account_url: None,
            nonce: None,
        })
    }

    /// Get new nonce from ACME server
    async fn get_nonce(&mut self) -> Result<String> {
        let response = self
            .http_client
            .head(&self.directory.new_nonce)
            .send()
            .await
            .context("requesting new nonce")?;

        let nonce = response
            .headers()
            .get("replay-nonce")
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| anyhow::anyhow!("no nonce in response"))?
            .to_string();

        self.nonce = Some(nonce.clone());
        Ok(nonce)
    }

    /// Create JWS (JSON Web Signature) for ACME request
    fn create_jws(&self, payload: &serde_json::Value, url: &str) -> Result<serde_json::Value> {
        // Create protected header according to RFC 8555
        let protected = json!({
            "alg": "EdDSA",
            "jwk": self.config.account_key.public_key_jwk(),
            "nonce": self.nonce.as_ref().ok_or_else(|| anyhow::anyhow!("no nonce available"))?,
            "url": url
        });

        // Encode protected header and payload as base64url (RFC 7515)
        let protected_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_string(&protected)?.as_bytes());

        let payload_b64 = if payload.is_null() {
            String::new() // Empty payload for POST-as-GET
        } else {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_string(payload)?.as_bytes())
        };

        // Create signing input: protected.payload (RFC 7515 Section 5.1)
        let signing_input = format!("{}.{}", protected_b64, payload_b64);

        // Sign using Ed25519
        let signature_bytes = self.config.account_key.sign(signing_input.as_bytes());

        // Encode signature as base64url
        let signature_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature_bytes);

        Ok(json!({
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": signature_b64
        }))
    }

    /// Register or retrieve ACME account
    pub async fn register_account(&mut self) -> Result<AcmeAccount> {
        // Get nonce
        self.get_nonce().await?;

        // Prepare account creation payload
        let mut payload = json!({
            "termsOfServiceAgreed": true
        });

        if let Some(ref email) = self.config.contact_email {
            payload["contact"] = json!([format!("mailto:{}", email)]);
        }

        // Create JWS
        let jws = self.create_jws(&payload, &self.directory.new_account)?;

        // Send request
        let response = self
            .http_client
            .post(&self.directory.new_account)
            .json(&jws)
            .send()
            .await
            .context("registering ACME account")?;

        let status = response.status();
        let location = response
            .headers()
            .get("location")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        // Check if account already exists (status 200)
        if status == 200 {
            let account: AcmeAccount = response.json().await?;
            self.account_url = location;
            info!("ACME account already exists");
            return Ok(account);
        }

        // New account created (status 201)
        if status != 201 {
            let text = response.text().await.unwrap_or_default();
            bail!("failed to register account: {} - {}", status, text);
        }

        let account: AcmeAccount = response.json().await?;
        self.account_url = location;

        info!("ACME account registered successfully");
        Ok(account)
    }

    /// Create new order for certificate
    pub async fn create_order(&mut self, domains: &[String]) -> Result<AcmeOrder> {
        self.get_nonce().await?;

        let identifiers: Vec<Identifier> = domains
            .iter()
            .map(|domain| Identifier {
                type_: "dns".to_string(),
                value: domain.clone(),
            })
            .collect();

        let payload = json!({
            "identifiers": identifiers
        });

        let jws = self.create_jws(&payload, &self.directory.new_order)?;

        let response = self
            .http_client
            .post(&self.directory.new_order)
            .json(&jws)
            .send()
            .await
            .context("creating ACME order")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            bail!("failed to create order: {} - {}", status, text);
        }

        let order: AcmeOrder = response.json().await?;
        info!("ACME order created for domains: {:?}", domains);
        Ok(order)
    }

    /// Get authorization details
    pub async fn get_authorization(&mut self, auth_url: &str) -> Result<AcmeAuthorization> {
        self.get_nonce().await?;

        let payload = json!({});
        let jws = self.create_jws(&payload, auth_url)?;

        let response = self
            .http_client
            .post(auth_url)
            .json(&jws)
            .send()
            .await
            .context("fetching authorization")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            bail!("failed to get authorization: {} - {}", status, text);
        }

        let auth: AcmeAuthorization = response.json().await?;
        Ok(auth)
    }

    /// Get DNS-01 challenge token and key authorization
    pub fn get_dns01_challenge(&self, challenge: &Challenge) -> Result<(String, String)> {
        let token = challenge
            .token
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no token in challenge"))?;

        // Calculate thumbprint: base64url(SHA256(JWK))
        // JWK must be in canonical form (sorted keys, no whitespace)
        let jwk_canonical = serde_json::to_string(self.config.account_key.public_key_jwk())
            .context("serializing JWK")?;

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(jwk_canonical.as_bytes());
        let thumbprint_hash = hasher.finalize();
        let thumbprint = URL_SAFE_NO_PAD.encode(thumbprint_hash);

        // Create key authorization: token + "." + thumbprint
        let key_authorization = format!("{}.{}", token, thumbprint);

        // DNS-01 record value: base64url(SHA256(key_authorization))
        let mut hasher = Sha256::new();
        hasher.update(key_authorization.as_bytes());
        let hash = hasher.finalize();
        let record_value = URL_SAFE_NO_PAD.encode(hash);

        Ok((key_authorization, record_value))
    }

    /// Complete challenge (after DNS record is set)
    pub async fn complete_challenge(&mut self, challenge_url: &str) -> Result<()> {
        self.get_nonce().await?;

        let payload = json!({});
        let jws = self.create_jws(&payload, challenge_url)?;

        let response = self
            .http_client
            .post(challenge_url)
            .json(&jws)
            .send()
            .await
            .context("completing challenge")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            bail!("failed to complete challenge: {} - {}", status, text);
        }

        info!("Challenge completed successfully");
        Ok(())
    }

    /// Finalize order and get certificate
    pub async fn finalize_order(&mut self, finalize_url: &str, csr: &[u8]) -> Result<String> {
        self.get_nonce().await?;

        let payload = json!({
            "csr": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(csr)
        });

        let jws = self.create_jws(&payload, finalize_url)?;

        let response = self
            .http_client
            .post(finalize_url)
            .json(&jws)
            .send()
            .await
            .context("finalizing order")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            bail!("failed to finalize order: {} - {}", status, text);
        }

        let order: AcmeOrder = response.json().await?;

        // Poll for certificate
        if let Some(cert_url) = &order.certificate {
            let cert = self.download_certificate(cert_url).await?;
            info!("Certificate obtained successfully");
            return Ok(cert);
        }

        bail!("order finalized but certificate not ready yet");
    }

    /// Download certificate from URL
    pub async fn download_certificate(&mut self, cert_url: &str) -> Result<String> {
        self.get_nonce().await?;

        let payload = json!({});
        let jws = self.create_jws(&payload, cert_url)?;

        let response = self
            .http_client
            .post(cert_url)
            .json(&jws)
            .send()
            .await
            .context("downloading certificate")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            bail!("failed to download certificate: {} - {}", status, text);
        }

        let cert = response.text().await?;
        Ok(cert)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_type_as_str() {
        assert_eq!(ChallengeType::Http01.as_str(), "http-01");
        assert_eq!(ChallengeType::Dns01.as_str(), "dns-01");
    }

    #[test]
    fn test_acme_account_key_generation() {
        let key = AcmeAccountKey::generate().expect("failed to generate key");
        assert!(key.public_key_jwk().get("kty").is_some());
        assert_eq!(
            key.public_key_jwk().get("kty").unwrap().as_str(),
            Some("OKP")
        );
        assert_eq!(
            key.public_key_jwk().get("crv").unwrap().as_str(),
            Some("Ed25519")
        );

        // Test signing
        let message = b"test message";
        let signature = key.sign(message);
        assert_eq!(signature.len(), 64); // Ed25519 signature is 64 bytes
    }

    #[test]
    fn test_acme_client_config_new() {
        let config = AcmeClientConfig::new().expect("should create config");
        assert_eq!(config.directory_url, endpoints::LETS_ENCRYPT_STAGING);
        assert_eq!(config.preferred_challenge, ChallengeType::Dns01);
    }
}
