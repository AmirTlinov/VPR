//! Bootstrap Manifest Client
//!
//! Provides client-side logic for fetching and caching signed bootstrap manifests.
//! Supports multiple fallback mechanisms: RSS → ODoH → DoH → Domain Fronting → Cached

use crate::domain_fronting::{DomainFronter, FrontConfig, FrontedRequest};
use crate::stego_rss::{StegoMethod, StegoRssConfig, StegoRssDecoder};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::fs;
use tokio::time::sleep;
use tracing::{debug, info, warn};
use vpr_crypto::manifest::{ManifestPayload, SignedManifest};

/// Configuration for ManifestClient
#[derive(Debug, Clone)]
pub struct ManifestClientConfig {
    /// Expected public key for manifest signature verification (32 bytes)
    pub expected_pubkey: [u8; 32],
    /// Cache directory for manifests
    pub cache_dir: PathBuf,
    /// RSS feed URLs (highest priority, steganographic)
    pub rss_feeds: Vec<String>,
    /// Steganographic method to use for RSS decoding
    pub rss_stego_method: StegoMethod,
    /// ODoH relay endpoints
    pub odoh_relays: Vec<String>,
    /// DoH endpoints (fallback)
    pub doh_endpoints: Vec<String>,
    /// Domain fronting configurations
    pub front_configs: Vec<FrontConfig>,
    /// Request timeout
    pub timeout: Duration,
    /// Maximum retry attempts
    pub max_retries: u32,
    /// Retry backoff base (exponential backoff)
    pub retry_backoff_base: Duration,
}

impl Default for ManifestClientConfig {
    fn default() -> Self {
        Self {
            expected_pubkey: [0u8; 32],
            cache_dir: dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".vpr")
                .join("manifests"),
            rss_feeds: Vec::new(),
            rss_stego_method: StegoMethod::Hybrid,
            odoh_relays: Vec::new(),
            doh_endpoints: Vec::new(),
            front_configs: Vec::new(),
            timeout: Duration::from_secs(30),
            max_retries: 3,
            retry_backoff_base: Duration::from_secs(1),
        }
    }
}

/// Client for fetching and caching bootstrap manifests
pub struct ManifestClient {
    config: ManifestClientConfig,
    fronter: DomainFronter,
    http_client: reqwest::Client,
}

impl ManifestClient {
    /// Create new ManifestClient with config
    pub fn new(config: ManifestClientConfig) -> Result<Self> {
        let fronter = DomainFronter::new(config.front_configs.clone()).with_timeout(config.timeout);

        let http_client = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .context("building HTTP client")?;

        Ok(Self {
            config,
            fronter,
            http_client,
        })
    }

    /// Fetch manifest with fallback mechanisms
    ///
    /// Priority: RSS → ODoH → DoH → Domain Fronting → Cached
    pub async fn fetch_manifest(&mut self) -> Result<ManifestPayload> {
        // Try RSS feeds first (highest priority, steganographic)
        for feed_url in &self.config.rss_feeds {
            match self.fetch_from_rss(feed_url).await {
                Ok(manifest) => {
                    info!(feed = %feed_url, "Successfully fetched manifest via RSS");
                    return Ok(manifest);
                }
                Err(e) => {
                    debug!(feed = %feed_url, %e, "RSS fetch failed");
                }
            }
        }

        // Try ODoH
        for relay in &self.config.odoh_relays {
            match self.fetch_from_odoh(relay).await {
                Ok(manifest) => {
                    info!(relay = %relay, "Successfully fetched manifest via ODoH");
                    return Ok(manifest);
                }
                Err(e) => {
                    warn!(relay = %relay, %e, "ODoH fetch failed");
                }
            }
        }

        // Try DoH fallback
        for endpoint in &self.config.doh_endpoints {
            match self.fetch_from_doh(endpoint).await {
                Ok(manifest) => {
                    info!(endpoint = %endpoint, "Successfully fetched manifest via DoH");
                    return Ok(manifest);
                }
                Err(e) => {
                    warn!(endpoint = %endpoint, %e, "DoH fetch failed");
                }
            }
        }

        // Try domain fronting
        for _attempt in 0..self.config.max_retries {
            let front_opt = self.fronter.next_front().cloned();
            if let Some(front) = front_opt {
                let front_domain = front.front_domain.clone();
                match self.fetch_from_domain_fronting(&front).await {
                    Ok(manifest) => {
                        info!(front = %front_domain, "Successfully fetched manifest via domain fronting");
                        self.fronter.mark_working(&front_domain);
                        return Ok(manifest);
                    }
                    Err(e) => {
                        warn!(front = %front_domain, %e, "Domain fronting fetch failed");
                        self.fronter.mark_failed(&front_domain);
                    }
                }
            }
            sleep(self.config.retry_backoff_base).await;
        }

        // Fallback to cached manifest
        self.fetch_cached().await
    }

    /// Fetch manifest via RSS feed (steganographic)
    async fn fetch_from_rss(&self, feed_url: &str) -> Result<ManifestPayload> {
        // Fetch RSS XML
        let response = self
            .http_client
            .get(feed_url)
            .header(
                "Accept",
                "application/rss+xml, application/xml, text/xml, */*",
            )
            .send()
            .await
            .context("RSS HTTP request failed")?;

        if !response.status().is_success() {
            anyhow::bail!("RSS HTTP request failed: {}", response.status());
        }

        let rss_xml = response.text().await.context("reading RSS response")?;

        // Decode steganographic manifest from RSS
        let decoder_config = StegoRssConfig {
            method: self.config.rss_stego_method,
            feed_title: String::new(), // Not needed for decoding
            feed_description: String::new(),
            feed_link: String::new(),
            min_items: 0,
            max_items: 0,
            random_order: false,
            seed: None,
        };
        let decoder = StegoRssDecoder::new(decoder_config);

        // Try to decode as SignedManifest first
        match decoder.decode_manifest(&rss_xml) {
            Ok(signed) => {
                let payload = signed
                    .verify(&self.config.expected_pubkey)
                    .context("verifying RSS manifest signature")?;

                // Cache the manifest
                self.cache_manifest(&signed).await?;

                Ok(payload)
            }
            Err(_) => {
                // Fallback: try decoding as payload directly
                let payload = decoder
                    .decode_payload(&rss_xml)
                    .context("decoding RSS manifest payload")?;

                // Verify payload is valid
                if payload.is_expired() && !payload.is_stale() {
                    anyhow::bail!("RSS manifest payload is expired");
                }

                Ok(payload)
            }
        }
    }

    /// Fetch manifest via ODoH (Oblivious DoH)
    async fn fetch_from_odoh(&self, relay: &str) -> Result<ManifestPayload> {
        // TODO: Implement ODoH protocol
        // For now, treat as regular HTTPS endpoint
        let url = format!("https://{}/manifest.json", relay);
        self.fetch_from_url(&url).await
    }

    /// Fetch manifest via DoH (DNS over HTTPS)
    async fn fetch_from_doh(&self, endpoint: &str) -> Result<ManifestPayload> {
        let url = format!("https://{}/manifest.json", endpoint);
        self.fetch_from_url(&url).await
    }

    /// Fetch manifest via domain fronting
    async fn fetch_from_domain_fronting(&self, front: &FrontConfig) -> Result<ManifestPayload> {
        let request = FrontedRequest::get(front.clone(), "/manifest.json");
        let url = request.url();

        // Build request with domain fronting headers
        let mut req = self.http_client.get(&url).header("Host", request.host());

        // Add standard headers
        for (key, value) in self.fronter.build_headers(front) {
            req = req.header(key, value);
        }

        let response = req.send().await.context("domain fronting request failed")?;

        if !response.status().is_success() {
            anyhow::bail!("domain fronting request failed: {}", response.status());
        }

        let signed: SignedManifest = response
            .json()
            .await
            .context("parsing domain fronting response")?;

        let payload = signed
            .verify(&self.config.expected_pubkey)
            .context("verifying domain fronting manifest")?;

        // Cache the manifest
        self.cache_manifest(&signed).await?;

        Ok(payload)
    }

    /// Fetch manifest from URL (generic HTTPS)
    async fn fetch_from_url(&self, url: &str) -> Result<ManifestPayload> {
        let response = self
            .http_client
            .get(url)
            .send()
            .await
            .context("HTTP request failed")?;

        if !response.status().is_success() {
            anyhow::bail!("HTTP request failed: {}", response.status());
        }

        let signed: SignedManifest = response.json().await.context("parsing manifest response")?;

        let payload = signed
            .verify(&self.config.expected_pubkey)
            .context("verifying manifest signature")?;

        // Cache the manifest
        self.cache_manifest(&signed).await?;

        Ok(payload)
    }

    /// Fetch cached manifest from disk
    async fn fetch_cached(&self) -> Result<ManifestPayload> {
        let cache_file = self.config.cache_dir.join("manifest.json");

        if !cache_file.exists() {
            anyhow::bail!("no cached manifest available");
        }

        let data = fs::read(&cache_file)
            .await
            .context("reading cached manifest")?;

        let signed: SignedManifest =
            serde_json::from_slice(&data).context("parsing cached manifest")?;

        // Verify signature
        let payload = signed
            .verify(&self.config.expected_pubkey)
            .context("verifying cached manifest signature")?;

        // Check if cached manifest is stale but usable
        if payload.is_expired() {
            if payload.is_stale() {
                warn!("Using stale cached manifest (within fallback grace period)");
                return Ok(payload);
            } else {
                anyhow::bail!("cached manifest is too old");
            }
        }

        info!("Using cached manifest");
        Ok(payload)
    }

    /// Cache manifest to disk
    ///
    /// This method is public to allow tests and external code to cache manifests
    pub async fn cache_manifest(&self, signed: &SignedManifest) -> Result<()> {
        // Ensure cache directory exists
        fs::create_dir_all(&self.config.cache_dir)
            .await
            .context("creating cache directory")?;

        let cache_file = self.config.cache_dir.join("manifest.json");
        let json = signed.to_json().context("serializing manifest")?;

        fs::write(&cache_file, json.as_bytes())
            .await
            .context("writing cached manifest")?;

        debug!(path = %cache_file.display(), "Cached manifest");
        Ok(())
    }

    /// Get cache directory
    pub fn cache_dir(&self) -> &Path {
        &self.config.cache_dir
    }

    /// Check if cached manifest exists and is fresh
    pub async fn has_fresh_cache(&self) -> bool {
        let cache_file = self.config.cache_dir.join("manifest.json");
        if !cache_file.exists() {
            return false;
        }

        match self.fetch_cached().await {
            Ok(payload) => !payload.is_expired() && !payload.is_stale(),
            Err(_) => false,
        }
    }

    /// Clear cached manifest
    pub async fn clear_cache(&self) -> Result<()> {
        let cache_file = self.config.cache_dir.join("manifest.json");
        if cache_file.exists() {
            fs::remove_file(&cache_file)
                .await
                .context("removing cached manifest")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::field_reassign_with_default)]

    use super::*;
    use tempfile::TempDir;
    use vpr_crypto::keys::SigningKeypair;
    use vpr_crypto::manifest::{ManifestPayload, ServerEndpoint};

    #[tokio::test]
    async fn test_manifest_client_config_default() {
        let config = ManifestClientConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.timeout, Duration::from_secs(30));
    }

    #[tokio::test]
    async fn test_cache_manifest() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let keypair = SigningKeypair::generate();
        let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];
        let payload = ManifestPayload::new(servers);
        let signed = SignedManifest::sign(&payload, &keypair).expect("failed to sign");

        let mut config = ManifestClientConfig::default();
        config.cache_dir = temp_dir.path().to_path_buf();
        config.expected_pubkey = keypair.public_bytes();

        let client = ManifestClient::new(config).expect("failed to create client");
        client
            .cache_manifest(&signed)
            .await
            .expect("failed to cache");

        // Verify cache file exists
        let cache_file = temp_dir.path().join("manifest.json");
        assert!(cache_file.exists());

        // Verify we can read it back
        let cached = client.fetch_cached().await.expect("failed to fetch cached");
        assert_eq!(cached.servers.len(), 1);
    }

    #[tokio::test]
    async fn test_fetch_cached_expired() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let keypair = SigningKeypair::generate();
        let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];
        let mut payload = ManifestPayload::new(servers);
        // Make it expired
        payload.expires_at = 0;
        let signed = SignedManifest::sign(&payload, &keypair).expect("failed to sign");

        let mut config = ManifestClientConfig::default();
        config.cache_dir = temp_dir.path().to_path_buf();
        config.expected_pubkey = keypair.public_bytes();

        let client = ManifestClient::new(config).expect("failed to create client");
        client
            .cache_manifest(&signed)
            .await
            .expect("failed to cache");

        // Should fail because expired
        let result = client.fetch_cached().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_clear_cache() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let keypair = SigningKeypair::generate();
        let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];
        let payload = ManifestPayload::new(servers);
        let signed = SignedManifest::sign(&payload, &keypair).expect("failed to sign");

        let mut config = ManifestClientConfig::default();
        config.cache_dir = temp_dir.path().to_path_buf();
        config.expected_pubkey = keypair.public_bytes();

        let client = ManifestClient::new(config).expect("failed to create client");
        client
            .cache_manifest(&signed)
            .await
            .expect("failed to cache");

        // Verify cache exists
        let cache_file = temp_dir.path().join("manifest.json");
        assert!(cache_file.exists());

        // Clear cache
        client.clear_cache().await.expect("failed to clear cache");
        assert!(!cache_file.exists());
    }

    #[tokio::test]
    async fn test_clear_cache_nonexistent() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let mut config = ManifestClientConfig::default();
        config.cache_dir = temp_dir.path().to_path_buf();

        let client = ManifestClient::new(config).expect("failed to create client");

        // Should not error on nonexistent cache
        let result = client.clear_cache().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_has_fresh_cache_no_cache() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let mut config = ManifestClientConfig::default();
        config.cache_dir = temp_dir.path().to_path_buf();

        let client = ManifestClient::new(config).expect("failed to create client");
        assert!(!client.has_fresh_cache().await);
    }

    #[tokio::test]
    async fn test_has_fresh_cache_with_fresh() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let keypair = SigningKeypair::generate();
        let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];
        let payload = ManifestPayload::new(servers);
        let signed = SignedManifest::sign(&payload, &keypair).expect("failed to sign");

        let mut config = ManifestClientConfig::default();
        config.cache_dir = temp_dir.path().to_path_buf();
        config.expected_pubkey = keypair.public_bytes();

        let client = ManifestClient::new(config).expect("failed to create client");
        client
            .cache_manifest(&signed)
            .await
            .expect("failed to cache");

        assert!(client.has_fresh_cache().await);
    }

    #[tokio::test]
    async fn test_has_fresh_cache_expired() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let keypair = SigningKeypair::generate();
        let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];
        let mut payload = ManifestPayload::new(servers);
        payload.expires_at = 0; // expired
        let signed = SignedManifest::sign(&payload, &keypair).expect("failed to sign");

        let mut config = ManifestClientConfig::default();
        config.cache_dir = temp_dir.path().to_path_buf();
        config.expected_pubkey = keypair.public_bytes();

        let client = ManifestClient::new(config).expect("failed to create client");
        client
            .cache_manifest(&signed)
            .await
            .expect("failed to cache");

        assert!(!client.has_fresh_cache().await);
    }

    #[tokio::test]
    async fn test_cache_dir_getter() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let mut config = ManifestClientConfig::default();
        config.cache_dir = temp_dir.path().to_path_buf();

        let client = ManifestClient::new(config).expect("failed to create client");
        assert_eq!(client.cache_dir(), temp_dir.path());
    }

    #[test]
    fn test_manifest_client_config_clone() {
        let config1 = ManifestClientConfig::default();
        let config2 = config1.clone();
        assert_eq!(config1.max_retries, config2.max_retries);
        assert_eq!(config1.timeout, config2.timeout);
    }

    #[tokio::test]
    async fn test_fetch_cached_no_cache() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let mut config = ManifestClientConfig::default();
        config.cache_dir = temp_dir.path().to_path_buf();

        let client = ManifestClient::new(config).expect("failed to create client");
        let result = client.fetch_cached().await;
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("no cached"));
    }

    #[tokio::test]
    async fn test_cache_manifest_creates_directory() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let nested_cache = temp_dir.path().join("nested").join("cache").join("dir");
        let keypair = SigningKeypair::generate();
        let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];
        let payload = ManifestPayload::new(servers);
        let signed = SignedManifest::sign(&payload, &keypair).expect("failed to sign");

        let mut config = ManifestClientConfig::default();
        config.cache_dir = nested_cache.clone();
        config.expected_pubkey = keypair.public_bytes();

        let client = ManifestClient::new(config).expect("failed to create client");

        // Directory should not exist yet
        assert!(!nested_cache.exists());

        client
            .cache_manifest(&signed)
            .await
            .expect("failed to cache");

        // Directory should be created
        assert!(nested_cache.exists());
        assert!(nested_cache.join("manifest.json").exists());
    }

    #[tokio::test]
    async fn test_fetch_cached_invalid_signature() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let keypair1 = SigningKeypair::generate();
        let keypair2 = SigningKeypair::generate();
        let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];
        let payload = ManifestPayload::new(servers);
        // Sign with keypair1
        let signed = SignedManifest::sign(&payload, &keypair1).expect("failed to sign");

        let mut config = ManifestClientConfig::default();
        config.cache_dir = temp_dir.path().to_path_buf();
        // But expect keypair2's public key
        config.expected_pubkey = keypair2.public_bytes();

        let client = ManifestClient::new(config).expect("failed to create client");
        client
            .cache_manifest(&signed)
            .await
            .expect("failed to cache");

        // Should fail signature verification
        let result = client.fetch_cached().await;
        assert!(result.is_err());
    }

    #[test]
    fn test_config_custom_values() {
        let mut config = ManifestClientConfig::default();
        config.max_retries = 5;
        config.timeout = Duration::from_secs(60);
        config.retry_backoff_base = Duration::from_secs(2);
        config.rss_feeds = vec!["http://feed1.com".to_string()];
        config.doh_endpoints = vec!["doh.example.com".to_string()];

        assert_eq!(config.max_retries, 5);
        assert_eq!(config.timeout, Duration::from_secs(60));
        assert_eq!(config.rss_feeds.len(), 1);
        assert_eq!(config.doh_endpoints.len(), 1);
    }
}
