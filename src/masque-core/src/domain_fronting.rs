//! Domain Fronting Support
//!
//! Implements domain fronting technique for censorship circumvention.
//! The client connects to a CDN using the CDN's domain in TLS SNI,
//! but sends the real target domain in the HTTP Host header.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, warn};

/// CDN provider type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CdnProvider {
    /// Cloudflare CDN
    Cloudflare,
    /// Fastly CDN
    Fastly,
    /// Amazon CloudFront
    CloudFront,
    /// Google Cloud CDN / App Engine
    Google,
    /// Microsoft Azure CDN
    Azure,
    /// Akamai CDN
    Akamai,
    /// Custom/unknown CDN
    Custom,
}

impl CdnProvider {
    /// Get default front domain for this CDN
    pub fn default_front(&self) -> Option<&'static str> {
        match self {
            Self::Cloudflare => Some("cloudflare.com"),
            Self::Fastly => Some("fastly.net"),
            Self::CloudFront => Some("cloudfront.net"),
            Self::Google => Some("google.com"),
            Self::Azure => Some("azureedge.net"),
            Self::Akamai => Some("akamai.net"),
            Self::Custom => None,
        }
    }

    /// Check if provider is known to block domain fronting
    pub fn fronting_blocked(&self) -> bool {
        // Note: Most major CDNs have started blocking domain fronting
        // This list may need updates based on current CDN policies
        match self {
            Self::CloudFront => true, // AWS blocked since 2018
            Self::Google => true,     // GCP blocked since 2018
            _ => false,
        }
    }
}

/// Domain fronting configuration for a single front
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrontConfig {
    /// CDN provider
    pub provider: CdnProvider,
    /// Domain to use in TLS SNI (the "front")
    pub front_domain: String,
    /// Real target domain (goes in Host header)
    pub target_domain: String,
    /// Optional specific IP to connect to
    pub ip_override: Option<String>,
    /// Path prefix for requests
    #[serde(default)]
    pub path_prefix: String,
    /// Priority (lower = higher priority)
    #[serde(default = "default_priority")]
    pub priority: u32,
    /// Whether this front is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_priority() -> u32 {
    100
}

fn default_enabled() -> bool {
    true
}

impl FrontConfig {
    /// Create new front config
    pub fn new(provider: CdnProvider, front: &str, target: &str) -> Self {
        Self {
            provider,
            front_domain: front.to_string(),
            target_domain: target.to_string(),
            ip_override: None,
            path_prefix: String::new(),
            priority: 100,
            enabled: true,
        }
    }

    /// Set IP override
    pub fn with_ip(mut self, ip: &str) -> Self {
        self.ip_override = Some(ip.to_string());
        self
    }

    /// Set path prefix
    pub fn with_path_prefix(mut self, prefix: &str) -> Self {
        self.path_prefix = prefix.to_string();
        self
    }

    /// Set priority
    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    /// Get the domain to use for TLS connection
    pub fn tls_domain(&self) -> &str {
        &self.front_domain
    }

    /// Get the Host header value
    pub fn host_header(&self) -> &str {
        &self.target_domain
    }

    /// Build full URL with path
    pub fn build_url(&self, path: &str) -> String {
        let base = if self.path_prefix.is_empty() {
            path.to_string()
        } else {
            format!("{}{}", self.path_prefix.trim_end_matches('/'), path)
        };
        format!("https://{}{}", self.front_domain, base)
    }
}

/// Domain fronting manager
#[derive(Debug, Clone)]
pub struct DomainFronter {
    /// Available fronts by provider
    fronts: Vec<FrontConfig>,
    /// Connection timeout
    timeout: Duration,
    /// Current front index
    current_front_idx: usize,
    /// Blocked fronts (temporarily)
    blocked_fronts: HashMap<String, std::time::Instant>,
    /// Block duration
    block_duration: Duration,
}

impl DomainFronter {
    /// Create new fronter with configs
    pub fn new(fronts: Vec<FrontConfig>) -> Self {
        let mut sorted_fronts = fronts;
        sorted_fronts.sort_by_key(|f| f.priority);

        Self {
            fronts: sorted_fronts,
            timeout: Duration::from_secs(30),
            current_front_idx: 0,
            blocked_fronts: HashMap::new(),
            block_duration: Duration::from_secs(300), // 5 min block
        }
    }

    /// Set connection timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Get enabled fronts
    pub fn enabled_fronts(&self) -> impl Iterator<Item = &FrontConfig> {
        self.fronts.iter().filter(|f| f.enabled)
    }

    /// Get number of available fronts
    pub fn available_count(&self) -> usize {
        self.fronts.iter().filter(|f| f.enabled && !self.is_blocked(&f.front_domain)).count()
    }

    /// Check if a front is temporarily blocked
    fn is_blocked(&self, front_domain: &str) -> bool {
        if let Some(blocked_at) = self.blocked_fronts.get(front_domain) {
            blocked_at.elapsed() < self.block_duration
        } else {
            false
        }
    }

    /// Get next available front
    pub fn next_front(&mut self) -> Option<&FrontConfig> {
        // Clean up expired blocks
        self.blocked_fronts
            .retain(|_, blocked_at| blocked_at.elapsed() < self.block_duration);

        let enabled: Vec<_> = self
            .fronts
            .iter()
            .filter(|f| f.enabled && !self.is_blocked(&f.front_domain))
            .collect();

        if enabled.is_empty() {
            return None;
        }

        self.current_front_idx = (self.current_front_idx + 1) % enabled.len();
        enabled.get(self.current_front_idx).copied()
    }

    /// Mark a front as failed (temporarily block it)
    pub fn mark_failed(&mut self, front_domain: &str) {
        warn!(front = front_domain, "Marking front as temporarily blocked");
        self.blocked_fronts
            .insert(front_domain.to_string(), std::time::Instant::now());
    }

    /// Mark a front as working (remove from blocked list)
    pub fn mark_working(&mut self, front_domain: &str) {
        debug!(front = front_domain, "Front is working");
        self.blocked_fronts.remove(front_domain);
    }

    /// Build HTTP request headers for domain fronting
    pub fn build_headers(&self, front: &FrontConfig) -> Vec<(String, String)> {
        vec![
            ("Host".to_string(), front.target_domain.clone()),
            (
                "User-Agent".to_string(),
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string(),
            ),
            ("Accept".to_string(), "*/*".to_string()),
            ("Accept-Encoding".to_string(), "gzip, deflate, br".to_string()),
            ("Connection".to_string(), "keep-alive".to_string()),
        ]
    }

    /// Get TLS config for connecting to front
    pub fn tls_server_name<'a>(&self, front: &'a FrontConfig) -> &'a str {
        &front.front_domain
    }
}

/// Request builder for domain-fronted connections
pub struct FrontedRequest {
    front: FrontConfig,
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Option<Vec<u8>>,
}

impl FrontedRequest {
    /// Create GET request
    pub fn get(front: FrontConfig, path: &str) -> Self {
        Self {
            front,
            method: "GET".to_string(),
            path: path.to_string(),
            headers: HashMap::new(),
            body: None,
        }
    }

    /// Create POST request
    pub fn post(front: FrontConfig, path: &str) -> Self {
        Self {
            front,
            method: "POST".to_string(),
            path: path.to_string(),
            headers: HashMap::new(),
            body: None,
        }
    }

    /// Add custom header
    pub fn header(mut self, key: &str, value: &str) -> Self {
        self.headers.insert(key.to_string(), value.to_string());
        self
    }

    /// Set request body
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }

    /// Get the front config
    pub fn front(&self) -> &FrontConfig {
        &self.front
    }

    /// Get full URL
    pub fn url(&self) -> String {
        self.front.build_url(&self.path)
    }

    /// Get Host header value (the real target)
    pub fn host(&self) -> &str {
        &self.front.target_domain
    }

    /// Get TLS SNI value (the front)
    pub fn sni(&self) -> &str {
        &self.front.front_domain
    }
}

/// Reflector configuration for running a fronted endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReflectorConfig {
    /// Expected Host header values
    pub allowed_hosts: Vec<String>,
    /// Path to forward to backend
    pub backend_path: String,
    /// Backend address
    pub backend_addr: String,
}

impl ReflectorConfig {
    pub fn new(allowed_hosts: Vec<String>, backend: &str) -> Self {
        Self {
            allowed_hosts,
            backend_path: "/".to_string(),
            backend_addr: backend.to_string(),
        }
    }

    /// Check if Host header is allowed
    pub fn is_host_allowed(&self, host: &str) -> bool {
        self.allowed_hosts.iter().any(|h| h == host || host.ends_with(&format!(".{}", h)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cdn_provider_default_front() {
        assert_eq!(
            CdnProvider::Cloudflare.default_front(),
            Some("cloudflare.com")
        );
        assert!(CdnProvider::Custom.default_front().is_none());
    }

    #[test]
    fn test_cdn_provider_fronting_blocked() {
        assert!(CdnProvider::CloudFront.fronting_blocked());
        assert!(CdnProvider::Google.fronting_blocked());
        assert!(!CdnProvider::Cloudflare.fronting_blocked());
    }

    #[test]
    fn test_front_config_new() {
        let config = FrontConfig::new(CdnProvider::Cloudflare, "cdn.example.com", "real.target.com");
        assert_eq!(config.tls_domain(), "cdn.example.com");
        assert_eq!(config.host_header(), "real.target.com");
    }

    #[test]
    fn test_front_config_build_url() {
        let config = FrontConfig::new(CdnProvider::Cloudflare, "cdn.example.com", "real.target.com")
            .with_path_prefix("/proxy");

        assert_eq!(
            config.build_url("/api/data"),
            "https://cdn.example.com/proxy/api/data"
        );
    }

    #[test]
    fn test_fronter_new() {
        let fronts = vec![
            FrontConfig::new(CdnProvider::Cloudflare, "cf.example.com", "target.com")
                .with_priority(10),
            FrontConfig::new(CdnProvider::Fastly, "fs.example.com", "target.com")
                .with_priority(20),
        ];

        let fronter = DomainFronter::new(fronts);
        assert_eq!(fronter.available_count(), 2);
    }

    #[test]
    fn test_fronter_next_front() {
        let fronts = vec![
            FrontConfig::new(CdnProvider::Cloudflare, "cf.example.com", "target.com"),
        ];

        let mut fronter = DomainFronter::new(fronts);
        let front = fronter.next_front();

        assert!(front.is_some());
        assert_eq!(front.unwrap().front_domain, "cf.example.com");
    }

    #[test]
    fn test_fronter_mark_failed() {
        let fronts = vec![
            FrontConfig::new(CdnProvider::Cloudflare, "cf.example.com", "target.com"),
            FrontConfig::new(CdnProvider::Fastly, "fs.example.com", "target.com"),
        ];

        let mut fronter = DomainFronter::new(fronts);
        fronter.mark_failed("cf.example.com");

        assert_eq!(fronter.available_count(), 1);
    }

    #[test]
    fn test_fronted_request_get() {
        let front = FrontConfig::new(CdnProvider::Cloudflare, "cdn.example.com", "target.com");
        let request = FrontedRequest::get(front, "/api/data");

        assert_eq!(request.url(), "https://cdn.example.com/api/data");
        assert_eq!(request.host(), "target.com");
        assert_eq!(request.sni(), "cdn.example.com");
    }

    #[test]
    fn test_fronted_request_with_header() {
        let front = FrontConfig::new(CdnProvider::Cloudflare, "cdn.example.com", "target.com");
        let request = FrontedRequest::post(front, "/api")
            .header("Content-Type", "application/json");

        assert!(request.headers.contains_key("Content-Type"));
    }

    #[test]
    fn test_reflector_config() {
        let config = ReflectorConfig::new(
            vec!["target.com".to_string(), "alt.target.com".to_string()],
            "127.0.0.1:8080",
        );

        assert!(config.is_host_allowed("target.com"));
        assert!(config.is_host_allowed("alt.target.com"));
        assert!(config.is_host_allowed("sub.target.com"));
        assert!(!config.is_host_allowed("evil.com"));
    }

    #[test]
    fn test_build_headers() {
        let fronts = vec![FrontConfig::new(
            CdnProvider::Cloudflare,
            "cdn.example.com",
            "target.com",
        )];

        let fronter = DomainFronter::new(fronts.clone());
        let headers = fronter.build_headers(&fronts[0]);

        let host = headers.iter().find(|(k, _)| k == "Host");
        assert!(host.is_some());
        assert_eq!(host.unwrap().1, "target.com");
    }
}
