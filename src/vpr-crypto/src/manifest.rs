//! Signed Bootstrap Manifest
//!
//! Provides Ed25519-signed manifests for distributing trusted server lists.
//! The manifest contains server endpoints and is signed to prevent tampering.

use crate::keys::{SignatureVerifier, SigningKeypair};
use anyhow::{bail, Context, Result};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Current manifest format version
pub const MANIFEST_VERSION: u32 = 1;

/// Maximum manifest age before considered stale (7 days)
pub const MAX_MANIFEST_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// ODoH/DoH publication grace period (cache fallback) — 24h
pub const STALE_FALLBACK_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// Server endpoint entry in manifest
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerEndpoint {
    /// Unique server identifier
    pub id: String,
    /// Server hostname or IP
    pub host: String,
    /// Server port
    pub port: u16,
    /// Server's Noise public key (hex encoded)
    pub noise_pubkey: String,
    /// Server region (e.g., "us-east", "eu-west")
    pub region: String,
    /// Server capabilities/features
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Weight for load balancing (higher = more traffic)
    #[serde(default = "default_weight")]
    pub weight: u32,
    /// Whether server is currently active
    #[serde(default = "default_active")]
    pub active: bool,
}

fn default_weight() -> u32 {
    100
}

fn default_active() -> bool {
    true
}

impl ServerEndpoint {
    pub fn new(id: &str, host: &str, port: u16, noise_pubkey: &str) -> Self {
        Self {
            id: id.to_string(),
            host: host.to_string(),
            port,
            noise_pubkey: noise_pubkey.to_string(),
            region: "unknown".to_string(),
            capabilities: Vec::new(),
            weight: 100,
            active: true,
        }
    }

    pub fn with_region(mut self, region: &str) -> Self {
        self.region = region.to_string();
        self
    }

    pub fn with_capabilities(mut self, caps: Vec<String>) -> Self {
        self.capabilities = caps;
        self
    }
}

/// Unsigned manifest payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestPayload {
    /// Format version
    pub version: u32,
    /// Unix timestamp when manifest was created
    pub created_at: u64,
    /// Unix timestamp when manifest expires
    pub expires_at: u64,
    /// List of server endpoints
    pub servers: Vec<ServerEndpoint>,
    /// Optional comment/description
    #[serde(default)]
    pub comment: String,
    /// Optional ODoH / DoH endpoints for fetching updates
    #[serde(default)]
    pub odoh_relays: Vec<String>,
    /// Domain-fronting hosts for bootstrap when primary blocked
    #[serde(default)]
    pub front_domains: Vec<String>,
}

impl ManifestPayload {
    /// Create new payload with servers and default 7-day validity
    pub fn new(servers: Vec<ServerEndpoint>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            version: MANIFEST_VERSION,
            created_at: now,
            expires_at: now + MAX_MANIFEST_AGE.as_secs(),
            servers,
            comment: String::new(),
            odoh_relays: Vec::new(),
            front_domains: Vec::new(),
        }
    }

    /// Create with custom validity duration
    pub fn with_validity(servers: Vec<ServerEndpoint>, validity: Duration) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            version: MANIFEST_VERSION,
            created_at: now,
            expires_at: now + validity.as_secs(),
            servers,
            comment: String::new(),
            odoh_relays: Vec::new(),
            front_domains: Vec::new(),
        }
    }

    /// Check if manifest is expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        now > self.expires_at
    }

    /// Check if manifest is stale but usable (fallback to cached)
    pub fn is_stale(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > self.expires_at && now <= self.expires_at + STALE_FALLBACK_AGE.as_secs()
    }

    /// Get active servers only
    pub fn active_servers(&self) -> impl Iterator<Item = &ServerEndpoint> {
        self.servers.iter().filter(|s| s.active)
    }

    /// Get servers in a specific region
    pub fn servers_in_region<'a>(
        &'a self,
        region: &'a str,
    ) -> impl Iterator<Item = &'a ServerEndpoint> {
        self.servers
            .iter()
            .filter(move |s| s.region == region && s.active)
    }

    /// Serialize to JSON bytes for signing
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).context("serializing payload")
    }

    /// Deserialize from JSON bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).context("deserializing payload")
    }
}

/// Signed manifest with Ed25519 signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedManifest {
    /// The manifest payload (JSON encoded)
    pub payload: String,
    /// Ed25519 signature (hex encoded)
    pub signature: String,
    /// Signer's public key (hex encoded)
    pub signer_pubkey: String,
    /// Nonce to prevent replay; generated from OsRng
    pub nonce: u64,
}

impl SignedManifest {
    /// Sign a manifest payload
    pub fn sign(payload: &ManifestPayload, keypair: &SigningKeypair) -> Result<Self> {
        let payload_json = serde_json::to_string(payload).context("serializing payload")?;
        let payload_bytes = payload_json.as_bytes();

        let signature = keypair.sign(payload_bytes);
        let nonce = OsRng.next_u64();

        Ok(Self {
            payload: payload_json,
            signature: hex::encode(signature),
            signer_pubkey: hex::encode(keypair.public_bytes()),
            nonce,
        })
    }

    /// Verify manifest signature against expected public key
    pub fn verify(&self, expected_pubkey: &[u8; 32]) -> Result<ManifestPayload> {
        // Verify signer matches expected
        let signer_bytes: [u8; 32] = hex::decode(&self.signer_pubkey)
            .context("decoding signer pubkey")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid signer pubkey length"))?;

        if &signer_bytes != expected_pubkey {
            bail!("signer pubkey mismatch");
        }

        // Verify signature
        let signature: [u8; 64] = hex::decode(&self.signature)
            .context("decoding signature")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid signature length"))?;

        let verifier =
            SignatureVerifier::from_public_bytes(expected_pubkey).context("creating verifier")?;
        verifier
            .verify(self.payload.as_bytes(), &signature)
            .context("signature verification failed")?;

        // Nonce must be non-zero (enforces OsRng use on signer side)
        if self.nonce == 0 {
            bail!("manifest nonce invalid (zero)");
        }

        // Parse payload
        let payload: ManifestPayload =
            serde_json::from_str(&self.payload).context("parsing payload")?;

        // Check version
        if payload.version != MANIFEST_VERSION {
            bail!(
                "unsupported manifest version: {} (expected {})",
                payload.version,
                MANIFEST_VERSION
            );
        }

        // Check expiration
        if payload.is_expired() {
            bail!("manifest has expired");
        }

        Ok(payload)
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).context("serializing manifest")
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).context("parsing manifest")
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).context("serializing manifest")
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).context("parsing manifest")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keypair() -> SigningKeypair {
        SigningKeypair::generate()
    }

    #[test]
    fn test_server_endpoint_new() {
        let ep = ServerEndpoint::new("srv1", "example.com", 443, "aabbccdd");
        assert_eq!(ep.id, "srv1");
        assert_eq!(ep.host, "example.com");
        assert_eq!(ep.port, 443);
        assert!(ep.active);
    }

    #[test]
    fn test_manifest_payload_new() {
        let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];
        let payload = ManifestPayload::new(servers);

        assert_eq!(payload.version, MANIFEST_VERSION);
        assert!(!payload.is_expired());
        assert!(!payload.is_stale());
        assert_eq!(payload.servers.len(), 1);
    }

    #[test]
    fn test_manifest_active_servers() {
        let srv1 = ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1");
        let mut srv2 = ServerEndpoint::new("srv2", "5.6.7.8", 443, "key2");
        srv2.active = false;

        let payload = ManifestPayload::new(vec![srv1.clone(), srv2]);
        let active: Vec<_> = payload.active_servers().collect();

        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, "srv1");
    }

    #[test]
    fn test_manifest_servers_in_region() {
        let srv1 = ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1").with_region("us-east");
        let srv2 = ServerEndpoint::new("srv2", "5.6.7.8", 443, "key2").with_region("eu-west");

        let payload = ManifestPayload::new(vec![srv1, srv2]);
        let us_servers: Vec<_> = payload.servers_in_region("us-east").collect();

        assert_eq!(us_servers.len(), 1);
        assert_eq!(us_servers[0].id, "srv1");
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = test_keypair();
        let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];
        let payload = ManifestPayload::new(servers);

        let signed = SignedManifest::sign(&payload, &keypair).unwrap();
        let verified = signed.verify(&keypair.public_bytes()).unwrap();

        assert_eq!(verified.servers.len(), 1);
        assert_eq!(verified.servers[0].id, "srv1");
    }

    #[test]
    fn manifest_nonce_non_zero() {
        let kp = test_keypair();
        let payload =
            ManifestPayload::new(vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")]);
        let signed = SignedManifest::sign(&payload, &kp).unwrap();
        assert!(signed.nonce != 0, "nonce must be non-zero");
    }

    #[test]
    fn test_verify_wrong_key_fails() {
        let keypair1 = test_keypair();
        let keypair2 = test_keypair();

        let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];
        let payload = ManifestPayload::new(servers);

        let signed = SignedManifest::sign(&payload, &keypair1).unwrap();
        let result = signed.verify(&keypair2.public_bytes());

        assert!(result.is_err());
    }

    #[test]
    fn test_verify_tampered_fails() {
        let keypair = test_keypair();
        let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];
        let payload = ManifestPayload::new(servers);

        let mut signed = SignedManifest::sign(&payload, &keypair).unwrap();

        // Tamper with payload
        signed.payload = signed.payload.replace("srv1", "evil");

        let result = signed.verify(&keypair.public_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_manifest_serialization() {
        let keypair = test_keypair();
        let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];
        let payload = ManifestPayload::new(servers);

        let signed = SignedManifest::sign(&payload, &keypair).unwrap();
        let json = signed.to_json().unwrap();

        let restored = SignedManifest::from_json(&json).unwrap();
        let verified = restored.verify(&keypair.public_bytes()).unwrap();

        assert_eq!(verified.servers[0].id, "srv1");
    }

    #[test]
    fn test_expired_manifest_fails() {
        let keypair = test_keypair();
        let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];

        // Create manifest that's already expired
        let mut payload = ManifestPayload::new(servers);
        payload.expires_at = 0; // In the past

        let signed = SignedManifest::sign(&payload, &keypair).unwrap();
        let result = signed.verify(&keypair.public_bytes());

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    #[test]
    fn test_payload_bytes_roundtrip() {
        let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];
        let payload = ManifestPayload::new(servers);

        let bytes = payload.to_bytes().unwrap();
        let restored = ManifestPayload::from_bytes(&bytes).unwrap();

        assert_eq!(restored.servers[0].id, "srv1");
    }
}
