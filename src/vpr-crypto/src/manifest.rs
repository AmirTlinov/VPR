//! Signed Bootstrap Manifest
//!
//! Provides Ed25519-signed manifests for distributing trusted server lists.
//! The manifest contains server endpoints and is signed to prevent tampering.

use crate::keys::{SignatureVerifier, SigningKeypair};
use anyhow::{bail, Context, Result};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Version compatibility information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionInfo {
    /// Manifest version
    pub version: u32,
    /// Current supported version
    pub current_version: u32,
    /// Minimum supported version
    pub min_supported: u32,
    /// Maximum supported version
    pub max_supported: u32,
    /// Whether version is in supported range
    pub is_supported: bool,
    /// Whether version is compatible with current version
    pub is_compatible: bool,
}

/// Current manifest format version
pub const MANIFEST_VERSION: u32 = 1;

/// Minimum supported manifest version (for backward compatibility)
pub const MIN_MANIFEST_VERSION: u32 = 1;

/// Maximum supported manifest version (for forward compatibility checks)
pub const MAX_MANIFEST_VERSION: u32 = 1;

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

    /// Validate the noise_pubkey field
    ///
    /// Returns Ok if the pubkey is valid hex-encoded 32-byte X25519 public key,
    /// Err with description otherwise.
    pub fn validate_pubkey(&self) -> Result<[u8; 32]> {
        let bytes = hex::decode(&self.noise_pubkey).context("noise_pubkey is not valid hex")?;

        if bytes.len() != 32 {
            bail!("noise_pubkey must be 32 bytes, got {} bytes", bytes.len());
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }

    /// Check if pubkey is valid without returning the bytes
    pub fn is_pubkey_valid(&self) -> bool {
        self.validate_pubkey().is_ok()
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
            .expect("system time should be after UNIX epoch")
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
            .expect("system time should be after UNIX epoch")
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
            .expect("system time should be after UNIX epoch")
            .as_secs();

        now > self.expires_at
    }

    /// Check if manifest is stale but usable (fallback to cached)
    pub fn is_stale(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after UNIX epoch")
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

    /// Check if manifest version is supported
    pub fn is_version_supported(&self) -> bool {
        self.version >= MIN_MANIFEST_VERSION && self.version <= MAX_MANIFEST_VERSION
    }

    /// Check if manifest version is compatible with current version
    pub fn is_version_compatible(&self) -> bool {
        // For now, only exact version match is supported
        // In future, we can add backward/forward compatibility rules
        self.version == MANIFEST_VERSION
    }

    /// Get version compatibility info
    pub fn version_info(&self) -> VersionInfo {
        VersionInfo {
            version: self.version,
            current_version: MANIFEST_VERSION,
            min_supported: MIN_MANIFEST_VERSION,
            max_supported: MAX_MANIFEST_VERSION,
            is_supported: self.is_version_supported(),
            is_compatible: self.is_version_compatible(),
        }
    }

    /// Migrate manifest to current version (if possible)
    pub fn migrate_to_current(&self) -> Result<Self> {
        if self.version == MANIFEST_VERSION {
            return Ok(self.clone());
        }

        if !self.is_version_supported() {
            bail!(
                "cannot migrate manifest version {} (supported range: {}-{})",
                self.version,
                MIN_MANIFEST_VERSION,
                MAX_MANIFEST_VERSION
            );
        }

        // For now, only version 1 is supported, so migration is identity
        // In future, add migration logic here
        Ok(self.clone())
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

        // Check version compatibility
        if !payload.is_version_supported() {
            bail!(
                "unsupported manifest version: {} (supported range: {}-{})",
                payload.version,
                MIN_MANIFEST_VERSION,
                MAX_MANIFEST_VERSION
            );
        }

        // Try to migrate if needed
        let payload = if !payload.is_version_compatible() {
            payload
                .migrate_to_current()
                .context("failed to migrate manifest to current version")?
        } else {
            payload
        };

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

        let signed =
            SignedManifest::sign(&payload, &keypair).expect("test: failed to sign manifest");
        let verified = signed
            .verify(&keypair.public_bytes())
            .expect("test: failed to verify manifest");

        assert_eq!(verified.servers.len(), 1);
        assert_eq!(verified.servers[0].id, "srv1");
    }

    #[test]
    fn manifest_nonce_non_zero() {
        let kp = test_keypair();
        let payload =
            ManifestPayload::new(vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")]);
        let signed = SignedManifest::sign(&payload, &kp).expect("test: failed to sign manifest");
        assert!(signed.nonce != 0, "nonce must be non-zero");
    }

    #[test]
    fn test_verify_wrong_key_fails() {
        let keypair1 = test_keypair();
        let keypair2 = test_keypair();

        let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];
        let payload = ManifestPayload::new(servers);

        let signed =
            SignedManifest::sign(&payload, &keypair1).expect("test: failed to sign manifest");
        let result = signed.verify(&keypair2.public_bytes());

        assert!(result.is_err());
    }

    #[test]
    fn test_verify_tampered_fails() {
        let keypair = test_keypair();
        let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];
        let payload = ManifestPayload::new(servers);

        let mut signed =
            SignedManifest::sign(&payload, &keypair).expect("test: failed to sign manifest");

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

        let signed =
            SignedManifest::sign(&payload, &keypair).expect("test: failed to sign manifest");
        let json = signed
            .to_json()
            .expect("test: failed to serialize manifest");

        let restored =
            SignedManifest::from_json(&json).expect("test: failed to deserialize manifest");
        let verified = restored
            .verify(&keypair.public_bytes())
            .expect("test: failed to verify manifest");

        assert_eq!(verified.servers[0].id, "srv1");
    }

    #[test]
    fn test_expired_manifest_fails() {
        let keypair = test_keypair();
        let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];

        // Create manifest that's already expired
        let mut payload = ManifestPayload::new(servers);
        payload.expires_at = 0; // In the past

        let signed =
            SignedManifest::sign(&payload, &keypair).expect("test: failed to sign manifest");
        let result = signed.verify(&keypair.public_bytes());

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    #[test]
    fn test_payload_bytes_roundtrip() {
        let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];
        let payload = ManifestPayload::new(servers);

        let bytes = payload
            .to_bytes()
            .expect("test: failed to serialize payload");
        let restored =
            ManifestPayload::from_bytes(&bytes).expect("test: failed to deserialize payload");

        assert_eq!(restored.servers[0].id, "srv1");
    }

    #[test]
    fn test_version_supported() {
        let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];
        let payload = ManifestPayload::new(servers);

        // Current version should be supported
        assert!(payload.is_version_supported());
        assert!(payload.is_version_compatible());

        // Version info should be correct
        let info = payload.version_info();
        assert_eq!(info.version, MANIFEST_VERSION);
        assert_eq!(info.current_version, MANIFEST_VERSION);
        assert!(info.is_supported);
        assert!(info.is_compatible);
    }

    #[test]
    fn test_version_migration() {
        let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];
        let payload = ManifestPayload::new(servers);

        // Migration of current version should be identity
        let migrated = payload
            .migrate_to_current()
            .expect("migration should succeed");
        assert_eq!(payload.version, migrated.version);
        assert_eq!(payload.servers.len(), migrated.servers.len());
    }

    #[test]
    fn test_version_info() {
        let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];
        let payload = ManifestPayload::new(servers);

        let info = payload.version_info();
        assert_eq!(info.version, MANIFEST_VERSION);
        assert_eq!(info.min_supported, MIN_MANIFEST_VERSION);
        assert_eq!(info.max_supported, MAX_MANIFEST_VERSION);
        assert!(info.is_supported);
        assert!(info.is_compatible);
    }

    #[test]
    fn test_constants() {
        assert_eq!(MANIFEST_VERSION, 1);
        assert_eq!(MIN_MANIFEST_VERSION, 1);
        assert_eq!(MAX_MANIFEST_VERSION, 1);
        assert_eq!(MAX_MANIFEST_AGE.as_secs(), 7 * 24 * 60 * 60);
        assert_eq!(STALE_FALLBACK_AGE.as_secs(), 24 * 60 * 60);
    }

    #[test]
    fn test_server_endpoint_with_region() {
        let ep = ServerEndpoint::new("srv1", "example.com", 443, "aabbccdd").with_region("eu-west");
        assert_eq!(ep.region, "eu-west");
    }

    #[test]
    fn test_server_endpoint_with_capabilities() {
        let caps = vec!["masque".to_string(), "doh".to_string()];
        let ep = ServerEndpoint::new("srv1", "example.com", 443, "aabbccdd")
            .with_capabilities(caps.clone());
        assert_eq!(ep.capabilities, caps);
    }

    #[test]
    fn test_server_endpoint_validate_pubkey_valid() {
        // Valid 32-byte hex pubkey
        let pubkey_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let ep = ServerEndpoint::new("srv1", "example.com", 443, pubkey_hex);
        let result = ep.validate_pubkey();
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_server_endpoint_validate_pubkey_invalid_hex() {
        let ep = ServerEndpoint::new("srv1", "example.com", 443, "not-valid-hex!");
        let result = ep.validate_pubkey();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not valid hex"));
    }

    #[test]
    fn test_server_endpoint_validate_pubkey_wrong_length() {
        // Only 16 bytes (32 hex chars needed, we have 16)
        let ep = ServerEndpoint::new("srv1", "example.com", 443, "0123456789abcdef");
        let result = ep.validate_pubkey();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("32 bytes"));
    }

    #[test]
    fn test_server_endpoint_is_pubkey_valid() {
        let valid_pubkey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let ep_valid = ServerEndpoint::new("srv1", "example.com", 443, valid_pubkey);
        assert!(ep_valid.is_pubkey_valid());

        let ep_invalid = ServerEndpoint::new("srv2", "example.com", 443, "invalid");
        assert!(!ep_invalid.is_pubkey_valid());
    }

    #[test]
    fn test_server_endpoint_defaults() {
        let ep = ServerEndpoint::new("srv1", "example.com", 443, "key");
        assert_eq!(ep.weight, 100);
        assert!(ep.active);
        assert_eq!(ep.region, "unknown");
        assert!(ep.capabilities.is_empty());
    }

    #[test]
    fn test_server_endpoint_serde() {
        let ep = ServerEndpoint::new("srv1", "example.com", 443, "aabbccdd")
            .with_region("us-east")
            .with_capabilities(vec!["masque".to_string()]);

        let json = serde_json::to_string(&ep).unwrap();
        let restored: ServerEndpoint = serde_json::from_str(&json).unwrap();

        assert_eq!(ep, restored);
    }

    #[test]
    fn test_manifest_payload_with_validity() {
        let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];
        let payload = ManifestPayload::with_validity(servers, Duration::from_secs(3600)); // 1 hour

        assert!(!payload.is_expired());
        // expires_at should be about 1 hour from now
        let expected_expires = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        assert!((payload.expires_at as i64 - expected_expires as i64).abs() < 5);
        // 5 second tolerance
    }

    #[test]
    fn test_manifest_payload_comment() {
        let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];
        let mut payload = ManifestPayload::new(servers);
        payload.comment = "Test manifest".to_string();

        let bytes = payload.to_bytes().unwrap();
        let restored = ManifestPayload::from_bytes(&bytes).unwrap();
        assert_eq!(restored.comment, "Test manifest");
    }

    #[test]
    fn test_manifest_payload_odoh_relays() {
        let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];
        let mut payload = ManifestPayload::new(servers);
        payload.odoh_relays = vec!["relay1.example.com".to_string()];

        let bytes = payload.to_bytes().unwrap();
        let restored = ManifestPayload::from_bytes(&bytes).unwrap();
        assert_eq!(restored.odoh_relays.len(), 1);
        assert_eq!(restored.odoh_relays[0], "relay1.example.com");
    }

    #[test]
    fn test_manifest_payload_front_domains() {
        let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];
        let mut payload = ManifestPayload::new(servers);
        payload.front_domains = vec!["cdn.example.com".to_string()];

        let bytes = payload.to_bytes().unwrap();
        let restored = ManifestPayload::from_bytes(&bytes).unwrap();
        assert_eq!(restored.front_domains.len(), 1);
    }

    #[test]
    fn test_manifest_is_stale() {
        let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];
        let mut payload = ManifestPayload::new(servers);

        // Set expires_at to 10 seconds ago (expired but not stale)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        payload.expires_at = now - 10;

        assert!(payload.is_expired());
        assert!(payload.is_stale()); // Within STALE_FALLBACK_AGE (24h)

        // Set expires_at to more than 24h ago (too stale)
        payload.expires_at = now - STALE_FALLBACK_AGE.as_secs() - 100;
        assert!(payload.is_expired());
        assert!(!payload.is_stale()); // Past STALE_FALLBACK_AGE
    }

    #[test]
    fn test_version_info_struct() {
        let info = VersionInfo {
            version: 1,
            current_version: 1,
            min_supported: 1,
            max_supported: 2,
            is_supported: true,
            is_compatible: true,
        };

        assert_eq!(info.version, 1);
        assert!(info.is_supported);

        let info2 = info.clone();
        assert_eq!(info, info2);

        let debug = format!("{:?}", info);
        assert!(debug.contains("VersionInfo"));
    }

    #[test]
    fn test_signed_manifest_bytes_roundtrip() {
        let keypair = test_keypair();
        let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];
        let payload = ManifestPayload::new(servers);

        let signed = SignedManifest::sign(&payload, &keypair).unwrap();
        let bytes = signed.to_bytes().unwrap();
        let restored = SignedManifest::from_bytes(&bytes).unwrap();

        assert_eq!(signed.signature, restored.signature);
        assert_eq!(signed.signer_pubkey, restored.signer_pubkey);
        assert_eq!(signed.nonce, restored.nonce);
    }

    #[test]
    fn test_signed_manifest_verify_invalid_signer_length() {
        let keypair = test_keypair();
        let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];
        let payload = ManifestPayload::new(servers);

        let mut signed = SignedManifest::sign(&payload, &keypair).unwrap();
        signed.signer_pubkey = "aabb".to_string(); // Too short

        let result = signed.verify(&keypair.public_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_signed_manifest_verify_invalid_signature_length() {
        let keypair = test_keypair();
        let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];
        let payload = ManifestPayload::new(servers);

        let mut signed = SignedManifest::sign(&payload, &keypair).unwrap();
        signed.signature = "aabb".to_string(); // Too short for 64-byte signature

        let result = signed.verify(&keypair.public_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_signed_manifest_verify_zero_nonce() {
        let keypair = test_keypair();
        let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];
        let payload = ManifestPayload::new(servers);

        let mut signed = SignedManifest::sign(&payload, &keypair).unwrap();
        signed.nonce = 0; // Invalid

        let result = signed.verify(&keypair.public_bytes());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("nonce"));
    }

    #[test]
    fn test_unsupported_version_fails_verification() {
        let keypair = test_keypair();
        let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];
        let mut payload = ManifestPayload::new(servers);
        payload.version = 999; // Unsupported version

        let signed = SignedManifest::sign(&payload, &keypair).unwrap();
        let result = signed.verify(&keypair.public_bytes());

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unsupported"));
    }

    #[test]
    fn test_migrate_unsupported_version_fails() {
        let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];
        let mut payload = ManifestPayload::new(servers);
        payload.version = 999;

        let result = payload.migrate_to_current();
        assert!(result.is_err());
    }

    #[test]
    fn test_manifest_payload_debug() {
        let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];
        let payload = ManifestPayload::new(servers);

        let debug = format!("{:?}", payload);
        assert!(debug.contains("ManifestPayload"));
        assert!(debug.contains("version"));
    }

    #[test]
    fn test_signed_manifest_debug() {
        let keypair = test_keypair();
        let servers = vec![ServerEndpoint::new("srv1", "1.2.3.4", 443, "key1")];
        let payload = ManifestPayload::new(servers);

        let signed = SignedManifest::sign(&payload, &keypair).unwrap();
        let debug = format!("{:?}", signed);
        assert!(debug.contains("SignedManifest"));
    }
}
