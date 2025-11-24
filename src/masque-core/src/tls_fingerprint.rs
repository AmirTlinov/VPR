//! TLS Fingerprint Obfuscation
//!
//! Implements browser-like TLS fingerprints to evade DPI detection.
//! Supports Chrome, Firefox, and Safari profiles with JA3/JA3S hash generation.
//!
//! # JA3 Fingerprint Format
//! `SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats`
//!
//! Example Chrome JA3: `771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0`

use rustls::crypto::ring::cipher_suite::*;
use rustls::crypto::ring::kx_group;
use rustls::crypto::SupportedKxGroup;
use rustls::SupportedCipherSuite;
use std::fmt;

/// TLS version constants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TlsVersion {
    Tls10 = 0x0301,
    Tls11 = 0x0302,
    Tls12 = 0x0303,
    Tls13 = 0x0304,
}

impl TlsVersion {
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    /// Convert to decimal for JA3
    pub fn ja3_value(self) -> u16 {
        match self {
            TlsVersion::Tls10 => 769,
            TlsVersion::Tls11 => 770,
            TlsVersion::Tls12 => 771,
            TlsVersion::Tls13 => 771, // TLS 1.3 uses 771 in ClientHello for compatibility
        }
    }
}

/// Common TLS cipher suites
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum CipherSuite {
    // TLS 1.3 cipher suites
    Tls13Aes128GcmSha256 = 0x1301,
    Tls13Aes256GcmSha384 = 0x1302,
    Tls13Chacha20Poly1305Sha256 = 0x1303,

    // TLS 1.2 cipher suites (ECDHE)
    EcdheEcdsaAes128GcmSha256 = 0xC02B,
    EcdheRsaAes128GcmSha256 = 0xC02F,
    EcdheEcdsaAes256GcmSha384 = 0xC02C,
    EcdheRsaAes256GcmSha384 = 0xC030,
    EcdheEcdsaChacha20Poly1305 = 0xCCA9,
    EcdheRsaChacha20Poly1305 = 0xCCA8,

    // Legacy (for fingerprint matching)
    EcdheEcdsaAes128Sha256 = 0xC023,
    EcdheRsaAes128Sha256 = 0xC027,
    RsaAes128GcmSha256 = 0x009C,
    RsaAes256GcmSha384 = 0x009D,
    RsaAes128Sha = 0x002F,
    RsaAes256Sha = 0x0035,
}

impl CipherSuite {
    pub fn as_u16(self) -> u16 {
        self as u16
    }
}

/// TLS extensions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TlsExtension {
    ServerName = 0,
    StatusRequest = 5,
    SupportedGroups = 10,
    EcPointFormats = 11,
    SignatureAlgorithms = 13,
    UseSrtp = 14,
    Heartbeat = 15,
    ApplicationLayerProtocolNegotiation = 16,
    SignedCertificateTimestamp = 18,
    Padding = 21,
    EncryptThenMac = 22,
    ExtendedMasterSecret = 23,
    CompressCertificate = 27,
    RecordSizeLimit = 28,
    SessionTicket = 35,
    PreSharedKey = 41,
    EarlyData = 42,
    SupportedVersions = 43,
    Cookie = 44,
    PskKeyExchangeModes = 45,
    CertificateAuthorities = 47,
    PostHandshakeAuth = 49,
    SignatureAlgorithmsCert = 50,
    KeyShare = 51,
    Quic = 57,
    RenegotiationInfo = 65281,
    // GREASE values (randomized)
    Grease0 = 0x0A0A,
    Grease1 = 0x1A1A,
    Grease2 = 0x2A2A,
    Grease3 = 0x3A3A,
}

impl TlsExtension {
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    /// Check if this is a GREASE value
    pub fn is_grease(self) -> bool {
        matches!(
            self,
            TlsExtension::Grease0
                | TlsExtension::Grease1
                | TlsExtension::Grease2
                | TlsExtension::Grease3
        )
    }
}

/// Elliptic curve groups
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum EllipticCurve {
    X25519 = 29,
    Secp256r1 = 23,
    Secp384r1 = 24,
    Secp521r1 = 25,
    X448 = 30,
    // GREASE
    Grease = 0x0A0A,
}

impl EllipticCurve {
    pub fn as_u16(self) -> u16 {
        self as u16
    }
}

/// EC point formats
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EcPointFormat {
    Uncompressed = 0,
}

impl EcPointFormat {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Browser TLS profile
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsProfile {
    /// Chrome 120+ fingerprint
    Chrome,
    /// Firefox 121+ fingerprint
    Firefox,
    /// Safari 17+ fingerprint
    Safari,
    /// Randomized profile (harder to fingerprint)
    Random,
    /// Custom profile
    Custom,
}

impl TlsProfile {
    /// Get cipher suites for this profile
    pub fn cipher_suites(&self) -> Vec<u16> {
        match self {
            TlsProfile::Chrome => vec![
                0x1301, // TLS_AES_128_GCM_SHA256
                0x1302, // TLS_AES_256_GCM_SHA384
                0x1303, // TLS_CHACHA20_POLY1305_SHA256
                0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                0xC02C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                0xCCA9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                0xCCA8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
                0xC013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
                0xC014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
                0x009C, // TLS_RSA_WITH_AES_128_GCM_SHA256
                0x009D, // TLS_RSA_WITH_AES_256_GCM_SHA384
                0x002F, // TLS_RSA_WITH_AES_128_CBC_SHA
                0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
            ],
            TlsProfile::Firefox => vec![
                0x1301, // TLS_AES_128_GCM_SHA256
                0x1303, // TLS_CHACHA20_POLY1305_SHA256
                0x1302, // TLS_AES_256_GCM_SHA384
                0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                0xCCA9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                0xCCA8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
                0xC02C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                0xC013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
                0xC014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
            ],
            TlsProfile::Safari => vec![
                0x1301, // TLS_AES_128_GCM_SHA256
                0x1302, // TLS_AES_256_GCM_SHA384
                0x1303, // TLS_CHACHA20_POLY1305_SHA256
                0xC02C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                0xCCA9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                0xCCA8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            ],
            TlsProfile::Random | TlsProfile::Custom => {
                vec![0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030]
            }
        }
    }

    /// Get TLS extensions for this profile
    pub fn extensions(&self) -> Vec<u16> {
        match self {
            TlsProfile::Chrome => vec![
                0,     // server_name
                23,    // extended_master_secret
                65281, // renegotiation_info
                10,    // supported_groups
                11,    // ec_point_formats
                35,    // session_ticket
                16,    // application_layer_protocol_negotiation
                5,     // status_request
                13,    // signature_algorithms
                18,    // signed_certificate_timestamp
                51,    // key_share
                45,    // psk_key_exchange_modes
                43,    // supported_versions
                27,    // compress_certificate
                17513, // application_settings
            ],
            TlsProfile::Firefox => vec![
                0,     // server_name
                23,    // extended_master_secret
                65281, // renegotiation_info
                10,    // supported_groups
                11,    // ec_point_formats
                35,    // session_ticket
                16,    // application_layer_protocol_negotiation
                5,     // status_request
                34,    // delegated_credentials
                51,    // key_share
                45,    // psk_key_exchange_modes
                43,    // supported_versions
                13,    // signature_algorithms
                28,    // record_size_limit
            ],
            TlsProfile::Safari => vec![
                0,     // server_name
                23,    // extended_master_secret
                65281, // renegotiation_info
                10,    // supported_groups
                11,    // ec_point_formats
                16,    // application_layer_protocol_negotiation
                5,     // status_request
                13,    // signature_algorithms
                18,    // signed_certificate_timestamp
                51,    // key_share
                45,    // psk_key_exchange_modes
                43,    // supported_versions
            ],
            TlsProfile::Random | TlsProfile::Custom => {
                vec![0, 23, 65281, 10, 11, 35, 16, 5, 13, 51, 45, 43]
            }
        }
    }

    /// Get elliptic curves for this profile
    pub fn elliptic_curves(&self) -> Vec<u16> {
        match self {
            TlsProfile::Chrome => vec![29, 23, 24], // x25519, secp256r1, secp384r1
            TlsProfile::Firefox => vec![29, 23, 24, 25], // + secp521r1
            TlsProfile::Safari => vec![29, 23, 24],
            TlsProfile::Random | TlsProfile::Custom => vec![29, 23, 24],
        }
    }

    /// Get EC point formats for this profile
    pub fn ec_point_formats(&self) -> Vec<u8> {
        vec![0] // uncompressed for all browsers
    }
}

impl TlsProfile {
    pub fn rustls_cipher_suites(&self) -> Vec<SupportedCipherSuite> {
        let suites = match self {
            TlsProfile::Chrome => vec![
                TLS13_AES_128_GCM_SHA256,
                TLS13_AES_256_GCM_SHA384,
                TLS13_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            ],
            TlsProfile::Firefox => vec![
                TLS13_AES_128_GCM_SHA256,
                TLS13_CHACHA20_POLY1305_SHA256,
                TLS13_AES_256_GCM_SHA384,
                TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            ],
            TlsProfile::Safari => vec![
                TLS13_AES_128_GCM_SHA256,
                TLS13_AES_256_GCM_SHA384,
                TLS13_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            ],
            TlsProfile::Random | TlsProfile::Custom => vec![
                TLS13_AES_128_GCM_SHA256,
                TLS13_AES_256_GCM_SHA384,
                TLS13_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            ],
        };
        suites
    }

    pub fn rustls_kx_groups(&self) -> Vec<&'static dyn SupportedKxGroup> {
        match self {
            TlsProfile::Chrome => vec![
                kx_group::X25519,
                kx_group::SECP256R1,
                kx_group::SECP384R1,
            ],
            TlsProfile::Firefox => vec![
                kx_group::X25519,
                kx_group::SECP256R1,
                kx_group::SECP384R1,
            ],
            TlsProfile::Safari => vec![
                kx_group::X25519,
                kx_group::SECP256R1,
                kx_group::SECP384R1,
            ],
            TlsProfile::Random | TlsProfile::Custom => vec![
                kx_group::X25519,
                kx_group::SECP256R1,
                kx_group::SECP384R1,
            ],
        }
    }
}

impl fmt::Display for TlsProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsProfile::Chrome => write!(f, "Chrome"),
            TlsProfile::Firefox => write!(f, "Firefox"),
            TlsProfile::Safari => write!(f, "Safari"),
            TlsProfile::Random => write!(f, "Random"),
            TlsProfile::Custom => write!(f, "Custom"),
        }
    }
}

impl std::str::FromStr for TlsProfile {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "chrome" => Ok(TlsProfile::Chrome),
            "firefox" => Ok(TlsProfile::Firefox),
            "safari" => Ok(TlsProfile::Safari),
            "random" => Ok(TlsProfile::Random),
            "custom" => Ok(TlsProfile::Custom),
            _ => Err(format!("unknown TLS profile: {}", s)),
        }
    }
}

/// JA3 fingerprint data
#[derive(Debug, Clone)]
pub struct Ja3Fingerprint {
    /// TLS version (decimal)
    pub tls_version: u16,
    /// Cipher suites (decimal, hyphen-separated)
    pub cipher_suites: Vec<u16>,
    /// Extensions (decimal, hyphen-separated)
    pub extensions: Vec<u16>,
    /// Elliptic curves (decimal, hyphen-separated)
    pub elliptic_curves: Vec<u16>,
    /// EC point formats (decimal, hyphen-separated)
    pub ec_point_formats: Vec<u8>,
}

impl Ja3Fingerprint {
    /// Create JA3 fingerprint from TLS profile
    pub fn from_profile(profile: &TlsProfile) -> Self {
        Self {
            tls_version: TlsVersion::Tls12.ja3_value(),
            cipher_suites: profile.cipher_suites(),
            extensions: profile.extensions(),
            elliptic_curves: profile.elliptic_curves(),
            ec_point_formats: profile.ec_point_formats(),
        }
    }

    /// Generate JA3 string
    pub fn to_ja3_string(&self) -> String {
        let ciphers = self
            .cipher_suites
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("-");

        let extensions = self
            .extensions
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("-");

        let curves = self
            .elliptic_curves
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("-");

        let formats = self
            .ec_point_formats
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join("-");

        format!(
            "{},{},{},{},{}",
            self.tls_version, ciphers, extensions, curves, formats
        )
    }

    /// Compute JA3 MD5 hash
    pub fn to_ja3_hash(&self) -> String {
        let ja3_string = self.to_ja3_string();
        let digest = md5::compute(ja3_string.as_bytes());
        format!("{:x}", digest)
    }
}

/// Known browser JA3 hashes for verification
pub mod known_ja3 {
    /// Chrome 120 on Windows (approximate)
    pub const CHROME_120: &str = "cd08e31494f9531f560d64c695473da9";
    /// Firefox 121 on Windows (approximate)
    pub const FIREFOX_121: &str = "3b5074b1b5d032e5620f69f9f700ff0e";
    /// Safari 17 on macOS (approximate)
    pub const SAFARI_17: &str = "773906b0efdefa24a7f2b8eb6985bf37";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ja3_string_generation() {
        let fp = Ja3Fingerprint::from_profile(&TlsProfile::Chrome);
        let ja3 = fp.to_ja3_string();

        // Should start with TLS version
        assert!(ja3.starts_with("771,"));

        // Should have 5 comma-separated parts
        assert_eq!(ja3.split(',').count(), 5);
    }

    #[test]
    fn test_ja3_hash_deterministic() {
        let fp1 = Ja3Fingerprint::from_profile(&TlsProfile::Chrome);
        let fp2 = Ja3Fingerprint::from_profile(&TlsProfile::Chrome);

        assert_eq!(fp1.to_ja3_hash(), fp2.to_ja3_hash());
    }

    #[test]
    fn test_different_profiles_different_hashes() {
        let chrome = Ja3Fingerprint::from_profile(&TlsProfile::Chrome);
        let firefox = Ja3Fingerprint::from_profile(&TlsProfile::Firefox);

        assert_ne!(chrome.to_ja3_hash(), firefox.to_ja3_hash());
    }

    #[test]
    fn test_profile_from_str() {
        assert_eq!("chrome".parse::<TlsProfile>().unwrap(), TlsProfile::Chrome);
        assert_eq!(
            "Firefox".parse::<TlsProfile>().unwrap(),
            TlsProfile::Firefox
        );
        assert_eq!("SAFARI".parse::<TlsProfile>().unwrap(), TlsProfile::Safari);
        assert!("invalid".parse::<TlsProfile>().is_err());
    }

    #[test]
    fn test_cipher_suites_not_empty() {
        for profile in [TlsProfile::Chrome, TlsProfile::Firefox, TlsProfile::Safari] {
            let suites = profile.cipher_suites();
            assert!(
                !suites.is_empty(),
                "Profile {:?} has empty cipher suites",
                profile
            );
            // All profiles should support TLS 1.3 suites
            assert!(
                suites.contains(&0x1301),
                "Profile {:?} missing TLS 1.3 AES-128-GCM",
                profile
            );
        }
    }

    #[test]
    fn test_extensions_include_required() {
        for profile in [TlsProfile::Chrome, TlsProfile::Firefox, TlsProfile::Safari] {
            let exts = profile.extensions();
            // All should have server_name (0)
            assert!(
                exts.contains(&0),
                "Profile {:?} missing server_name",
                profile
            );
            // All should have supported_versions (43)
            assert!(
                exts.contains(&43),
                "Profile {:?} missing supported_versions",
                profile
            );
        }
    }

    #[test]
    fn test_elliptic_curves_include_x25519() {
        for profile in [TlsProfile::Chrome, TlsProfile::Firefox, TlsProfile::Safari] {
            let curves = profile.elliptic_curves();
            assert!(curves.contains(&29), "Profile {:?} missing x25519", profile);
        }
    }
}
