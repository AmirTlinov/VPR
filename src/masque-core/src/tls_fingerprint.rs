//! TLS fingerprinting and obfuscation utilities.
//! Provides browser-like JA3/JA3S/JA4 generation plus rustls cipher/kx profiles.

use rand::rngs::OsRng;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rustls::crypto::ring::cipher_suite::*;
use rustls::crypto::ring::kx_group;
use rustls::crypto::SupportedKxGroup;
use rustls::SupportedCipherSuite;
use std::fmt;

/// GREASE generation strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GreaseMode {
    /// Random per call (default)
    Random,
    /// Deterministic GREASE value seeded
    Deterministic(u64),
}

fn grease_value(mode: GreaseMode) -> u16 {
    const GREASE_VALUES: [u16; 16] = [
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa,
        0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
    ];
    let idx = match mode {
        GreaseMode::Random => OsRng.gen_range(0..GREASE_VALUES.len()),
        GreaseMode::Deterministic(seed) => {
            let mut rng = ChaCha20Rng::seed_from_u64(seed);
            rng.gen_range(0..GREASE_VALUES.len())
        }
    };
    GREASE_VALUES[idx]
}

/// TLS version constants (for JA3 numeric representation)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TlsVersion {
    Tls10 = 0x0301,
    Tls11 = 0x0302,
    Tls12 = 0x0303,
    Tls13 = 0x0304,
}

impl TlsVersion {
    pub fn ja3_value(self) -> u16 {
        match self {
            TlsVersion::Tls10 => 769,
            TlsVersion::Tls11 => 770,
            TlsVersion::Tls12 => 771,
            TlsVersion::Tls13 => 771,
        }
    }
}

/// Browser TLS profile to mimic
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsProfile {
    Chrome,
    Firefox,
    Safari,
    Random,
    Custom,
}

impl TlsProfile {
    pub fn cipher_suites(&self) -> Vec<u16> {
        match self {
            TlsProfile::Chrome => vec![
                0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013,
                0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
            ],
            TlsProfile::Firefox => vec![
                0x1301, 0x1303, 0x1302, 0xC02B, 0xC02F, 0xCCA9, 0xCCA8, 0xC02C, 0xC030, 0xC013,
                0xC014,
            ],
            TlsProfile::Safari => vec![
                0x1301, 0x1302, 0x1303, 0xC02C, 0xC02B, 0xC030, 0xC02F, 0xCCA9, 0xCCA8,
            ],
            TlsProfile::Random | TlsProfile::Custom => {
                vec![0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030]
            }
        }
    }

    pub fn extensions_with_mode(&self, grease: GreaseMode) -> Vec<u16> {
        let grease_val = grease_value(grease);
        match self {
            TlsProfile::Chrome => vec![
                grease_val, 0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513,
            ],
            TlsProfile::Firefox => vec![
                grease_val, 0, 23, 65281, 10, 11, 35, 16, 5, 34, 51, 45, 43, 13, 28,
            ],
            TlsProfile::Safari => vec![grease_val, 0, 23, 65281, 10, 11, 16, 5, 13, 18, 51, 45, 43],
            TlsProfile::Random | TlsProfile::Custom => vec![grease_val, 0, 23, 65281, 10, 11, 35],
        }
    }

    pub fn extensions(&self) -> Vec<u16> {
        self.extensions_with_mode(GreaseMode::Random)
    }

    pub fn elliptic_curves(&self) -> Vec<u16> {
        match self {
            TlsProfile::Chrome => vec![29, 23, 24],
            TlsProfile::Firefox => vec![29, 23, 24, 25],
            TlsProfile::Safari => vec![29, 23, 24],
            TlsProfile::Random | TlsProfile::Custom => vec![29, 23, 24],
        }
    }

    pub fn ec_point_formats(&self) -> Vec<u8> {
        vec![0]
    }

    pub fn rustls_cipher_suites(&self) -> Vec<SupportedCipherSuite> {
        match self {
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
        }
    }

    pub fn rustls_kx_groups(&self) -> Vec<&'static dyn SupportedKxGroup> {
        match self {
            TlsProfile::Chrome
            | TlsProfile::Firefox
            | TlsProfile::Safari
            | TlsProfile::Random
            | TlsProfile::Custom => {
                vec![kx_group::X25519, kx_group::SECP256R1, kx_group::SECP384R1]
            }
        }
    }
}

impl fmt::Display for TlsProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            TlsProfile::Chrome => "Chrome",
            TlsProfile::Firefox => "Firefox",
            TlsProfile::Safari => "Safari",
            TlsProfile::Random => "Random",
            TlsProfile::Custom => "Custom",
        };
        write!(f, "{}", name)
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

/// JA3 fingerprint (ClientHello)
#[derive(Debug, Clone)]
pub struct Ja3Fingerprint {
    pub tls_version: u16,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub elliptic_curves: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
}

impl Ja3Fingerprint {
    pub fn from_profile(profile: &TlsProfile) -> Self {
        Self::from_profile_with_grease(profile, GreaseMode::Random)
    }

    pub fn from_profile_with_grease(profile: &TlsProfile, grease: GreaseMode) -> Self {
        Self {
            tls_version: TlsVersion::Tls12.ja3_value(),
            cipher_suites: profile.cipher_suites(),
            extensions: profile.extensions_with_mode(grease),
            elliptic_curves: profile.elliptic_curves(),
            ec_point_formats: profile.ec_point_formats(),
        }
    }

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

    pub fn to_ja3_hash(&self) -> String {
        let digest = md5::compute(self.to_ja3_string().as_bytes());
        format!("{:x}", digest)
    }
}

/// JA3S (ServerHello) fingerprint
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja3sFingerprint {
    pub tls_version: u16,
    pub selected_cipher: u16,
    pub extensions: Vec<u16>,
}

impl Ja3sFingerprint {
    pub fn from_profile(profile: &TlsProfile, selected_cipher: u16) -> Self {
        Self::from_profile_with_grease(profile, selected_cipher, GreaseMode::Random)
    }

    pub fn from_profile_with_grease(
        profile: &TlsProfile,
        selected_cipher: u16,
        grease: GreaseMode,
    ) -> Self {
        Self {
            tls_version: TlsVersion::Tls12.ja3_value(),
            selected_cipher,
            extensions: profile.extensions_with_mode(grease),
        }
    }

    pub fn to_ja3s_string(&self) -> String {
        let exts = self
            .extensions
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("-");
        format!("{},{},{}", self.tls_version, self.selected_cipher, exts)
    }

    pub fn to_ja3s_hash(&self) -> String {
        format!("{:x}", md5::compute(self.to_ja3s_string().as_bytes()))
    }
}

/// Simplified JA4 fingerprint (client)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja4Fingerprint {
    pub tls_version: u16,
    pub cipher_count: usize,
    pub extension_count: usize,
    pub group_count: usize,
}

impl Ja4Fingerprint {
    pub fn from_profile(profile: &TlsProfile) -> Self {
        Self {
            tls_version: TlsVersion::Tls12.ja3_value(),
            cipher_count: profile.cipher_suites().len(),
            extension_count: profile.extensions().len(),
            group_count: profile.elliptic_curves().len(),
        }
    }

    pub fn to_hash(&self) -> String {
        format!("{:x}", md5::compute(self.to_string().as_bytes()))
    }
}

impl fmt::Display for Ja4Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "c{}-s{}-e{}-g{}",
            self.tls_version, self.cipher_count, self.extension_count, self.group_count
        )
    }
}

/// Known JA3 hashes for quick comparisons
pub mod known_ja3 {
    pub const CHROME_120: &str = "cd08e31494f9531f560d64c695473da9";
    pub const FIREFOX_121: &str = "3b5074b1b5d032e5620f69f9f700ff0e";
    pub const SAFARI_17: &str = "773906b0efdefa24a7f2b8eb6985bf37";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ja3_hash_deterministic_with_same_seed() {
        let fp1 = Ja3Fingerprint::from_profile_with_grease(
            &TlsProfile::Chrome,
            GreaseMode::Deterministic(42),
        );
        let fp2 = Ja3Fingerprint::from_profile_with_grease(
            &TlsProfile::Chrome,
            GreaseMode::Deterministic(42),
        );
        assert_eq!(fp1.to_ja3_hash(), fp2.to_ja3_hash());
    }

    #[test]
    fn ja3s_hash_has_length() {
        let fp = Ja3sFingerprint::from_profile(&TlsProfile::Chrome, 0x1301);
        assert_eq!(fp.to_ja3s_hash().len(), 32);
    }

    #[test]
    fn ja4_string_and_hash() {
        let fp = Ja4Fingerprint::from_profile(&TlsProfile::Firefox);
        assert!(fp.to_string().starts_with("c"));
        assert_eq!(fp.to_hash().len(), 32);
    }
}
