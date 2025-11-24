//! VPR AI - Traffic Morphing for Anti-Censorship
//!
//! This crate provides AI-powered traffic morphing to evade deep packet inspection.
//! It transforms VPN traffic patterns to resemble legitimate applications like
//! YouTube streaming, Zoom calls, or web browsing.

pub mod features;
pub mod morpher;
pub mod profiles;

use std::time::Duration;
use thiserror::Error;

/// Target traffic profile for morphing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TrafficProfile {
    /// YouTube 4K streaming pattern
    #[default]
    YouTube,
    /// Zoom video call pattern
    Zoom,
    /// Online gaming (FPS-like)
    Gaming,
    /// General web browsing
    Browsing,
    /// Netflix streaming
    Netflix,
}

impl std::fmt::Display for TrafficProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::YouTube => write!(f, "youtube"),
            Self::Zoom => write!(f, "zoom"),
            Self::Gaming => write!(f, "gaming"),
            Self::Browsing => write!(f, "browsing"),
            Self::Netflix => write!(f, "netflix"),
        }
    }
}

impl std::str::FromStr for TrafficProfile {
    type Err = AiError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "youtube" => Ok(Self::YouTube),
            "zoom" => Ok(Self::Zoom),
            "gaming" => Ok(Self::Gaming),
            "browsing" | "web" => Ok(Self::Browsing),
            "netflix" => Ok(Self::Netflix),
            _ => Err(AiError::UnknownProfile(s.to_string())),
        }
    }
}

/// Morphing decision from the AI model
#[derive(Debug, Clone)]
pub struct MorphDecision {
    /// Additional delay before sending (for timing obfuscation)
    pub delay: Duration,
    /// Padding bytes to add to packet
    pub padding_size: usize,
    /// Should we inject cover traffic after this packet?
    pub inject_cover: bool,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
}

impl Default for MorphDecision {
    fn default() -> Self {
        Self {
            delay: Duration::ZERO,
            padding_size: 0,
            inject_cover: false,
            confidence: 1.0,
        }
    }
}

/// AI morpher errors
#[derive(Debug, Error)]
pub enum AiError {
    #[error("unknown traffic profile: {0}")]
    UnknownProfile(String),

    #[error("model not loaded")]
    ModelNotLoaded,

    #[error("inference failed: {0}")]
    InferenceFailed(String),

    #[error("feature extraction failed: {0}")]
    FeatureExtractionFailed(String),

    #[cfg(feature = "onnx")]
    #[error("ONNX runtime error: {0}")]
    OnnxError(#[from] ort::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Result type for AI operations
pub type Result<T> = std::result::Result<T, AiError>;

/// Trait for traffic morphers
pub trait TrafficMorpher: Send + Sync {
    /// Process an outgoing packet and get morphing decision
    fn morph_outgoing(&mut self, packet: &[u8]) -> Result<MorphDecision>;

    /// Process incoming packet (for learning/adaptation)
    fn observe_incoming(&mut self, packet: &[u8]) -> Result<()>;

    /// Generate cover traffic packet if needed
    fn generate_cover(&mut self) -> Result<Option<Vec<u8>>>;

    /// Get current target profile
    fn profile(&self) -> TrafficProfile;

    /// Reset internal state (e.g., after connection reset)
    fn reset(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_parsing() {
        assert_eq!("youtube".parse::<TrafficProfile>().unwrap(), TrafficProfile::YouTube);
        assert_eq!("ZOOM".parse::<TrafficProfile>().unwrap(), TrafficProfile::Zoom);
        assert_eq!("gaming".parse::<TrafficProfile>().unwrap(), TrafficProfile::Gaming);
        assert!("unknown".parse::<TrafficProfile>().is_err());
    }

    #[test]
    fn test_profile_display() {
        assert_eq!(format!("{}", TrafficProfile::YouTube), "youtube");
        assert_eq!(format!("{}", TrafficProfile::Zoom), "zoom");
    }
}
