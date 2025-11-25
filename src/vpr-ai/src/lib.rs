//! VPR AI - Traffic Morphing for Anti-Censorship
//!
//! This crate provides AI-powered traffic morphing to evade deep packet inspection.
//! It transforms VPN traffic patterns to resemble legitimate applications like
//! YouTube streaming, Zoom calls, or web browsing.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    TrafficMorpher                           │
//! │  ┌─────────────────┐        ┌─────────────────────────────┐ │
//! │  │ RuleBasedMorpher│        │      OnnxMorpher            │ │
//! │  │ (fallback)      │   OR   │ (AI-powered, ~20M params)   │ │
//! │  └────────┬────────┘        └──────────────┬──────────────┘ │
//! │           │                                │                │
//! │           ▼                                ▼                │
//! │  ┌─────────────────────────────────────────────────────────┐│
//! │  │              CoverGenerator                             ││
//! │  │  - Profile-aware packet synthesis                       ││
//! │  │  - Realistic payload patterns (RTP/TLS/Game)            ││
//! │  │  - Cryptographically random content                     ││
//! │  └─────────────────────────────────────────────────────────┘│
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Security Model
//!
//! Cover traffic is designed to be indistinguishable from legitimate traffic:
//! - **Size distribution**: Matches target profile statistics
//! - **Payload entropy**: High entropy (encrypted) with protocol-like headers
//! - **Timing patterns**: Follows profile delay distributions
//!
//! # Example
//!
//! ```rust,ignore
//! use vpr_ai::{TrafficProfile, TrafficMorpher, morpher::create_morpher};
//!
//! let mut morpher = create_morpher(TrafficProfile::YouTube, None);
//!
//! // Process outgoing packet
//! let decision = morpher.morph_outgoing(&packet)?;
//! // Apply padding, delay, and potentially inject cover traffic
//! ```

pub mod cover;
pub mod dpi_simulator;
pub mod e2e_test;
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

    #[cfg(feature = "_onnx_core")]
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
        assert_eq!(
            "youtube".parse::<TrafficProfile>().unwrap(),
            TrafficProfile::YouTube
        );
        assert_eq!(
            "ZOOM".parse::<TrafficProfile>().unwrap(),
            TrafficProfile::Zoom
        );
        assert_eq!(
            "gaming".parse::<TrafficProfile>().unwrap(),
            TrafficProfile::Gaming
        );
        assert!("unknown".parse::<TrafficProfile>().is_err());
    }

    #[test]
    fn test_profile_display() {
        assert_eq!(format!("{}", TrafficProfile::YouTube), "youtube");
        assert_eq!(format!("{}", TrafficProfile::Zoom), "zoom");
    }

    #[test]
    fn test_profile_parsing_all_variants() {
        // Test all lowercase variants
        assert_eq!("youtube".parse::<TrafficProfile>().unwrap(), TrafficProfile::YouTube);
        assert_eq!("zoom".parse::<TrafficProfile>().unwrap(), TrafficProfile::Zoom);
        assert_eq!("gaming".parse::<TrafficProfile>().unwrap(), TrafficProfile::Gaming);
        assert_eq!("browsing".parse::<TrafficProfile>().unwrap(), TrafficProfile::Browsing);
        assert_eq!("netflix".parse::<TrafficProfile>().unwrap(), TrafficProfile::Netflix);
    }

    #[test]
    fn test_profile_parsing_case_insensitive() {
        assert_eq!("YOUTUBE".parse::<TrafficProfile>().unwrap(), TrafficProfile::YouTube);
        assert_eq!("YouTube".parse::<TrafficProfile>().unwrap(), TrafficProfile::YouTube);
        assert_eq!("yOuTuBe".parse::<TrafficProfile>().unwrap(), TrafficProfile::YouTube);
    }

    #[test]
    fn test_profile_parsing_web_alias() {
        // "web" is an alias for "browsing"
        assert_eq!("web".parse::<TrafficProfile>().unwrap(), TrafficProfile::Browsing);
        assert_eq!("WEB".parse::<TrafficProfile>().unwrap(), TrafficProfile::Browsing);
    }

    #[test]
    fn test_profile_parsing_invalid() {
        let result = "invalid_profile".parse::<TrafficProfile>();
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("unknown traffic profile"));
        assert!(msg.contains("invalid_profile"));
    }

    #[test]
    fn test_profile_display_all_variants() {
        assert_eq!(format!("{}", TrafficProfile::YouTube), "youtube");
        assert_eq!(format!("{}", TrafficProfile::Zoom), "zoom");
        assert_eq!(format!("{}", TrafficProfile::Gaming), "gaming");
        assert_eq!(format!("{}", TrafficProfile::Browsing), "browsing");
        assert_eq!(format!("{}", TrafficProfile::Netflix), "netflix");
    }

    #[test]
    fn test_profile_roundtrip() {
        // Display -> Parse should roundtrip
        for profile in [
            TrafficProfile::YouTube,
            TrafficProfile::Zoom,
            TrafficProfile::Gaming,
            TrafficProfile::Browsing,
            TrafficProfile::Netflix,
        ] {
            let display = format!("{}", profile);
            let parsed: TrafficProfile = display.parse().unwrap();
            assert_eq!(profile, parsed);
        }
    }

    #[test]
    fn test_profile_default() {
        let default = TrafficProfile::default();
        assert_eq!(default, TrafficProfile::YouTube);
    }

    #[test]
    fn test_profile_debug() {
        let debug = format!("{:?}", TrafficProfile::Gaming);
        assert!(debug.contains("Gaming"));
    }

    #[test]
    fn test_profile_clone() {
        let original = TrafficProfile::Netflix;
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_profile_copy() {
        let original = TrafficProfile::Zoom;
        let copied = original; // Copy, not move
        assert_eq!(original, copied);
    }

    #[test]
    fn test_profile_eq() {
        assert_eq!(TrafficProfile::YouTube, TrafficProfile::YouTube);
        assert_ne!(TrafficProfile::YouTube, TrafficProfile::Netflix);
    }

    #[test]
    fn test_morph_decision_default() {
        let decision = MorphDecision::default();
        assert_eq!(decision.delay, Duration::ZERO);
        assert_eq!(decision.padding_size, 0);
        assert!(!decision.inject_cover);
        assert!((decision.confidence - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_morph_decision_clone() {
        let decision = MorphDecision {
            delay: Duration::from_millis(100),
            padding_size: 64,
            inject_cover: true,
            confidence: 0.95,
        };
        let cloned = decision.clone();
        assert_eq!(decision.delay, cloned.delay);
        assert_eq!(decision.padding_size, cloned.padding_size);
        assert_eq!(decision.inject_cover, cloned.inject_cover);
        assert!((decision.confidence - cloned.confidence).abs() < 0.001);
    }

    #[test]
    fn test_morph_decision_debug() {
        let decision = MorphDecision::default();
        let debug = format!("{:?}", decision);
        assert!(debug.contains("MorphDecision"));
        assert!(debug.contains("delay"));
        assert!(debug.contains("padding_size"));
    }

    #[test]
    fn test_ai_error_unknown_profile() {
        let err = AiError::UnknownProfile("test".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("unknown traffic profile"));
        assert!(msg.contains("test"));
    }

    #[test]
    fn test_ai_error_model_not_loaded() {
        let err = AiError::ModelNotLoaded;
        let msg = format!("{}", err);
        assert!(msg.contains("model not loaded"));
    }

    #[test]
    fn test_ai_error_inference_failed() {
        let err = AiError::InferenceFailed("tensor shape mismatch".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("inference failed"));
        assert!(msg.contains("tensor shape mismatch"));
    }

    #[test]
    fn test_ai_error_feature_extraction() {
        let err = AiError::FeatureExtractionFailed("invalid packet".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("feature extraction"));
        assert!(msg.contains("invalid packet"));
    }

    #[test]
    fn test_ai_error_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = AiError::IoError(io_err);
        let msg = format!("{}", err);
        assert!(msg.contains("IO error"));
    }

    #[test]
    fn test_ai_error_debug() {
        let err = AiError::ModelNotLoaded;
        let debug = format!("{:?}", err);
        assert!(debug.contains("ModelNotLoaded"));
    }

    #[test]
    fn test_result_type_ok() {
        let result: Result<u32> = Ok(42);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_result_type_err() {
        let result: Result<u32> = Err(AiError::ModelNotLoaded);
        assert!(result.is_err());
    }
}
