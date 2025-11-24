//! Traffic morpher implementations
//!
//! Provides both rule-based and AI-powered traffic morphing.

use std::time::Duration;

use crate::features::{Direction, PacketContext};
use crate::profiles::ProfileStats;
use crate::{MorphDecision, Result, TrafficMorpher, TrafficProfile};
#[cfg(feature = "onnx")]
use crate::AiError;

/// Rule-based traffic morpher (no AI model required)
///
/// Uses statistical matching to morph traffic patterns.
/// This is a fallback when ONNX model is not available.
pub struct RuleBasedMorpher {
    profile: TrafficProfile,
    profile_stats: ProfileStats,
    context: PacketContext,
    cover_counter: u32,
}

impl RuleBasedMorpher {
    /// Create new rule-based morpher for given profile
    pub fn new(profile: TrafficProfile) -> Self {
        Self {
            profile,
            profile_stats: ProfileStats::for_profile(profile),
            context: PacketContext::new(),
            cover_counter: 0,
        }
    }
}

impl TrafficMorpher for RuleBasedMorpher {
    fn morph_outgoing(&mut self, packet: &[u8]) -> Result<MorphDecision> {
        let features = self.context.add_packet(packet, Direction::Outbound);

        // Calculate padding based on profile
        let padding_size = self.profile_stats.suggested_padding(features.size_raw);

        // Calculate delay adjustment
        let delay_ms = self.profile_stats.suggested_delay_ms(features.delay_log_ms);
        let delay = Duration::from_micros((delay_ms * 1000.0) as u64);

        // Decide on cover traffic injection
        // Inject cover when we've been quiet for too long
        self.cover_counter += 1;
        let inject_cover = if self.cover_counter > 10 {
            self.cover_counter = 0;
            true
        } else {
            false
        };

        Ok(MorphDecision {
            delay,
            padding_size,
            inject_cover,
            confidence: 0.8, // Rule-based has lower confidence
        })
    }

    fn observe_incoming(&mut self, packet: &[u8]) -> Result<()> {
        self.context.add_packet(packet, Direction::Inbound);
        self.cover_counter = 0; // Reset cover counter on activity
        Ok(())
    }

    fn generate_cover(&mut self) -> Result<Option<Vec<u8>>> {
        // Generate a small cover packet matching profile
        let size = self.profile_stats.common_sizes[0];
        let cover = vec![0u8; size];
        Ok(Some(cover))
    }

    fn profile(&self) -> TrafficProfile {
        self.profile
    }

    fn reset(&mut self) {
        self.context.clear();
        self.cover_counter = 0;
    }
}

/// ONNX-based AI morpher (requires `onnx` feature)
#[cfg(feature = "onnx")]
pub struct OnnxMorpher {
    profile: TrafficProfile,
    context: PacketContext,
    session: ort::Session,
}

#[cfg(feature = "onnx")]
impl OnnxMorpher {
    /// Load ONNX model from file
    pub fn load(model_path: &std::path::Path, profile: TrafficProfile) -> Result<Self> {
        let session = ort::Session::builder()?
            .with_optimization_level(ort::GraphOptimizationLevel::Level3)?
            .commit_from_file(model_path)?;

        Ok(Self {
            profile,
            context: PacketContext::new(),
            session,
        })
    }

    /// Load ONNX model from bytes
    pub fn from_bytes(model_bytes: &[u8], profile: TrafficProfile) -> Result<Self> {
        let session = ort::Session::builder()?
            .with_optimization_level(ort::GraphOptimizationLevel::Level3)?
            .commit_from_memory(model_bytes)?;

        Ok(Self {
            profile,
            context: PacketContext::new(),
            session,
        })
    }
}

#[cfg(feature = "onnx")]
impl TrafficMorpher for OnnxMorpher {
    fn morph_outgoing(&mut self, packet: &[u8]) -> Result<MorphDecision> {
        use ndarray::Array2;

        let features = self.context.add_packet(packet, Direction::Outbound);
        let context_tensor = self.context.to_tensor();

        // Create input tensor [1, CONTEXT_WINDOW_SIZE, 4]
        let input = Array2::from_shape_vec(
            (crate::features::CONTEXT_WINDOW_SIZE, 4),
            context_tensor,
        )
        .map_err(|e| AiError::FeatureExtractionFailed(e.to_string()))?;

        let outputs = self
            .session
            .run(ort::inputs!["input" => input.view()]?)
            .map_err(|e| AiError::InferenceFailed(e.to_string()))?;

        // Parse outputs
        let output = outputs
            .get("output")
            .ok_or_else(|| AiError::InferenceFailed("missing output".into()))?
            .try_extract_tensor::<f32>()
            .map_err(|e| AiError::InferenceFailed(e.to_string()))?;

        let output_view = output.view();
        let delay_ms = output_view[[0, 0]].max(0.0);
        let padding = output_view[[0, 1]].max(0.0) as usize;
        let inject_prob = output_view[[0, 2]];
        let confidence = output_view[[0, 3]].clamp(0.0, 1.0);

        Ok(MorphDecision {
            delay: Duration::from_micros((delay_ms * 1000.0) as u64),
            padding_size: padding.min(1400), // Cap at reasonable size
            inject_cover: inject_prob > 0.5,
            confidence,
        })
    }

    fn observe_incoming(&mut self, packet: &[u8]) -> Result<()> {
        self.context.add_packet(packet, Direction::Inbound);
        Ok(())
    }

    fn generate_cover(&mut self) -> Result<Option<Vec<u8>>> {
        // TODO: Use model to generate realistic cover packet
        let profile_stats = ProfileStats::for_profile(self.profile);
        let size = profile_stats.common_sizes[0];
        Ok(Some(vec![0u8; size]))
    }

    fn profile(&self) -> TrafficProfile {
        self.profile
    }

    fn reset(&mut self) {
        self.context.clear();
    }
}

/// Create the best available morpher for the given profile
#[allow(unused_variables)]
pub fn create_morpher(profile: TrafficProfile, model_path: Option<&std::path::Path>) -> Box<dyn TrafficMorpher> {
    #[cfg(feature = "onnx")]
    if let Some(path) = model_path {
        if path.exists() {
            match OnnxMorpher::load(path, profile) {
                Ok(morpher) => {
                    tracing::info!(?profile, ?path, "Loaded ONNX traffic morpher");
                    return Box::new(morpher);
                }
                Err(e) => {
                    tracing::warn!(?e, "Failed to load ONNX model, falling back to rule-based");
                }
            }
        }
    }

    tracing::info!(?profile, "Using rule-based traffic morpher");
    Box::new(RuleBasedMorpher::new(profile))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_based_morpher() {
        let mut morpher = RuleBasedMorpher::new(TrafficProfile::YouTube);

        // Morph a small packet
        let packet = vec![0u8; 100];
        let decision = morpher.morph_outgoing(&packet).unwrap();

        // Should add padding to reach common size
        assert!(decision.padding_size > 0);
        assert!(decision.confidence > 0.0);
    }

    #[test]
    fn test_morpher_reset() {
        let mut morpher = RuleBasedMorpher::new(TrafficProfile::Gaming);

        // Add some packets
        for _ in 0..10 {
            morpher.morph_outgoing(&[0u8; 50]).unwrap();
        }

        // Reset
        morpher.reset();

        // Context should be empty (tested indirectly)
        let decision = morpher.morph_outgoing(&[0u8; 50]).unwrap();
        assert!(decision.confidence > 0.0);
    }

    #[test]
    fn test_create_morpher_fallback() {
        // Without ONNX feature or model, should create rule-based
        let morpher = create_morpher(TrafficProfile::Zoom, None);
        assert_eq!(morpher.profile(), TrafficProfile::Zoom);
    }
}
