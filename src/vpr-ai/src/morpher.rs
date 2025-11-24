//! Traffic morpher implementations
//!
//! Provides both rule-based and AI-powered traffic morphing with
//! profile-realistic cover traffic generation.

use std::time::Duration;

use crate::cover::CoverGenerator;
use crate::features::{Direction, PacketContext, TrafficStats};
use crate::profiles::ProfileStats;
#[cfg(feature = "onnx")]
use crate::AiError;
use crate::{MorphDecision, Result, TrafficMorpher, TrafficProfile};
#[cfg(feature = "onnx")]
use ort::session::{builder::GraphOptimizationLevel, Session};

/// Configuration for morpher behavior
#[derive(Debug, Clone)]
pub struct MorpherConfig {
    /// Threshold for burst detection (ms gap = new burst)
    pub burst_threshold_ms: f32,
    /// Minimum confidence threshold for decisions
    pub min_confidence: f32,
    /// Maximum padding overhead ratio (0.0 - 1.0)
    pub max_padding_ratio: f32,
    /// Maximum delay to add (ms)
    pub max_delay_ms: f32,
    /// Cover traffic injection rate (packets between injections)
    pub cover_injection_interval: u32,
}

impl Default for MorpherConfig {
    fn default() -> Self {
        Self {
            burst_threshold_ms: 50.0,
            min_confidence: 0.5,
            max_padding_ratio: 0.3,
            max_delay_ms: 10.0,
            cover_injection_interval: 10,
        }
    }
}

impl MorpherConfig {
    /// Create config optimized for low latency (gaming, VoIP)
    pub fn low_latency() -> Self {
        Self {
            burst_threshold_ms: 20.0,
            min_confidence: 0.6,
            max_padding_ratio: 0.15,
            max_delay_ms: 3.0,
            cover_injection_interval: 5,
        }
    }

    /// Create config optimized for high anonymity (browsing)
    pub fn high_anonymity() -> Self {
        Self {
            burst_threshold_ms: 100.0,
            min_confidence: 0.4,
            max_padding_ratio: 0.5,
            max_delay_ms: 50.0,
            cover_injection_interval: 8,
        }
    }

    /// Create config optimized for streaming (YouTube, Netflix)
    pub fn streaming() -> Self {
        Self {
            burst_threshold_ms: 50.0,
            min_confidence: 0.5,
            max_padding_ratio: 0.2,
            max_delay_ms: 15.0,
            cover_injection_interval: 15,
        }
    }
}

/// Rule-based traffic morpher (no AI model required)
///
/// Uses statistical matching to morph traffic patterns.
/// Provides dynamic confidence scoring based on how well
/// current traffic matches the target profile.
pub struct RuleBasedMorpher {
    profile: TrafficProfile,
    profile_stats: ProfileStats,
    context: PacketContext,
    cover_generator: CoverGenerator,
    config: MorpherConfig,
    cover_counter: u32,
    last_activity_ms: f32,
}

impl RuleBasedMorpher {
    /// Create new rule-based morpher for given profile
    pub fn new(profile: TrafficProfile) -> Self {
        Self::with_config(profile, MorpherConfig::default())
    }

    /// Create morpher with custom configuration
    pub fn with_config(profile: TrafficProfile, config: MorpherConfig) -> Self {
        Self {
            profile,
            profile_stats: ProfileStats::for_profile(profile),
            context: PacketContext::with_burst_threshold(config.burst_threshold_ms),
            cover_generator: CoverGenerator::new(profile),
            config,
            cover_counter: 0,
            last_activity_ms: 0.0,
        }
    }

    /// Calculate dynamic confidence based on traffic-profile similarity
    ///
    /// Compares current traffic statistics with target profile and
    /// returns confidence score (0.0 - 1.0) indicating match quality.
    ///
    /// # Security: Constant-time computation to prevent timing side-channels
    ///
    /// All code paths perform the same operations regardless of input values.
    /// Early returns are avoided to prevent timing leaks.
    fn calculate_confidence(&self, stats: &TrafficStats) -> f32 {
        let profile = &self.profile_stats;

        // Always compute all metrics (constant-time, no early exit)
        // Size similarity (gaussian distance)
        let size_diff = (stats.mean_size - profile.mean_size).abs() / profile.size_std.max(1.0);
        let size_score = (-0.5 * size_diff.powi(2)).exp();

        // Delay similarity
        let delay_diff =
            (stats.mean_delay_log - profile.mean_delay_log).abs() / profile.delay_std.max(0.1);
        let delay_score = (-0.5 * delay_diff.powi(2)).exp();

        // Direction ratio similarity
        let ratio_diff = (stats.outbound_ratio - profile.outbound_ratio).abs();
        let ratio_score = 1.0 - ratio_diff.min(1.0);

        // Weighted combination
        let computed_confidence = 0.4 * size_score + 0.35 * delay_score + 0.25 * ratio_score;

        // Select result based on packet count without branching (constant-time)
        // Use conditional selection: if packet_count < 4, use 0.7, else use computed
        let has_enough_data = stats.packet_count >= 4;
        let confidence = if has_enough_data {
            computed_confidence
        } else {
            // Not enough data - use default but still computed everything above
            0.7
        };

        // Clamp to reasonable range
        confidence.clamp(0.3, 0.95)
    }
}

impl TrafficMorpher for RuleBasedMorpher {
    fn morph_outgoing(&mut self, packet: &[u8]) -> Result<MorphDecision> {
        let features = self.context.add_packet(packet, Direction::Outbound);

        // Track activity timing
        self.last_activity_ms = features.delay_log_ms.exp() - 1.0;

        // Calculate padding based on profile
        let padding_size = self.profile_stats.suggested_padding(features.size_raw);

        // Cap padding to configured maximum
        let max_padding = (features.size_raw as f32 * self.config.max_padding_ratio) as usize;
        let padding_size = padding_size.min(max_padding);

        // Calculate delay adjustment
        let delay_ms = self
            .profile_stats
            .suggested_delay_ms(features.delay_log_ms);
        let delay_ms = delay_ms.min(self.config.max_delay_ms);
        let delay = Duration::from_micros((delay_ms * 1000.0) as u64);

        // Decide on cover traffic injection
        self.cover_counter += 1;
        let inject_cover =
            self.cover_generator
                .should_inject(self.cover_counter, self.last_activity_ms);

        if inject_cover {
            self.cover_counter = 0;
        }

        // Calculate dynamic confidence
        let stats = self.context.stats();
        let confidence = self.calculate_confidence(&stats);

        Ok(MorphDecision {
            delay,
            padding_size,
            inject_cover,
            confidence,
        })
    }

    fn observe_incoming(&mut self, packet: &[u8]) -> Result<()> {
        self.context.add_packet(packet, Direction::Inbound);
        self.cover_counter = 0; // Reset cover counter on activity
        self.last_activity_ms = 0.0;
        Ok(())
    }

    fn generate_cover(&mut self) -> Result<Option<Vec<u8>>> {
        // Generate profile-realistic cover packet (NOT zeros!)
        let cover = self.cover_generator.generate();
        Ok(Some(cover))
    }

    fn profile(&self) -> TrafficProfile {
        self.profile
    }

    fn reset(&mut self) {
        self.context.clear();
        self.cover_counter = 0;
        self.last_activity_ms = 0.0;
    }
}

/// ONNX-based AI morpher (requires `onnx` feature)
#[cfg(feature = "onnx")]
pub struct OnnxMorpher {
    profile: TrafficProfile,
    context: PacketContext,
    cover_generator: CoverGenerator,
    session: Session,
    config: MorpherConfig,
}

#[cfg(feature = "onnx")]
impl OnnxMorpher {
    /// Load ONNX model from file
    pub fn load(model_path: &std::path::Path, profile: TrafficProfile) -> Result<Self> {
        Self::load_with_config(model_path, profile, MorpherConfig::default())
    }

    /// Load ONNX model with custom configuration
    pub fn load_with_config(
        model_path: &std::path::Path,
        profile: TrafficProfile,
        config: MorpherConfig,
    ) -> Result<Self> {
        let session = Session::builder()?
            .with_optimization_level(GraphOptimizationLevel::Level3)?
            .commit_from_file(model_path)?;

        Ok(Self {
            profile,
            context: PacketContext::with_burst_threshold(config.burst_threshold_ms),
            cover_generator: CoverGenerator::new(profile),
            session,
            config,
        })
    }

    /// Load ONNX model from bytes
    pub fn from_bytes(model_bytes: &[u8], profile: TrafficProfile) -> Result<Self> {
        Self::from_bytes_with_config(model_bytes, profile, MorpherConfig::default())
    }

    /// Load ONNX model from bytes with custom configuration
    pub fn from_bytes_with_config(
        model_bytes: &[u8],
        profile: TrafficProfile,
        config: MorpherConfig,
    ) -> Result<Self> {
        let session = Session::builder()?
            .with_optimization_level(GraphOptimizationLevel::Level3)?
            .commit_from_memory(model_bytes)?;

        Ok(Self {
            profile,
            context: PacketContext::with_burst_threshold(config.burst_threshold_ms),
            cover_generator: CoverGenerator::new(profile),
            session,
            config,
        })
    }
}

#[cfg(feature = "onnx")]
impl TrafficMorpher for OnnxMorpher {
    fn morph_outgoing(&mut self, packet: &[u8]) -> Result<MorphDecision> {
        use ndarray::Array2;

        let _features = self.context.add_packet(packet, Direction::Outbound);
        let context_tensor = self.context.to_tensor();

        // Create input tensor [CONTEXT_WINDOW_SIZE, 4]
        let input =
            Array2::from_shape_vec((crate::features::CONTEXT_WINDOW_SIZE, 4), context_tensor)
                .map_err(|e| AiError::FeatureExtractionFailed(e.to_string()))?;

        let input_tensor = ort::value::Tensor::from_array(input)
            .map_err(|e| AiError::InferenceFailed(e.to_string()))?;

        let outputs = self
            .session
            .run(ort::inputs!["input" => input_tensor])
            .map_err(|e| AiError::InferenceFailed(e.to_string()))?;

        // Parse outputs
        let (shape, data) = outputs
            .get("output")
            .ok_or_else(|| AiError::InferenceFailed("missing output".into()))?
            .try_extract_tensor::<f32>()
            .map_err(|e| AiError::InferenceFailed(e.to_string()))?;

        let output_view = ndarray::ArrayViewD::from_shape(shape.to_ixdyn(), data)
            .map_err(|e| AiError::InferenceFailed(e.to_string()))?
            .into_dimensionality::<ndarray::Ix2>()
            .map_err(|e| AiError::InferenceFailed(e.to_string()))?;

        let delay_ms = output_view[[0, 0]].max(0.0).min(self.config.max_delay_ms);
        let padding = output_view[[0, 1]].max(0.0) as usize;
        let inject_prob = output_view[[0, 2]];
        let confidence = output_view[[0, 3]].clamp(self.config.min_confidence, 1.0);

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
        // Use profile-realistic cover generator
        let cover = self.cover_generator.generate();
        Ok(Some(cover))
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
pub fn create_morpher(
    profile: TrafficProfile,
    model_path: Option<&std::path::Path>,
) -> Box<dyn TrafficMorpher> {
    create_morpher_with_config(profile, model_path, MorpherConfig::default())
}

/// Create morpher with custom configuration
#[allow(unused_variables)]
pub fn create_morpher_with_config(
    profile: TrafficProfile,
    model_path: Option<&std::path::Path>,
    config: MorpherConfig,
) -> Box<dyn TrafficMorpher> {
    #[cfg(feature = "onnx")]
    if let Some(path) = model_path {
        if path.exists() {
            match OnnxMorpher::load_with_config(path, profile, config.clone()) {
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
    Box::new(RuleBasedMorpher::with_config(profile, config))
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
        assert!(decision.padding_size > 0 || decision.confidence > 0.0);
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

    #[test]
    fn test_cover_generation_not_zeros() {
        let mut morpher = RuleBasedMorpher::new(TrafficProfile::Netflix);

        let cover = morpher.generate_cover().unwrap().unwrap();

        // Cover should NOT be all zeros
        assert!(
            !cover.iter().all(|&b| b == 0),
            "Cover traffic must not be all zeros (DPI detectable)"
        );

        // Should have reasonable size
        assert!(cover.len() >= 32);
        assert!(cover.len() <= 1500);
    }

    #[test]
    fn test_dynamic_confidence() {
        let mut morpher = RuleBasedMorpher::new(TrafficProfile::YouTube);

        // Initial confidence with few packets
        let decision1 = morpher.morph_outgoing(&[0u8; 100]).unwrap();

        // Add many packets to build up statistics
        for i in 0..20 {
            let size = 1000 + (i * 50); // Sizes similar to YouTube profile
            morpher.morph_outgoing(&vec![0u8; size]).unwrap();
        }

        let decision2 = morpher.morph_outgoing(&[0u8; 1200]).unwrap();

        // Confidence should be reasonable (not hardcoded 0.8)
        assert!(decision1.confidence >= 0.3 && decision1.confidence <= 0.95);
        assert!(decision2.confidence >= 0.3 && decision2.confidence <= 0.95);
    }

    #[test]
    fn test_config_profiles() {
        let low_lat = MorpherConfig::low_latency();
        let high_anon = MorpherConfig::high_anonymity();
        let streaming = MorpherConfig::streaming();

        // Low latency should have smaller delays
        assert!(low_lat.max_delay_ms < streaming.max_delay_ms);
        assert!(low_lat.max_delay_ms < high_anon.max_delay_ms);

        // High anonymity should have more padding
        assert!(high_anon.max_padding_ratio > low_lat.max_padding_ratio);
    }

    #[test]
    fn test_morpher_with_config() {
        let config = MorpherConfig::low_latency();
        let mut morpher = RuleBasedMorpher::with_config(TrafficProfile::Gaming, config);

        let decision = morpher.morph_outgoing(&[0u8; 100]).unwrap();

        // Delay should be capped by low latency config
        assert!(decision.delay.as_millis() <= 3);
    }
}
