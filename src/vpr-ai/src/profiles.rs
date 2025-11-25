//! Traffic profile definitions for morphing targets
//!
//! Each profile defines the statistical characteristics of a legitimate
//! traffic pattern that we want to emulate.

use crate::TrafficProfile;

/// Statistical profile of a traffic type
#[derive(Debug, Clone)]
pub struct ProfileStats {
    /// Profile name
    pub name: TrafficProfile,
    /// Target mean packet size
    pub mean_size: f32,
    /// Target packet size standard deviation
    pub size_std: f32,
    /// Target mean inter-packet delay (log ms)
    pub mean_delay_log: f32,
    /// Target delay standard deviation
    pub delay_std: f32,
    /// Typical outbound/total ratio
    pub outbound_ratio: f32,
    /// Common packet sizes (for bucket padding)
    pub common_sizes: &'static [usize],
    /// Typical burst lengths
    pub burst_lengths: (usize, usize), // (min, max)
}

impl ProfileStats {
    /// Get profile stats for a given profile type
    pub fn for_profile(profile: TrafficProfile) -> Self {
        match profile {
            TrafficProfile::YouTube => YOUTUBE_PROFILE,
            TrafficProfile::Zoom => ZOOM_PROFILE,
            TrafficProfile::Gaming => GAMING_PROFILE,
            TrafficProfile::Browsing => BROWSING_PROFILE,
            TrafficProfile::Netflix => NETFLIX_PROFILE,
        }
    }

    /// Calculate how much padding to add to match this profile
    pub fn suggested_padding(&self, current_size: usize) -> usize {
        // Find nearest common size that's >= current
        for &target in self.common_sizes {
            if target >= current_size {
                return target - current_size;
            }
        }
        // If larger than all common sizes, pad to nearest 64 bytes
        let aligned = (current_size + 63) & !63;
        aligned - current_size
    }

    /// Calculate suggested delay adjustment
    pub fn suggested_delay_ms(&self, current_delay_log: f32) -> f32 {
        // If current delay is too low, add some delay
        if current_delay_log < self.mean_delay_log - self.delay_std {
            let target = self.mean_delay_log - self.delay_std * 0.5;
            let target_ms = target.exp() - 1.0;
            let current_ms = current_delay_log.exp() - 1.0;
            (target_ms - current_ms).max(0.0)
        } else {
            0.0
        }
    }
}

/// YouTube 4K streaming profile
/// Characteristics: Large packets, bursty downloads, small acks
pub const YOUTUBE_PROFILE: ProfileStats = ProfileStats {
    name: TrafficProfile::YouTube,
    mean_size: 1100.0,
    size_std: 400.0,
    mean_delay_log: 2.5, // ~11ms average
    delay_std: 1.5,
    outbound_ratio: 0.15, // Mostly inbound (video data)
    common_sizes: &[64, 128, 576, 1200, 1400, 1500],
    burst_lengths: (5, 30),
};

/// Zoom video call profile
/// Characteristics: Bidirectional, regular intervals, medium packets
pub const ZOOM_PROFILE: ProfileStats = ProfileStats {
    name: TrafficProfile::Zoom,
    mean_size: 800.0,
    size_std: 300.0,
    mean_delay_log: 2.0, // ~6ms average (for 30fps video)
    delay_std: 0.8,
    outbound_ratio: 0.45, // Nearly symmetric
    common_sizes: &[64, 200, 400, 800, 1200],
    burst_lengths: (2, 8),
};

/// Online gaming (FPS) profile
/// Characteristics: Small packets, very low latency, regular
pub const GAMING_PROFILE: ProfileStats = ProfileStats {
    name: TrafficProfile::Gaming,
    mean_size: 150.0,
    size_std: 80.0,
    mean_delay_log: 1.5, // ~3.5ms average (high tick rate)
    delay_std: 0.5,
    outbound_ratio: 0.50, // Symmetric
    common_sizes: &[32, 64, 128, 256, 512],
    burst_lengths: (1, 4),
};

/// Web browsing profile
/// Characteristics: Bursty, variable sizes, long pauses
pub const BROWSING_PROFILE: ProfileStats = ProfileStats {
    name: TrafficProfile::Browsing,
    mean_size: 600.0,
    size_std: 500.0,
    mean_delay_log: 3.5, // ~32ms average (includes think time)
    delay_std: 2.0,
    outbound_ratio: 0.25, // Mostly downloads
    common_sizes: &[64, 256, 512, 1024, 1400, 1500],
    burst_lengths: (3, 20),
};

/// Netflix streaming profile
/// Similar to YouTube but with different packet patterns
pub const NETFLIX_PROFILE: ProfileStats = ProfileStats {
    name: TrafficProfile::Netflix,
    mean_size: 1200.0,
    size_std: 350.0,
    mean_delay_log: 2.3, // ~9ms average
    delay_std: 1.2,
    outbound_ratio: 0.10, // Almost all inbound
    common_sizes: &[64, 576, 1200, 1400, 1500],
    burst_lengths: (10, 50),
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_padding() {
        let youtube = ProfileStats::for_profile(TrafficProfile::YouTube);

        assert_eq!(youtube.suggested_padding(50), 14); // -> 64
        assert_eq!(youtube.suggested_padding(64), 0); // already aligned
        assert_eq!(youtube.suggested_padding(100), 28); // -> 128
        assert_eq!(youtube.suggested_padding(1400), 0); // exactly on boundary
    }

    #[test]
    fn test_profile_delay() {
        let gaming = ProfileStats::for_profile(TrafficProfile::Gaming);

        // Very fast packet should be delayed
        let delay = gaming.suggested_delay_ms(0.5);
        assert!(delay > 0.0);

        // Normal speed packet should not be delayed
        let delay = gaming.suggested_delay_ms(1.5);
        assert_eq!(delay, 0.0);
    }

    #[test]
    fn test_all_profiles_exist() {
        // Ensure all TrafficProfile variants have a corresponding ProfileStats
        let _ = ProfileStats::for_profile(TrafficProfile::YouTube);
        let _ = ProfileStats::for_profile(TrafficProfile::Zoom);
        let _ = ProfileStats::for_profile(TrafficProfile::Gaming);
        let _ = ProfileStats::for_profile(TrafficProfile::Browsing);
        let _ = ProfileStats::for_profile(TrafficProfile::Netflix);
    }

    #[test]
    fn test_youtube_profile_values() {
        let profile = ProfileStats::for_profile(TrafficProfile::YouTube);
        assert!(matches!(profile.name, TrafficProfile::YouTube));
        assert!((profile.mean_size - 1100.0).abs() < 0.01);
        assert!((profile.outbound_ratio - 0.15).abs() < 0.01);
        assert!(!profile.common_sizes.is_empty());
        assert!(profile.burst_lengths.0 < profile.burst_lengths.1);
    }

    #[test]
    fn test_zoom_profile_values() {
        let profile = ProfileStats::for_profile(TrafficProfile::Zoom);
        assert!(matches!(profile.name, TrafficProfile::Zoom));
        assert!((profile.mean_size - 800.0).abs() < 0.01);
        // Zoom is nearly symmetric (bidirectional video call)
        assert!((profile.outbound_ratio - 0.45).abs() < 0.01);
    }

    #[test]
    fn test_gaming_profile_values() {
        let profile = ProfileStats::for_profile(TrafficProfile::Gaming);
        assert!(matches!(profile.name, TrafficProfile::Gaming));
        // Gaming has small packets
        assert!(profile.mean_size < 200.0);
        // Gaming is symmetric
        assert!((profile.outbound_ratio - 0.50).abs() < 0.01);
        // Gaming has short bursts
        assert!(profile.burst_lengths.1 <= 10);
    }

    #[test]
    fn test_browsing_profile_values() {
        let profile = ProfileStats::for_profile(TrafficProfile::Browsing);
        assert!(matches!(profile.name, TrafficProfile::Browsing));
        // Browsing has high delay variance (includes think time)
        assert!(profile.delay_std > 1.5);
        // Browsing is mostly downloads
        assert!(profile.outbound_ratio < 0.3);
    }

    #[test]
    fn test_netflix_profile_values() {
        let profile = ProfileStats::for_profile(TrafficProfile::Netflix);
        assert!(matches!(profile.name, TrafficProfile::Netflix));
        // Netflix is almost all inbound
        assert!(profile.outbound_ratio < 0.15);
        // Netflix has long bursts
        assert!(profile.burst_lengths.1 >= 30);
    }

    #[test]
    fn test_profile_stats_clone() {
        let original = ProfileStats::for_profile(TrafficProfile::Gaming);
        let cloned = original.clone();
        assert!((original.mean_size - cloned.mean_size).abs() < 0.001);
        assert!((original.outbound_ratio - cloned.outbound_ratio).abs() < 0.001);
    }

    #[test]
    fn test_profile_stats_debug() {
        let profile = ProfileStats::for_profile(TrafficProfile::YouTube);
        let debug = format!("{:?}", profile);
        assert!(debug.contains("ProfileStats"));
        assert!(debug.contains("YouTube"));
    }

    #[test]
    fn test_padding_larger_than_all_common_sizes() {
        let gaming = ProfileStats::for_profile(TrafficProfile::Gaming);
        // Gaming max common size is 512
        let padding = gaming.suggested_padding(600);
        // Should pad to nearest 64: 640 - 600 = 40
        assert_eq!(padding, 40);
    }

    #[test]
    fn test_padding_zero_size() {
        let profile = ProfileStats::for_profile(TrafficProfile::YouTube);
        // Zero-size packet should pad to smallest common size (64)
        let padding = profile.suggested_padding(0);
        assert_eq!(padding, 64);
    }

    #[test]
    fn test_padding_exact_common_size() {
        let profile = ProfileStats::for_profile(TrafficProfile::Netflix);
        // Check that exact common sizes return 0 padding
        for &size in profile.common_sizes {
            assert_eq!(profile.suggested_padding(size), 0, "size {} should have 0 padding", size);
        }
    }

    #[test]
    fn test_delay_high_current_delay() {
        let profile = ProfileStats::for_profile(TrafficProfile::Browsing);
        // Very high delay (already slow) should not be delayed further
        let delay = profile.suggested_delay_ms(10.0);
        assert_eq!(delay, 0.0);
    }

    #[test]
    fn test_delay_at_threshold() {
        let profile = ProfileStats::for_profile(TrafficProfile::Gaming);
        // At exactly mean - std, should not delay
        let threshold = profile.mean_delay_log - profile.delay_std;
        let delay = profile.suggested_delay_ms(threshold);
        assert_eq!(delay, 0.0);
    }

    #[test]
    fn test_delay_just_below_threshold() {
        let profile = ProfileStats::for_profile(TrafficProfile::Gaming);
        // Just below threshold should add some delay
        let threshold = profile.mean_delay_log - profile.delay_std - 0.1;
        let delay = profile.suggested_delay_ms(threshold);
        assert!(delay > 0.0);
    }

    #[test]
    fn test_common_sizes_are_sorted() {
        // All profiles should have common_sizes in ascending order
        for &profile_type in &[
            TrafficProfile::YouTube,
            TrafficProfile::Zoom,
            TrafficProfile::Gaming,
            TrafficProfile::Browsing,
            TrafficProfile::Netflix,
        ] {
            let profile = ProfileStats::for_profile(profile_type);
            for i in 1..profile.common_sizes.len() {
                assert!(
                    profile.common_sizes[i] > profile.common_sizes[i - 1],
                    "{:?} common_sizes not sorted at index {}",
                    profile_type,
                    i
                );
            }
        }
    }

    #[test]
    fn test_burst_lengths_valid() {
        // All profiles should have min <= max
        for &profile_type in &[
            TrafficProfile::YouTube,
            TrafficProfile::Zoom,
            TrafficProfile::Gaming,
            TrafficProfile::Browsing,
            TrafficProfile::Netflix,
        ] {
            let profile = ProfileStats::for_profile(profile_type);
            assert!(
                profile.burst_lengths.0 <= profile.burst_lengths.1,
                "{:?} burst_lengths min > max",
                profile_type
            );
            assert!(profile.burst_lengths.0 > 0, "{:?} burst min is 0", profile_type);
        }
    }

    #[test]
    fn test_profile_constants_accessible() {
        // Direct access to constants
        assert!((YOUTUBE_PROFILE.mean_size - 1100.0).abs() < 0.01);
        assert!((ZOOM_PROFILE.mean_size - 800.0).abs() < 0.01);
        assert!((GAMING_PROFILE.mean_size - 150.0).abs() < 0.01);
        assert!((BROWSING_PROFILE.mean_size - 600.0).abs() < 0.01);
        assert!((NETFLIX_PROFILE.mean_size - 1200.0).abs() < 0.01);
    }

    #[test]
    fn test_outbound_ratio_range() {
        // All outbound ratios should be in [0, 1]
        for &profile_type in &[
            TrafficProfile::YouTube,
            TrafficProfile::Zoom,
            TrafficProfile::Gaming,
            TrafficProfile::Browsing,
            TrafficProfile::Netflix,
        ] {
            let profile = ProfileStats::for_profile(profile_type);
            assert!(
                profile.outbound_ratio >= 0.0 && profile.outbound_ratio <= 1.0,
                "{:?} outbound_ratio out of range: {}",
                profile_type,
                profile.outbound_ratio
            );
        }
    }
}
