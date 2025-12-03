//! Suspicion tracking for probe detection and DPI resistance.

use std::sync::Mutex;

/// Tracks suspicion score for adaptive security measures.
///
/// Score ranges from 0.0 (no suspicion) to 100.0 (maximum suspicion).
/// Higher scores trigger more aggressive countermeasures like:
/// - Disabling canary TLS profiles
/// - Increasing padding
/// - Stricter timing checks
#[derive(Debug, Default)]
pub struct SuspicionTracker {
    score: Mutex<f64>,
}

impl SuspicionTracker {
    /// Create a new tracker with zero suspicion
    pub fn new() -> Self {
        Self {
            score: Mutex::new(0.0),
        }
    }

    /// Add to the suspicion score (clamped to 0.0-100.0)
    pub fn add(&self, delta: f64) {
        if let Ok(mut s) = self.score.lock() {
            *s = (*s + delta).clamp(0.0, 100.0);
        }
    }

    /// Get current suspicion score
    pub fn current(&self) -> f64 {
        self.score.lock().map(|s| *s).unwrap_or(0.0)
    }

    /// Export suspicion score in Prometheus text format
    pub fn prometheus(&self, prefix: &str) -> String {
        let val = self.score.lock().map(|s| *s).unwrap_or(0.0);
        format!("{prefix}_score {{}} {val}\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suspicion_clamped_to_range() {
        let tracker = SuspicionTracker::new();
        tracker.add(150.0);
        assert_eq!(tracker.current(), 100.0);

        tracker.add(-200.0);
        assert_eq!(tracker.current(), 0.0);
    }

    #[test]
    fn suspicion_accumulates() {
        let tracker = SuspicionTracker::new();
        tracker.add(10.0);
        tracker.add(20.0);
        assert_eq!(tracker.current(), 30.0);
    }
}
