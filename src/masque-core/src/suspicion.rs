//! Suspicion score tracker for adaptive stealth decisions (TLS canary, padding, cover).
//!
//! Maintains a bounded score [0.0, 100.0], supports event-based bumps with EWMA-like decay,
//! and exposes Prometheus-compatible metrics.

use std::sync::{
    atomic::{AtomicU32, Ordering},
    Mutex,
};
use std::time::{Duration, Instant};

const SCALE: f64 = 100.0;
const ONE: u32 = 10_000; // 100.00 scaled by 100

/// Default decay half-life (in seconds)
const DEFAULT_HALF_LIFE: f64 = 30.0;

#[derive(Debug)]
pub struct SuspicionTracker {
    score_milli: AtomicU32,
    last_update: Mutex<Instant>,
    half_life: f64,
}

impl Default for SuspicionTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl SuspicionTracker {
    pub fn new() -> Self {
        Self::with_half_life(DEFAULT_HALF_LIFE)
    }

    pub fn with_half_life(half_life: f64) -> Self {
        Self {
            score_milli: AtomicU32::new(0),
            last_update: Mutex::new(Instant::now()),
            half_life,
        }
    }

    /// Add suspicion weight in range [0, 100].
    pub fn add(&self, weight: f64) {
        self.decay();
        let delta = (weight.clamp(0.0, SCALE) * 100.0) as u32;
        let mut current = self.score_milli.load(Ordering::Relaxed);
        loop {
            let next = (current.saturating_add(delta)).min(ONE);
            match self.score_milli.compare_exchange(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }

    /// Decay score based on elapsed time with exponential half-life.
    pub fn decay(&self) {
        let mut guard = self.last_update.lock().expect("suspicion mutex poisoned");
        let now = Instant::now();
        let elapsed = now.duration_since(*guard);
        if elapsed.is_zero() {
            return;
        }
        *guard = now;
        drop(guard);

        let factor = decay_factor(elapsed, self.half_life);
        let current = self.score_milli.load(Ordering::Relaxed) as f64;
        let decayed = (current * factor).round() as u32;
        self.score_milli.store(decayed.min(ONE), Ordering::Relaxed);
    }

    /// Current score in [0.0, 100.0]
    pub fn current(&self) -> f64 {
        self.decay();
        (self.score_milli.load(Ordering::Relaxed) as f64) / 100.0
    }

    /// Prometheus exposition format
    pub fn prometheus(&self, prefix: &str) -> String {
        format!(
            "# HELP {p}_score Suspicion score (0-100)\n# TYPE {p}_score gauge\n{p}_score {val:.2}\n",
            p = prefix,
            val = self.current()
        )
    }
}

fn decay_factor(elapsed: Duration, half_life: f64) -> f64 {
    if half_life <= 0.0 {
        return 0.0;
    }
    let secs = elapsed.as_secs_f64();
    2f64.powf(-secs / half_life)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suspicion_add_and_decay() {
        let s = SuspicionTracker::with_half_life(1.0);
        s.add(20.0);
        assert!(s.current() >= 19.9);
        std::thread::sleep(Duration::from_millis(1100));
        let decayed = s.current();
        assert!(decayed < 20.0);
    }

    #[test]
    fn suspicion_clamped() {
        let s = SuspicionTracker::new();
        s.add(200.0);
        assert!((s.current() - 100.0).abs() < 0.01);
    }

    #[test]
    fn test_new_tracker() {
        let tracker = SuspicionTracker::new();
        assert!(tracker.current() < 0.01);
    }

    #[test]
    fn test_default_tracker() {
        let tracker = SuspicionTracker::default();
        assert!(tracker.current() < 0.01);
    }

    #[test]
    fn test_with_half_life() {
        let tracker = SuspicionTracker::with_half_life(60.0);
        tracker.add(50.0);
        // Should be close to 50 immediately
        assert!((tracker.current() - 50.0).abs() < 1.0);
    }

    #[test]
    fn test_add_negative_clamped() {
        let tracker = SuspicionTracker::new();
        tracker.add(-10.0);
        // Negative clamped to 0
        assert!(tracker.current() < 0.01);
    }

    #[test]
    fn test_add_multiple() {
        let tracker = SuspicionTracker::new();
        tracker.add(10.0);
        tracker.add(20.0);
        tracker.add(30.0);
        // Should be close to 60 (10 + 20 + 30)
        let current = tracker.current();
        assert!(current >= 55.0 && current <= 65.0);
    }

    #[test]
    fn test_add_up_to_max() {
        let tracker = SuspicionTracker::new();
        for _ in 0..20 {
            tracker.add(50.0);
        }
        // Should cap at 100
        let current = tracker.current();
        assert!((current - 100.0).abs() < 0.01);
    }

    #[test]
    fn test_decay_explicit() {
        let tracker = SuspicionTracker::with_half_life(0.5);
        tracker.add(80.0);
        std::thread::sleep(Duration::from_millis(600));
        tracker.decay();
        // After ~1 half-life, should be around 40
        let current = tracker.current();
        assert!(current < 60.0);
    }

    #[test]
    fn test_decay_factor_zero_half_life() {
        let factor = decay_factor(Duration::from_secs(1), 0.0);
        assert_eq!(factor, 0.0);
    }

    #[test]
    fn test_decay_factor_negative_half_life() {
        let factor = decay_factor(Duration::from_secs(1), -5.0);
        assert_eq!(factor, 0.0);
    }

    #[test]
    fn test_decay_factor_normal() {
        // After 1 half-life, factor should be 0.5
        let factor = decay_factor(Duration::from_secs(30), 30.0);
        assert!((factor - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_decay_factor_two_half_lives() {
        // After 2 half-lives, factor should be 0.25
        let factor = decay_factor(Duration::from_secs(60), 30.0);
        assert!((factor - 0.25).abs() < 0.01);
    }

    #[test]
    fn test_prometheus_format() {
        let tracker = SuspicionTracker::new();
        tracker.add(42.0);
        let prom = tracker.prometheus("test");
        assert!(prom.contains("# HELP test_score"));
        assert!(prom.contains("# TYPE test_score gauge"));
        assert!(prom.contains("test_score"));
    }

    #[test]
    fn test_prometheus_prefix() {
        let tracker = SuspicionTracker::new();
        let prom = tracker.prometheus("myprefix");
        assert!(prom.contains("myprefix_score"));
    }

    #[test]
    fn test_current_triggers_decay() {
        let tracker = SuspicionTracker::with_half_life(0.1);
        tracker.add(50.0);
        std::thread::sleep(Duration::from_millis(150));
        // current() should trigger decay
        let val = tracker.current();
        assert!(val < 50.0);
    }

    #[test]
    fn test_tracker_debug() {
        let tracker = SuspicionTracker::new();
        let debug_str = format!("{:?}", tracker);
        assert!(debug_str.contains("SuspicionTracker"));
    }
}
