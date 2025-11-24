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
}
