//! Active Probe Protection
//!
//! Detects and blocks active probing attacks (protocol probing, replay, scanning).
//! Uses PQ challenge-response and timing analysis to identify probes.

use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// Default ban duration for detected probes
pub const DEFAULT_BAN_DURATION: Duration = Duration::from_secs(300); // 5 minutes

/// Maximum failed attempts before ban
pub const MAX_FAILED_ATTEMPTS: u32 = 3;

/// Challenge validity duration
pub const CHALLENGE_VALIDITY: Duration = Duration::from_secs(30);

/// Probe detection result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeDetection {
    /// Connection appears legitimate
    Legitimate,
    /// Potential probe detected (soft block)
    Suspicious(String),
    /// Definite probe (hard block)
    Blocked(String),
}

/// Probe protection configuration
#[derive(Debug, Clone)]
pub struct ProbeProtectionConfig {
    /// Enable challenge-response verification
    pub challenge_enabled: bool,
    /// Challenge difficulty (bytes of leading zeros required)
    pub challenge_difficulty: u8,
    /// Ban duration for detected probes
    pub ban_duration: Duration,
    /// Maximum failed attempts before ban
    pub max_failed_attempts: u32,
    /// Enable timing analysis
    pub timing_analysis: bool,
    /// Minimum handshake time (too fast = probe)
    pub min_handshake_time: Duration,
    /// Maximum handshake time (too slow = timeout)
    pub max_handshake_time: Duration,
}

impl Default for ProbeProtectionConfig {
    fn default() -> Self {
        Self {
            challenge_enabled: true,
            challenge_difficulty: 2, // 2 leading zero bytes
            ban_duration: DEFAULT_BAN_DURATION,
            max_failed_attempts: MAX_FAILED_ATTEMPTS,
            timing_analysis: true,
            min_handshake_time: Duration::from_millis(50),
            max_handshake_time: Duration::from_secs(10),
        }
    }
}

/// Tracking entry for an IP
#[derive(Debug, Clone)]
struct IpEntry {
    failed_attempts: u32,
    last_attempt: Instant,
    banned_until: Option<Instant>,
    challenges_issued: u32,
}

impl Default for IpEntry {
    fn default() -> Self {
        Self {
            failed_attempts: 0,
            last_attempt: Instant::now(),
            banned_until: None,
            challenges_issued: 0,
        }
    }
}

/// Probe protection metrics
#[derive(Debug, Default)]
pub struct ProbeMetrics {
    /// Total connections checked
    pub connections_checked: AtomicU64,
    /// Connections blocked as probes
    pub probes_blocked: AtomicU64,
    /// Suspicious connections detected
    pub suspicious_detected: AtomicU64,
    /// Challenges issued
    pub challenges_issued: AtomicU64,
    /// Challenges passed
    pub challenges_passed: AtomicU64,
    /// Currently banned IPs
    pub banned_ips: AtomicU64,
}

impl ProbeMetrics {
    pub fn snapshot(&self) -> ProbeMetricsSnapshot {
        ProbeMetricsSnapshot {
            connections_checked: self.connections_checked.load(Ordering::Relaxed),
            probes_blocked: self.probes_blocked.load(Ordering::Relaxed),
            suspicious_detected: self.suspicious_detected.load(Ordering::Relaxed),
            challenges_issued: self.challenges_issued.load(Ordering::Relaxed),
            challenges_passed: self.challenges_passed.load(Ordering::Relaxed),
            banned_ips: self.banned_ips.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ProbeMetricsSnapshot {
    pub connections_checked: u64,
    pub probes_blocked: u64,
    pub suspicious_detected: u64,
    pub challenges_issued: u64,
    pub challenges_passed: u64,
    pub banned_ips: u64,
}

/// Challenge for proof-of-work verification
#[derive(Debug, Clone)]
pub struct Challenge {
    /// Random nonce
    pub nonce: [u8; 32],
    /// Required difficulty (leading zero bytes)
    pub difficulty: u8,
    /// When challenge was issued
    pub issued_at: Instant,
    /// Challenge expires at
    pub expires_at: Instant,
}

impl Challenge {
    /// Generate new challenge
    pub fn new(difficulty: u8) -> Self {
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);

        let now = Instant::now();
        Self {
            nonce,
            difficulty,
            issued_at: now,
            expires_at: now + CHALLENGE_VALIDITY,
        }
    }

    /// Verify challenge response
    pub fn verify(&self, response: &[u8; 32]) -> bool {
        // Check expiration
        if Instant::now() > self.expires_at {
            return false;
        }

        // Compute hash of nonce + response
        let mut hasher = Sha256::new();
        hasher.update(&self.nonce);
        hasher.update(response);
        let hash = hasher.finalize();

        // Check leading zero bytes
        for i in 0..self.difficulty as usize {
            if i >= hash.len() || hash[i] != 0 {
                return false;
            }
        }
        true
    }

    /// Serialize challenge for transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(33);
        buf.extend_from_slice(&self.nonce);
        buf.push(self.difficulty);
        buf
    }

    /// Deserialize challenge
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() != 33 {
            return None;
        }
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&data[..32]);
        let difficulty = data[32];

        let now = Instant::now();
        Some(Self {
            nonce,
            difficulty,
            issued_at: now,
            expires_at: now + CHALLENGE_VALIDITY,
        })
    }
}

/// Probe protection engine
pub struct ProbeProtector {
    config: ProbeProtectionConfig,
    ip_tracking: RwLock<HashMap<IpAddr, IpEntry>>,
    pending_challenges: RwLock<HashMap<[u8; 32], Challenge>>,
    metrics: ProbeMetrics,
}

impl ProbeProtector {
    /// Create new probe protector
    pub fn new(config: ProbeProtectionConfig) -> Self {
        Self {
            config,
            ip_tracking: RwLock::new(HashMap::new()),
            pending_challenges: RwLock::new(HashMap::new()),
            metrics: ProbeMetrics::default(),
        }
    }

    /// Check if IP is allowed to connect
    pub fn check_ip(&self, ip: IpAddr) -> ProbeDetection {
        self.metrics
            .connections_checked
            .fetch_add(1, Ordering::Relaxed);

        let tracking = self.ip_tracking.read().unwrap();
        if let Some(entry) = tracking.get(&ip) {
            // Check if banned
            if let Some(banned_until) = entry.banned_until {
                if Instant::now() < banned_until {
                    self.metrics.probes_blocked.fetch_add(1, Ordering::Relaxed);
                    return ProbeDetection::Blocked(format!("IP {} is banned", ip));
                }
            }

            // Check failed attempts
            if entry.failed_attempts >= self.config.max_failed_attempts {
                self.metrics
                    .suspicious_detected
                    .fetch_add(1, Ordering::Relaxed);
                return ProbeDetection::Suspicious(format!(
                    "IP {} has {} failed attempts",
                    ip, entry.failed_attempts
                ));
            }
        }

        ProbeDetection::Legitimate
    }

    /// Record a failed connection attempt
    pub fn record_failure(&self, ip: IpAddr) {
        let mut tracking = self.ip_tracking.write().unwrap();
        let entry = tracking.entry(ip).or_default();

        entry.failed_attempts += 1;
        entry.last_attempt = Instant::now();

        if entry.failed_attempts >= self.config.max_failed_attempts {
            entry.banned_until = Some(Instant::now() + self.config.ban_duration);
            self.metrics.banned_ips.fetch_add(1, Ordering::Relaxed);
            warn!(%ip, attempts = entry.failed_attempts, "IP banned due to failed attempts");
        }
    }

    /// Record a successful connection
    pub fn record_success(&self, ip: IpAddr) {
        let mut tracking = self.ip_tracking.write().unwrap();
        if let Some(entry) = tracking.get_mut(&ip) {
            // Reset failed attempts on success
            entry.failed_attempts = 0;
            entry.banned_until = None;
        }
    }

    /// Issue a challenge for an IP
    pub fn issue_challenge(&self, _ip: IpAddr) -> Challenge {
        self.metrics
            .challenges_issued
            .fetch_add(1, Ordering::Relaxed);

        let challenge = Challenge::new(self.config.challenge_difficulty);

        let mut pending = self.pending_challenges.write().unwrap();
        pending.insert(challenge.nonce, challenge.clone());

        debug!(difficulty = challenge.difficulty, "Challenge issued");
        challenge
    }

    /// Verify a challenge response
    pub fn verify_challenge(&self, nonce: &[u8; 32], response: &[u8; 32]) -> bool {
        let mut pending = self.pending_challenges.write().unwrap();

        if let Some(challenge) = pending.remove(nonce) {
            if challenge.verify(response) {
                self.metrics
                    .challenges_passed
                    .fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }

        false
    }

    /// Check handshake timing
    pub fn check_timing(&self, handshake_duration: Duration) -> ProbeDetection {
        if !self.config.timing_analysis {
            return ProbeDetection::Legitimate;
        }

        if handshake_duration < self.config.min_handshake_time {
            self.metrics
                .suspicious_detected
                .fetch_add(1, Ordering::Relaxed);
            return ProbeDetection::Suspicious(format!(
                "Handshake too fast: {:?}",
                handshake_duration
            ));
        }

        if handshake_duration > self.config.max_handshake_time {
            return ProbeDetection::Blocked(format!("Handshake timeout: {:?}", handshake_duration));
        }

        ProbeDetection::Legitimate
    }

    /// Get metrics
    pub fn metrics(&self) -> &ProbeMetrics {
        &self.metrics
    }

    /// Cleanup expired entries
    pub fn cleanup(&self) {
        let now = Instant::now();

        // Cleanup IP tracking
        {
            let mut tracking = self.ip_tracking.write().unwrap();
            tracking.retain(|_, entry| {
                // Keep if banned and not expired, or if recently active
                if let Some(banned_until) = entry.banned_until {
                    if now < banned_until {
                        return true;
                    }
                }
                // Keep entries active within last hour
                now.duration_since(entry.last_attempt) < Duration::from_secs(3600)
            });
        }

        // Cleanup expired challenges
        {
            let mut pending = self.pending_challenges.write().unwrap();
            pending.retain(|_, challenge| now < challenge.expires_at);
        }
    }
}

impl Default for ProbeProtector {
    fn default() -> Self {
        Self::new(ProbeProtectionConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))
    }

    #[test]
    fn test_new_ip_is_legitimate() {
        let protector = ProbeProtector::default();
        assert_eq!(protector.check_ip(test_ip()), ProbeDetection::Legitimate);
    }

    #[test]
    fn test_ban_after_failures() {
        let protector = ProbeProtector::new(ProbeProtectionConfig {
            max_failed_attempts: 3,
            ..Default::default()
        });

        let ip = test_ip();

        // First two failures should still be legitimate
        protector.record_failure(ip);
        protector.record_failure(ip);
        assert_eq!(protector.check_ip(ip), ProbeDetection::Legitimate);

        // Third failure should trigger suspicious/ban
        protector.record_failure(ip);

        match protector.check_ip(ip) {
            ProbeDetection::Blocked(_) => (), // Expected
            other => panic!("Expected Blocked, got {:?}", other),
        }
    }

    #[test]
    fn test_success_resets_failures() {
        let protector = ProbeProtector::default();
        let ip = test_ip();

        protector.record_failure(ip);
        protector.record_failure(ip);
        protector.record_success(ip);

        // Should be reset to legitimate
        assert_eq!(protector.check_ip(ip), ProbeDetection::Legitimate);
    }

    #[test]
    fn test_challenge_generation() {
        let protector = ProbeProtector::default();
        let challenge = protector.issue_challenge(test_ip());

        assert_eq!(challenge.nonce.len(), 32);
        assert!(challenge.difficulty > 0);
    }

    #[test]
    fn test_challenge_verification() {
        let challenge = Challenge::new(0); // 0 difficulty = any response works

        // With 0 difficulty, any response should pass
        let response = [0u8; 32];
        assert!(challenge.verify(&response));
    }

    #[test]
    fn test_timing_too_fast() {
        let protector = ProbeProtector::new(ProbeProtectionConfig {
            timing_analysis: true,
            min_handshake_time: Duration::from_millis(100),
            ..Default::default()
        });

        let result = protector.check_timing(Duration::from_millis(10));
        match result {
            ProbeDetection::Suspicious(_) => (),
            other => panic!("Expected Suspicious, got {:?}", other),
        }
    }

    #[test]
    fn test_timing_normal() {
        let protector = ProbeProtector::new(ProbeProtectionConfig {
            timing_analysis: true,
            min_handshake_time: Duration::from_millis(50),
            max_handshake_time: Duration::from_secs(10),
            ..Default::default()
        });

        let result = protector.check_timing(Duration::from_millis(500));
        assert_eq!(result, ProbeDetection::Legitimate);
    }

    #[test]
    fn test_metrics() {
        let protector = ProbeProtector::default();
        let ip = test_ip();

        protector.check_ip(ip);
        protector.issue_challenge(ip);

        let metrics = protector.metrics().snapshot();
        assert_eq!(metrics.connections_checked, 1);
        assert_eq!(metrics.challenges_issued, 1);
    }

    #[test]
    fn test_challenge_serialization() {
        let challenge = Challenge::new(2);
        let bytes = challenge.to_bytes();

        assert_eq!(bytes.len(), 33);

        let restored = Challenge::from_bytes(&bytes).unwrap();
        assert_eq!(restored.nonce, challenge.nonce);
        assert_eq!(restored.difficulty, challenge.difficulty);
    }
}
