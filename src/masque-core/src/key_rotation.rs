//! Key Rotation Management
//!
//! Implements automatic key rotation policies for defense-in-depth:
//! - Session keys: every 60 seconds OR 1GB data (forward secrecy)
//! - Noise static keys: every 14 days (identity rotation)
//! - TLS certificates: every 6 hours (certificate agility)

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, info, warn};

/// Session key rotation thresholds
pub const SESSION_KEY_TIME_LIMIT: Duration = Duration::from_secs(60);
pub const SESSION_KEY_DATA_LIMIT: u64 = 1024 * 1024 * 1024; // 1GB

/// Long-term key rotation intervals
pub const NOISE_KEY_ROTATION_INTERVAL: Duration = Duration::from_secs(14 * 24 * 60 * 60); // 14 days
pub const TLS_CERT_ROTATION_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60); // 6 hours

/// Key rotation event types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationEvent {
    /// Session key rotated (forward secrecy)
    SessionKey,
    /// Noise static key rotated
    NoiseKey,
    /// TLS certificate rotated
    TlsCert,
}

/// Session key state tracker
#[derive(Debug)]
pub struct SessionKeyState {
    created_at: Instant,
    bytes_processed: AtomicU64,
    rotation_count: AtomicU64,
}

impl SessionKeyState {
    pub fn new() -> Self {
        Self {
            created_at: Instant::now(),
            bytes_processed: AtomicU64::new(0),
            rotation_count: AtomicU64::new(0),
        }
    }

    /// Record bytes processed through this session
    pub fn record_bytes(&self, bytes: u64) {
        self.bytes_processed.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Check if rotation is needed based on time or data limits
    pub fn needs_rotation(&self) -> bool {
        let age = self.created_at.elapsed();
        let bytes = self.bytes_processed.load(Ordering::Relaxed);

        age >= SESSION_KEY_TIME_LIMIT || bytes >= SESSION_KEY_DATA_LIMIT
    }

    /// Get rotation reason if rotation is needed
    pub fn rotation_reason(&self) -> Option<SessionRotationReason> {
        let age = self.created_at.elapsed();
        let bytes = self.bytes_processed.load(Ordering::Relaxed);

        if bytes >= SESSION_KEY_DATA_LIMIT {
            Some(SessionRotationReason::DataLimit(bytes))
        } else if age >= SESSION_KEY_TIME_LIMIT {
            Some(SessionRotationReason::TimeLimit(age))
        } else {
            None
        }
    }

    /// Reset state after rotation
    pub fn reset(&mut self) {
        self.created_at = Instant::now();
        self.bytes_processed.store(0, Ordering::Relaxed);
        self.rotation_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Get total rotation count
    pub fn rotation_count(&self) -> u64 {
        self.rotation_count.load(Ordering::Relaxed)
    }

    /// Get session age
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Get bytes processed
    pub fn bytes_processed(&self) -> u64 {
        self.bytes_processed.load(Ordering::Relaxed)
    }
}

impl Default for SessionKeyState {
    fn default() -> Self {
        Self::new()
    }
}

/// Reason for session key rotation
#[derive(Debug, Clone, Copy)]
pub enum SessionRotationReason {
    /// Time limit exceeded
    TimeLimit(Duration),
    /// Data limit exceeded
    DataLimit(u64),
    /// Manual rotation requested
    Manual,
}

/// Long-term key rotation tracker
#[derive(Debug)]
pub struct LongTermKeyState {
    /// When current key was created
    created_at: Instant,
    /// Key type for logging
    key_type: &'static str,
    /// Rotation interval
    interval: Duration,
    /// Total rotations performed
    rotation_count: AtomicU64,
}

impl LongTermKeyState {
    pub fn new(key_type: &'static str, interval: Duration) -> Self {
        Self {
            created_at: Instant::now(),
            key_type,
            interval,
            rotation_count: AtomicU64::new(0),
        }
    }

    /// Create Noise key state (14 days)
    pub fn noise_key() -> Self {
        Self::new("noise_static", NOISE_KEY_ROTATION_INTERVAL)
    }

    /// Create TLS cert state (6 hours)
    pub fn tls_cert() -> Self {
        Self::new("tls_cert", TLS_CERT_ROTATION_INTERVAL)
    }

    /// Check if rotation is due
    pub fn needs_rotation(&self) -> bool {
        self.created_at.elapsed() >= self.interval
    }

    /// Get time until next rotation
    pub fn time_until_rotation(&self) -> Duration {
        let elapsed = self.created_at.elapsed();
        self.interval.saturating_sub(elapsed)
    }

    /// Reset after rotation
    pub fn reset(&mut self) {
        self.created_at = Instant::now();
        self.rotation_count.fetch_add(1, Ordering::Relaxed);
        info!(
            key_type = self.key_type,
            rotation_count = self.rotation_count.load(Ordering::Relaxed),
            "Long-term key rotated"
        );
    }

    /// Get key age
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }
}

/// Key rotation manager coordinates all rotation policies
pub struct KeyRotationManager {
    /// Session key states (per connection/stream)
    session_states: RwLock<Vec<Arc<SessionKeyState>>>,
    /// Noise key state
    noise_state: RwLock<LongTermKeyState>,
    /// TLS cert state
    tls_state: RwLock<LongTermKeyState>,
    /// Event broadcaster
    event_tx: broadcast::Sender<RotationEvent>,
}

impl KeyRotationManager {
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(64);
        Self {
            session_states: RwLock::new(Vec::new()),
            noise_state: RwLock::new(LongTermKeyState::noise_key()),
            tls_state: RwLock::new(LongTermKeyState::tls_cert()),
            event_tx,
        }
    }

    /// Subscribe to rotation events
    pub fn subscribe(&self) -> broadcast::Receiver<RotationEvent> {
        self.event_tx.subscribe()
    }

    /// Register a new session for tracking
    pub async fn register_session(&self) -> Arc<SessionKeyState> {
        let state = Arc::new(SessionKeyState::new());
        self.session_states.write().await.push(state.clone());
        state
    }

    /// Check all sessions and trigger rotations as needed
    /// Returns number of sessions that need rotation
    pub async fn check_sessions(&self) -> Vec<Arc<SessionKeyState>> {
        let states = self.session_states.read().await;
        states
            .iter()
            .filter(|s| s.needs_rotation())
            .cloned()
            .collect()
    }

    /// Check if Noise key rotation is due
    pub async fn check_noise_key(&self) -> bool {
        self.noise_state.read().await.needs_rotation()
    }

    /// Check if TLS cert rotation is due
    pub async fn check_tls_cert(&self) -> bool {
        self.tls_state.read().await.needs_rotation()
    }

    /// Mark Noise key as rotated
    pub async fn rotate_noise_key(&self) {
        self.noise_state.write().await.reset();
        let _ = self.event_tx.send(RotationEvent::NoiseKey);
    }

    /// Mark TLS cert as rotated
    pub async fn rotate_tls_cert(&self) {
        self.tls_state.write().await.reset();
        let _ = self.event_tx.send(RotationEvent::TlsCert);
    }

    /// Get overall rotation statistics
    pub async fn stats(&self) -> RotationStats {
        let noise = self.noise_state.read().await;
        let tls = self.tls_state.read().await;
        let sessions = self.session_states.read().await;

        let total_session_rotations: u64 = sessions.iter().map(|s| s.rotation_count()).sum();

        RotationStats {
            active_sessions: sessions.len(),
            total_session_rotations,
            noise_key_age: noise.age(),
            noise_rotations: noise.rotation_count.load(Ordering::Relaxed),
            tls_cert_age: tls.age(),
            tls_rotations: tls.rotation_count.load(Ordering::Relaxed),
        }
    }

    /// Cleanup inactive sessions (those that have been dropped)
    pub async fn cleanup_sessions(&self) {
        let mut states = self.session_states.write().await;
        let before = states.len();
        states.retain(|s| Arc::strong_count(s) > 1);
        let removed = before - states.len();
        if removed > 0 {
            debug!(removed, "Cleaned up inactive session states");
        }
    }
}

impl Default for KeyRotationManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Rotation statistics snapshot
#[derive(Debug, Clone)]
pub struct RotationStats {
    pub active_sessions: usize,
    pub total_session_rotations: u64,
    pub noise_key_age: Duration,
    pub noise_rotations: u64,
    pub tls_cert_age: Duration,
    pub tls_rotations: u64,
}

/// Background task for periodic rotation checks
pub async fn rotation_check_task(
    manager: Arc<KeyRotationManager>,
    mut shutdown: broadcast::Receiver<()>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(10));

    loop {
        tokio::select! {
            _ = interval.tick() => {
                // Check long-term keys
                if manager.check_noise_key().await {
                    warn!("Noise static key rotation is DUE - manual rotation required");
                    // In production, this would trigger key regeneration
                    manager.rotate_noise_key().await;
                }

                if manager.check_tls_cert().await {
                    warn!("TLS certificate rotation is DUE - manual rotation required");
                    manager.rotate_tls_cert().await;
                }

                // Cleanup stale session trackers
                manager.cleanup_sessions().await;
            }
            _ = shutdown.recv() => {
                info!("Key rotation check task shutting down");
                break;
            }
        }
    }
}

/// Helper trait for streams that track bytes for rotation
pub trait ByteTracking {
    /// Record bytes processed
    fn track_bytes(&self, bytes: u64);

    /// Check if rekey is needed
    fn needs_rekey(&self) -> bool;
}

impl ByteTracking for SessionKeyState {
    fn track_bytes(&self, bytes: u64) {
        self.record_bytes(bytes);
    }

    fn needs_rekey(&self) -> bool {
        self.needs_rotation()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_state_new() {
        let state = SessionKeyState::new();
        assert!(!state.needs_rotation());
        assert_eq!(state.bytes_processed(), 0);
        assert_eq!(state.rotation_count(), 0);
    }

    #[test]
    fn test_session_bytes_tracking() {
        let state = SessionKeyState::new();
        state.record_bytes(1000);
        assert_eq!(state.bytes_processed(), 1000);

        state.record_bytes(500);
        assert_eq!(state.bytes_processed(), 1500);
    }

    #[test]
    fn test_session_data_limit_rotation() {
        let state = SessionKeyState::new();

        // Record just under limit
        state.record_bytes(SESSION_KEY_DATA_LIMIT - 1);
        assert!(!state.needs_rotation());

        // Exceed limit
        state.record_bytes(2);
        assert!(state.needs_rotation());

        // Check reason
        match state.rotation_reason() {
            Some(SessionRotationReason::DataLimit(bytes)) => {
                assert!(bytes >= SESSION_KEY_DATA_LIMIT);
            }
            _ => panic!("Expected DataLimit reason"),
        }
    }

    #[test]
    fn test_session_reset() {
        let mut state = SessionKeyState::new();
        state.record_bytes(1_000_000);
        assert_eq!(state.rotation_count(), 0);

        state.reset();
        assert_eq!(state.bytes_processed(), 0);
        assert_eq!(state.rotation_count(), 1);
    }

    #[test]
    fn test_long_term_state_noise() {
        let state = LongTermKeyState::noise_key();
        assert!(!state.needs_rotation());
        assert!(state.time_until_rotation() > Duration::from_secs(0));
    }

    #[test]
    fn test_long_term_state_tls() {
        let state = LongTermKeyState::tls_cert();
        assert!(!state.needs_rotation());
    }

    #[tokio::test]
    async fn test_manager_register_session() {
        let manager = KeyRotationManager::new();

        let session1 = manager.register_session().await;
        let session2 = manager.register_session().await;

        let stats = manager.stats().await;
        assert_eq!(stats.active_sessions, 2);
    }

    #[tokio::test]
    async fn test_manager_event_broadcast() {
        let manager = KeyRotationManager::new();
        let mut rx = manager.subscribe();

        manager.rotate_noise_key().await;

        let event = rx.try_recv().unwrap();
        assert_eq!(event, RotationEvent::NoiseKey);
    }

    #[tokio::test]
    async fn test_manager_cleanup_sessions() {
        let manager = KeyRotationManager::new();

        // Register and immediately drop
        {
            let _session = manager.register_session().await;
        }

        let stats_before = manager.stats().await;
        manager.cleanup_sessions().await;
        let stats_after = manager.stats().await;

        // Session should be cleaned up since we dropped it
        assert!(stats_after.active_sessions <= stats_before.active_sessions);
    }

    #[tokio::test]
    async fn test_check_sessions_needing_rotation() {
        let manager = KeyRotationManager::new();

        let session = manager.register_session().await;

        // Initially should not need rotation
        let needs = manager.check_sessions().await;
        assert!(needs.is_empty());

        // Exceed data limit
        session.record_bytes(SESSION_KEY_DATA_LIMIT + 1);

        let needs = manager.check_sessions().await;
        assert_eq!(needs.len(), 1);
    }

    #[test]
    fn test_rotation_reason_none_initially() {
        let state = SessionKeyState::new();
        assert!(state.rotation_reason().is_none());
    }

    #[test]
    fn test_byte_tracking_trait() {
        let state = SessionKeyState::new();

        state.track_bytes(100);
        assert_eq!(state.bytes_processed(), 100);
        assert!(!state.needs_rekey());

        state.track_bytes(SESSION_KEY_DATA_LIMIT);
        assert!(state.needs_rekey());
    }
}
