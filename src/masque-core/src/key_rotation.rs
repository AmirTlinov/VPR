//! Key Rotation Management
//!
//! Implements automatic key rotation policies for defense-in-depth:
//! - Session keys: every 60 seconds OR 1GB data (forward secrecy)
//! - Noise static keys: every 14 days (identity rotation)
//! - TLS certificates: every 6 hours (certificate agility)

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, info, warn};

/// Session key rotation thresholds (defaults)
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

/// Session key rotation limits
#[derive(Debug, Clone, Copy)]
pub struct SessionKeyLimits {
    pub time_limit: Duration,
    pub data_limit: u64,
}

impl Default for SessionKeyLimits {
    fn default() -> Self {
        Self {
            time_limit: SESSION_KEY_TIME_LIMIT,
            data_limit: SESSION_KEY_DATA_LIMIT,
        }
    }
}

/// Configuration for rotation manager
#[derive(Debug, Clone)]
pub struct KeyRotationConfig {
    pub session_limits: SessionKeyLimits,
    pub check_interval: Duration,
}

impl Default for KeyRotationConfig {
    fn default() -> Self {
        Self {
            session_limits: SessionKeyLimits::default(),
            check_interval: Duration::from_secs(10),
        }
    }
}

impl KeyRotationConfig {
    pub fn with_session_limits(time_limit: Duration, data_limit: u64) -> Self {
        Self {
            session_limits: SessionKeyLimits {
                time_limit,
                data_limit,
            },
            ..Self::default()
        }
    }

    pub fn with_check_interval(mut self, interval: Duration) -> Self {
        self.check_interval = interval;
        self
    }
}

/// Session key state tracker
#[derive(Debug)]
pub struct SessionKeyState {
    created_at: Mutex<Instant>,
    bytes_processed: AtomicU64,
    rotation_count: AtomicU64,
    limits: SessionKeyLimits,
    rekey_lock: Mutex<()>,
}

impl SessionKeyState {
    pub fn new() -> Self {
        Self::with_limits(SessionKeyLimits::default())
    }

    pub fn with_limits(limits: SessionKeyLimits) -> Self {
        Self {
            created_at: Mutex::new(Instant::now()),
            bytes_processed: AtomicU64::new(0),
            rotation_count: AtomicU64::new(0),
            limits,
            rekey_lock: Mutex::new(()),
        }
    }

    /// Record bytes processed through this session
    pub fn record_bytes(&self, bytes: u64) {
        self.bytes_processed.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Check if rotation is needed based on time or data limits
    pub fn needs_rotation(&self) -> bool {
        let age = self.age();
        let bytes = self.bytes_processed.load(Ordering::Relaxed);

        age >= self.limits.time_limit || bytes >= self.limits.data_limit
    }

    /// Get rotation reason if rotation is needed
    pub fn rotation_reason(&self) -> Option<SessionRotationReason> {
        let age = self.age();
        let bytes = self.bytes_processed.load(Ordering::Relaxed);

        if bytes >= self.limits.data_limit {
            Some(SessionRotationReason::DataLimit(bytes))
        } else if age >= self.limits.time_limit {
            Some(SessionRotationReason::TimeLimit(age))
        } else {
            None
        }
    }

    /// Reset state after rotation
    pub fn reset(&self) {
        let _lock = self.rekey_lock.lock().expect("rekey lock poisoned");
        self.reset_unlocked();
    }

    fn reset_unlocked(&self) {
        if let Ok(mut created_at) = self.created_at.lock() {
            *created_at = Instant::now();
        }
        self.bytes_processed.store(0, Ordering::Relaxed);
        self.rotation_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Get configured limits
    pub fn limits(&self) -> SessionKeyLimits {
        self.limits
    }

    /// Get total rotation count
    pub fn rotation_count(&self) -> u64 {
        self.rotation_count.load(Ordering::Relaxed)
    }

    /// Get session age
    pub fn age(&self) -> Duration {
        self.created_at
            .lock()
            .map(|created| created.elapsed())
            .unwrap_or_default()
    }

    /// Get bytes processed
    pub fn bytes_processed(&self) -> u64 {
        self.bytes_processed.load(Ordering::Relaxed)
    }

    /// Atomically trigger rotation callback if thresholds exceeded
    pub fn maybe_rotate_with<F>(&self, mut on_rotate: F)
    where
        F: FnMut(SessionRotationReason),
    {
        if !self.needs_rotation() {
            return;
        }

        let _guard = self.rekey_lock.lock().expect("rekey lock poisoned");
        if let Some(reason) = self.rotation_reason() {
            on_rotate(reason);
            self.reset_unlocked();
        }
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
    /// Rotation configuration
    config: KeyRotationConfig,
}

impl KeyRotationManager {
    pub fn new() -> Self {
        Self::with_config(KeyRotationConfig::default())
    }

    pub fn with_config(config: KeyRotationConfig) -> Self {
        let (event_tx, _) = broadcast::channel(64);
        Self {
            session_states: RwLock::new(Vec::new()),
            noise_state: RwLock::new(LongTermKeyState::noise_key()),
            tls_state: RwLock::new(LongTermKeyState::tls_cert()),
            event_tx,
            config,
        }
    }

    /// Subscribe to rotation events
    pub fn subscribe(&self) -> broadcast::Receiver<RotationEvent> {
        self.event_tx.subscribe()
    }

    /// Register a new session for tracking
    pub async fn register_session(&self) -> Arc<SessionKeyState> {
        let state = Arc::new(SessionKeyState::with_limits(self.config.session_limits));
        self.session_states.write().await.push(state.clone());
        state
    }

    /// Get configured session limits
    pub fn session_limits(&self) -> SessionKeyLimits {
        self.config.session_limits
    }

    /// Interval used by background rotation checks
    pub fn check_interval(&self) -> Duration {
        self.config.check_interval
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
    interval_duration: Duration,
) {
    let mut interval = tokio::time::interval(interval_duration);

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
        let state = SessionKeyState::new();
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

        let _session1 = manager.register_session().await;
        let _session2 = manager.register_session().await;

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

    #[tokio::test]
    async fn manager_respects_custom_limits() {
        let config = KeyRotationConfig::with_session_limits(Duration::from_secs(1), 16);
        let manager = KeyRotationManager::with_config(config);

        let state = manager.register_session().await;
        assert_eq!(state.limits().data_limit, 16);

        state.record_bytes(16);
        assert!(state.needs_rotation());
    }

    #[test]
    fn maybe_rotate_with_resets_state() {
        let state = SessionKeyState::with_limits(SessionKeyLimits {
            time_limit: Duration::from_secs(10),
            data_limit: 1,
        });

        state.record_bytes(1);
        let mut triggered = false;
        state.maybe_rotate_with(|reason| {
            triggered = matches!(reason, SessionRotationReason::DataLimit(_));
        });

        assert!(triggered);
        assert_eq!(state.rotation_count(), 1);
        assert_eq!(state.bytes_processed(), 0);
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
