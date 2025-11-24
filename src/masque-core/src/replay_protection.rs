//! Replay protection for handshake messages
//!
//! Prevents replay attacks by tracking message hashes with time-based expiration.
//! Uses SHA-256 hash of the first N bytes of each message for deduplication.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};
use tracing::{trace, warn};

/// Default time-to-live for nonces (5 minutes)
pub const DEFAULT_TTL: Duration = Duration::from_secs(300);

/// Maximum number of bytes to hash from each message
const HASH_PREFIX_LEN: usize = 128;

/// Hash of a message prefix (first 16 bytes of SHA-256)
type NonceHash = [u8; 16];

/// Entry in the nonce cache with expiration time
#[derive(Debug, Clone)]
struct NonceEntry {
    /// When this entry expires
    expires_at: Instant,
}

/// Replay protection error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayError {
    /// Message has already been seen (replay attack)
    DuplicateMessage,
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateMessage => write!(f, "duplicate message detected (replay attack)"),
        }
    }
}

impl std::error::Error for ReplayError {}

/// Metrics for replay protection
#[derive(Debug, Default)]
pub struct ReplayMetrics {
    /// Number of unique messages processed
    pub messages_processed: AtomicU64,
    /// Number of replay attempts blocked
    pub replays_blocked: AtomicU64,
    /// Number of expired entries cleaned up
    pub entries_expired: AtomicU64,
}

impl ReplayMetrics {
    /// Get current metrics snapshot
    pub fn snapshot(&self) -> ReplayMetricsSnapshot {
        ReplayMetricsSnapshot {
            messages_processed: self.messages_processed.load(Ordering::Relaxed),
            replays_blocked: self.replays_blocked.load(Ordering::Relaxed),
            entries_expired: self.entries_expired.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of replay metrics at a point in time
#[derive(Debug, Clone, Copy)]
pub struct ReplayMetricsSnapshot {
    pub messages_processed: u64,
    pub replays_blocked: u64,
    pub entries_expired: u64,
}

/// Thread-safe nonce cache for replay protection
pub struct NonceCache {
    /// Map of nonce hashes to their entries
    cache: RwLock<HashMap<NonceHash, NonceEntry>>,
    /// Time-to-live for entries
    ttl: Duration,
    /// Metrics
    metrics: ReplayMetrics,
    /// Last cleanup time
    last_cleanup: RwLock<Instant>,
    /// Cleanup interval (clean expired entries every N seconds)
    cleanup_interval: Duration,
}

impl NonceCache {
    /// Create a new nonce cache with default TTL (5 minutes)
    pub fn new() -> Self {
        Self::with_ttl(DEFAULT_TTL)
    }

    /// Create a new nonce cache with custom TTL
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            ttl,
            metrics: ReplayMetrics::default(),
            last_cleanup: RwLock::new(Instant::now()),
            cleanup_interval: Duration::from_secs(60),
        }
    }

    /// Check if a message is a replay and record it if not
    ///
    /// Returns Ok(()) if message is new, Err(ReplayError) if it's a replay
    pub fn check_and_record(&self, message: &[u8]) -> Result<(), ReplayError> {
        let hash = self.compute_hash(message);
        let now = Instant::now();

        // Try read lock first to check if message exists
        {
            let cache = self.cache.read().unwrap();
            if let Some(entry) = cache.get(&hash) {
                if entry.expires_at > now {
                    let blocked = self.metrics.replays_blocked.fetch_add(1, Ordering::Relaxed) + 1;
                    warn!(target: "telemetry.replay", blocked, "replay detected");
                    return Err(ReplayError::DuplicateMessage);
                }
                // Entry exists but expired, will be replaced
            }
        }

        // Need write lock to insert
        {
            let mut cache = self.cache.write().unwrap();

            // Double-check after acquiring write lock
            if let Some(entry) = cache.get(&hash) {
                if entry.expires_at > now {
                    let blocked = self.metrics.replays_blocked.fetch_add(1, Ordering::Relaxed) + 1;
                    warn!(target: "telemetry.replay", blocked, "replay detected");
                    return Err(ReplayError::DuplicateMessage);
                }
            }

            // Insert new entry
            cache.insert(
                hash,
                NonceEntry {
                    expires_at: now + self.ttl,
                },
            );
            self.metrics
                .messages_processed
                .fetch_add(1, Ordering::Relaxed);
            trace!(target: "telemetry.replay", processed = self.metrics.messages_processed.load(Ordering::Relaxed));
        }

        // Periodic cleanup
        self.maybe_cleanup();

        Ok(())
    }

    /// Check if a message would be a replay without recording it
    pub fn is_replay(&self, message: &[u8]) -> bool {
        let hash = self.compute_hash(message);
        let now = Instant::now();

        let cache = self.cache.read().unwrap();
        if let Some(entry) = cache.get(&hash) {
            return entry.expires_at > now;
        }
        false
    }

    /// Get current metrics
    pub fn metrics(&self) -> &ReplayMetrics {
        &self.metrics
    }

    /// Get number of entries in cache
    pub fn len(&self) -> usize {
        self.cache.read().unwrap().len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.cache.read().unwrap().is_empty()
    }

    /// Force cleanup of expired entries
    pub fn cleanup(&self) {
        let now = Instant::now();
        let mut cache = self.cache.write().unwrap();
        let initial_len = cache.len();

        cache.retain(|_, entry| entry.expires_at > now);

        let removed = initial_len - cache.len();
        if removed > 0 {
            self.metrics
                .entries_expired
                .fetch_add(removed as u64, Ordering::Relaxed);
        }

        *self.last_cleanup.write().unwrap() = now;
    }

    /// Compute hash of message prefix
    fn compute_hash(&self, message: &[u8]) -> NonceHash {
        let prefix_len = message.len().min(HASH_PREFIX_LEN);
        let mut hasher = Sha256::new();
        hasher.update(&message[..prefix_len]);
        let result = hasher.finalize();

        let mut hash = [0u8; 16];
        hash.copy_from_slice(&result[..16]);
        hash
    }

    /// Cleanup expired entries if enough time has passed
    fn maybe_cleanup(&self) {
        let now = Instant::now();
        let should_cleanup = {
            let last = self.last_cleanup.read().unwrap();
            now.duration_since(*last) >= self.cleanup_interval
        };

        if should_cleanup {
            self.cleanup();
        }
    }
}

impl Default for NonceCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_message_accepted() {
        let cache = NonceCache::new();
        let msg = b"hello world handshake message";
        assert!(cache.check_and_record(msg).is_ok());
        assert_eq!(cache.metrics().snapshot().messages_processed, 1);
    }

    #[test]
    fn test_replay_blocked() {
        let cache = NonceCache::new();
        let msg = b"unique handshake message";

        // First time should succeed
        assert!(cache.check_and_record(msg).is_ok());

        // Second time should fail (replay)
        assert_eq!(
            cache.check_and_record(msg),
            Err(ReplayError::DuplicateMessage)
        );

        let metrics = cache.metrics().snapshot();
        assert_eq!(metrics.messages_processed, 1);
        assert_eq!(metrics.replays_blocked, 1);
    }

    #[test]
    fn test_different_messages_accepted() {
        let cache = NonceCache::new();
        let msg1 = b"first handshake message";
        let msg2 = b"second handshake message";

        assert!(cache.check_and_record(msg1).is_ok());
        assert!(cache.check_and_record(msg2).is_ok());
        assert_eq!(cache.metrics().snapshot().messages_processed, 2);
    }

    #[test]
    fn test_expired_message_accepted_again() {
        // Use very short TTL for testing
        let cache = NonceCache::with_ttl(Duration::from_millis(50));
        let msg = b"expiring message";

        assert!(cache.check_and_record(msg).is_ok());

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(100));

        // Should be accepted again after expiration
        assert!(cache.check_and_record(msg).is_ok());
        assert_eq!(cache.metrics().snapshot().messages_processed, 2);
    }

    #[test]
    fn test_is_replay_check() {
        let cache = NonceCache::new();
        let msg = b"check replay message";

        // Not recorded yet
        assert!(!cache.is_replay(msg));

        // Record it
        cache.check_and_record(msg).unwrap();

        // Now it's a replay
        assert!(cache.is_replay(msg));
    }

    #[test]
    fn test_cleanup() {
        let cache = NonceCache::with_ttl(Duration::from_millis(50));

        // Add some messages
        for i in 0..10 {
            let msg = format!("message {}", i);
            cache.check_and_record(msg.as_bytes()).unwrap();
        }
        assert_eq!(cache.len(), 10);

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(100));

        // Force cleanup
        cache.cleanup();

        assert_eq!(cache.len(), 0);
        assert_eq!(cache.metrics().snapshot().entries_expired, 10);
    }

    #[test]
    fn test_hash_uses_prefix() {
        let cache = NonceCache::new();

        // Two messages with same prefix but different suffix
        let mut msg1 = vec![0u8; 200];
        let mut msg2 = vec![0u8; 200];

        // Same first 128 bytes
        for i in 0..128 {
            msg1[i] = i as u8;
            msg2[i] = i as u8;
        }

        // Different suffix
        msg1[150] = 1;
        msg2[150] = 2;

        // Should be treated as same message (only prefix is hashed)
        assert!(cache.check_and_record(&msg1).is_ok());
        assert_eq!(
            cache.check_and_record(&msg2),
            Err(ReplayError::DuplicateMessage)
        );
    }
}
