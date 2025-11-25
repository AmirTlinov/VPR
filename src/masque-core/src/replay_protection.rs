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
    /// Internal cache error (lock poisoned due to panic in another thread)
    CacheCorrupted,
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateMessage => write!(f, "duplicate message detected (replay attack)"),
            Self::CacheCorrupted => write!(f, "replay protection cache corrupted (lock poisoned)"),
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

    /// Render metrics in Prometheus text exposition format.
    pub fn to_prometheus(&self, prefix: &str) -> String {
        let snap = self.snapshot();
        format!(
            concat!(
                "# TYPE {p}_messages_processed counter\n",
                "{p}_messages_processed {mp}\n",
                "# TYPE {p}_replays_blocked counter\n",
                "{p}_replays_blocked {rb}\n",
                "# TYPE {p}_entries_expired counter\n",
                "{p}_entries_expired {ee}\n"
            ),
            p = prefix,
            mp = snap.messages_processed,
            rb = snap.replays_blocked,
            ee = snap.entries_expired
        )
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
    /// Soft ceiling on entries to prevent unbounded growth
    max_entries: usize,
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
            max_entries: 50_000,
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
            let cache = match self.cache.read() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    warn!(target: "telemetry.replay", "cache lock poisoned, recovering");
                    poisoned.into_inner()
                }
            };
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
            let mut cache = match self.cache.write() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    warn!(target: "telemetry.replay", "cache lock poisoned on write, recovering");
                    poisoned.into_inner()
                }
            };

            // Double-check after acquiring write lock
            if let Some(entry) = cache.get(&hash) {
                if entry.expires_at > now {
                    let blocked = self.metrics.replays_blocked.fetch_add(1, Ordering::Relaxed) + 1;
                    warn!(target: "telemetry.replay", blocked, "replay detected");
                    return Err(ReplayError::DuplicateMessage);
                }
            }

            if cache.len() >= self.max_entries {
                warn!(
                    target: "telemetry.replay",
                    size = cache.len(),
                    "replay cache at soft limit, triggering cleanup"
                );
                // Attempt cleanup while still holding the lock by filtering expired entries.
                let before = cache.len();
                cache.retain(|_, entry| entry.expires_at > now);
                let removed = before - cache.len();
                if removed > 0 {
                    self.metrics
                        .entries_expired
                        .fetch_add(removed as u64, Ordering::Relaxed);
                }
            }

            if cache.len() >= self.max_entries {
                self.evict_oldest(&mut cache, now);
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

        let cache = match self.cache.read() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!(target: "telemetry.replay", "cache lock poisoned in is_replay, recovering");
                poisoned.into_inner()
            }
        };
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
        match self.cache.read() {
            Ok(guard) => guard.len(),
            Err(poisoned) => {
                warn!(target: "telemetry.replay", "cache lock poisoned in len, recovering");
                poisoned.into_inner().len()
            }
        }
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        match self.cache.read() {
            Ok(guard) => guard.is_empty(),
            Err(poisoned) => {
                warn!(target: "telemetry.replay", "cache lock poisoned in is_empty, recovering");
                poisoned.into_inner().is_empty()
            }
        }
    }

    /// Force cleanup of expired entries
    pub fn cleanup(&self) {
        let now = Instant::now();
        let mut cache = match self.cache.write() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!(target: "telemetry.replay", "cache lock poisoned in cleanup, recovering");
                poisoned.into_inner()
            }
        };
        let initial_len = cache.len();

        cache.retain(|_, entry| entry.expires_at > now);

        let removed = initial_len - cache.len();
        if removed > 0 {
            self.metrics
                .entries_expired
                .fetch_add(removed as u64, Ordering::Relaxed);
        }

        match self.last_cleanup.write() {
            Ok(mut guard) => *guard = now,
            Err(poisoned) => {
                warn!(target: "telemetry.replay", "cleanup lock poisoned, recovering");
                *poisoned.into_inner() = now;
            }
        }
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
            let last = match self.last_cleanup.read() {
                Ok(guard) => *guard,
                Err(poisoned) => {
                    warn!(target: "telemetry.replay", "cleanup lock poisoned in maybe_cleanup, recovering");
                    *poisoned.into_inner()
                }
            };
            now.duration_since(last) >= self.cleanup_interval
        };

        if should_cleanup {
            self.cleanup();
        }
    }

    fn evict_oldest(&self, cache: &mut HashMap<NonceHash, NonceEntry>, now: Instant) {
        if cache.is_empty() {
            return;
        }
        let mut items: Vec<(NonceHash, Instant)> =
            cache.iter().map(|(k, v)| (*k, v.expires_at)).collect();
        items.sort_by_key(|(_, v)| *v);
        let to_remove = cache
            .len()
            .saturating_sub(self.max_entries.saturating_sub(1));
        for (key, _) in items.into_iter().take(to_remove) {
            cache.remove(&key);
        }
        let removed = to_remove as u64;
        if removed > 0 {
            self.metrics
                .entries_expired
                .fetch_add(removed, Ordering::Relaxed);
            warn!(
                target: "telemetry.replay",
                removed,
                "evicted entries to honor soft limit"
            );
        }
        match self.last_cleanup.write() {
            Ok(mut guard) => *guard = now,
            Err(poisoned) => {
                warn!(target: "telemetry.replay", "cleanup lock poisoned in evict_oldest, recovering");
                *poisoned.into_inner() = now;
            }
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
        cache
            .check_and_record(msg)
            .expect("test: failed to record message");

        // Now it's a replay
        assert!(cache.is_replay(msg));
    }

    #[test]
    fn test_cleanup() {
        let cache = NonceCache::with_ttl(Duration::from_millis(50));

        // Add some messages
        for i in 0..10 {
            let msg = format!("message {}", i);
            cache
                .check_and_record(msg.as_bytes())
                .expect("test: failed to record message");
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

    #[test]
    fn test_prometheus_export() {
        let cache = NonceCache::new();
        let msg = b"prom metrics";
        let _ = cache.check_and_record(msg);
        let _ = cache.check_and_record(msg);

        let prom = cache.metrics().to_prometheus("replay");
        assert!(prom.contains("replay_messages_processed"));
        assert!(prom.contains("replay_replays_blocked"));
        assert!(prom.contains("replay_entries_expired"));
    }

    #[test]
    fn test_replay_error_display() {
        let err = ReplayError::DuplicateMessage;
        assert!(err.to_string().contains("duplicate message"));

        let err = ReplayError::CacheCorrupted;
        assert!(err.to_string().contains("corrupted"));
    }

    #[test]
    fn test_replay_error_equality() {
        assert_eq!(ReplayError::DuplicateMessage, ReplayError::DuplicateMessage);
        assert_eq!(ReplayError::CacheCorrupted, ReplayError::CacheCorrupted);
        assert_ne!(ReplayError::DuplicateMessage, ReplayError::CacheCorrupted);
    }

    #[test]
    fn test_replay_error_is_error_trait() {
        let err: &dyn std::error::Error = &ReplayError::DuplicateMessage;
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn test_replay_metrics_default() {
        let metrics = ReplayMetrics::default();
        let snap = metrics.snapshot();
        assert_eq!(snap.messages_processed, 0);
        assert_eq!(snap.replays_blocked, 0);
        assert_eq!(snap.entries_expired, 0);
    }

    #[test]
    fn test_replay_metrics_snapshot_clone() {
        let metrics = ReplayMetrics::default();
        metrics.messages_processed.fetch_add(5, Ordering::Relaxed);
        let snap = metrics.snapshot();
        let snap_clone = snap;
        assert_eq!(snap.messages_processed, snap_clone.messages_processed);
    }

    #[test]
    fn test_nonce_cache_default() {
        let cache = NonceCache::default();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_nonce_cache_is_empty() {
        let cache = NonceCache::new();
        assert!(cache.is_empty());
        assert!(cache.check_and_record(b"msg").is_ok());
        assert!(!cache.is_empty());
    }

    #[test]
    fn test_nonce_cache_len() {
        let cache = NonceCache::new();
        assert_eq!(cache.len(), 0);

        for i in 0..5 {
            let msg = format!("msg_{}", i);
            assert!(cache.check_and_record(msg.as_bytes()).is_ok());
        }
        assert_eq!(cache.len(), 5);
    }

    #[test]
    fn test_is_replay_without_recording() {
        let cache = NonceCache::new();
        let msg = b"test message";

        // Check doesn't record
        assert!(!cache.is_replay(msg));
        assert!(!cache.is_replay(msg)); // Still not a replay

        // Record it
        assert!(cache.check_and_record(msg).is_ok());
        assert!(cache.is_replay(msg)); // Now it's a replay
    }

    #[test]
    fn test_is_replay_after_expiration() {
        let cache = NonceCache::with_ttl(Duration::from_millis(30));
        let msg = b"expiring check";

        assert!(cache.check_and_record(msg).is_ok());
        assert!(cache.is_replay(msg));

        std::thread::sleep(Duration::from_millis(60));

        // After expiration, not a replay anymore
        assert!(!cache.is_replay(msg));
    }

    #[test]
    fn test_empty_message() {
        let cache = NonceCache::new();
        let empty: &[u8] = b"";

        assert!(cache.check_and_record(empty).is_ok());
        assert_eq!(
            cache.check_and_record(empty),
            Err(ReplayError::DuplicateMessage)
        );
    }

    #[test]
    fn test_very_short_message() {
        let cache = NonceCache::new();
        let short = b"a";

        assert!(cache.check_and_record(short).is_ok());
        assert!(cache.is_replay(short));
    }

    #[test]
    fn test_very_long_message() {
        let cache = NonceCache::new();
        let long_msg = vec![42u8; 10000];

        assert!(cache.check_and_record(&long_msg).is_ok());
        assert!(cache.is_replay(&long_msg));
    }

    #[test]
    fn test_cleanup_on_non_expired() {
        let cache = NonceCache::new(); // 5 min TTL

        for i in 0..5 {
            let msg = format!("no_expire_{}", i);
            cache.check_and_record(msg.as_bytes()).unwrap();
        }

        assert_eq!(cache.len(), 5);
        cache.cleanup();
        // Nothing should be removed (not expired)
        assert_eq!(cache.len(), 5);
    }

    #[test]
    fn test_metrics_increment() {
        let cache = NonceCache::new();

        // Process unique messages
        for i in 0..3 {
            let msg = format!("unique_{}", i);
            cache.check_and_record(msg.as_bytes()).unwrap();
        }

        // Try replays
        for i in 0..2 {
            let msg = format!("unique_{}", i);
            let _ = cache.check_and_record(msg.as_bytes());
        }

        let snap = cache.metrics().snapshot();
        assert_eq!(snap.messages_processed, 3);
        assert_eq!(snap.replays_blocked, 2);
    }

    #[test]
    fn test_prometheus_format_valid() {
        let cache = NonceCache::new();
        cache.check_and_record(b"test1").unwrap();
        let _ = cache.check_and_record(b"test1"); // replay

        let prom = cache.metrics().to_prometheus("rp");
        // Check Prometheus format
        assert!(prom.contains("# TYPE rp_messages_processed counter"));
        assert!(prom.contains("rp_messages_processed 1"));
        assert!(prom.contains("rp_replays_blocked 1"));
        assert!(prom.contains("rp_entries_expired 0"));
    }

    #[test]
    fn test_hash_prefix_boundary() {
        let cache = NonceCache::new();

        // Messages identical up to HASH_PREFIX_LEN (128) should be treated same
        let mut msg1 = vec![0u8; 128];
        let mut msg2 = vec![0u8; 129];
        for i in 0..128 {
            msg1[i] = (i % 256) as u8;
            msg2[i] = (i % 256) as u8;
        }
        msg2[128] = 99; // Extra byte after prefix

        cache.check_and_record(&msg1).unwrap();
        // Should be duplicate since first 128 bytes are identical
        assert_eq!(
            cache.check_and_record(&msg2),
            Err(ReplayError::DuplicateMessage)
        );
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let cache = Arc::new(NonceCache::new());
        let mut handles = vec![];

        for i in 0..4 {
            let cache_clone = Arc::clone(&cache);
            let handle = thread::spawn(move || {
                for j in 0..100 {
                    let msg = format!("thread_{}_{}", i, j);
                    let _ = cache_clone.check_and_record(msg.as_bytes());
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Should have 400 unique messages
        assert_eq!(cache.metrics().snapshot().messages_processed, 400);
    }

    #[test]
    fn test_default_ttl_constant() {
        assert_eq!(DEFAULT_TTL, Duration::from_secs(300));
    }

    #[test]
    fn test_nonce_entry_debug() {
        // NonceEntry is private but we can test the cache behavior
        let cache = NonceCache::with_ttl(Duration::from_millis(10));
        cache.check_and_record(b"debug_test").unwrap();
        // Entry should exist
        assert!(!cache.is_empty());
    }

    #[test]
    fn test_replay_metrics_snapshot_debug() {
        let snap = ReplayMetricsSnapshot {
            messages_processed: 10,
            replays_blocked: 5,
            entries_expired: 2,
        };
        let debug_str = format!("{:?}", snap);
        assert!(debug_str.contains("10"));
        assert!(debug_str.contains("5"));
        assert!(debug_str.contains("2"));
    }
}
