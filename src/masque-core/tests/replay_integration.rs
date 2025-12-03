#![allow(clippy::needless_range_loop)]

use masque_core::replay_protection::{NonceCache, DEFAULT_TTL};
use std::time::Duration;
use tokio::time::sleep;

/// Integration-style check: ensure 5-minute window semantics (shortened here),
/// prefix hashing, and refusal metrics are wired end-to-end.
#[tokio::test]
async fn replay_window_enforced_and_metric_recorded() {
    // Short TTL to avoid long sleeps; logic identical to 5-minute window.
    let ttl = Duration::from_millis(200);
    let cache = NonceCache::with_ttl(ttl);

    // Message longer than HASH_PREFIX_LEN to exercise prefix hashing path.
    let mut msg = vec![0u8; 256];
    for i in 0..msg.len() {
        msg[i] = (i % 251) as u8;
    }

    // First pass accepted.
    assert!(cache.check_and_record(&msg).is_ok());

    // Immediate replay rejected and counted.
    assert!(cache.check_and_record(&msg).is_err());
    let snap = cache.metrics().snapshot();
    assert_eq!(snap.messages_processed, 1);
    assert_eq!(snap.replays_blocked, 1);

    // Wait for TTL to expire, then message should be accepted again.
    sleep(ttl + Duration::from_millis(50)).await;
    assert!(cache.check_and_record(&msg).is_ok());

    // Metrics reflect an additional processed message.
    let snap = cache.metrics().snapshot();
    assert_eq!(snap.messages_processed, 2);
    assert_eq!(snap.replays_blocked, 1);

    // Sanity check default window (5 minutes) constant for docs/alerting.
    assert_eq!(DEFAULT_TTL, Duration::from_secs(300));
}
