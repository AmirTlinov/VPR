# Security Policies (VPR)

## Randomness (CRIT-001)
- **Source**: All key generation and nonces use `rand::rngs::OsRng` through crate-local helpers (`vpr-crypto::rng::secure_rng`, `masque-core::rng::secure_rng`).
- **Verification**: Unit tests assert at least one OsRng call during key generation and session-id creation.
- **Determinism**: No seeded or thread-local RNGs in production code. Tests may instrument counting but still draw from OsRng.

## Hybrid ML-KEM Secret Hygiene (CRIT-002)
- **Storage**: ML-KEM private key bytes are wrapped in `Zeroizing<Vec<u8>>` (`HybridMlKemSecret`), avoiding long-lived library structs.
- **Drop semantics**: `HybridKeypair::drop` zeroizes both X25519 secret and ML-KEM bytes, followed by a compiler fence to prevent elision.
- **Testing**: `mlkem_secret_zeroizes` confirms buffer is zero after explicit drop; coverage run is required for changes in this area.

## Replay Protection Window (CRIT-003)
- **Window**: Sliding TTL = 300 seconds (5 minutes) using `std::time::Instant` (monotonic; immune to ≤60s clock drift).
- **Keying**: SHA-256 over the first 128 bytes of the handshake message; 16-byte prefix of the digest is used as cache key.
- **Data structure**: HashMap<16-byte key, expiry> guarded by RwLock; O(1) expected insert/check, periodic cleanup every 60s.
- **Telemetry**: `telemetry.replay` tracing events emit counters `blocked` and `processed`; metrics snapshot available via `ReplayMetrics`.
- **Integrity**: Messages newer than TTL are accepted; duplicates within window are refused and counted; expired entries are reclaimed.

## Operational Notes
- Avoid logging raw packet or handshake contents; only counters are emitted for replay events.
- Running `cargo test -p vpr-crypto --lib` and `cargo test -p masque-core --tests replay_integration` is mandatory after RNG/PKI/replay changes.
