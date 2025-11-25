use rand::{rngs::OsRng, CryptoRng, RngCore};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Default cryptographically secure RNG for masque-core.
pub type SecureRng = OsRng;

static OSRNG_CALLS: AtomicU64 = AtomicU64::new(0);
static COUNTING_ENABLED: AtomicBool = AtomicBool::new(cfg!(test));

#[derive(Default)]
struct CountingOsRng {
    inner: SecureRng,
}

impl CountingOsRng {
    fn increment(&self) {
        if COUNTING_ENABLED.load(Ordering::Relaxed) {
            OSRNG_CALLS.fetch_add(1, Ordering::SeqCst);
        }
    }
}

impl RngCore for CountingOsRng {
    fn next_u32(&mut self) -> u32 {
        self.increment();
        self.inner.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.increment();
        self.inner.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.increment();
        self.inner.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.increment();
        self.inner.try_fill_bytes(dest)
    }
}

impl CryptoRng for CountingOsRng {}

/// Return cryptographically secure RNG. Counting can be toggled for tests.
pub fn secure_rng() -> impl RngCore + CryptoRng {
    CountingOsRng::default()
}

/// Generate a random u64 using the secure RNG.
pub fn random_u64() -> u64 {
    let mut rng = secure_rng();
    rng.next_u64()
}

/// Enable instrumentation for counting OsRng invocations (used in tests).
pub fn enable_counting() {
    COUNTING_ENABLED.store(true, Ordering::Relaxed);
}

/// Disable instrumentation to avoid overhead when not needed.
pub fn disable_counting() {
    COUNTING_ENABLED.store(false, Ordering::Relaxed);
}

pub fn reset_osrng_calls() {
    OSRNG_CALLS.store(0, Ordering::SeqCst);
}

pub fn osrng_call_count() -> u64 {
    OSRNG_CALLS.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Mutex to serialize tests that modify global counting state
    static TEST_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn random_u64_uses_osrng() {
        let _guard = TEST_MUTEX.lock().unwrap();
        enable_counting();
        reset_osrng_calls();
        let _ = random_u64();
        assert!(osrng_call_count() >= 1, "OsRng must be used for randomness");
    }

    #[test]
    fn counting_toggle_controls_instrumentation() {
        let _guard = TEST_MUTEX.lock().unwrap();
        disable_counting();
        reset_osrng_calls();
        let _ = random_u64();
        assert_eq!(osrng_call_count(), 0, "Counting disabled should not track");

        enable_counting();
        reset_osrng_calls();
        let _ = random_u64();
        assert!(osrng_call_count() >= 1, "Counting must track when enabled");
    }

    #[test]
    fn test_secure_rng_fill_bytes() {
        let _guard = TEST_MUTEX.lock().unwrap();
        enable_counting();
        reset_osrng_calls();

        let mut buf = [0u8; 32];
        let mut rng = secure_rng();
        rng.fill_bytes(&mut buf);

        assert!(osrng_call_count() >= 1);
        // Check that buffer is likely not all zeros
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_secure_rng_try_fill_bytes() {
        let _guard = TEST_MUTEX.lock().unwrap();
        enable_counting();
        reset_osrng_calls();

        let mut buf = [0u8; 16];
        let mut rng = secure_rng();
        let result = rng.try_fill_bytes(&mut buf);

        assert!(result.is_ok());
        assert!(osrng_call_count() >= 1);
    }

    #[test]
    fn test_secure_rng_next_u32() {
        let _guard = TEST_MUTEX.lock().unwrap();
        enable_counting();
        reset_osrng_calls();

        let mut rng = secure_rng();
        let _v = rng.next_u32();

        assert!(osrng_call_count() >= 1);
    }

    #[test]
    fn test_random_u64_returns_different_values() {
        let _guard = TEST_MUTEX.lock().unwrap();
        enable_counting();

        // With cryptographic randomness, we should get different values
        let v1 = random_u64();
        let v2 = random_u64();
        let v3 = random_u64();

        // Extremely unlikely all three would be equal
        assert!(!(v1 == v2 && v2 == v3));
    }

    #[test]
    fn test_reset_osrng_calls() {
        let _guard = TEST_MUTEX.lock().unwrap();
        enable_counting();

        let _ = random_u64();
        assert!(osrng_call_count() >= 1);

        reset_osrng_calls();
        assert_eq!(osrng_call_count(), 0);
    }

    #[test]
    fn test_counting_osrng_default() {
        let _guard = TEST_MUTEX.lock().unwrap();
        enable_counting();
        reset_osrng_calls();

        let mut rng = CountingOsRng::default();
        let _ = rng.next_u64();

        assert!(osrng_call_count() >= 1);
    }

    #[test]
    fn test_counting_multiple_operations() {
        let _guard = TEST_MUTEX.lock().unwrap();
        enable_counting();
        reset_osrng_calls();

        let mut rng = secure_rng();
        let _ = rng.next_u32();
        let _ = rng.next_u64();
        let mut buf = [0u8; 8];
        rng.fill_bytes(&mut buf);

        assert!(osrng_call_count() >= 3);
    }
}
