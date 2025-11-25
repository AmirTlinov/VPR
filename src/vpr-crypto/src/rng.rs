use rand::{rngs::OsRng, CryptoRng, RngCore};

#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};

/// Default cryptographically secure RNG for the crate.
pub type SecureRng = OsRng;

#[cfg(test)]
static OSRNG_CALLS: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
#[derive(Default)]
struct CountingOsRng {
    inner: SecureRng,
}

#[cfg(test)]
impl CountingOsRng {
    fn increment(&self) {
        OSRNG_CALLS.fetch_add(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
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

#[cfg(test)]
impl CryptoRng for CountingOsRng {}

/// Return cryptographically secure RNG (OsRng in production, counted in tests).
pub fn secure_rng() -> impl RngCore + CryptoRng {
    #[cfg(test)]
    {
        CountingOsRng::default()
    }
    #[cfg(not(test))]
    {
        OsRng
    }
}

/// Fill the provided buffer with secure randomness.
pub fn fill(dest: &mut [u8]) {
    let mut rng = secure_rng();
    rng.fill_bytes(dest);
}

#[cfg(test)]
pub fn reset_osrng_calls() {
    OSRNG_CALLS.store(0, Ordering::SeqCst);
}

#[cfg(test)]
pub fn osrng_call_count() -> u64 {
    OSRNG_CALLS.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_tracks_osrng_usage() {
        reset_osrng_calls();
        let mut buf = [0u8; 32];
        fill(&mut buf);
        assert!(osrng_call_count() >= 1, "OsRng must be invoked during fill");
        assert!(
            buf.iter().any(|&b| b != 0),
            "fill must mutate provided buffer"
        );
    }

    #[test]
    fn test_fill_empty_buffer() {
        reset_osrng_calls();
        let mut buf = [0u8; 0];
        fill(&mut buf);
        // Even with empty buffer, the RNG should be obtained
        assert!(osrng_call_count() >= 1);
    }

    #[test]
    fn test_fill_small_buffer() {
        reset_osrng_calls();
        let mut buf = [0u8; 1];
        fill(&mut buf);
        assert!(osrng_call_count() >= 1);
    }

    #[test]
    fn test_fill_large_buffer() {
        reset_osrng_calls();
        let mut buf = [0u8; 1024];
        fill(&mut buf);
        assert!(osrng_call_count() >= 1);
        // Large buffer should have randomness (extremely unlikely all zeros)
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_fill_produces_different_values() {
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        fill(&mut buf1);
        fill(&mut buf2);
        // Two random fills should produce different values (probabilistic)
        assert_ne!(buf1, buf2, "Two random fills should differ");
    }

    #[test]
    fn test_secure_rng_next_u32() {
        reset_osrng_calls();
        let mut rng = secure_rng();
        let _v1 = rng.next_u32();
        let _v2 = rng.next_u32();
        // Should be different (probabilistic, but extremely unlikely to be same)
        assert!(osrng_call_count() >= 2);
        // Note: there's a tiny chance they could be equal, but extremely unlikely
        // We just verify the RNG is being called
    }

    #[test]
    fn test_secure_rng_next_u64() {
        reset_osrng_calls();
        let mut rng = secure_rng();
        let v1 = rng.next_u64();
        let v2 = rng.next_u64();
        assert!(osrng_call_count() >= 2);
        // Very unlikely to be equal
        let _ = (v1, v2);
    }

    #[test]
    fn test_secure_rng_fill_bytes() {
        reset_osrng_calls();
        let mut rng = secure_rng();
        let mut buf = [0u8; 16];
        rng.fill_bytes(&mut buf);
        assert!(osrng_call_count() >= 1);
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_secure_rng_try_fill_bytes() {
        reset_osrng_calls();
        let mut rng = secure_rng();
        let mut buf = [0u8; 16];
        let result = rng.try_fill_bytes(&mut buf);
        assert!(result.is_ok());
        assert!(osrng_call_count() >= 1);
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_reset_osrng_calls() {
        // Fill to generate some calls
        let mut buf = [0u8; 32];
        fill(&mut buf);
        let count_after_fill = osrng_call_count();

        // Reset and verify
        reset_osrng_calls();
        assert_eq!(osrng_call_count(), 0);

        // Verify we can count again
        fill(&mut buf);
        assert!(osrng_call_count() >= 1);

        // This count should be less than the cumulative before reset
        // (or equal if exact same number of calls)
        let _ = count_after_fill;
    }

    #[test]
    fn test_osrng_call_count_accumulates() {
        reset_osrng_calls();

        let mut buf = [0u8; 8];
        fill(&mut buf);
        let count1 = osrng_call_count();

        fill(&mut buf);
        let count2 = osrng_call_count();

        // Count should increase (or stay same if counted once per operation)
        assert!(count2 >= count1);
    }

    #[test]
    fn test_counting_osrng_default() {
        let rng = CountingOsRng::default();
        // Just verify it can be created
        let _ = rng;
    }

    #[test]
    fn test_multiple_secure_rng_instances() {
        reset_osrng_calls();
        let mut rng1 = secure_rng();
        let mut rng2 = secure_rng();

        let v1 = rng1.next_u64();
        let v2 = rng2.next_u64();

        // Both should work independently
        assert!(osrng_call_count() >= 2);
        let _ = (v1, v2);
    }
}
