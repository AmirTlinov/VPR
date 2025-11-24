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
        SecureRng
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
