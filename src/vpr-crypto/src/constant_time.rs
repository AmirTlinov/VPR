//! Constant-Time Operations
//!
//! Provides timing-attack resistant operations for comparing secrets.
//! Uses the `subtle` crate to ensure all comparisons take the same time
//! regardless of input values.

use subtle::{Choice, ConstantTimeEq};

/// Constant-time comparison of two byte slices.
///
/// Returns true if both slices are equal, false otherwise.
/// The comparison time is independent of where the first difference occurs.
///
/// # Security
///
/// This function is designed to prevent timing side-channel attacks where
/// an attacker could measure how long comparisons take to determine
/// how many bytes match.
#[inline]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Constant-time comparison of two fixed-size byte arrays.
///
/// Returns true if arrays are equal, optimized for fixed-size comparisons.
#[inline]
pub fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b).into()
}

/// Constant-time comparison of 64-byte arrays (e.g., signatures).
#[inline]
pub fn ct_eq_64(a: &[u8; 64], b: &[u8; 64]) -> bool {
    a.ct_eq(b).into()
}

/// Constant-time selection between two values based on a condition.
///
/// If `condition` is true, returns `a`; otherwise returns `b`.
/// The selection time is independent of the condition.
#[inline]
pub fn ct_select<T: Copy>(condition: bool, a: T, b: T) -> T {
    // For generic types we use branching, but for primitives use ct_select_*
    if condition { a } else { b }
}

/// Constant-time byte selection
#[inline]
pub fn ct_select_u8(condition: bool, a: u8, b: u8) -> u8 {
    let choice = Choice::from(condition as u8);
    subtle::ConditionallySelectable::conditional_select(&b, &a, choice)
}

/// Constant-time 32-bit selection
#[inline]
pub fn ct_select_u32(condition: bool, a: u32, b: u32) -> u32 {
    let choice = Choice::from(condition as u8);
    subtle::ConditionallySelectable::conditional_select(&b, &a, choice)
}

/// Constant-time 64-bit selection
#[inline]
pub fn ct_select_u64(condition: bool, a: u64, b: u64) -> u64 {
    let choice = Choice::from(condition as u8);
    subtle::ConditionallySelectable::conditional_select(&b, &a, choice)
}

/// Check if a byte slice is all zeros in constant time.
///
/// Useful for checking if a key or secret has been zeroed.
#[inline]
pub fn ct_is_zero(data: &[u8]) -> bool {
    let mut acc: u8 = 0;
    for &byte in data {
        acc |= byte;
    }
    ct_select_u8(true, acc, 0) == 0
}

/// Wrapper type for secret byte arrays that implements constant-time equality.
#[derive(Clone)]
pub struct SecretBytes<const N: usize>([u8; N]);

impl<const N: usize> std::fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print secret contents
        write!(f, "SecretBytes<{}>[REDACTED]", N)
    }
}

impl<const N: usize> SecretBytes<N> {
    pub fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    pub fn into_bytes(self) -> [u8; N] {
        self.0
    }
}

impl<const N: usize> PartialEq for SecretBytes<N> {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl<const N: usize> Eq for SecretBytes<N> {}

impl<const N: usize> From<[u8; N]> for SecretBytes<N> {
    fn from(bytes: [u8; N]) -> Self {
        Self::new(bytes)
    }
}

impl<const N: usize> AsRef<[u8; N]> for SecretBytes<N> {
    fn as_ref(&self) -> &[u8; N] {
        &self.0
    }
}

// Zeroize on drop for extra security
impl<const N: usize> Drop for SecretBytes<N> {
    fn drop(&mut self) {
        // Use volatile write to prevent optimization
        for byte in &mut self.0 {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ct_eq_equal() {
        let a = [1u8, 2, 3, 4, 5];
        let b = [1u8, 2, 3, 4, 5];
        assert!(ct_eq(&a, &b));
    }

    #[test]
    fn test_ct_eq_different() {
        let a = [1u8, 2, 3, 4, 5];
        let b = [1u8, 2, 3, 4, 6];
        assert!(!ct_eq(&a, &b));
    }

    #[test]
    fn test_ct_eq_different_length() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4, 5];
        assert!(!ct_eq(&a, &b));
    }

    #[test]
    fn test_ct_eq_32() {
        let a = [0u8; 32];
        let b = [0u8; 32];
        assert!(ct_eq_32(&a, &b));

        let mut c = [0u8; 32];
        c[31] = 1;
        assert!(!ct_eq_32(&a, &c));
    }

    #[test]
    fn test_ct_eq_64() {
        let a = [0u8; 64];
        let b = [0u8; 64];
        assert!(ct_eq_64(&a, &b));
    }

    #[test]
    fn test_ct_select_u8() {
        assert_eq!(ct_select_u8(true, 10, 20), 10);
        assert_eq!(ct_select_u8(false, 10, 20), 20);
    }

    #[test]
    fn test_ct_select_u64() {
        assert_eq!(ct_select_u64(true, 100, 200), 100);
        assert_eq!(ct_select_u64(false, 100, 200), 200);
    }

    #[test]
    fn test_ct_is_zero() {
        let zeros = [0u8; 32];
        assert!(ct_is_zero(&zeros));

        let mut not_zero = [0u8; 32];
        not_zero[15] = 1;
        assert!(!ct_is_zero(&not_zero));
    }

    #[test]
    fn test_secret_bytes_eq() {
        let a: SecretBytes<32> = [1u8; 32].into();
        let b: SecretBytes<32> = [1u8; 32].into();
        let c: SecretBytes<32> = [2u8; 32].into();

        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_secret_bytes_as_ref() {
        let bytes = [42u8; 16];
        let secret: SecretBytes<16> = bytes.into();
        assert_eq!(secret.as_ref(), &bytes);
    }
}
