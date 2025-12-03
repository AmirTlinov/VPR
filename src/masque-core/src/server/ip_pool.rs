//! IP address pool management for VPN clients.

use anyhow::{bail, Result};
use std::net::Ipv4Addr;

/// Maximum pool size to prevent memory exhaustion (16M addresses = 16MB bitmap)
const MAX_POOL_SIZE: u64 = 16 * 1024 * 1024;

/// IP address pool for allocating client addresses.
///
/// Uses a simple bitmap to track allocated addresses in a contiguous range.
///
/// # Security
/// - Validates range to prevent integer overflow
/// - Limits pool size to prevent memory exhaustion
/// - Safe from underflow when end < start
#[derive(Debug)]
pub struct IpPool {
    start: u32,
    end: u32,
    allocated: Vec<bool>,
}

impl IpPool {
    /// Create a new IP pool with the given range (inclusive)
    ///
    /// # Errors
    /// - Returns error if end address is less than start address
    /// - Returns error if pool size exceeds MAX_POOL_SIZE
    pub fn new(start: Ipv4Addr, end: Ipv4Addr) -> Result<Self> {
        let start_u32 = u32::from(start);
        let end_u32 = u32::from(end);

        // Security: Prevent underflow/overflow
        if end_u32 < start_u32 {
            bail!(
                "Invalid IP pool range: end ({}) must be >= start ({})",
                end,
                start
            );
        }

        // Calculate size using u64 to prevent overflow
        let size_u64 = (end_u32 as u64) - (start_u32 as u64) + 1;

        // Security: Prevent memory exhaustion
        if size_u64 > MAX_POOL_SIZE {
            bail!(
                "IP pool too large: {} addresses exceeds maximum of {}",
                size_u64,
                MAX_POOL_SIZE
            );
        }

        // Safe to cast now - we've verified it fits
        let size = size_u64 as usize;

        Ok(Self {
            start: start_u32,
            end: end_u32,
            allocated: vec![false; size],
        })
    }

    /// Allocate the next available IP address
    pub fn allocate(&mut self) -> Option<Ipv4Addr> {
        for (i, used) in self.allocated.iter_mut().enumerate() {
            if !*used {
                *used = true;
                return Some(Ipv4Addr::from(self.start + i as u32));
            }
        }
        None
    }

    /// Release an IP address back to the pool
    pub fn release(&mut self, ip: Ipv4Addr) {
        let ip_u32 = u32::from(ip);
        if ip_u32 >= self.start && ip_u32 <= self.end {
            let idx = (ip_u32 - self.start) as usize;
            if idx < self.allocated.len() {
                self.allocated[idx] = false;
            }
        }
    }

    /// Get the number of available addresses
    pub fn available(&self) -> usize {
        self.allocated.iter().filter(|&&used| !used).count()
    }

    /// Get the total pool size
    pub fn capacity(&self) -> usize {
        self.allocated.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_allocates_sequentially() {
        let mut pool = IpPool::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 3))
            .expect("valid pool range");

        assert_eq!(pool.allocate(), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(pool.allocate(), Some(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(pool.allocate(), Some(Ipv4Addr::new(10, 0, 0, 3)));
        assert_eq!(pool.allocate(), None);
    }

    #[test]
    fn pool_release_allows_reuse() {
        let mut pool = IpPool::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
            .expect("valid pool range");

        let ip1 = pool.allocate().unwrap();
        let _ip2 = pool.allocate().unwrap();
        assert!(pool.allocate().is_none());

        pool.release(ip1);
        assert_eq!(pool.allocate(), Some(ip1));
    }

    #[test]
    fn pool_capacity_and_available() {
        let mut pool = IpPool::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 10))
            .expect("valid pool range");

        assert_eq!(pool.capacity(), 10);
        assert_eq!(pool.available(), 10);

        pool.allocate();
        pool.allocate();
        assert_eq!(pool.available(), 8);
    }

    #[test]
    fn pool_invalid_range_end_before_start() {
        // end < start should fail
        let result = IpPool::new(Ipv4Addr::new(10, 0, 0, 10), Ipv4Addr::new(10, 0, 0, 1));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be >= start"));
    }

    #[test]
    fn pool_single_address() {
        // Single address pool should work
        let mut pool = IpPool::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 1))
            .expect("valid single-address pool");

        assert_eq!(pool.capacity(), 1);
        assert_eq!(pool.allocate(), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(pool.allocate(), None);
    }
}
