//! IP address pool management for VPN clients.

use std::net::Ipv4Addr;

/// IP address pool for allocating client addresses.
///
/// Uses a simple bitmap to track allocated addresses in a contiguous range.
#[derive(Debug)]
pub struct IpPool {
    start: u32,
    end: u32,
    allocated: Vec<bool>,
}

impl IpPool {
    /// Create a new IP pool with the given range (inclusive)
    pub fn new(start: Ipv4Addr, end: Ipv4Addr) -> Self {
        let start_u32 = u32::from(start);
        let end_u32 = u32::from(end);
        let size = (end_u32 - start_u32 + 1) as usize;

        Self {
            start: start_u32,
            end: end_u32,
            allocated: vec![false; size],
        }
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
        let mut pool = IpPool::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 3));

        assert_eq!(pool.allocate(), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(pool.allocate(), Some(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(pool.allocate(), Some(Ipv4Addr::new(10, 0, 0, 3)));
        assert_eq!(pool.allocate(), None);
    }

    #[test]
    fn pool_release_allows_reuse() {
        let mut pool = IpPool::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));

        let ip1 = pool.allocate().unwrap();
        let _ip2 = pool.allocate().unwrap();
        assert!(pool.allocate().is_none());

        pool.release(ip1);
        assert_eq!(pool.allocate(), Some(ip1));
    }

    #[test]
    fn pool_capacity_and_available() {
        let mut pool = IpPool::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 10));

        assert_eq!(pool.capacity(), 10);
        assert_eq!(pool.available(), 10);

        pool.allocate();
        pool.allocate();
        assert_eq!(pool.available(), 8);
    }
}
