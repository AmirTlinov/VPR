//! Server state management for VPN client sessions.

use super::{generate_session_id, IpPool, SESSION_TIMEOUT};
use bytes::Bytes;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;
use tracing::debug;
use vpr_crypto::ct_eq_32;

use crate::key_rotation::SessionKeyState;

/// Active client session with allocated IP and connection
pub struct ClientSession {
    #[allow(dead_code)]
    pub connection: quinn::Connection,
    #[allow(dead_code)]
    pub allocated_ip: Ipv4Addr,
    /// IPv6 address derived from IPv4 (ULA fd09::/64 + IPv4 suffix)
    #[allow(dead_code)]
    pub allocated_ip6: Ipv6Addr,
    pub tx: mpsc::Sender<Bytes>,
    #[allow(dead_code)]
    pub session_state: Arc<SessionKeyState>,
}

/// Persistent session info for reconnection support
pub struct SessionInfo {
    /// Allocated IP address for this session
    pub allocated_ip: Ipv4Addr,
    /// Client's Noise public key (for identity verification)
    #[allow(dead_code)]
    pub client_pubkey: [u8; 32],
    /// When session was last active
    pub last_seen: Instant,
}

/// Shared server state containing all client sessions and IP pool
pub struct ServerState {
    /// Active client sessions indexed by their allocated IPv4
    pub clients: HashMap<Ipv4Addr, ClientSession>,
    /// Active client senders indexed by their allocated IPv6 (for IPv6 packet routing)
    pub clients_v6: HashMap<Ipv6Addr, mpsc::Sender<Bytes>>,
    /// Persistent sessions indexed by session_id (for reconnect)
    pub sessions: HashMap<String, SessionInfo>,
    /// IP address pool
    pub ip_pool: IpPool,
}

impl ServerState {
    /// Create a new server state with the given IP pool range
    pub fn new(pool_start: Ipv4Addr, pool_end: Ipv4Addr) -> Self {
        Self {
            clients: HashMap::new(),
            clients_v6: HashMap::new(),
            sessions: HashMap::new(),
            ip_pool: IpPool::new(pool_start, pool_end),
        }
    }

    /// Try to restore session by session_id
    #[allow(dead_code)]
    pub fn restore_session(&mut self, session_id: &str, client_pubkey: &[u8; 32]) -> Option<Ipv4Addr> {
        if let Some(session) = self.sessions.get(session_id) {
            // Verify client identity and session freshness
            // Use constant-time comparison to prevent timing attacks
            if ct_eq_32(&session.client_pubkey, client_pubkey)
                && session.last_seen.elapsed() < SESSION_TIMEOUT
            {
                return Some(session.allocated_ip);
            }
        }
        None
    }

    /// Create new session with IP allocation
    pub fn create_session(&mut self, client_pubkey: [u8; 32]) -> Option<(String, Ipv4Addr)> {
        let ip = self.ip_pool.allocate()?;
        let session_id = generate_session_id();

        self.sessions.insert(
            session_id.clone(),
            SessionInfo {
                allocated_ip: ip,
                client_pubkey,
                last_seen: Instant::now(),
            },
        );

        Some((session_id, ip))
    }

    /// Update session last_seen time
    pub fn touch_session(&mut self, session_id: &str) {
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.last_seen = Instant::now();
        }
    }

    /// Cleanup expired sessions and release their IPs
    pub fn cleanup_expired_sessions(&mut self) {
        let expired: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.last_seen.elapsed() > SESSION_TIMEOUT)
            .map(|(id, _)| id.clone())
            .collect();

        for id in expired {
            if let Some(session) = self.sessions.remove(&id) {
                self.ip_pool.release(session.allocated_ip);
                debug!(session_id = %id, "Session expired and cleaned up");
            }
        }
    }

    /// Get count of active clients
    pub fn active_client_count(&self) -> usize {
        self.clients.len()
    }

    /// Get count of preserved sessions (may be reconnectable)
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}
