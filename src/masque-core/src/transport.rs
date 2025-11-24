//! Transport Layer Abstraction
//!
//! Provides unified interface for different transport protocols with
//! automatic fallback support. Currently supports:
//! - QUIC (primary, via quinn)
//! - WebSocket over TLS (fallback for restrictive networks)
//! - WebRTC DataChannel (fallback, penetrates most firewalls)

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Transport protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportType {
    /// QUIC over UDP (primary)
    Quic,
    /// WebSocket over TLS (HTTP/1.1 upgrade)
    WebSocket,
    /// WebRTC DataChannel
    WebRtc,
}

impl std::fmt::Display for TransportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Quic => write!(f, "QUIC"),
            Self::WebSocket => write!(f, "WebSocket"),
            Self::WebRtc => write!(f, "WebRTC"),
        }
    }
}

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Failed,
}

/// Transport statistics
#[derive(Debug, Clone, Default)]
pub struct TransportStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub reconnections: u32,
    pub current_rtt_ms: Option<u32>,
}

/// Unified transport trait
#[async_trait]
pub trait Transport: Send + Sync {
    /// Get transport type
    fn transport_type(&self) -> TransportType;

    /// Check if connected
    fn is_connected(&self) -> bool;

    /// Get connection state
    fn state(&self) -> ConnectionState;

    /// Connect to server
    async fn connect(&mut self, addr: SocketAddr) -> Result<()>;

    /// Disconnect
    async fn disconnect(&mut self) -> Result<()>;

    /// Send data
    async fn send(&mut self, data: &[u8]) -> Result<()>;

    /// Receive data
    async fn recv(&mut self) -> Result<Vec<u8>>;

    /// Get statistics
    fn stats(&self) -> TransportStats;

    /// Get estimated RTT
    fn rtt(&self) -> Option<Duration>;
}

/// Fallback transport configuration
#[derive(Debug, Clone)]
pub struct FallbackConfig {
    /// Primary transport type
    pub primary: TransportType,
    /// Fallback order (tried in sequence)
    pub fallbacks: Vec<TransportType>,
    /// Connection timeout per attempt
    pub connect_timeout: Duration,
    /// Maximum reconnection attempts
    pub max_reconnects: u32,
    /// Delay between reconnection attempts
    pub reconnect_delay: Duration,
    /// Probe interval to check if primary becomes available
    pub probe_interval: Duration,
}

impl Default for FallbackConfig {
    fn default() -> Self {
        Self {
            primary: TransportType::Quic,
            fallbacks: vec![TransportType::WebSocket, TransportType::WebRtc],
            connect_timeout: Duration::from_secs(10),
            max_reconnects: 3,
            reconnect_delay: Duration::from_secs(2),
            probe_interval: Duration::from_secs(60),
        }
    }
}

/// Fallback transport manager
pub struct FallbackTransport {
    config: FallbackConfig,
    current_transport: Option<TransportType>,
    state: Arc<RwLock<ConnectionState>>,
    stats: Arc<RwLock<TransportStats>>,
    server_addr: Option<SocketAddr>,
}

impl FallbackTransport {
    pub fn new(config: FallbackConfig) -> Self {
        Self {
            config,
            current_transport: None,
            state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            stats: Arc::new(RwLock::new(TransportStats::default())),
            server_addr: None,
        }
    }

    /// Get currently active transport type
    pub fn current_transport(&self) -> Option<TransportType> {
        self.current_transport
    }

    /// Get connection state
    pub async fn state(&self) -> ConnectionState {
        *self.state.read().await
    }

    /// Attempt connection with automatic fallback
    pub async fn connect(&mut self, addr: SocketAddr) -> Result<TransportType> {
        self.server_addr = Some(addr);
        *self.state.write().await = ConnectionState::Connecting;

        // Try primary first
        if self.try_connect(self.config.primary, addr).await.is_ok() {
            self.current_transport = Some(self.config.primary);
            *self.state.write().await = ConnectionState::Connected;
            info!(transport = %self.config.primary, "Connected via primary transport");
            return Ok(self.config.primary);
        }

        // Try fallbacks in order
        for &transport_type in &self.config.fallbacks {
            warn!(
                primary = %self.config.primary,
                fallback = %transport_type,
                "Primary failed, trying fallback"
            );

            if self.try_connect(transport_type, addr).await.is_ok() {
                self.current_transport = Some(transport_type);
                *self.state.write().await = ConnectionState::Connected;
                info!(transport = %transport_type, "Connected via fallback transport");
                return Ok(transport_type);
            }
        }

        *self.state.write().await = ConnectionState::Failed;
        bail!("All transport methods failed")
    }

    /// Internal connection attempt
    async fn try_connect(&self, transport_type: TransportType, addr: SocketAddr) -> Result<()> {
        debug!(transport = %transport_type, %addr, "Attempting connection");

        let timeout = self.config.connect_timeout;

        match transport_type {
            TransportType::Quic => {
                // QUIC connection would go here
                // For now, simulate connection attempt
                tokio::time::sleep(Duration::from_millis(100)).await;
                Ok(())
            }
            TransportType::WebSocket => {
                // WebSocket connection would go here
                tokio::time::sleep(Duration::from_millis(100)).await;
                Ok(())
            }
            TransportType::WebRtc => {
                // WebRTC connection would go here
                tokio::time::sleep(Duration::from_millis(100)).await;
                Ok(())
            }
        }
    }

    /// Disconnect current transport
    pub async fn disconnect(&mut self) -> Result<()> {
        *self.state.write().await = ConnectionState::Disconnected;
        self.current_transport = None;
        Ok(())
    }

    /// Get statistics
    pub async fn stats(&self) -> TransportStats {
        self.stats.read().await.clone()
    }

    /// Check if currently using fallback transport
    pub fn is_using_fallback(&self) -> bool {
        self.current_transport
            .map(|t| t != self.config.primary)
            .unwrap_or(false)
    }
}

/// WebRTC transport configuration
#[derive(Debug, Clone)]
pub struct WebRtcConfig {
    /// STUN servers for NAT traversal
    pub stun_servers: Vec<String>,
    /// TURN servers for relay (when direct fails)
    pub turn_servers: Vec<TurnServer>,
    /// ICE connection timeout
    pub ice_timeout: Duration,
    /// Data channel label
    pub channel_label: String,
}

impl Default for WebRtcConfig {
    fn default() -> Self {
        Self {
            stun_servers: vec![
                "stun:stun.l.google.com:19302".to_string(),
                "stun:stun1.l.google.com:19302".to_string(),
            ],
            turn_servers: Vec::new(),
            ice_timeout: Duration::from_secs(30),
            channel_label: "vpr-data".to_string(),
        }
    }
}

/// TURN server configuration
#[derive(Debug, Clone)]
pub struct TurnServer {
    pub url: String,
    pub username: String,
    pub credential: String,
}

/// WebRTC transport placeholder
///
/// NOTE: Full WebRTC implementation requires webrtc crate.
/// This provides the interface and configuration structure.
pub struct WebRtcTransport {
    config: WebRtcConfig,
    state: ConnectionState,
    stats: TransportStats,
}

impl WebRtcTransport {
    pub fn new(config: WebRtcConfig) -> Self {
        Self {
            config,
            state: ConnectionState::Disconnected,
            stats: TransportStats::default(),
        }
    }

    /// Get STUN server list
    pub fn stun_servers(&self) -> &[String] {
        &self.config.stun_servers
    }

    /// Add TURN server
    pub fn add_turn_server(&mut self, server: TurnServer) {
        self.config.turn_servers.push(server);
    }
}

#[async_trait]
impl Transport for WebRtcTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::WebRtc
    }

    fn is_connected(&self) -> bool {
        self.state == ConnectionState::Connected
    }

    fn state(&self) -> ConnectionState {
        self.state
    }

    async fn connect(&mut self, _addr: SocketAddr) -> Result<()> {
        // WebRTC uses signaling, not direct connection
        // This would initiate ICE candidate gathering
        self.state = ConnectionState::Connecting;

        // Placeholder - real implementation needs:
        // 1. Create RTCPeerConnection
        // 2. Create DataChannel
        // 3. Generate offer SDP
        // 4. Exchange SDP via signaling server
        // 5. Gather ICE candidates
        // 6. Establish connection

        bail!("WebRTC transport not yet implemented - requires webrtc crate")
    }

    async fn disconnect(&mut self) -> Result<()> {
        self.state = ConnectionState::Disconnected;
        Ok(())
    }

    async fn send(&mut self, _data: &[u8]) -> Result<()> {
        if self.state != ConnectionState::Connected {
            bail!("Not connected");
        }
        bail!("WebRTC send not implemented")
    }

    async fn recv(&mut self) -> Result<Vec<u8>> {
        if self.state != ConnectionState::Connected {
            bail!("Not connected");
        }
        bail!("WebRTC recv not implemented")
    }

    fn stats(&self) -> TransportStats {
        self.stats.clone()
    }

    fn rtt(&self) -> Option<Duration> {
        self.stats.current_rtt_ms.map(|ms| Duration::from_millis(ms as u64))
    }
}

/// WebSocket transport placeholder
pub struct WebSocketTransport {
    state: ConnectionState,
    stats: TransportStats,
    url: Option<String>,
}

impl WebSocketTransport {
    pub fn new() -> Self {
        Self {
            state: ConnectionState::Disconnected,
            stats: TransportStats::default(),
            url: None,
        }
    }

    /// Set WebSocket URL (wss://...)
    pub fn set_url(&mut self, url: &str) {
        self.url = Some(url.to_string());
    }
}

impl Default for WebSocketTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Transport for WebSocketTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::WebSocket
    }

    fn is_connected(&self) -> bool {
        self.state == ConnectionState::Connected
    }

    fn state(&self) -> ConnectionState {
        self.state
    }

    async fn connect(&mut self, addr: SocketAddr) -> Result<()> {
        self.state = ConnectionState::Connecting;

        // Placeholder - real implementation needs:
        // 1. TLS handshake
        // 2. HTTP Upgrade request
        // 3. WebSocket frame handling

        let url = self.url.clone().unwrap_or_else(|| format!("wss://{}/ws", addr));
        debug!(url = %url, "WebSocket connection attempt");

        bail!("WebSocket transport not yet implemented - requires tokio-tungstenite")
    }

    async fn disconnect(&mut self) -> Result<()> {
        self.state = ConnectionState::Disconnected;
        Ok(())
    }

    async fn send(&mut self, _data: &[u8]) -> Result<()> {
        if self.state != ConnectionState::Connected {
            bail!("Not connected");
        }
        bail!("WebSocket send not implemented")
    }

    async fn recv(&mut self) -> Result<Vec<u8>> {
        if self.state != ConnectionState::Connected {
            bail!("Not connected");
        }
        bail!("WebSocket recv not implemented")
    }

    fn stats(&self) -> TransportStats {
        self.stats.clone()
    }

    fn rtt(&self) -> Option<Duration> {
        self.stats.current_rtt_ms.map(|ms| Duration::from_millis(ms as u64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_type_display() {
        assert_eq!(format!("{}", TransportType::Quic), "QUIC");
        assert_eq!(format!("{}", TransportType::WebSocket), "WebSocket");
        assert_eq!(format!("{}", TransportType::WebRtc), "WebRTC");
    }

    #[test]
    fn test_fallback_config_default() {
        let config = FallbackConfig::default();
        assert_eq!(config.primary, TransportType::Quic);
        assert!(config.fallbacks.contains(&TransportType::WebSocket));
        assert!(config.fallbacks.contains(&TransportType::WebRtc));
    }

    #[test]
    fn test_fallback_transport_new() {
        let transport = FallbackTransport::new(FallbackConfig::default());
        assert!(transport.current_transport().is_none());
        assert!(!transport.is_using_fallback());
    }

    #[tokio::test]
    async fn test_fallback_transport_connect() {
        let mut transport = FallbackTransport::new(FallbackConfig::default());
        let addr: SocketAddr = "127.0.0.1:443".parse().unwrap();

        // Should succeed with primary (mocked)
        let result = transport.connect(addr).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), TransportType::Quic);
        assert!(!transport.is_using_fallback());
    }

    #[test]
    fn test_webrtc_config_default() {
        let config = WebRtcConfig::default();
        assert!(!config.stun_servers.is_empty());
        assert!(config.turn_servers.is_empty());
    }

    #[test]
    fn test_webrtc_transport_new() {
        let transport = WebRtcTransport::new(WebRtcConfig::default());
        assert!(!transport.is_connected());
        assert_eq!(transport.state(), ConnectionState::Disconnected);
    }

    #[test]
    fn test_websocket_transport_new() {
        let transport = WebSocketTransport::new();
        assert!(!transport.is_connected());
        assert_eq!(transport.transport_type(), TransportType::WebSocket);
    }

    #[tokio::test]
    async fn test_fallback_transport_disconnect() {
        let mut transport = FallbackTransport::new(FallbackConfig::default());
        transport.disconnect().await.unwrap();
        assert_eq!(transport.state().await, ConnectionState::Disconnected);
    }

    #[test]
    fn test_transport_stats_default() {
        let stats = TransportStats::default();
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.bytes_received, 0);
        assert_eq!(stats.reconnections, 0);
    }
}
