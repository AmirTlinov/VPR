//! VPN configuration exchange protocol
//!
//! After Noise handshake, server sends VpnConfig to client with:
//! - Allocated IP address
//! - Gateway address
//! - DNS servers
//! - Routes to push
//!
//! Wire format: length-prefixed JSON for simplicity and extensibility.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum config message size (64KB)
const MAX_CONFIG_SIZE: usize = 65536;

/// VPN configuration sent from server to client after handshake
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnConfig {
    /// Client's allocated IP address
    pub client_ip: Ipv4Addr,
    /// Netmask for the VPN network
    pub netmask: Ipv4Addr,
    /// Gateway IP (server's TUN address)
    pub gateway: Ipv4Addr,
    /// DNS servers to use (optional)
    #[serde(default)]
    pub dns_servers: Vec<IpAddr>,
    /// Routes to push to client (CIDR notation)
    #[serde(default)]
    pub routes: Vec<String>,
    /// MTU for TUN device
    pub mtu: u16,
    /// Session ID for reconnection
    #[serde(default)]
    pub session_id: Option<String>,
    /// Padding strategy name (none|bucket|rand-bucket|mtu)
    #[serde(default)]
    pub padding_strategy: Option<String>,
    /// Max jitter for padding (microseconds)
    #[serde(default)]
    pub padding_max_jitter_us: Option<u64>,
    /// Minimum packet size after padding
    #[serde(default)]
    pub padding_min_size: Option<usize>,
    /// MTU to use for padding calculations
    #[serde(default)]
    pub padding_mtu: Option<u16>,
    /// Session rekey interval in seconds (server-driven)
    #[serde(default)]
    pub session_rekey_secs: Option<u64>,
    /// Session rekey data limit in bytes (server-driven)
    #[serde(default)]
    pub session_rekey_bytes: Option<u64>,
}

impl VpnConfig {
    /// Create a basic VPN config
    pub fn new(client_ip: Ipv4Addr, gateway: Ipv4Addr) -> Self {
        Self {
            client_ip,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            gateway,
            dns_servers: vec![],
            routes: vec![],
            mtu: 1400,
            session_id: None,
            padding_strategy: None,
            padding_max_jitter_us: None,
            padding_min_size: None,
            padding_mtu: None,
            session_rekey_secs: None,
            session_rekey_bytes: None,
        }
    }

    /// Add DNS server
    pub fn with_dns(mut self, dns: IpAddr) -> Self {
        self.dns_servers.push(dns);
        self
    }

    /// Set session rekey thresholds so client matches server policy
    pub fn with_rotation(mut self, secs: u64, bytes: u64) -> Self {
        self.session_rekey_secs = Some(secs);
        self.session_rekey_bytes = Some(bytes);
        self
    }

    /// Add route
    pub fn with_route(mut self, route: impl Into<String>) -> Self {
        self.routes.push(route.into());
        self
    }

    /// Set MTU
    pub fn with_mtu(mut self, mtu: u16) -> Self {
        self.mtu = mtu;
        self
    }

    /// Set session ID
    pub fn with_session_id(mut self, id: impl Into<String>) -> Self {
        self.session_id = Some(id.into());
        self
    }

    /// Set padding parameters to sync client/server behavior
    pub fn with_padding(
        mut self,
        strategy: impl Into<String>,
        max_jitter_us: u64,
        min_size: usize,
        mtu: u16,
    ) -> Self {
        self.padding_strategy = Some(strategy.into());
        self.padding_max_jitter_us = Some(max_jitter_us);
        self.padding_min_size = Some(min_size);
        self.padding_mtu = Some(mtu);
        self
    }

    /// Serialize to bytes (length-prefixed JSON)
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let json = serde_json::to_vec(self).context("serializing VpnConfig")?;
        if json.len() > MAX_CONFIG_SIZE {
            bail!("VpnConfig too large: {} bytes", json.len());
        }

        let mut buf = Vec::with_capacity(4 + json.len());
        buf.extend_from_slice(&(json.len() as u32).to_be_bytes());
        buf.extend_from_slice(&json);
        Ok(buf)
    }

    /// Deserialize from bytes (length-prefixed JSON)
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            bail!("VpnConfig data too short");
        }

        let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if len > MAX_CONFIG_SIZE {
            bail!("VpnConfig too large: {} bytes", len);
        }
        if data.len() < 4 + len {
            bail!("VpnConfig truncated: expected {} bytes", len);
        }

        serde_json::from_slice(&data[4..4 + len]).context("deserializing VpnConfig")
    }

    /// Send config over async stream
    pub async fn send<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<()> {
        let bytes = self.to_bytes()?;
        writer
            .write_all(&bytes)
            .await
            .context("writing VpnConfig")?;
        writer.flush().await.context("flushing VpnConfig")?;
        Ok(())
    }

    /// Receive config from async stream
    pub async fn recv<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        // Read length prefix
        let mut len_buf = [0u8; 4];
        reader
            .read_exact(&mut len_buf)
            .await
            .context("reading VpnConfig length")?;

        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_CONFIG_SIZE {
            bail!("VpnConfig too large: {} bytes", len);
        }

        // Read JSON payload
        let mut json_buf = vec![0u8; len];
        reader
            .read_exact(&mut json_buf)
            .await
            .context("reading VpnConfig payload")?;

        serde_json::from_slice(&json_buf).context("deserializing VpnConfig")
    }
}

/// Client acknowledgment sent back to server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigAck {
    /// Whether client accepted the config
    pub accepted: bool,
    /// Error message if not accepted
    #[serde(default)]
    pub error: Option<String>,
}

impl ConfigAck {
    pub fn ok() -> Self {
        Self {
            accepted: true,
            error: None,
        }
    }

    pub fn error(msg: impl Into<String>) -> Self {
        Self {
            accepted: false,
            error: Some(msg.into()),
        }
    }

    /// Send ack over async stream
    pub async fn send<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<()> {
        let json = serde_json::to_vec(self).context("serializing ConfigAck")?;
        let len = (json.len() as u32).to_be_bytes();
        writer.write_all(&len).await?;
        writer.write_all(&json).await?;
        writer.flush().await?;
        Ok(())
    }

    /// Receive ack from async stream
    pub async fn recv<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;

        if len > 4096 {
            bail!("ConfigAck too large");
        }

        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf).await?;
        serde_json::from_slice(&buf).context("deserializing ConfigAck")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_config_propagation_roundtrip() {
        let config = VpnConfig::new(Ipv4Addr::new(10, 8, 0, 5), Ipv4Addr::new(10, 8, 0, 1))
            .with_dns(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
            .with_dns(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
            .with_route("0.0.0.0/0")
            .with_mtu(1400);

        let bytes = config.to_bytes().unwrap();
        let parsed = VpnConfig::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.client_ip, config.client_ip);
        assert_eq!(parsed.gateway, config.gateway);
        assert_eq!(parsed.dns_servers.len(), 2);
        assert_eq!(parsed.dns_servers[0], IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(parsed.routes.len(), 1);
        assert_eq!(parsed.mtu, 1400);
    }

    #[test]
    fn test_config_ack_roundtrip() {
        let ack = ConfigAck::ok();
        let json = serde_json::to_vec(&ack).unwrap();
        let parsed: ConfigAck = serde_json::from_slice(&json).unwrap();
        assert!(parsed.accepted);
        assert!(parsed.error.is_none());

        let ack = ConfigAck::error("test error");
        let json = serde_json::to_vec(&ack).unwrap();
        let parsed: ConfigAck = serde_json::from_slice(&json).unwrap();
        assert!(!parsed.accepted);
        assert_eq!(parsed.error.as_deref(), Some("test error"));
    }

    #[test]
    fn test_vpn_config_builder() {
        let config = VpnConfig::new(Ipv4Addr::new(10, 8, 0, 2), Ipv4Addr::new(10, 8, 0, 1))
            .with_session_id("abc123");

        assert_eq!(config.session_id, Some("abc123".to_string()));
    }

    #[test]
    fn test_vpn_config_rotation_roundtrip() {
        let config = VpnConfig::new(Ipv4Addr::new(10, 8, 0, 2), Ipv4Addr::new(10, 8, 0, 1))
            .with_rotation(42, 2048);

        let bytes = config.to_bytes().unwrap();
        let parsed = VpnConfig::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.session_rekey_secs, Some(42));
        assert_eq!(parsed.session_rekey_bytes, Some(2048));
    }

    #[test]
    fn test_vpn_config_dns_ipv6_roundtrip() {
        let config = VpnConfig::new(Ipv4Addr::new(10, 8, 0, 2), Ipv4Addr::new(10, 8, 0, 1))
            .with_dns(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)))
            .with_dns(IpAddr::V6("2001:4860:4860::8888".parse().unwrap()));

        let bytes = config.to_bytes().unwrap();
        let parsed = VpnConfig::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.dns_servers.len(), 2);
        assert_eq!(parsed.dns_servers[0], IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)));
        assert_eq!(
            parsed.dns_servers[1],
            IpAddr::V6("2001:4860:4860::8888".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn test_async_send_recv() {
        let config = VpnConfig::new(Ipv4Addr::new(10, 8, 0, 10), Ipv4Addr::new(10, 8, 0, 1));

        let (mut client, mut server) = tokio::io::duplex(1024);

        let send_task = tokio::spawn(async move {
            config.send(&mut client).await.unwrap();
        });

        let recv_task = tokio::spawn(async move { VpnConfig::recv(&mut server).await.unwrap() });

        send_task.await.unwrap();
        let received = recv_task.await.unwrap();

        assert_eq!(received.client_ip, Ipv4Addr::new(10, 8, 0, 10));
    }
}
