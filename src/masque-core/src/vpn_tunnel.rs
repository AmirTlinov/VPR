//! VPN tunnel integration: TUN device <-> MASQUE CONNECT-UDP
//!
//! This module bridges the local TUN interface with the MASQUE tunnel,
//! forwarding IP packets through encrypted QUIC datagrams.

use crate::masque::UdpCapsule;
use crate::tun::{IpPacketInfo, TunConfig, TunReader, TunWriter};
use anyhow::{Context, Result};
use bytes::Bytes;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

/// VPN tunnel configuration
#[derive(Debug, Clone)]
pub struct VpnTunnelConfig {
    /// TUN device configuration
    pub tun: TunConfig,
    /// Server endpoint for MASQUE connection
    pub server_addr: String,
    /// Server name for TLS/QUIC
    pub server_name: String,
    /// Target address for CONNECT-UDP (typically server's internal IP)
    pub target_addr: Ipv4Addr,
    /// Target port
    pub target_port: u16,
}

impl VpnTunnelConfig {
    /// Create client configuration with default TUN settings
    pub fn client(
        tun_address: Ipv4Addr,
        server_addr: String,
        server_name: String,
        target_addr: Ipv4Addr,
    ) -> Self {
        Self {
            tun: TunConfig::client(tun_address),
            server_addr,
            server_name,
            target_addr,
            target_port: 0, // Will be assigned by server
        }
    }
}

/// Encapsulates IP packets for transport over MASQUE
///
/// IP packets from TUN are wrapped in UDP capsules for QUIC datagram transport.
/// The encapsulation format follows RFC 9297 (HTTP Datagrams).
#[derive(Debug)]
pub struct PacketEncapsulator {
    /// Context ID for this tunnel (0 for default)
    context_id: u64,
}

impl PacketEncapsulator {
    pub fn new() -> Self {
        Self { context_id: 0 }
    }

    /// Encapsulate IP packet for MASQUE transport
    pub fn encapsulate(&self, ip_packet: Bytes) -> Bytes {
        let capsule = UdpCapsule {
            context_id: self.context_id,
            payload: ip_packet,
        };
        capsule.encode()
    }

    /// Decapsulate MASQUE datagram to IP packet
    pub fn decapsulate(&self, datagram: Bytes) -> Result<Bytes> {
        let capsule = UdpCapsule::decode(datagram)?;
        if capsule.context_id != self.context_id {
            warn!(
                expected = self.context_id,
                got = capsule.context_id,
                "unexpected context ID"
            );
        }
        Ok(capsule.payload)
    }
}

impl Default for PacketEncapsulator {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for VPN tunnel
#[derive(Debug, Default)]
pub struct TunnelStats {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

/// Async task for reading TUN and sending to channel
pub async fn tun_to_channel(mut tun_reader: TunReader, tx: mpsc::Sender<Bytes>) -> Result<()> {
    loop {
        match tun_reader.read_packet().await {
            Ok(packet) => {
                // Validate packet structure before forwarding
                match IpPacketInfo::parse(&packet) {
                    Ok(info) => {
                        debug!(
                            src = %info.src_addr,
                            dst = %info.dst_addr,
                            proto = info.protocol_name(),
                            len = info.total_len,
                            "TUN packet"
                        );
                    }
                    Err(e) => {
                        warn!(%e, packet_len = packet.len(), "Invalid IP packet from TUN, dropping");
                        continue; // Drop invalid packets
                    }
                }

                if tx.send(packet).await.is_err() {
                    debug!("TUN reader: channel closed");
                    break;
                }
            }
            Err(e) => {
                error!(%e, "TUN read error");
                break;
            }
        }
    }
    Ok(())
}

/// Async task for receiving from channel and writing to TUN
pub async fn channel_to_tun(
    mut tun_writer: TunWriter,
    mut rx: mpsc::Receiver<Bytes>,
) -> Result<()> {
    while let Some(packet) = rx.recv().await {
        if let Err(e) = tun_writer.write_packet(&packet).await {
            error!(%e, "TUN write error");
            break;
        }
    }
    debug!("TUN writer: channel closed");
    Ok(())
}

/// Forward packets from TUN to QUIC connection
pub async fn forward_tun_to_quic(
    mut rx: mpsc::Receiver<Bytes>,
    connection: quinn::Connection,
    encapsulator: Arc<PacketEncapsulator>,
    padder: Option<Arc<crate::padding::Padder>>,
) -> Result<()> {
    while let Some(packet) = rx.recv().await {
        let payload = if let Some(p) = &padder {
            let padded = p.pad(&packet);
            if let Some(delay) = p.jitter_delay() {
                sleep(delay).await;
            }
            Bytes::from(padded)
        } else {
            packet
        };

        let datagram = encapsulator.encapsulate(payload);
        if let Err(e) = connection.send_datagram(datagram) {
            match e {
                quinn::SendDatagramError::ConnectionLost(_) => {
                    info!("QUIC connection lost");
                    break;
                }
                quinn::SendDatagramError::Disabled => {
                    error!("QUIC datagrams disabled");
                    break;
                }
                quinn::SendDatagramError::TooLarge => {
                    warn!("datagram too large, dropping");
                }
                _ => {
                    warn!(%e, "datagram send error");
                }
            }
        }
    }
    Ok(())
}

/// Forward packets from QUIC connection to TUN
pub async fn forward_quic_to_tun(
    connection: quinn::Connection,
    tx: mpsc::Sender<Bytes>,
    encapsulator: Arc<PacketEncapsulator>,
) -> Result<()> {
    loop {
        match connection.read_datagram().await {
            Ok(datagram) => match encapsulator.decapsulate(datagram) {
                Ok(packet) => {
                    if tx.send(packet).await.is_err() {
                        debug!("QUIC reader: TUN channel closed");
                        break;
                    }
                }
                Err(e) => {
                    warn!(%e, "decapsulation error");
                }
            },
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                info!("QUIC connection closed by application");
                break;
            }
            Err(quinn::ConnectionError::ConnectionClosed(_)) => {
                info!("QUIC connection closed");
                break;
            }
            Err(e) => {
                error!(%e, "QUIC datagram read error");
                break;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_encapsulation_roundtrip() {
        let encap = PacketEncapsulator::new();
        let original = Bytes::from_static(&[0x45, 0x00, 0x00, 0x28, 0x00, 0x00]);

        let encoded = encap.encapsulate(original.clone());
        let decoded = encap.decapsulate(encoded).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_encapsulator_context_id() {
        let encap = PacketEncapsulator::new();
        assert_eq!(encap.context_id, 0);
    }

    #[test]
    fn test_tunnel_stats_default() {
        let stats = TunnelStats::default();
        assert_eq!(stats.packets_sent, 0);
        assert_eq!(stats.bytes_received, 0);
    }

    #[test]
    fn test_vpn_config_client() {
        let config = VpnTunnelConfig::client(
            Ipv4Addr::new(10, 8, 0, 2),
            "example.com:443".into(),
            "example.com".into(),
            Ipv4Addr::new(10, 8, 0, 1),
        );

        assert_eq!(config.tun.address, Ipv4Addr::new(10, 8, 0, 2));
        assert_eq!(config.tun.name, "vpr0");
        assert_eq!(config.server_name, "example.com");
    }
}
