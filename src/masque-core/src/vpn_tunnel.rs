//! VPN tunnel integration: TUN device <-> MASQUE CONNECT-UDP
//!
//! This module bridges the local TUN interface with the MASQUE tunnel,
//! forwarding IP packets through encrypted QUIC datagrams.

use crate::cover_traffic::CoverTrafficGenerator;
use crate::dpi_feedback::DpiFeedbackController;
use crate::key_rotation::SessionKeyState;
use crate::masque::UdpCapsule;
use crate::suspicion::SuspicionTracker;
use crate::traffic_monitor::TrafficMonitor;
use crate::tun::{IpPacketInfo, TunConfig, TunReader, TunWriter};
use anyhow::Result;
use bytes::Bytes;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{interval, sleep, Duration};
use tracing::{debug, error, info, trace, warn};

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
        let capsule = UdpCapsule::with_context_id(self.context_id, ip_packet);
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
    let mut consecutive_errors = 0u32;
    const MAX_CONSECUTIVE_ERRORS: u32 = 10;

    while let Some(packet) = rx.recv().await {
        // Validate packet before writing to TUN
        if packet.is_empty() {
            trace!("Skipping empty packet");
            continue;
        }

        // Check IP version (first 4 bits)
        let version = packet[0] >> 4;
        if version != 4 && version != 6 {
            trace!(
                version = version,
                len = packet.len(),
                "Skipping non-IP packet (possibly cover traffic)"
            );
            continue;
        }

        // Validate minimum packet length
        let min_len = if version == 4 { 20 } else { 40 };
        if packet.len() < min_len {
            warn!(
                version = version,
                len = packet.len(),
                min_len = min_len,
                "Skipping truncated IP packet"
            );
            continue;
        }

        if let Err(e) = tun_writer.write_packet(&packet).await {
            consecutive_errors += 1;
            warn!(
                %e,
                consecutive_errors,
                packet_len = packet.len(),
                "TUN write error"
            );

            if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                error!(
                    consecutive_errors,
                    "Too many consecutive TUN write errors, stopping"
                );
                break;
            }
        } else {
            consecutive_errors = 0;
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
    tracker: Option<Arc<SessionKeyState>>,
    dpi_feedback: Option<Arc<DpiFeedbackController>>,
    traffic_monitor: Option<Arc<TrafficMonitor>>,
) -> Result<()> {
    while let Some(packet) = rx.recv().await {
        // Update padder suspicion based on DPI feedback if available
        // The padder will use its adaptive strategy selection based on suspicion bucket
        if let Some(feedback) = &dpi_feedback {
            if let Some(p) = &padder {
                let suspicion = feedback.current_suspicion();
                p.update_suspicion(suspicion);
            }
        }

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

        // Record traffic in monitor
        if let Some(monitor) = &traffic_monitor {
            monitor.record_packet(datagram.len());
        }

        if let Some(state) = &tracker {
            state.record_bytes(datagram.len() as u64);
            state.maybe_rotate_with(|reason| {
                info!(?reason, "Client session rekey (tx)");
                connection.force_key_update();
            });
        }
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

/// Background task to periodically update suspicion score in DPI feedback controller
/// from SuspicionTracker
pub async fn suspicion_update_task(
    suspicion_tracker: Arc<SuspicionTracker>,
    dpi_feedback: Arc<DpiFeedbackController>,
) -> Result<()> {
    let update_interval = dpi_feedback.update_interval();
    let mut interval_timer = interval(update_interval);

    loop {
        interval_timer.tick().await;
        let score = suspicion_tracker.current();
        dpi_feedback.update_suspicion(score);
        trace!(
            suspicion = %score,
            bucket = ?dpi_feedback.current_bucket(),
            "Updated suspicion score from tracker"
        );
    }
}

/// Background task to periodically update cover traffic generator with real traffic rate
/// from TrafficMonitor
pub async fn traffic_monitor_update_task(
    traffic_monitor: Arc<TrafficMonitor>,
    cover_generator: Arc<tokio::sync::Mutex<CoverTrafficGenerator>>,
    update_interval: Duration,
) -> Result<()> {
    let mut interval_timer = interval(update_interval);

    loop {
        interval_timer.tick().await;
        let real_traffic_rate = traffic_monitor.get_packets_per_sec();

        // Update cover traffic generator with real traffic rate
        let mut gen = cover_generator.lock().await;
        gen.update_real_traffic_rate(real_traffic_rate);

        trace!(
            real_traffic_rate = %real_traffic_rate,
            "Updated cover traffic generator with real traffic rate"
        );
    }
}

/// Forward packets from QUIC connection to TUN
pub async fn forward_quic_to_tun(
    connection: quinn::Connection,
    tx: mpsc::Sender<Bytes>,
    encapsulator: Arc<PacketEncapsulator>,
    tracker: Option<Arc<SessionKeyState>>,
    traffic_monitor: Option<Arc<TrafficMonitor>>,
) -> Result<()> {
    loop {
        match connection.read_datagram().await {
            Ok(datagram) => {
                // Record traffic in monitor
                if let Some(monitor) = &traffic_monitor {
                    monitor.record_packet(datagram.len());
                }

                if let Some(state) = &tracker {
                    state.record_bytes(datagram.len() as u64);
                    state.maybe_rotate_with(|reason| {
                        info!(?reason, "Client session rekey (rx)");
                        connection.force_key_update();
                    });
                }
                match encapsulator.decapsulate(datagram) {
                    Ok(packet) => {
                        if tx.send(packet).await.is_err() {
                            debug!("QUIC reader: TUN channel closed");
                            break;
                        }
                    }
                    Err(e) => {
                        warn!(%e, "decapsulation error");
                    }
                }
            }
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
