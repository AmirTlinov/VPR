//! TUN device read/write tasks for VPN server.

use super::ServerState;
use bytes::Bytes;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, trace, warn};

use crate::tun::{IpPacketInfo, TunReader, TunWriter};

/// Task to write packets to TUN device
pub async fn tun_writer_task(mut tun_writer: TunWriter, mut rx: mpsc::Receiver<Bytes>) {
    while let Some(packet) = rx.recv().await {
        if let Err(e) = tun_writer.write_packet(&packet).await {
            error!(%e, "TUN write error");
        }
    }
    debug!("TUN writer task ended");
}

/// Task to read from TUN and route packets to clients
pub async fn tun_reader_task(mut tun_reader: TunReader, state: Arc<RwLock<ServerState>>) {
    loop {
        match tun_reader.read_packet().await {
            Ok(packet) => match IpPacketInfo::parse(&packet) {
                Ok(info) => {
                    // Dual-stack: route by IPv4 or IPv6 destination
                    if let Some(dst_ipv4) = info.dst_addr.as_ipv4() {
                        let st = state.read().await;
                        if let Some(session) = st.clients.get(&dst_ipv4) {
                            if session.tx.send(packet).await.is_err() {
                                debug!(dst = %dst_ipv4, "Client channel closed");
                            }
                        } else {
                            debug!(dst = %dst_ipv4, "No client for destination");
                        }
                    } else if let Some(dst_ipv6) = info.dst_addr.as_ipv6() {
                        // IPv6 packet - lookup in clients_v6
                        let st = state.read().await;
                        if let Some(tx) = st.clients_v6.get(&dst_ipv6) {
                            if tx.send(packet).await.is_err() {
                                debug!(dst = %dst_ipv6, "Client channel closed (IPv6)");
                            }
                        } else {
                            // Link-local and multicast IPv6 are common, log at trace
                            trace!(
                                dst = %dst_ipv6,
                                protocol = %info.protocol_name(),
                                "No client for IPv6 destination"
                            );
                        }
                    }
                }
                Err(e) => {
                    warn!(%e, packet_len = packet.len(), "Invalid IP packet from TUN, dropping");
                }
            },
            Err(e) => {
                error!(%e, "TUN read error");
                break;
            }
        }
    }
    debug!("TUN reader task ended");
}
