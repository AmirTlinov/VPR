//! HTTP/3 server for MASQUE CONNECT-UDP
//!
//! Provides HTTP/3 Extended CONNECT handling using h3 and h3-quinn.

use crate::hybrid_handshake::HybridServer;
use crate::masque::{extract_connect_udp_target, is_connect_udp, UdpCapsule};
use anyhow::{Context, Result};
use bytes::Bytes;
use h3::server::Connection as H3Connection;
use quinn::{Endpoint, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

/// Configuration for the H3 MASQUE server
pub struct H3ServerConfig {
    pub bind: SocketAddr,
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    pub enable_datagrams: bool,
    pub idle_timeout: Duration,
}

/// Run HTTP/3 MASQUE server
pub async fn run_h3_server(config: H3ServerConfig, hybrid_server: Arc<HybridServer>) -> Result<()> {
    let mut transport_config = TransportConfig::default();
    transport_config.max_idle_timeout(Some(config.idle_timeout.try_into()?));

    // Enable QUIC datagrams for UDP forwarding
    if config.enable_datagrams {
        transport_config.datagram_receive_buffer_size(Some(65536));
        transport_config.datagram_send_buffer_size(65536);
    }

    let mut server_config = quinn::ServerConfig::with_single_cert(config.certs, config.key)?;
    server_config.transport_config(Arc::new(transport_config));

    let endpoint = Endpoint::server(server_config, config.bind)?;
    info!(bind = %config.bind, "HTTP/3 MASQUE server started");

    while let Some(incoming) = endpoint.accept().await {
        let hs = hybrid_server.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    if let Err(err) = handle_h3_connection(connection, hs).await {
                        error!(%err, "H3 connection error");
                    }
                }
                Err(err) => error!(%err, "H3 incoming error"),
            }
        });
    }

    Ok(())
}

/// Handle a single HTTP/3 connection
async fn handle_h3_connection(
    connection: quinn::Connection,
    hybrid_server: Arc<HybridServer>,
) -> Result<()> {
    let remote = connection.remote_address();
    info!(%remote, "H3 connection established");

    // Wrap quinn connection for h3
    let h3_conn = h3_quinn::Connection::new(connection.clone());
    let mut h3 = H3Connection::new(h3_conn).await?;

    loop {
        match h3.accept().await {
            Ok(Some(resolver)) => {
                let hs = hybrid_server.clone();
                let conn = connection.clone();
                tokio::spawn(async move {
                    // Resolve the request to get headers and stream
                    match resolver.resolve_request().await {
                        Ok((request, stream)) => {
                            if let Err(err) = handle_h3_request(request, stream, conn, hs).await {
                                warn!(%err, "H3 request error");
                            }
                        }
                        Err(err) => {
                            warn!(%err, "H3 request resolve error");
                        }
                    }
                });
            }
            Ok(None) => {
                debug!("H3 connection closed gracefully");
                break;
            }
            Err(err) => {
                error!(%err, "H3 accept error");
                break;
            }
        }
    }

    Ok(())
}

/// Handle a single HTTP/3 request
async fn handle_h3_request(
    request: http::Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    connection: quinn::Connection,
    hybrid_server: Arc<HybridServer>,
) -> Result<()> {
    let method = request.method();
    let path = request.uri().path();
    let headers = request.headers();

    // Check for Extended CONNECT with connect-udp protocol
    let protocol = headers
        .get(":protocol")
        .or_else(|| headers.get("x-protocol"))
        .and_then(|v| v.to_str().ok());

    debug!(
        method = %method,
        path = %path,
        protocol = ?protocol,
        "H3 request received"
    );

    if is_connect_udp(method, protocol) {
        handle_connect_udp(request, stream, connection, hybrid_server).await
    } else {
        // Return 405 Method Not Allowed for non-CONNECT-UDP
        let response = http::Response::builder()
            .status(http::StatusCode::METHOD_NOT_ALLOWED)
            .body(())?;
        stream.send_response(response).await?;
        Ok(())
    }
}

/// Handle CONNECT-UDP request
async fn handle_connect_udp(
    request: http::Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    connection: quinn::Connection,
    hybrid_server: Arc<HybridServer>,
) -> Result<()> {
    let path = request.uri().path();
    let headers = request.headers();

    // Extract and validate target
    let target = extract_connect_udp_target(headers, path)?;
    target.validate()?;

    info!(
        target_host = %target.host,
        target_port = target.port,
        "CONNECT-UDP request"
    );

    // Send 200 OK with Capsule-Protocol header
    let response = http::Response::builder()
        .status(http::StatusCode::OK)
        .header("capsule-protocol", "?1")
        .body(())?;
    stream.send_response(response).await?;

    // Bind local UDP socket for proxying
    let socket = Arc::new(
        UdpSocket::bind("0.0.0.0:0")
            .await
            .context("binding UDP socket")?,
    );
    socket
        .connect(target.to_socket_addr_str())
        .await
        .with_context(|| format!("connecting to {}", target.to_socket_addr_str()))?;

    info!(
        local_addr = %socket.local_addr()?,
        target = %target.to_socket_addr_str(),
        "UDP proxy established"
    );

    // Start bidirectional datagram forwarding
    forward_datagrams(connection, socket, stream).await
}

/// Forward QUIC datagrams to/from UDP socket
async fn forward_datagrams(
    connection: quinn::Connection,
    socket: Arc<UdpSocket>,
    stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> Result<()> {
    // Client -> Target (QUIC datagrams -> UDP)
    let conn_clone = connection.clone();
    let socket_clone = socket.clone();
    let to_target = tokio::spawn(async move {
        let buf = vec![0u8; 65536];
        loop {
            match conn_clone.read_datagram().await {
                Ok(datagram) => {
                    match UdpCapsule::decode(datagram) {
                        Ok(capsule) => {
                            if capsule.context_id == 0 {
                                // Raw UDP payload
                                if let Err(err) = socket_clone.send(&capsule.payload).await {
                                    warn!(%err, "UDP send error");
                                    break;
                                }
                            } else {
                                debug!(
                                    context_id = capsule.context_id,
                                    "ignoring non-zero context ID"
                                );
                            }
                        }
                        Err(err) => {
                            warn!(%err, "capsule decode error");
                        }
                    }
                }
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => break,
                Err(quinn::ConnectionError::ConnectionClosed(_)) => break,
                Err(err) => {
                    warn!(%err, "QUIC datagram read error");
                    break;
                }
            }
        }
        Result::<_>::Ok(())
    });

    // Target -> Client (UDP -> QUIC datagrams)
    let to_client = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match socket.recv(&mut buf).await {
                Ok(n) if n > 0 => {
                    let capsule = UdpCapsule::new(Bytes::copy_from_slice(&buf[..n]));
                    let encoded = capsule.encode();
                    if let Err(err) = connection.send_datagram(encoded) {
                        warn!(%err, "QUIC datagram send error");
                        break;
                    }
                }
                Ok(_) => break, // Socket closed
                Err(err) => {
                    warn!(%err, "UDP recv error");
                    break;
                }
            }
        }
        Result::<_>::Ok(())
    });

    // Wait for either direction to complete
    tokio::select! {
        res = to_target => { res??; }
        res = to_client => { res??; }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_connect_udp() {
        assert!(is_connect_udp(&http::Method::CONNECT, Some("connect-udp")));
        assert!(!is_connect_udp(&http::Method::GET, Some("connect-udp")));
        assert!(!is_connect_udp(&http::Method::CONNECT, None));
        assert!(!is_connect_udp(&http::Method::CONNECT, Some("websocket")));
    }
}
