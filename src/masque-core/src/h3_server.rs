//! HTTP/3 server for MASQUE CONNECT-UDP
//!
//! Provides HTTP/3 Extended CONNECT handling using h3 and h3-quinn.

use crate::hybrid_handshake::HybridServer;
use crate::masque::{extract_connect_udp_target, is_connect_udp, CapsuleBuffer, UdpCapsule};
use anyhow::{Context, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use h3::server::Connection as H3Connection;
use quinn::{Endpoint, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
// AsyncWriteExt is used for write_all on SendStream
#[allow(unused_imports)]
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};
use vpr_crypto::noise::{NoiseResponder, NoiseTransport};

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

/// Perform Noise handshake via Capsule Protocol
///
/// Reads first handshake message from capsule and performs IK handshake.
/// Returns NoiseTransport and handshake response capsule bytes to send.
async fn perform_noise_handshake(
    hybrid_server: &HybridServer,
    first_message: Vec<u8>,
) -> Result<(NoiseTransport, Bytes)> {
    // Create responder using server's secret key
    let server_secret = hybrid_server.secret_bytes();
    let mut responder = NoiseResponder::new_ik(&server_secret).context("creating IK responder")?;

    // Read client's first message
    let (_payload, peer_hybrid) = responder
        .read_message(&first_message)
        .context("reading client handshake")?;

    // Write response: [Noise e,ee,se] + [ServerHybridPublic] + [ML-KEM ciphertext]
    let (msg2, _hybrid_secret) = responder
        .write_message(b"", &peer_hybrid)
        .context("writing server handshake")?;

    // Format response as capsule: [u32 BE length][capsule encoded]
    let handshake_capsule = UdpCapsule::new_handshake(Bytes::from(msg2));
    let encoded = handshake_capsule.encode();
    let mut capsule_data = BytesMut::with_capacity(4 + encoded.len());
    capsule_data.put_u32(encoded.len() as u32);
    capsule_data.extend_from_slice(&encoded);

    let capsule_bytes = capsule_data.freeze();

    debug!(
        response_size = capsule_bytes.len(),
        "Handshake response prepared"
    );

    // Transition to transport mode
    let transport = responder.into_transport().context("transport mode")?;

    Ok((transport, capsule_bytes))
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
    // Per RFC 9298 §3.2 register DATAGRAM Flow ID (0) via response header
    let response = http::Response::builder()
        .status(http::StatusCode::OK)
        .header("capsule-protocol", "?1")
        .header("datagram-flow-id", "0")
        .body(())?;
    stream.send_response(response).await?;

    // Perform Noise handshake via Capsule Protocol
    // Read handshake capsules from request stream
    let mut capsule_buf = CapsuleBuffer::new();
    let mut handshake_complete = false;
    let mut transport: Option<Arc<Mutex<NoiseTransport>>> = None;

    // Read first handshake message from stream
    let mut first_handshake_msg: Option<Vec<u8>> = None;
    loop {
        match stream.recv_data().await {
            Ok(Some(mut data_buf)) => {
                // Convert Buf to Bytes
                let mut bytes = BytesMut::with_capacity(data_buf.remaining());
                bytes.put(&mut data_buf);
                let data = bytes.freeze();

                // Add data to buffer and try to extract capsules
                if let Some(capsule) = capsule_buf.add_bytes(data)? {
                    if capsule.is_handshake() {
                        debug!(
                            "Received handshake capsule, size: {}",
                            capsule.payload.len()
                        );
                        first_handshake_msg = Some(capsule.payload.to_vec());
                        break;
                    } else {
                        // Non-handshake capsule before handshake - error
                        warn!("Received non-handshake capsule before handshake completion");
                        break;
                    }
                }
            }
            Ok(None) => {
                // Stream ended before handshake
                break;
            }
            Err(e) => {
                warn!(%e, "Error reading from stream during handshake");
                break;
            }
        }
    }

    // Perform handshake if we received the first message
    let mut handshake_response: Option<Bytes> = None;
    if let Some(msg1) = first_handshake_msg {
        match perform_noise_handshake(&hybrid_server, msg1).await {
            Ok((t, response_bytes)) => {
                transport = Some(Arc::new(Mutex::new(t)));
                handshake_complete = true;
                handshake_response = Some(response_bytes);
                info!("Noise handshake completed successfully");
            }
            Err(e) => {
                warn!(%e, "Noise handshake failed, proceeding without encryption");
            }
        }
    } else {
        warn!("No handshake message received, proceeding without encryption");
    }

    // Handshake response will be sent through QUIC datagrams (RFC 9298 compliant)
    // This approach is safer and more portable than trying to access internal stream structures

    // Create channel for sending handshake response (fallback if not sent above)
    let (handshake_tx, handshake_rx) = tokio::sync::mpsc::channel(1);

    // Send handshake response through channel if we still have one
    if let Some(response) = handshake_response {
        debug!(
            response_size = response.len(),
            "Handshake response prepared, sending through channel for datagram fallback"
        );
        if let Err(e) = handshake_tx.send(response).await {
            warn!(%e, "Failed to send handshake response through channel");
        }
    }

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
        encrypted = handshake_complete,
        "UDP proxy established"
    );

    // Start bidirectional datagram forwarding
    forward_datagrams(connection, socket, stream, transport, Some(handshake_rx)).await
}

/// Forward QUIC datagrams to/from UDP socket
async fn forward_datagrams(
    connection: quinn::Connection,
    socket: Arc<UdpSocket>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    transport: Option<Arc<Mutex<NoiseTransport>>>,
    handshake_response_rx: Option<tokio::sync::mpsc::Receiver<Bytes>>,
) -> Result<()> {
    // Client -> Target (QUIC datagrams -> UDP)
    let conn_clone = connection.clone();
    let socket_clone = socket.clone();
    let transport_clone = transport.clone();
    let to_target = tokio::spawn(async move {
        let _buf = vec![0u8; 65536];
        use tokio::time::{timeout, Duration};
        const UDP_FORWARDING_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes
        
        loop {
            match timeout(UDP_FORWARDING_TIMEOUT, conn_clone.read_datagram()).await {
                Ok(Ok(datagram)) => {
                    match UdpCapsule::decode(datagram) {
                        Ok(capsule) => {
                            if capsule.is_udp() {
                                // Decrypt if transport is available
                                let payload = if let Some(ref t) = transport_clone {
                                    match t.lock() {
                                        Ok(mut transport) => {
                                            match transport.decrypt(&capsule.payload) {
                                                Ok(decrypted) => decrypted,
                                                Err(err) => {
                                                    warn!(%err, "decryption error");
                                                    continue;
                                                }
                                            }
                                        }
                                        Err(_) => {
                                            warn!("Failed to lock transport for decryption");
                                            continue;
                                        }
                                    }
                                } else {
                                    // No encryption, use raw payload
                                    capsule.payload.to_vec()
                                };

                                if let Err(err) = socket_clone.send(&payload).await {
                                    warn!(%err, "UDP send error");
                                    break;
                                }
                            } else if capsule.is_close() {
                                info!("Received Close capsule, shutting down UDP forwarding gracefully");
                                break; // Gracefully shutdown forwarding
                            } else if capsule.is_handshake() {
                                debug!("Received handshake capsule in datagram forwarding");
                                // Handshake capsules should be handled before forwarding starts
                            } else {
                                debug!(
                                    context_id = capsule.context_id,
                                    "ignoring unknown context ID"
                                );
                            }
                        }
                        Err(err) => {
                            warn!(%err, "capsule decode error");
                        }
                    }
                }
                Ok(Err(quinn::ConnectionError::ApplicationClosed { .. })) => {
                    debug!("QUIC connection closed by application");
                    break;
                }
                Ok(Err(quinn::ConnectionError::ConnectionClosed(_))) => {
                    debug!("QUIC connection closed");
                    break;
                }
                Ok(Err(err)) => {
                    warn!(%err, "QUIC datagram read error");
                    break;
                }
                Err(_) => {
                    warn!("UDP forwarding timeout after {} seconds, closing connection", UDP_FORWARDING_TIMEOUT.as_secs());
                    break;
                }
            }
        }
        Result::<_>::Ok(())
    });

    // Target -> Client (UDP -> QUIC datagrams)
    let transport_send = transport.clone();
    let conn_for_client = connection.clone();
    let to_client = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match socket.recv(&mut buf).await {
                Ok(n) if n > 0 => {
                    let payload = Bytes::copy_from_slice(&buf[..n]);

                    // Encrypt if transport is available
                    let encrypted_payload = if let Some(ref t) = transport_send {
                        match t.lock() {
                            Ok(mut transport) => match transport.encrypt(&payload) {
                                Ok(encrypted) => encrypted,
                                Err(err) => {
                                    warn!(%err, "encryption error");
                                    continue;
                                }
                            },
                            Err(_) => {
                                warn!("Failed to lock transport for encryption");
                                continue;
                            }
                        }
                    } else {
                        // No encryption, use raw payload
                        payload.to_vec()
                    };

                    let capsule = UdpCapsule::new(Bytes::from(encrypted_payload));
                    let encoded = capsule.encode();
                    if let Err(err) = conn_for_client.send_datagram(encoded) {
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

    // Send handshake response through QUIC datagrams as fallback
    // RequestStream in h3 0.0.8 doesn't expose write methods after send_response(),
    // and h3_quinn::BidiStream doesn't implement AsyncWrite, so we cannot write
    // directly to the inner stream. As an alternative, we'll send the handshake
    // response through QUIC datagrams with handshake context ID.
    let handshake_response_for_send = handshake_response_rx;

    // Clone connection for handshake sender (already cloned above for to_client)
    let conn_for_handshake = connection.clone();

    // Spawn a task to send handshake response through QUIC datagrams
    // This is a workaround since we cannot write to RequestStream/BidiStream directly
    let handshake_sender = handshake_response_for_send.map(|mut rx| {
        tokio::spawn(async move {
            if let Some(response) = rx.recv().await {
                debug!(
                    response_size = response.len(),
                    "Handshake response received, sending through QUIC datagrams"
                );

                // Send handshake response as a datagram with handshake context ID
                // Format: [varint context_id=1][handshake response bytes]
                let handshake_capsule = UdpCapsule::new_handshake(response);
                let encoded = handshake_capsule.encode();

                match conn_for_handshake.send_datagram(encoded) {
                    Ok(_) => {
                        debug!("Handshake response sent successfully via QUIC datagram");
                    }
                    Err(e) => {
                        warn!(%e, "Failed to send handshake response via QUIC datagram");
                    }
                }
            }
            Ok::<_, anyhow::Error>(())
        })
    });

    // Monitor request stream for FIN/abort and terminate both directions
    let stream_monitor = tokio::spawn(async move {
        while let Some(frame) = stream.recv_data().await? {
            // Capsules over request stream are not parsed yet; consume and ignore.
            if !frame.has_remaining() {
                continue;
            }
        }
        Ok::<_, h3::error::StreamError>(())
    });

    // Wait for any direction or stream to finish
    tokio::select! {
        res = to_target => { res??; }
        res = to_client => { res??; }
        res = stream_monitor => { res??; }
    }

    // Wait for handshake sender to complete if it was spawned
    if let Some(handle) = handshake_sender {
        if let Err(e) = handle.await {
            warn!(%e, "Handshake sender task error");
        }
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
