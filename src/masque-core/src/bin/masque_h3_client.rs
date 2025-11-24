//! Minimal MASQUE CONNECT-UDP over HTTP/3 client for e2e tests.
//! Connects to masque-core h3_masque endpoint and relays a single UDP packet
//! to target, validating round-trip.

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use clap::Parser;
use quinn::{ClientConfig, Endpoint};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig as RustlsClientConfig, DigitallySignedStruct, SignatureScheme};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser, Debug)]
#[command(name = "masque-h3-client", about = "MASQUE CONNECT-UDP tester")]
struct Args {
    /// MASQUE server addr (host:port)
    #[arg(long, default_value = "127.0.0.1:8443")]
    server: SocketAddr,

    /// Server name for TLS SNI
    #[arg(long, default_value = "masque.local")]
    server_name: String,

    /// Target host:port for CONNECT-UDP
    #[arg(long, default_value = "198.18.0.1:53")]
    target: String,

    /// Payload size (bytes)
    #[arg(long, default_value_t = 48)]
    payload: usize,

    /// Timeout seconds
    #[arg(long, default_value_t = 5)]
    timeout: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let subscriber = FmtSubscriber::builder()
        .with_max_level(tracing::Level::INFO)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    let args = Args::parse();
    run(args).await
}

async fn run(args: Args) -> Result<()> {
    let cfg = quic_client_config()?;
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())?;
    endpoint.set_default_client_config(cfg);

    let conn = endpoint
        .connect(args.server, &args.server_name)
        .context("quic connect")?
        .await
        .context("connecting")?;

    info!(remote = %conn.remote_address(), "quic established");

    let (mut h3, mut sender): (
        h3::client::Connection<_, Bytes>,
        h3::client::SendRequest<_, Bytes>,
    ) = h3::client::builder()
        .enable_datagram(true)
        .enable_extended_connect(true)
        .build(h3_quinn::Connection::new(conn.clone()))
        .await?;

    let path = format!(
        "https://{}/.well-known/masque/udp/{}/",
        args.server_name, args.target
    );
    let req = http::Request::builder()
        .method("CONNECT")
        .uri(&path)
        .header("x-protocol", "connect-udp") // server accepts fallback header
        .header("capsule-protocol", "?1")
        .body(())
        .unwrap();

    let mut req_stream = sender.send_request(req).await?;

    let resp = req_stream.recv_response().await?;
    if resp.status() != http::StatusCode::OK {
        return Err(anyhow!("status {}", resp.status()));
    }
    info!(status = %resp.status(), "connect-udp accepted");

    // Prepare payload
    let payload = vec![0xAB; args.payload];
    let mut buf = Vec::with_capacity(payload.len() + 1);
    buf.push(0); // varint encoding for context id 0
    buf.extend_from_slice(&payload);

    // Send datagram and wait for response datagram
    conn.send_datagram(Bytes::from(buf.clone()))?;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(args.timeout);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(anyhow!("timeout waiting for datagram"));
        }
        match tokio::time::timeout(remaining, conn.read_datagram()).await {
            Ok(Ok(d)) => {
                let slice = d.as_ref();
                let (cid, rest) = read_ctx(slice)?;
                if cid != 0 {
                    warn!(cid = %cid, "skipping datagram with other context");
                    continue;
                }
                if rest == payload.as_slice() {
                    info!(size = rest.len(), "payload match");
                    return Ok(());
                } else {
                    return Err(anyhow!("payload mismatch"));
                }
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Err(anyhow!("timeout waiting datagram")),
        }
    }
}

fn read_ctx(buf: &[u8]) -> Result<(u64, &[u8])> {
    if buf.is_empty() {
        return Err(anyhow!("empty datagram"));
    }
    Ok((buf[0] as u64, &buf[1..]))
}

fn quic_client_config() -> Result<ClientConfig> {
    let rustls = RustlsClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(rustls)?;
    Ok(ClientConfig::new(Arc::new(quic)))
}

#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        use SignatureScheme::*;
        vec![
            RSA_PSS_SHA256,
            ECDSA_NISTP256_SHA256,
            ECDSA_NISTP384_SHA384,
            RSA_PKCS1_SHA256,
        ]
    }
}
