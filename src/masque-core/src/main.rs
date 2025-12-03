//! MASQUE-core server with hybrid post-quantum Noise handshake
//!
//! Provides stealth VPN tunneling over:
//! - TLS/TCP with Noise_IK+ML-KEM768 handshake
//! - QUIC with Noise_IK+ML-KEM768 handshake
//!
//! Both paths use identical hybrid PQ cryptography for consistent security.

use anyhow::{bail, Context, Result};
use clap::Parser;
use quinn::{Endpoint, TransportConfig};
use rcgen::generate_simple_self_signed;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    ServerConfig,
};
use rustls_pemfile::{certs, private_key};
use serde::Deserialize;
use std::{fs, fs::File, io::BufReader, net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::{
    io::AsyncReadExt,
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream, UdpSocket},
};
use tokio_rustls::{server::TlsStream, TlsAcceptor};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use masque_core::h3_server::{run_h3_server, H3ServerConfig};
use masque_core::hybrid_handshake::HybridServer;
use masque_core::tunnel::{read_frame, write_frame, Proto};

#[derive(Parser, Debug)]
#[command(name = "masque-core", about = "MASQUE stealth VPN server")]
struct Args {
    /// TLS/TCP bind address
    #[arg(long, default_value = "0.0.0.0:4433")]
    bind: SocketAddr,

    /// QUIC bind address (optional)
    #[arg(long)]
    quic_bind: Option<SocketAddr>,

    /// TLS certificate path
    #[arg(long)]
    cert: Option<PathBuf>,

    /// TLS private key path
    #[arg(long)]
    key: Option<PathBuf>,

    /// QUIC certificate path (defaults to TLS cert)
    #[arg(long)]
    quic_cert: Option<PathBuf>,

    /// QUIC private key path (defaults to TLS key)
    #[arg(long)]
    quic_key: Option<PathBuf>,

    /// Config file path
    #[arg(long)]
    config: Option<PathBuf>,

    /// Directory containing Noise keypair (server.noise.key/pub)
    #[arg(long, required = true)]
    noise_dir: PathBuf,

    /// Noise keypair name (default: server)
    #[arg(long, default_value = "server")]
    noise_name: String,

    /// Enable HTTP/3 MASQUE CONNECT-UDP mode (RFC 9298)
    #[arg(long)]
    h3_masque: Option<SocketAddr>,
}

#[derive(Debug, Deserialize, Default)]
struct FileConfig {
    bind: Option<SocketAddr>,
    quic_bind: Option<SocketAddr>,
    h3_masque: Option<SocketAddr>,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    quic_cert: Option<PathBuf>,
    quic_key: Option<PathBuf>,
    noise_dir: Option<PathBuf>,
    noise_name: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install ring CryptoProvider");

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let file_cfg = args
        .config
        .as_ref()
        .map(load_config)
        .transpose()?
        .unwrap_or_default();

    let bind = file_cfg.bind.unwrap_or(args.bind);
    let quic_bind = file_cfg.quic_bind.or(args.quic_bind);
    let cert_path = args.cert.or(file_cfg.cert);
    let key_path = args.key.or(file_cfg.key);
    let quic_cert = args.quic_cert.or(file_cfg.quic_cert).or(cert_path.clone());
    let quic_key = args.quic_key.or(file_cfg.quic_key).or(key_path.clone());
    let noise_dir = file_cfg.noise_dir.unwrap_or(args.noise_dir);
    let noise_name = file_cfg.noise_name.unwrap_or(args.noise_name);

    // Load hybrid Noise server
    let hybrid_server = Arc::new(
        HybridServer::load(&noise_dir, &noise_name)
            .with_context(|| format!("loading noise keys from {:?}", noise_dir))?,
    );
    info!(
        noise_pubkey = hex::encode(hybrid_server.public_key()),
        "loaded hybrid PQ noise keypair"
    );

    let tls_config = build_tls_config(cert_path.as_ref(), key_path.as_ref())?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let listener = TcpListener::bind(bind).await?;
    info!(%bind, "TLS/TCP listener started");

    // Start QUIC server if configured
    if let Some(quic_addr) = quic_bind {
        let qc = quic_cert.clone();
        let qk = quic_key.clone();
        let hs = hybrid_server.clone();
        tokio::spawn(async move {
            if let Err(err) = run_quic(quic_addr, qc, qk, hs).await {
                error!(%err, "QUIC server failed");
            }
        });
        info!(%quic_addr, "QUIC listener started");
    }

    // Start HTTP/3 MASQUE server if configured
    let h3_masque_bind = args.h3_masque.or(file_cfg.h3_masque);
    if let Some(h3_addr) = h3_masque_bind {
        let (certs, key) = load_or_generate_cert(cert_path.as_ref(), key_path.as_ref())?;
        let h3_config = H3ServerConfig {
            bind: h3_addr,
            certs,
            key,
            enable_datagrams: true,
            idle_timeout: std::time::Duration::from_secs(120),
        };
        let hs = hybrid_server.clone();
        tokio::spawn(async move {
            if let Err(err) = run_h3_server(h3_config, hs).await {
                error!(%err, "H3 MASQUE server failed");
            }
        });
        info!(%h3_addr, "HTTP/3 MASQUE listener started (RFC 9298)");
    }

    // Main TLS/TCP accept loop
    loop {
        let (stream, addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let hs = hybrid_server.clone();

        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    if let Err(err) = handle_tls_connection(tls_stream, hs).await {
                        error!(?addr, %err, "TLS connection error");
                    }
                }
                Err(err) => error!(?addr, %err, "TLS handshake failed"),
            }
        });
    }
}

async fn handle_tls_connection(
    mut stream: TlsStream<TcpStream>,
    server: Arc<HybridServer>,
) -> Result<()> {
    info!("TLS established, starting hybrid PQ Noise handshake");

    // Perform hybrid Noise IK handshake
    let (_transport, hybrid_secret) = server
        .handshake_ik(&mut stream)
        .await
        .context("hybrid noise handshake")?;

    info!(
        hybrid_secret_prefix = hex::encode(&hybrid_secret.combined[..8]),
        "hybrid PQ handshake complete"
    );

    // Read connect request (first frame after handshake)
    let connect_frame = read_frame(&mut stream).await.context("reading connect")?;
    if connect_frame.is_empty() {
        bail!("empty connect request");
    }
    let connect =
        masque_core::tunnel::parse_connect_frame(&connect_frame).context("parsing connect")?;

    info!(target = %connect.to_target(), proto = ?connect.proto, "tunnel connect request");

    match connect.proto {
        Proto::Tcp => handle_tcp_proxy_raw(stream, connect).await,
        Proto::Udp => handle_udp_proxy_raw(stream, connect).await,
    }
}

/// Raw TCP proxy (after Noise handshake, using frame protocol)
async fn handle_tcp_proxy_raw<
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
>(
    stream: S,
    connect: masque_core::tunnel::ConnectRequest,
) -> Result<()> {
    let outbound = TcpStream::connect(connect.to_target())
        .await
        .with_context(|| format!("connecting to {}", connect.to_target()))?;

    let (mut tls_r, mut tls_w) = tokio::io::split(stream);
    let (mut out_r, mut out_w) = outbound.into_split();

    let to_remote = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = out_r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            write_frame(&mut tls_w, &buf[..n]).await?;
        }
        write_frame(&mut tls_w, &[]).await?;
        Result::<_>::Ok(())
    });

    let to_client = tokio::spawn(async move {
        loop {
            let frame = read_frame(&mut tls_r).await?;
            if frame.is_empty() {
                break;
            }
            out_w.write_all(&frame).await?;
        }
        Result::<_>::Ok(())
    });

    if let Err(err) = tokio::try_join!(to_remote, to_client) {
        warn!(%err, "TCP proxy task error");
    }
    Ok(())
}

/// Raw UDP proxy (after Noise handshake, using frame protocol)
async fn handle_udp_proxy_raw<
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
>(
    stream: S,
    connect: masque_core::tunnel::ConnectRequest,
) -> Result<()> {
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await.context("bind UDP")?);
    socket
        .connect(connect.to_target())
        .await
        .with_context(|| format!("UDP connect {}", connect.to_target()))?;

    let (mut tls_r, mut tls_w) = tokio::io::split(stream);

    let to_remote = {
        let socket = socket.clone();
        tokio::spawn(async move {
            loop {
                let frame = read_frame(&mut tls_r).await?;
                if frame.is_empty() {
                    break;
                }
                socket.send(&frame).await?;
            }
            Result::<_>::Ok(())
        })
    };

    let to_client = {
        let socket = socket.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let n = socket.recv(&mut buf).await?;
                write_frame(&mut tls_w, &buf[..n]).await?;
            }
            #[allow(unreachable_code)]
            Result::<_>::Ok(())
        })
    };

    tokio::select! {
        res = to_remote => { res??; }
        res = to_client => { res??; }
    }
    Ok(())
}

// ============================================================================
// QUIC Server
// ============================================================================

async fn run_quic(
    bind: SocketAddr,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    hybrid_server: Arc<HybridServer>,
) -> Result<()> {
    let (certs, key) = load_or_generate_cert(cert.as_ref(), key.as_ref())?;

    let mut server_config = quinn::ServerConfig::with_single_cert(certs, key)?;
    server_config.transport = Arc::new(TransportConfig::default());

    let endpoint = Endpoint::server(server_config, bind)?;

    while let Some(incoming) = endpoint.accept().await {
        let hs = hybrid_server.clone();
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(c) => c,
                Err(err) => {
                    error!(%err, "QUIC incoming error");
                    return;
                }
            };
            if let Err(err) = handle_quic_connection(conn, hs).await {
                error!(%err, "QUIC connection error");
            }
        });
    }
    Ok(())
}

async fn handle_quic_connection(
    connection: quinn::Connection,
    server: Arc<HybridServer>,
) -> Result<()> {
    info!(
        remote = %connection.remote_address(),
        "QUIC connection established"
    );

    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                let hs = server.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_quic_stream(send, recv, hs).await {
                        error!(%err, "QUIC stream error");
                    }
                });
            }
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => break,
            Err(quinn::ConnectionError::ConnectionClosed(_)) => break,
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

async fn handle_quic_stream(
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    server: Arc<HybridServer>,
) -> Result<()> {
    // Wrap QUIC streams in a bidirectional adapter
    let mut stream = QuicBiStream::new(send, recv);

    // Perform hybrid Noise handshake over QUIC stream
    let (_transport, hybrid_secret) = server
        .handshake_ik(&mut stream)
        .await
        .context("QUIC hybrid noise handshake")?;

    info!(
        hybrid_secret_prefix = hex::encode(&hybrid_secret.combined[..8]),
        "QUIC hybrid PQ handshake complete"
    );

    // Read connect request (first frame after handshake)
    let (send, mut recv) = stream.into_parts();
    let connect_frame = read_frame(&mut recv).await?;
    if connect_frame.is_empty() {
        bail!("empty QUIC connect request");
    }
    let connect = masque_core::tunnel::parse_connect_frame(&connect_frame)?;

    info!(target = %connect.to_target(), proto = ?connect.proto, "QUIC tunnel request");

    match connect.proto {
        Proto::Tcp => handle_quic_tcp(send, recv, connect).await,
        Proto::Udp => handle_quic_udp(send, recv, connect).await,
    }
}

/// Bidirectional QUIC stream adapter
struct QuicBiStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl QuicBiStream {
    fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self { send, recv }
    }

    fn into_parts(self) -> (quinn::SendStream, quinn::RecvStream) {
        (self.send, self.recv)
    }
}

impl tokio::io::AsyncRead for QuicBiStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for QuicBiStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match std::pin::Pin::new(&mut self.send).poll_write(cx, buf) {
            std::task::Poll::Ready(Ok(n)) => std::task::Poll::Ready(Ok(n)),
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match std::pin::Pin::new(&mut self.send).poll_flush(cx) {
            std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match std::pin::Pin::new(&mut self.send).poll_shutdown(cx) {
            std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

async fn handle_quic_tcp(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    connect: masque_core::tunnel::ConnectRequest,
) -> Result<()> {
    let outbound = TcpStream::connect(connect.to_target())
        .await
        .with_context(|| format!("connecting to {}", connect.to_target()))?;
    let (mut out_r, mut out_w) = outbound.into_split();

    let to_remote = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = out_r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            write_frame(&mut send, &buf[..n]).await?;
        }
        write_frame(&mut send, &[]).await?;
        Result::<_>::Ok(())
    });

    let to_client = tokio::spawn(async move {
        loop {
            let frame = read_frame(&mut recv).await?;
            if frame.is_empty() {
                break;
            }
            out_w.write_all(&frame).await?;
        }
        Result::<_>::Ok(())
    });

    if let Err(err) = tokio::try_join!(to_remote, to_client) {
        warn!(%err, "QUIC TCP proxy error");
    }
    Ok(())
}

async fn handle_quic_udp(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    connect: masque_core::tunnel::ConnectRequest,
) -> Result<()> {
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    socket.connect(connect.to_target()).await?;

    let to_remote = {
        let socket = socket.clone();
        tokio::spawn(async move {
            loop {
                let frame = read_frame(&mut recv).await?;
                if frame.is_empty() {
                    break;
                }
                socket.send(&frame).await?;
            }
            Result::<_>::Ok(())
        })
    };

    let to_client = {
        let socket = socket.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let n = socket.recv(&mut buf).await?;
                write_frame(&mut send, &buf[..n]).await?;
            }
            #[allow(unreachable_code)]
            Result::<_>::Ok(())
        })
    };

    tokio::select! {
        res = to_remote => { res??; }
        res = to_client => { res??; }
    }
    Ok(())
}

// ============================================================================
// TLS/Certificate utilities
// ============================================================================

fn build_tls_config(cert: Option<&PathBuf>, key: Option<&PathBuf>) -> Result<ServerConfig> {
    let (certs, key) = load_or_generate_cert(cert, key)?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(config)
}

fn load_or_generate_cert(
    cert: Option<&PathBuf>,
    key: Option<&PathBuf>,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    if let (Some(cert), Some(key)) = (cert, key) {
        Ok((load_certs(cert)?, load_key(key)?))
    } else {
        let generated = generate_simple_self_signed(["localhost".into()])?;
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
            generated.signing_key.serialize_der(),
        ));
        let cert = generated.cert.der().clone();
        Ok((vec![cert], key))
    }
}

fn load_certs(path: &PathBuf) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path).with_context(|| format!("reading cert {path:?}"))?;
    let mut reader = BufReader::new(file);
    let cert_list: Result<Vec<_>, _> = certs(&mut reader).collect();
    let cert_list = cert_list.context("parsing certs")?;
    if cert_list.is_empty() {
        bail!("no certificates in {path:?}");
    }
    Ok(cert_list)
}

fn load_key(path: &PathBuf) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path).with_context(|| format!("reading key {path:?}"))?;
    let mut reader = BufReader::new(file);
    match private_key(&mut reader).context("parsing key")? {
        Some(k) => Ok(k),
        None => bail!("no private key in {path:?}"),
    }
}

fn load_config(path: &PathBuf) -> Result<FileConfig> {
    let data =
        fs::read_to_string(path).with_context(|| format!("reading config {}", path.display()))?;
    let cfg: FileConfig = toml::from_str(&data).context("parsing config")?;
    Ok(cfg)
}
