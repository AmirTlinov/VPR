//! MASQUE-core client with hybrid post-quantum Noise handshake

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use quinn::{ClientConfig as QuinnClientConfig, Endpoint};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::ClientConfig;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::{net::SocketAddr, path::PathBuf, str::FromStr, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use masque_core::hybrid_handshake::HybridClient;
use masque_core::tunnel::{
    build_connect_frame, read_frame, write_frame, ConnectRequest, Proto, MAX_FRAME,
};
use vpr_crypto::keys::NoiseKeypair;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transport {
    Tls,
    Quic,
}

#[derive(Parser, Debug)]
#[command(name = "masque-client", about = "MASQUE stealth VPN client")]
struct Args {
    /// Server address (host:port)
    #[arg(long, default_value = "127.0.0.1:4433")]
    addr: String,

    /// TLS server name
    #[arg(long, default_value = "localhost")]
    server_name: String,

    /// Target address (host:port) to tunnel to
    #[arg(long, default_value = "1.1.1.1:53")]
    target: String,

    /// Protocol (tcp or udp)
    #[arg(long, default_value = "tcp", value_parser = parse_proto)]
    proto: Proto,

    /// Local UDP listen address (for UDP relay mode)
    #[arg(long, default_value = "127.0.0.1:9053")]
    udp_listen: String,

    /// Client Noise key directory
    #[arg(long, required = true)]
    noise_dir: PathBuf,

    /// Client Noise key name
    #[arg(long, default_value = "client")]
    noise_name: String,

    /// Server Noise public key file
    #[arg(long, required = true)]
    server_pub: PathBuf,

    /// Transport (tls or quic)
    #[arg(long, default_value = "tls", value_parser = parse_transport)]
    transport: Transport,

    /// QUIC server name (for certificate validation)
    #[arg(long, default_value = "localhost")]
    quic_server_name: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install rustls crypto provider (required for rustls 0.23+)
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    let args = Args::parse();
    match args.transport {
        Transport::Tls => run_tls_flow(args).await?,
        Transport::Quic => run_quic_flow(args).await?,
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct Target {
    host: String,
    port: u16,
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

impl FromStr for Target {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<_> = s.rsplitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(anyhow!("target must be host:port"));
        }
        let port: u16 = parts[0].parse()?;
        let host = parts[1].to_string();
        Ok(Self { host, port })
    }
}

fn parse_proto(s: &str) -> Result<Proto, String> {
    match s.to_ascii_lowercase().as_str() {
        "tcp" => Ok(Proto::Tcp),
        "udp" => Ok(Proto::Udp),
        _ => Err("proto must be tcp|udp".into()),
    }
}

fn parse_transport(s: &str) -> Result<Transport, String> {
    match s.to_ascii_lowercase().as_str() {
        "tls" => Ok(Transport::Tls),
        "quic" => Ok(Transport::Quic),
        _ => Err("transport must be tls|quic".into()),
    }
}

fn build_connector() -> TlsConnector {
    let verifier = Arc::new(NoVerifier);
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

async fn run_tls_flow(args: Args) -> Result<()> {
    let connector = build_connector();
    let tcp = TcpStream::connect(&args.addr)
        .await
        .with_context(|| format!("connecting to {}", args.addr))?;
    let server_name = ServerName::try_from(args.server_name.clone())
        .map_err(|_| anyhow!("invalid server name"))?;
    let mut stream = connector
        .connect(server_name, tcp)
        .await
        .context("TLS connect failed")?;

    // Load keys and perform hybrid Noise handshake
    let client_kp = NoiseKeypair::load(&args.noise_dir, &args.noise_name)
        .context("loading client noise key")?;
    let server_pub =
        NoiseKeypair::load_public(&args.server_pub).context("loading server public key")?;

    let client = HybridClient::new_ik(&client_kp.secret_bytes(), &server_pub);
    let (_transport, hybrid_secret) = client
        .handshake_ik(&mut stream)
        .await
        .context("hybrid noise handshake")?;

    info!(
        hybrid_secret_prefix = hex::encode(&hybrid_secret.combined[..8]),
        "hybrid PQ handshake complete"
    );

    let target = Target::from_str(&args.target)?;
    send_connect(&mut stream, &target, args.proto).await?;
    info!(target = %target, proto=?args.proto, transport=?args.transport, "connect sent");

    match args.proto {
        Proto::Tcp => pipe_stdio(stream).await?,
        Proto::Udp => {
            let listen = args.udp_listen.parse()?;
            run_udp_relay(stream, listen).await?;
        }
    }
    Ok(())
}

async fn run_quic_flow(args: Args) -> Result<()> {
    let target = Target::from_str(&args.target)?;

    // Build QUIC client config with certificate skip
    let tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();

    let quic_config = QuinnClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .context("creating quic client config")?,
    ));

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())?;
    endpoint.set_default_client_config(quic_config);

    let connection = endpoint
        .connect(args.addr.parse()?, &args.quic_server_name)
        .context("QUIC connect")?
        .await
        .context("QUIC handshake")?;

    let (send, recv) = connection.open_bi().await?;

    // Wrap in bidirectional stream for handshake
    let mut stream = QuicBiStream::new(send, recv);

    // Perform hybrid Noise handshake
    let client_kp = NoiseKeypair::load(&args.noise_dir, &args.noise_name)?;
    let server_pub = NoiseKeypair::load_public(&args.server_pub)?;

    let client = HybridClient::new_ik(&client_kp.secret_bytes(), &server_pub);
    let (_transport, hybrid_secret) = client
        .handshake_ik(&mut stream)
        .await
        .context("QUIC hybrid noise handshake")?;

    info!(
        hybrid_secret_prefix = hex::encode(&hybrid_secret.combined[..8]),
        "QUIC hybrid PQ handshake complete"
    );

    let (mut send, recv) = stream.into_parts();

    // Send connect request
    let frame = build_connect_frame(&ConnectRequest {
        proto: args.proto,
        host: target.host.clone(),
        port: target.port,
    })?;
    write_frame(&mut send, &frame).await?;
    info!(target = %target, proto=?args.proto, transport=?args.transport, "QUIC connect sent");

    match args.proto {
        Proto::Tcp => pipe_stdio_quic(send, recv).await?,
        Proto::Udp => {
            let listen = args.udp_listen.parse()?;
            run_udp_relay_quic((send, recv), listen).await?;
        }
    }
    Ok(())
}

async fn send_connect(
    stream: &mut TlsStream<TcpStream>,
    target: &Target,
    proto: Proto,
) -> Result<()> {
    let frame = build_connect_frame(&ConnectRequest {
        proto,
        host: target.host.clone(),
        port: target.port,
    })?;
    write_frame(stream, &frame).await?;
    Ok(())
}

async fn pipe_stdio(stream: TlsStream<TcpStream>) -> Result<()> {
    let (mut tls_r, mut tls_w) = tokio::io::split(stream);
    let mut stdin_stream = tokio::io::stdin();
    let mut stdout_stream = tokio::io::stdout();

    let to_server = tokio::spawn(async move {
        let mut buf = vec![0u8; 8 * 1024];
        loop {
            let n = stdin_stream.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            write_frame(&mut tls_w, &buf[..n]).await?;
        }
        write_frame(&mut tls_w, &[]).await?;
        Result::<_>::Ok(())
    });

    let from_server = tokio::spawn(async move {
        loop {
            let frame = read_frame(&mut tls_r).await?;
            if frame.is_empty() {
                break;
            }
            if frame.len() > MAX_FRAME {
                return Err(anyhow!("frame too large"));
            }
            stdout_stream.write_all(&frame).await?;
            stdout_stream.flush().await?;
        }
        Result::<_>::Ok(())
    });

    let (_to, _from) = tokio::try_join!(to_server, from_server)?;
    Ok(())
}

async fn pipe_stdio_quic(mut send: quinn::SendStream, mut recv: quinn::RecvStream) -> Result<()> {
    let mut stdin_stream = tokio::io::stdin();
    let mut stdout_stream = tokio::io::stdout();

    let to_remote = tokio::spawn(async move {
        let mut buf = vec![0u8; 8 * 1024];
        loop {
            let n = stdin_stream.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            write_frame(&mut send, &buf[..n]).await?;
        }
        write_frame(&mut send, &[]).await?;
        Result::<_>::Ok(())
    });

    let from_remote = tokio::spawn(async move {
        loop {
            let frame = read_frame(&mut recv).await?;
            if frame.is_empty() {
                break;
            }
            if frame.len() > MAX_FRAME {
                return Err(anyhow!("frame too large"));
            }
            stdout_stream.write_all(&frame).await?;
            stdout_stream.flush().await?;
        }
        Result::<_>::Ok(())
    });

    let (_to, _from) = tokio::try_join!(to_remote, from_remote)?;
    Ok(())
}

async fn run_udp_relay(stream: TlsStream<TcpStream>, listen: SocketAddr) -> Result<()> {
    let (mut tls_r, mut tls_w) = tokio::io::split(stream);
    let socket = Arc::new(UdpSocket::bind(listen).await?);
    info!(%listen, "UDP relay listening");

    let last_peer = Arc::new(Mutex::new(None::<SocketAddr>));

    let recv_task = {
        let socket = Arc::clone(&socket);
        let last_peer = Arc::clone(&last_peer);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let (n, peer) = socket.recv_from(&mut buf).await?;
                *last_peer.lock().await = Some(peer);
                write_frame(&mut tls_w, &buf[..n]).await?;
            }
            #[allow(unreachable_code)]
            Result::<_>::Ok(())
        })
    };

    let send_task = {
        let socket = socket.clone();
        tokio::spawn(async move {
            loop {
                let frame = read_frame(&mut tls_r).await?;
                if frame.is_empty() {
                    break;
                }
                if let Some(addr) = *last_peer.lock().await {
                    socket.send_to(&frame, addr).await?;
                }
            }
            Result::<_>::Ok(())
        })
    };

    tokio::select! {
        res = recv_task => { res??; }
        res = send_task => { res??; }
    }
    Ok(())
}

async fn run_udp_relay_quic(
    streams: (quinn::SendStream, quinn::RecvStream),
    listen: SocketAddr,
) -> Result<()> {
    let (mut send, mut recv) = streams;
    let socket = Arc::new(UdpSocket::bind(listen).await?);
    info!(%listen, "UDP relay (QUIC) listening");

    let last_peer = Arc::new(Mutex::new(None::<SocketAddr>));

    let recv_task = {
        let socket = Arc::clone(&socket);
        let last_peer = Arc::clone(&last_peer);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let (n, peer) = socket.recv_from(&mut buf).await?;
                *last_peer.lock().await = Some(peer);
                write_frame(&mut send, &buf[..n]).await?;
            }
            #[allow(unreachable_code)]
            Result::<_>::Ok(())
        })
    };

    let send_task = {
        let socket = socket.clone();
        tokio::spawn(async move {
            loop {
                let frame = read_frame(&mut recv).await?;
                if frame.is_empty() {
                    break;
                }
                if let Some(addr) = *last_peer.lock().await {
                    socket.send_to(&frame, addr).await?;
                }
            }
            Result::<_>::Ok(())
        })
    };

    tokio::select! {
        res = recv_task => { res??; }
        res = send_task => { res??; }
    }
    Ok(())
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
            std::task::Poll::Ready(Err(e)) => {
                std::task::Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match std::pin::Pin::new(&mut self.send).poll_flush(cx) {
            std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Ready(Err(e)) => {
                std::task::Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match std::pin::Pin::new(&mut self.send).poll_shutdown(cx) {
            std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Ready(Err(e)) => {
                std::task::Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}
