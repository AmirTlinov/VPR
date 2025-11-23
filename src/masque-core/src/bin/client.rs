use anyhow::{anyhow, Context, Result};
use clap::Parser;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::ClientConfig;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use snow::{params::NoiseParams, Builder as NoiseBuilder};
use std::{net::SocketAddr, path::Path, path::PathBuf, str::FromStr, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use masque_core::noise_keys::{load_keypair, load_public};
use masque_core::tunnel::{
    build_connect_frame, read_frame, write_frame, ConnectRequest, Proto, MAX_FRAME,
};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:4433")]
    addr: String,
    #[arg(long, default_value = "localhost")]
    server_name: String,
    #[arg(long, default_value = "1.1.1.1:53")]
    target: String,
    #[arg(long, default_value = "tcp", value_parser = parse_proto)]
    proto: Proto,
    #[arg(long, default_value = "127.0.0.1:9053")]
    udp_listen: String,
    #[arg(long, required = true)]
    noise_key: PathBuf,
    #[arg(long, required = true)]
    noise_peer_pub: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    let args = Args::parse();
    let connector = build_connector();
    let tcp = TcpStream::connect(&args.addr)
        .await
        .with_context(|| format!("connecting to {}", args.addr))?;
    let server_name = ServerName::try_from(args.server_name.clone())
        .map_err(|_| anyhow!("invalid server name"))?;
    let mut stream = connector
        .connect(server_name, tcp)
        .await
        .context("tls connect failed")?;

    perform_noise_handshake(&mut stream, &args.noise_key, &args.noise_peer_pub).await?;

    let target = Target::from_str(&args.target)?;
    send_connect(&mut stream, &target, args.proto).await?;
    info!(target = %target, proto=?args.proto, "connect sent");

    match args.proto {
        Proto::Tcp => pipe_stdio(stream).await?,
        Proto::Udp => {
            let listen = args.udp_listen.parse()?;
            run_udp_relay(stream, listen).await?;
        }
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

fn build_connector() -> TlsConnector {
    let verifier = Arc::new(NoVerifier);
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

async fn perform_noise_handshake(
    stream: &mut TlsStream<TcpStream>,
    priv_path: &Path,
    peer_pub_path: &Path,
) -> Result<()> {
    let kp = load_keypair(priv_path)?;
    let peer_pub = load_public(peer_pub_path)?;
    let params: NoiseParams = "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse()?;
    let mut noise = NoiseBuilder::new(params)
        .local_private_key(&kp.private)
        .remote_public_key(&peer_pub)
        .build_initiator()?;

    let mut msg = vec![0u8; 256];
    let len = noise.write_message(&[], &mut msg)?;
    write_frame(stream, &msg[..len]).await?;
    info!("sent Noise initiation ({} bytes)", len);

    let response = read_frame(stream).await?;
    let mut buf = vec![0u8; response.len() + 64];
    let len = noise.read_message(&response, &mut buf)?;
    info!("received Noise response ({} bytes)", len);
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
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();

    let to_server = tokio::spawn(async move {
        let mut buf = vec![0u8; 8 * 1024];
        loop {
            let n = stdin.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            write_frame(&mut tls_w, &buf[..n]).await?;
        }
        // send zero-length frame to indicate EOF
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
                return Err(anyhow!("frame from server too large"));
            }
            stdout.write_all(&frame).await?;
            stdout.flush().await?;
        }
        Result::<_>::Ok(())
    });

    let res = tokio::try_join!(to_server, from_server);
    if let Err(err) = res {
        Err(anyhow!("pipe error: {err}"))
    } else {
        Ok(())
    }
}

async fn run_udp_relay(stream: TlsStream<TcpStream>, listen: SocketAddr) -> Result<()> {
    let (mut tls_r, mut tls_w) = tokio::io::split(stream);
    let socket = Arc::new(
        UdpSocket::bind(listen)
            .await
            .with_context(|| format!("bind udp {listen}"))?,
    );
    info!(listen = %listen, "udp relay listening");

    // Remember the last sender to route responses.
    let last_peer = Arc::new(Mutex::new(None::<SocketAddr>));

    let recv_task = {
        let socket = Arc::clone(&socket);
        let last_peer = Arc::clone(&last_peer);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let (n, peer) = socket.recv_from(&mut buf).await?;
                {
                    let mut guard = last_peer.lock().await;
                    *guard = Some(peer);
                }
                write_frame(&mut tls_w, &buf[..n]).await?;
            }
            #[allow(unreachable_code)]
            Result::<_>::Ok(())
        })
    };

    let send_task = tokio::spawn(async move {
        loop {
            let frame = read_frame(&mut tls_r).await?;
            if frame.is_empty() {
                break;
            }
            let peer = {
                let guard = last_peer.lock().await;
                *guard
            };
            if let Some(addr) = peer {
                socket.send_to(&frame, addr).await?;
            }
        }
        Result::<_>::Ok(())
    });

    if let Err(err) = tokio::try_join!(recv_task, send_task) {
        Err(anyhow!("udp relay error: {err}"))
    } else {
        Ok(())
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
