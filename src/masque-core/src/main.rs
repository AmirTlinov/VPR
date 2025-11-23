use anyhow::{bail, Context, Result};
use clap::Parser;
use rcgen::generate_simple_self_signed;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    ServerConfig,
};
use rustls_pemfile::{certs, private_key};
use serde::Deserialize;
use snow::{params::NoiseParams, Builder as NoiseBuilder};
use std::{fs, fs::File, io::BufReader, net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::{
    io::AsyncReadExt,
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream, UdpSocket},
};
use tokio_rustls::{server::TlsStream, TlsAcceptor};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use masque_core::tunnel::{read_connect_request, read_frame, write_frame, Proto};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "0.0.0.0:4433")]
    bind: SocketAddr,
    #[arg(long)]
    cert: Option<PathBuf>,
    #[arg(long)]
    key: Option<PathBuf>,
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct FileConfig {
    bind: Option<SocketAddr>,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let file_cfg = args.config.as_ref().map(load_config).transpose()?;
    let bind = file_cfg
        .as_ref()
        .and_then(|cfg| cfg.bind)
        .unwrap_or(args.bind);
    let cert_path = args
        .cert
        .as_ref()
        .or_else(|| file_cfg.as_ref().and_then(|c| c.cert.as_ref()));
    let key_path = args
        .key
        .as_ref()
        .or_else(|| file_cfg.as_ref().and_then(|c| c.key.as_ref()));

    let tls_config = build_tls_config(cert_path, key_path)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let listener = TcpListener::bind(bind).await?;
    info!("listening = {}", bind);

    loop {
        let (stream, addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    if let Err(err) = handle_connection(tls_stream).await {
                        error!(?addr, %err, "connection error");
                    }
                }
                Err(err) => error!(?addr, %err, "TLS handshake failed"),
            }
        });
    }
}

fn build_tls_config(
    cert_path: Option<&PathBuf>,
    key_path: Option<&PathBuf>,
) -> Result<ServerConfig> {
    let (certs, key) = if let (Some(cert), Some(key)) = (cert_path, key_path) {
        (load_certs(cert)?, load_key(key)?)
    } else {
        let generated = generate_simple_self_signed(["localhost".to_string()])?;
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(generated.key_pair.serialize_der()));
        let cert = CertificateDer::from(generated.cert.der().clone());
        (vec![cert], key)
    };

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(config)
}

fn load_certs(path: &PathBuf) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path).with_context(|| format!("reading cert {path:?}"))?;
    let mut reader = BufReader::new(file);
    let cert_list: Result<Vec<_>, _> = certs(&mut reader).collect();
    let cert_list = cert_list.context("parsing certs")?;
    if cert_list.is_empty() {
        bail!("no certificates found in {path:?}");
    }
    Ok(cert_list)
}

fn load_key(path: &PathBuf) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path).with_context(|| format!("reading key {path:?}"))?;
    let mut reader = BufReader::new(file);
    match private_key(&mut reader).context("parsing private key")? {
        Some(k) => Ok(PrivateKeyDer::from(k)),
        None => bail!("no private key in {path:?}"),
    }
}

async fn handle_tcp_proxy(
    stream: TlsStream<TcpStream>,
    connect: masque_core::tunnel::ConnectRequest,
) -> Result<()> {
    let outbound = TcpStream::connect(connect.to_target())
        .await
        .with_context(|| format!("connecting to target {}", connect.to_target()))?;
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
        // EOF
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
        error!(%err, "tcp proxy error");
    }
    Ok(())
}

async fn handle_udp_proxy(
    stream: TlsStream<TcpStream>,
    connect: masque_core::tunnel::ConnectRequest,
) -> Result<()> {
    let socket = Arc::new(UdpSocket::bind(("0.0.0.0", 0)).await.context("bind udp")?);
    socket
        .connect(connect.to_target())
        .await
        .with_context(|| format!("udp connect {}", connect.to_target()))?;

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

    if let Err(err) = tokio::try_join!(to_remote, to_client) {
        error!(%err, "udp proxy error");
    }
    Ok(())
}

async fn handle_connection(mut stream: TlsStream<TcpStream>) -> Result<()> {
    info!("TLS connection established");
    let params: NoiseParams = "Noise_NN_25519_ChaChaPoly_BLAKE2s".parse()?;
    let mut noise = NoiseBuilder::new(params).build_responder()?;

    let client_msg = read_frame(&mut stream).await?;
    let mut buf = vec![0u8; client_msg.len() + 256];
    noise.read_message(&client_msg, &mut buf)?;
    info!(
        "Noise handshake message received ({} bytes)",
        client_msg.len()
    );

    let mut response = vec![0u8; 256];
    let len = noise.write_message(b"ack", &mut response)?;
    write_frame(&mut stream, &response[..len]).await?;
    info!("Noise handshake response sent");

    // Next frame must carry connect request
    let connect = read_connect_request(&mut stream).await?;
    info!(target = %connect.to_target(), proto=?connect.proto, "connect request received");

    match connect.proto {
        Proto::Tcp => handle_tcp_proxy(stream, connect).await,
        Proto::Udp => handle_udp_proxy(stream, connect).await,
    }
}

fn load_config(path: &PathBuf) -> Result<FileConfig> {
    let data = fs::read_to_string(path)
        .with_context(|| format!("reading config at {}", path.display()))?;
    let cfg: FileConfig =
        toml::from_str(&data).with_context(|| format!("parsing config at {}", path.display()))?;
    Ok(cfg)
}
