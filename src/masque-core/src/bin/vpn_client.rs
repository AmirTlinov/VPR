//! VPR VPN Client - Full tunnel mode with TUN device
//!
//! This binary creates a TUN interface and routes traffic through
//! a MASQUE CONNECT-UDP tunnel with hybrid post-quantum encryption.

use anyhow::{bail, Context, Result};
use clap::Parser;
use quinn::{ClientConfig as QuinnClientConfig, Endpoint, TransportConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

use masque_core::hybrid_handshake::HybridClient;
use masque_core::quic_stream::QuicBiStream;
use masque_core::tun::{setup_routing, DnsProtection, TunConfig, TunDevice};
use masque_core::vpn_config::{ConfigAck, VpnConfig};
use masque_core::vpn_tunnel::{
    channel_to_tun, forward_quic_to_tun, forward_tun_to_quic, tun_to_channel, PacketEncapsulator,
};
use vpr_crypto::keys::NoiseKeypair;

#[derive(Parser, Debug)]
#[command(name = "vpn-client", about = "VPR VPN client with TUN tunnel")]
struct Args {
    /// Server address (host:port)
    #[arg(long, default_value = "127.0.0.1:4433")]
    server: String,

    /// TLS/QUIC server name
    #[arg(long, default_value = "localhost")]
    server_name: String,

    /// TUN device name (empty = kernel assigns)
    #[arg(long, default_value = "vpr0")]
    tun_name: String,

    /// Local TUN IP address
    #[arg(long, default_value = "10.8.0.2")]
    tun_addr: Ipv4Addr,

    /// TUN netmask
    #[arg(long, default_value = "255.255.255.0")]
    tun_netmask: Ipv4Addr,

    /// MTU for TUN device (leave room for encapsulation)
    #[arg(long, default_value = "1400")]
    mtu: u16,

    /// Gateway IP for routing (server's TUN address)
    #[arg(long, default_value = "10.8.0.1")]
    gateway: Ipv4Addr,

    /// Configure default route through VPN
    #[arg(long)]
    set_default_route: bool,

    /// Directory containing Noise keys
    #[arg(long, default_value = ".")]
    noise_dir: PathBuf,

    /// Noise key name (will load {name}.noise.key)
    #[arg(long, default_value = "client")]
    noise_name: String,

    /// Server's public key file
    #[arg(long)]
    server_pub: PathBuf,

    /// Skip TLS certificate verification (INSECURE, for testing)
    #[arg(long)]
    insecure: bool,

    /// Idle timeout in seconds
    #[arg(long, default_value = "30")]
    idle_timeout: u64,

    /// Enable DNS leak protection (overwrites /etc/resolv.conf)
    #[arg(long)]
    dns_protection: bool,
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
    run_vpn_client(args).await
}

async fn run_vpn_client(args: Args) -> Result<()> {
    info!(
        server = %args.server,
        tun_name = %args.tun_name,
        "Starting VPR VPN client"
    );

    // Load Noise keys for hybrid PQ handshake
    let client_keypair = NoiseKeypair::load(&args.noise_dir, &args.noise_name)
        .context("loading client Noise keypair")?;

    let server_pub = std::fs::read(&args.server_pub)
        .with_context(|| format!("reading server pubkey {:?}", args.server_pub))?;

    // Parse server address
    let server_addr: SocketAddr = args
        .server
        .parse()
        .with_context(|| format!("parsing server address: {}", args.server))?;

    // Build QUIC client config
    let quic_config = build_quic_config(args.insecure, args.idle_timeout)?;

    // Bind local endpoint
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(quic_config);

    // Connect to server
    info!(server = %server_addr, "Connecting to VPN server...");

    let connection = endpoint
        .connect(server_addr, &args.server_name)?
        .await
        .context("QUIC connection failed")?;

    info!(
        remote = %connection.remote_address(),
        "QUIC connection established"
    );

    // Perform hybrid PQ Noise handshake
    let server_pub_bytes: [u8; 32] = server_pub
        .as_slice()
        .try_into()
        .context("server public key must be 32 bytes")?;

    let hybrid_client = HybridClient::new_ik(&client_keypair.secret_bytes(), &server_pub_bytes);

    // Open bidirectional stream for handshake and config
    let (send, recv) = connection
        .open_bi()
        .await
        .context("opening bidirectional stream")?;

    let mut stream = QuicBiStream::new(send, recv);

    let (_transport, hybrid_secret) = hybrid_client
        .handshake_ik(&mut stream)
        .await
        .context("hybrid noise handshake")?;

    info!(
        secret_prefix = hex::encode(&hybrid_secret.combined[..8]),
        "Hybrid PQ handshake complete"
    );

    // Receive VPN configuration from server
    let vpn_config = VpnConfig::recv(&mut stream)
        .await
        .context("receiving VPN config")?;

    info!(
        client_ip = %vpn_config.client_ip,
        gateway = %vpn_config.gateway,
        mtu = vpn_config.mtu,
        "Received VPN configuration"
    );

    // Create TUN device with server-assigned configuration
    let tun_config = TunConfig {
        name: args.tun_name.clone(),
        address: vpn_config.client_ip,
        netmask: vpn_config.netmask,
        mtu: vpn_config.mtu,
        destination: Some(vpn_config.gateway),
    };

    let tun = TunDevice::create(tun_config)
        .await
        .context("creating TUN device")?;

    info!(
        name = %tun.name(),
        addr = %vpn_config.client_ip,
        "TUN device created with server-assigned IP"
    );

    // Send acknowledgment to server
    ConfigAck::ok()
        .send(&mut stream)
        .await
        .context("sending config ack")?;

    info!("Config acknowledged, starting VPN tunnel");

    // Configure routing if requested
    if args.set_default_route {
        setup_routing(tun.name(), vpn_config.gateway).context("setting up routing")?;
    }

    // Enable DNS leak protection if requested
    let mut dns_protection = DnsProtection::new();
    if args.dns_protection && !vpn_config.dns_servers.is_empty() {
        dns_protection
            .enable(&vpn_config.dns_servers)
            .context("enabling DNS protection")?;
    }

    // Start VPN tunnel (dns_protection will auto-restore on drop)
    let result = run_vpn_tunnel(tun, connection).await;

    // Explicitly disable DNS protection on exit
    if dns_protection.is_active() {
        let _ = dns_protection.disable();
    }

    result
}

async fn run_vpn_tunnel(tun: TunDevice, connection: quinn::Connection) -> Result<()> {
    // Split TUN device into reader and writer
    let (tun_reader, tun_writer) = tun.split();

    // Create channels for packet flow
    // TUN -> QUIC channel
    let (tun_tx, tun_rx) = mpsc::channel::<bytes::Bytes>(1024);
    // QUIC -> TUN channel
    let (quic_tx, quic_rx) = mpsc::channel::<bytes::Bytes>(1024);

    let encapsulator = Arc::new(PacketEncapsulator::new());

    // Spawn tasks for bidirectional forwarding
    let conn_clone = connection.clone();
    let encap_clone = encapsulator.clone();

    // TUN reader -> channel
    let tun_read_task = tokio::spawn(async move {
        if let Err(e) = tun_to_channel(tun_reader, tun_tx).await {
            error!(%e, "TUN read task error");
        }
    });

    // Channel -> QUIC datagrams
    let tun_to_quic_task = tokio::spawn(async move {
        if let Err(e) = forward_tun_to_quic(tun_rx, conn_clone, encap_clone).await {
            error!(%e, "TUN->QUIC task error");
        }
    });

    // QUIC datagrams -> channel
    let quic_to_channel_task = tokio::spawn(async move {
        if let Err(e) = forward_quic_to_tun(connection, quic_tx, encapsulator).await {
            error!(%e, "QUIC->TUN task error");
        }
    });

    // Channel -> TUN writer
    let tun_write_task = tokio::spawn(async move {
        if let Err(e) = channel_to_tun(tun_writer, quic_rx).await {
            error!(%e, "TUN write task error");
        }
    });

    info!("VPN tunnel running. Press Ctrl+C to stop.");

    // Wait for any task to complete (usually means connection lost)
    tokio::select! {
        _ = tun_read_task => info!("TUN reader stopped"),
        _ = tun_to_quic_task => info!("TUN->QUIC forwarder stopped"),
        _ = quic_to_channel_task => info!("QUIC->TUN forwarder stopped"),
        _ = tun_write_task => info!("TUN writer stopped"),
        _ = tokio::signal::ctrl_c() => info!("Ctrl+C received, shutting down"),
    }

    Ok(())
}

fn build_quic_config(insecure: bool, idle_timeout: u64) -> Result<QuinnClientConfig> {
    let mut transport_config = TransportConfig::default();
    transport_config.max_idle_timeout(Some(Duration::from_secs(idle_timeout).try_into()?));

    // Enable QUIC datagrams for VPN traffic
    transport_config.datagram_receive_buffer_size(Some(65536));
    transport_config.datagram_send_buffer_size(65536);

    let crypto_config = if insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };

    let mut client_config = QuinnClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto_config)?,
    ));
    client_config.transport_config(Arc::new(transport_config));

    Ok(client_config)
}

/// Insecure certificate verifier for testing
#[derive(Debug)]
struct InsecureVerifier;

impl ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}
