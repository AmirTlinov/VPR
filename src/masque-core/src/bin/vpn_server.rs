//! VPR VPN Server - Full tunnel mode with TUN device
//!
//! This binary accepts VPN client connections, performs hybrid PQ handshake,
//! and forwards IP packets through a shared TUN interface.

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use quinn::{Endpoint, ServerConfig, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{certs, private_key};
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use masque_core::hybrid_handshake::HybridServer;
use masque_core::quic_stream::QuicBiStream;
use masque_core::tun::{enable_ip_forwarding, setup_nat, TunConfig, TunDevice};
use masque_core::vpn_config::{ConfigAck, VpnConfig};
use masque_core::vpn_tunnel::PacketEncapsulator;
use vpr_crypto::keys::NoiseKeypair;

#[derive(Parser, Debug)]
#[command(name = "vpn-server", about = "VPR VPN server with TUN tunnel")]
struct Args {
    /// QUIC bind address
    #[arg(long, default_value = "0.0.0.0:4433")]
    bind: SocketAddr,

    /// TUN device name
    #[arg(long, default_value = "vpr-srv0")]
    tun_name: String,

    /// Server TUN IP address (gateway for clients)
    #[arg(long, default_value = "10.8.0.1")]
    tun_addr: Ipv4Addr,

    /// TUN netmask
    #[arg(long, default_value = "255.255.255.0")]
    tun_netmask: Ipv4Addr,

    /// MTU for TUN device
    #[arg(long, default_value = "1400")]
    mtu: u16,

    /// Start of client IP pool
    #[arg(long, default_value = "10.8.0.2")]
    pool_start: Ipv4Addr,

    /// End of client IP pool
    #[arg(long, default_value = "10.8.0.254")]
    pool_end: Ipv4Addr,

    /// Directory containing Noise keys
    #[arg(long, default_value = ".")]
    noise_dir: PathBuf,

    /// Noise key name
    #[arg(long, default_value = "server")]
    noise_name: String,

    /// TLS certificate file (PEM)
    #[arg(long)]
    cert: PathBuf,

    /// TLS private key file (PEM)
    #[arg(long)]
    key: PathBuf,

    /// Outbound interface for NAT (e.g., eth0)
    #[arg(long)]
    outbound_iface: Option<String>,

    /// Enable IP forwarding
    #[arg(long)]
    enable_forwarding: bool,

    /// Idle timeout in seconds
    #[arg(long, default_value = "300")]
    idle_timeout: u64,
}

/// Client session with allocated IP and connection
struct ClientSession {
    connection: quinn::Connection,
    allocated_ip: Ipv4Addr,
    tx: mpsc::Sender<Bytes>,
}

/// IP address pool for clients
struct IpPool {
    start: u32,
    end: u32,
    allocated: Vec<bool>,
}

impl IpPool {
    fn new(start: Ipv4Addr, end: Ipv4Addr) -> Self {
        let start_u32 = u32::from(start);
        let end_u32 = u32::from(end);
        let size = (end_u32 - start_u32 + 1) as usize;

        Self {
            start: start_u32,
            end: end_u32,
            allocated: vec![false; size],
        }
    }

    fn allocate(&mut self) -> Option<Ipv4Addr> {
        for (i, used) in self.allocated.iter_mut().enumerate() {
            if !*used {
                *used = true;
                return Some(Ipv4Addr::from(self.start + i as u32));
            }
        }
        None
    }

    fn release(&mut self, ip: Ipv4Addr) {
        let ip_u32 = u32::from(ip);
        if ip_u32 >= self.start && ip_u32 <= self.end {
            let idx = (ip_u32 - self.start) as usize;
            if idx < self.allocated.len() {
                self.allocated[idx] = false;
            }
        }
    }
}

/// Shared server state
struct ServerState {
    /// Client sessions indexed by their allocated IP
    clients: HashMap<Ipv4Addr, ClientSession>,
    /// IP address pool
    ip_pool: IpPool,
}

impl ServerState {
    fn new(pool_start: Ipv4Addr, pool_end: Ipv4Addr) -> Self {
        Self {
            clients: HashMap::new(),
            ip_pool: IpPool::new(pool_start, pool_end),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install rustls crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    let args = Args::parse();
    run_vpn_server(args).await
}

async fn run_vpn_server(args: Args) -> Result<()> {
    info!(
        bind = %args.bind,
        tun_name = %args.tun_name,
        tun_addr = %args.tun_addr,
        "Starting VPR VPN server"
    );

    // Load Noise keypair for hybrid handshake
    let noise_keypair = NoiseKeypair::load(&args.noise_dir, &args.noise_name)
        .context("loading server Noise keypair")?;

    let hybrid_server = Arc::new(HybridServer::from_secret(&noise_keypair.secret_bytes()));

    info!(
        public_key = hex::encode(hybrid_server.public_key()),
        "Noise identity loaded"
    );

    // Load TLS certificates
    let certs = load_certs(&args.cert)?;
    let key = load_key(&args.key)?;

    // Create TUN device
    let tun_config = TunConfig {
        name: args.tun_name.clone(),
        address: args.tun_addr,
        netmask: args.tun_netmask,
        mtu: args.mtu,
        destination: None,
    };

    let tun = TunDevice::create(tun_config)
        .await
        .context("creating TUN device")?;

    info!(
        name = %tun.name(),
        addr = %args.tun_addr,
        "TUN device created"
    );

    // Enable IP forwarding if requested
    if args.enable_forwarding {
        enable_ip_forwarding().context("enabling IP forwarding")?;
    }

    // Setup NAT if outbound interface specified
    if let Some(ref iface) = args.outbound_iface {
        setup_nat(tun.name(), iface).context("setting up NAT")?;
    }

    // Build QUIC server config
    let server_config = build_server_config(certs, key, args.idle_timeout)?;

    // Create server endpoint
    let endpoint = Endpoint::server(server_config, args.bind)?;
    info!(bind = %args.bind, "QUIC endpoint listening");

    // Shared state
    let state = Arc::new(RwLock::new(ServerState::new(
        args.pool_start,
        args.pool_end,
    )));

    // Split TUN device
    let (tun_reader, tun_writer) = tun.split();

    // Channel for packets going to TUN
    let (to_tun_tx, to_tun_rx) = mpsc::channel::<Bytes>(4096);

    // Spawn TUN writer task
    let tun_write_task = tokio::spawn(tun_writer_task(tun_writer, to_tun_rx));

    // Spawn TUN reader task (routes packets to clients)
    let state_clone = state.clone();
    let tun_read_task = tokio::spawn(tun_reader_task(tun_reader, state_clone));

    // Capture config values for spawned tasks
    let gateway_ip = args.tun_addr;
    let mtu = args.mtu;

    // Accept client connections
    while let Some(incoming) = endpoint.accept().await {
        let hs = hybrid_server.clone();
        let st = state.clone();
        let to_tun = to_tun_tx.clone();

        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    let remote = connection.remote_address();
                    info!(%remote, "New VPN connection");

                    if let Err(e) =
                        handle_vpn_client_with_config(connection, hs, st, to_tun, gateway_ip, mtu)
                            .await
                    {
                        error!(%remote, %e, "Client error");
                    }
                }
                Err(e) => {
                    error!(%e, "Connection accept error");
                }
            }
        });
    }

    // Cleanup
    tun_write_task.abort();
    tun_read_task.abort();

    Ok(())
}

/// Handle a single VPN client connection
async fn handle_vpn_client_with_config(
    connection: quinn::Connection,
    hybrid_server: Arc<HybridServer>,
    state: Arc<RwLock<ServerState>>,
    to_tun_tx: mpsc::Sender<Bytes>,
    gateway_ip: Ipv4Addr,
    mtu: u16,
) -> Result<()> {
    let remote = connection.remote_address();

    // Wait for handshake stream
    let (send, recv) = connection
        .accept_bi()
        .await
        .context("accepting handshake stream")?;

    // Perform hybrid PQ Noise handshake
    let mut stream = QuicBiStream::new(send, recv);
    let (_transport, hybrid_secret) = hybrid_server
        .handshake_ik(&mut stream)
        .await
        .context("hybrid noise handshake")?;

    info!(
        %remote,
        secret_prefix = hex::encode(&hybrid_secret.combined[..8]),
        "Client authenticated"
    );

    // Allocate IP address for client
    let client_ip = {
        let mut st = state.write().await;
        st.ip_pool
            .allocate()
            .ok_or_else(|| anyhow::anyhow!("IP pool exhausted"))?
    };

    info!(%remote, client_ip = %client_ip, "IP allocated");

    // Send VPN configuration to client
    let vpn_config = VpnConfig::new(client_ip, gateway_ip)
        .with_mtu(mtu)
        .with_dns(Ipv4Addr::new(8, 8, 8, 8))
        .with_dns(Ipv4Addr::new(1, 1, 1, 1))
        .with_route("0.0.0.0/0"); // Full tunnel mode

    vpn_config
        .send(&mut stream)
        .await
        .context("sending VPN config")?;

    info!(%remote, client_ip = %client_ip, "VPN config sent");

    // Wait for client acknowledgment
    let ack = ConfigAck::recv(&mut stream)
        .await
        .context("receiving config ack")?;

    if !ack.accepted {
        let err_msg = ack.error.unwrap_or_else(|| "unknown error".into());
        error!(%remote, %err_msg, "Client rejected config");
        // Release IP before returning error
        let mut st = state.write().await;
        st.ip_pool.release(client_ip);
        anyhow::bail!("client rejected config: {}", err_msg);
    }

    info!(%remote, client_ip = %client_ip, "Client accepted config");

    // Create channel for packets going to this client
    let (client_tx, mut client_rx) = mpsc::channel::<Bytes>(1024);

    // Register client session
    {
        let mut st = state.write().await;
        st.clients.insert(
            client_ip,
            ClientSession {
                connection: connection.clone(),
                allocated_ip: client_ip,
                tx: client_tx,
            },
        );
    }

    let encapsulator = Arc::new(PacketEncapsulator::new());

    // Spawn task to send packets to client
    let conn_clone = connection.clone();
    let encap_clone = encapsulator.clone();
    let to_client_task = tokio::spawn(async move {
        while let Some(packet) = client_rx.recv().await {
            let datagram = encap_clone.encapsulate(packet);
            if let Err(e) = conn_clone.send_datagram(datagram) {
                debug!(%e, "Error sending to client");
                break;
            }
        }
    });

    // Forward datagrams from client to TUN
    loop {
        match connection.read_datagram().await {
            Ok(datagram) => match encapsulator.decapsulate(datagram) {
                Ok(packet) => {
                    if to_tun_tx.send(packet).await.is_err() {
                        warn!("TUN channel closed");
                        break;
                    }
                }
                Err(e) => {
                    warn!(%e, "Decapsulation error");
                }
            },
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                info!(%remote, "Client disconnected");
                break;
            }
            Err(quinn::ConnectionError::ConnectionClosed(_)) => {
                info!(%remote, "Connection closed");
                break;
            }
            Err(e) => {
                error!(%remote, %e, "Connection error");
                break;
            }
        }
    }

    // Cleanup
    to_client_task.abort();

    {
        let mut st = state.write().await;
        st.clients.remove(&client_ip);
        st.ip_pool.release(client_ip);
    }

    info!(%remote, client_ip = %client_ip, "Client session ended, IP released");

    Ok(())
}

/// Task to write packets to TUN device
async fn tun_writer_task(
    mut tun_writer: masque_core::tun::TunWriter,
    mut rx: mpsc::Receiver<Bytes>,
) {
    while let Some(packet) = rx.recv().await {
        if let Err(e) = tun_writer.write_packet(&packet).await {
            error!(%e, "TUN write error");
        }
    }
    debug!("TUN writer task ended");
}

/// Task to read from TUN and route packets to clients
async fn tun_reader_task(
    mut tun_reader: masque_core::tun::TunReader,
    state: Arc<RwLock<ServerState>>,
) {
    loop {
        match tun_reader.read_packet().await {
            Ok(packet) => {
                // Parse destination IP from packet
                if packet.len() >= 20 {
                    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

                    // Find client with this IP
                    let st = state.read().await;
                    if let Some(session) = st.clients.get(&dst_ip) {
                        if session.tx.send(packet).await.is_err() {
                            debug!(dst = %dst_ip, "Client channel closed");
                        }
                    } else {
                        // Packet for unknown destination, drop silently
                        debug!(dst = %dst_ip, "No client for destination");
                    }
                }
            }
            Err(e) => {
                error!(%e, "TUN read error");
                break;
            }
        }
    }
    debug!("TUN reader task ended");
}

fn build_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    idle_timeout: u64,
) -> Result<ServerConfig> {
    let mut transport_config = TransportConfig::default();
    transport_config.max_idle_timeout(Some(Duration::from_secs(idle_timeout).try_into()?));

    // Enable QUIC datagrams for VPN traffic
    transport_config.datagram_receive_buffer_size(Some(65536));
    transport_config.datagram_send_buffer_size(65536);

    let mut server_config = ServerConfig::with_single_cert(certs, key)?;
    server_config.transport_config(Arc::new(transport_config));

    Ok(server_config)
}

fn load_certs(path: &PathBuf) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path).with_context(|| format!("opening cert file {:?}", path))?;
    let mut reader = BufReader::new(file);
    certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .context("parsing certificates")
}

fn load_key(path: &PathBuf) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path).with_context(|| format!("opening key file {:?}", path))?;
    let mut reader = BufReader::new(file);
    private_key(&mut reader)
        .context("parsing private key")?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {:?}", path))
}
