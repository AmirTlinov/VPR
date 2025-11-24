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
use std::fs::{self, File};
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{broadcast, mpsc, RwLock};
use tokio::time::interval;
use tokio::time::sleep;
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use masque_core::cover_traffic::{CoverTrafficConfig, CoverTrafficGenerator, TrafficPattern};
use masque_core::hybrid_handshake::{read_handshake_msg, HybridServer};
use masque_core::key_rotation::{
    rotation_check_task, KeyRotationConfig, KeyRotationManager, SessionKeyState,
};
use masque_core::padding::{Padder, PaddingConfig, PaddingStrategy};
use masque_core::probe_protection::{ProbeDetection, ProbeProtectionConfig, ProbeProtector};
use masque_core::quic_stream::QuicBiStream;
use masque_core::replay_protection::NonceCache;
use masque_core::rng;
use masque_core::tls_fingerprint::{
    select_tls_profile, GreaseMode, Ja3Fingerprint, Ja3sFingerprint, Ja4Fingerprint, TlsProfile,
    TlsProfileBucket,
};
use masque_core::tun::{enable_ip_forwarding, setup_nat, TunConfig, TunDevice};
use masque_core::vpn_config::{ConfigAck, VpnConfig};
use masque_core::vpn_tunnel::PacketEncapsulator;
use vpr_crypto::ct_eq_32;
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

    /// DNS servers to push to clients (comma-separated). Defaults to public resolvers if empty.
    #[arg(long, value_delimiter = ',')]
    dns_servers: Vec<IpAddr>,

    /// MTU for TUN device
    #[arg(long, default_value = "1400")]
    mtu: u16,

    /// Start of client IP pool
    #[arg(long, default_value = "10.8.0.2")]
    pool_start: Ipv4Addr,

    /// End of client IP pool
    #[arg(long, default_value = "10.8.0.254")]
    pool_end: Ipv4Addr,

    /// Padding strategy: none|bucket|rand-bucket|mtu
    #[arg(long, default_value = "rand-bucket")]
    padding_strategy: String,

    /// Maximum jitter for padded sends (microseconds). 0 disables jitter.
    #[arg(long, default_value = "5000")]
    padding_max_jitter_us: u64,

    /// Minimum padded packet size (bytes)
    #[arg(long, default_value = "32")]
    padding_min_size: usize,

    /// Override MTU for padding (defaults to TUN MTU)
    #[arg(long)]
    padding_mtu: Option<u16>,

    /// Cover traffic base rate (pps)
    #[arg(long, default_value = "8.0")]
    cover_traffic_rate: f64,

    /// Cover traffic pattern: https|h3|webrtc|idle
    #[arg(long, default_value = "https")]
    cover_traffic_pattern: String,

    /// Probe protection: PoW difficulty (leading zero bytes)
    #[arg(long, default_value = "2")]
    probe_difficulty: u8,

    /// Probe protection: max failed attempts before ban
    #[arg(long, default_value = "3")]
    probe_max_failed_attempts: u32,

    /// Probe protection: ban duration seconds
    #[arg(long, default_value = "300")]
    probe_ban_seconds: u64,

    /// Probe protection: min handshake time ms (too fast -> suspicious)
    #[arg(long, default_value = "50")]
    probe_min_handshake_ms: u64,

    /// Probe protection: max handshake time ms (too slow -> blocked)
    #[arg(long, default_value = "10000")]
    probe_max_handshake_ms: u64,

    /// Write probe metrics to this path in Prometheus text format
    #[arg(long)]
    probe_metrics_path: Option<PathBuf>,

    /// Interval for probe metrics export (seconds)
    #[arg(long, default_value = "30")]
    probe_metrics_interval: u64,

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

    /// Session rekey time limit (seconds)
    #[arg(long, default_value = "60")]
    session_rekey_seconds: u64,

    /// Session rekey data limit (bytes)
    #[arg(long, default_value = "1073741824")]
    session_rekey_bytes: u64,

    /// TLS fingerprint profile to mimic (chrome, firefox, safari, random)
    #[arg(long, default_value = "chrome")]
    tls_profile: String,

    /// Canary TLS profile (chrome|firefox|safari|random|custom)
    #[arg(long, default_value = "safari")]
    tls_canary_profile: String,

    /// Percent of connections using canary profile
    #[arg(long, default_value = "5")]
    tls_canary_percent: f64,

    /// Seed for canary selection (0 = random)
    #[arg(long, default_value_t = 0)]
    tls_canary_seed: u64,

    /// GREASE mode: random|deterministic
    #[arg(long, default_value = "random")]
    tls_grease_mode: String,

    /// GREASE seed used when deterministic mode is selected
    #[arg(long, default_value_t = 0)]
    tls_grease_seed: u64,

    /// Export JA3/JA3S/JA4 metrics to Prometheus text file
    #[arg(long)]
    tls_fp_metrics_path: Option<PathBuf>,
}

/// Client session with allocated IP and connection
struct ClientSession {
    #[allow(dead_code)]
    connection: quinn::Connection,
    #[allow(dead_code)]
    allocated_ip: Ipv4Addr,
    tx: mpsc::Sender<Bytes>,
    #[allow(dead_code)]
    session_state: Arc<SessionKeyState>,
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

/// Persistent session info for reconnection support
struct SessionInfo {
    /// Allocated IP address for this session
    allocated_ip: Ipv4Addr,
    /// Client's Noise public key (for identity verification)
    #[allow(dead_code)]
    client_pubkey: [u8; 32],
    /// When session was last active
    last_seen: Instant,
}

/// Session timeout for reconnection (5 minutes)
const SESSION_TIMEOUT: Duration = Duration::from_secs(300);

/// Default DNS servers pushed to clients when none specified
const DEFAULT_DNS_SERVERS: [IpAddr; 2] = [
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
];

/// Shared server state
struct ServerState {
    /// Active client sessions indexed by their allocated IP
    clients: HashMap<Ipv4Addr, ClientSession>,
    /// Persistent sessions indexed by session_id (for reconnect)
    sessions: HashMap<String, SessionInfo>,
    /// IP address pool
    ip_pool: IpPool,
}

impl ServerState {
    fn new(pool_start: Ipv4Addr, pool_end: Ipv4Addr) -> Self {
        Self {
            clients: HashMap::new(),
            sessions: HashMap::new(),
            ip_pool: IpPool::new(pool_start, pool_end),
        }
    }

    /// Try to restore session by session_id
    #[allow(dead_code)]
    fn restore_session(&mut self, session_id: &str, client_pubkey: &[u8; 32]) -> Option<Ipv4Addr> {
        if let Some(session) = self.sessions.get(session_id) {
            // Verify client identity and session freshness
            // Use constant-time comparison to prevent timing attacks
            if ct_eq_32(&session.client_pubkey, client_pubkey)
                && session.last_seen.elapsed() < SESSION_TIMEOUT
            {
                return Some(session.allocated_ip);
            }
        }
        None
    }

    /// Create new session
    fn create_session(&mut self, client_pubkey: [u8; 32]) -> Option<(String, Ipv4Addr)> {
        let ip = self.ip_pool.allocate()?;
        let session_id = generate_session_id();

        self.sessions.insert(
            session_id.clone(),
            SessionInfo {
                allocated_ip: ip,
                client_pubkey,
                last_seen: Instant::now(),
            },
        );

        Some((session_id, ip))
    }

    /// Update session last_seen time
    fn touch_session(&mut self, session_id: &str) {
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.last_seen = Instant::now();
        }
    }

    /// Cleanup expired sessions
    fn cleanup_expired_sessions(&mut self) {
        let expired: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.last_seen.elapsed() > SESSION_TIMEOUT)
            .map(|(id, _)| id.clone())
            .collect();

        for id in expired {
            if let Some(session) = self.sessions.remove(&id) {
                self.ip_pool.release(session.allocated_ip);
                debug!(session_id = %id, "Session expired and cleaned up");
            }
        }
    }
}

/// Generate cryptographically secure session ID
fn generate_session_id() -> String {
    // Use 0 as fallback if system time is before UNIX epoch (should never happen)
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let random: u64 = rng::random_u64();
    format!("{:x}{:016x}", timestamp, random)
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

    let replay_cache = Arc::new(NonceCache::new());

    let padder = Arc::new(build_padder(&args));
    let padding_strategy = args.padding_strategy.clone();
    let padding_max_jitter_us = args.padding_max_jitter_us;
    let padding_min_size = args.padding_min_size;
    let padding_mtu = args.padding_mtu.unwrap_or(args.mtu);
    let dns_servers = Arc::new(resolve_dns_servers(&args));
    debug!(dns_servers = ?dns_servers, "DNS servers configured");

    let probe_protector = Arc::new(build_probe_protector(&args));

    if let Some(path) = args.probe_metrics_path.clone() {
        let pp = probe_protector.clone();
        let interval = args.probe_metrics_interval;
        tokio::spawn(async move { probe_metrics_task(pp, path, interval).await });
    }

    let hybrid_server = Arc::new(
        HybridServer::from_secret(&noise_keypair.secret_bytes())
            .with_replay_protection(replay_cache.clone()),
    );

    info!(
        public_key = hex::encode(hybrid_server.public_key()),
        "Noise identity loaded"
    );

    let rotation_config = KeyRotationConfig::with_session_limits(
        Duration::from_secs(args.session_rekey_seconds),
        args.session_rekey_bytes,
    );
    let rotation_manager = Arc::new(KeyRotationManager::with_config(rotation_config.clone()));
    let (rotation_shutdown_tx, rotation_shutdown_rx) = broadcast::channel(1);
    let rotation_task = tokio::spawn(rotation_check_task(
        rotation_manager.clone(),
        rotation_shutdown_rx,
        rotation_config.check_interval,
    ));

    // Load TLS certificates
    let certs = load_certs(&args.cert)?;
    let key = load_key(&args.key)?;

    let tls_profile: TlsProfile = args.tls_profile.parse().unwrap_or(TlsProfile::Chrome);
    info!(profile = %tls_profile, "TLS profile configured (server)");

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

    // TLS fingerprint profile with canary rollout
    let main_profile: TlsProfile = args.tls_profile.parse().unwrap_or(TlsProfile::Chrome);
    let canary_profile = args
        .tls_canary_profile
        .parse()
        .ok()
        .filter(|p: &TlsProfile| !matches!(p, TlsProfile::Custom));
    let (tls_profile, tls_bucket) = select_tls_profile(
        main_profile,
        canary_profile,
        args.tls_canary_percent,
        Some(args.tls_canary_seed).filter(|s| *s != 0),
    );
    let grease_mode = parse_grease_mode(&args.tls_grease_mode, args.tls_grease_seed);
    let (ja3, ja3s, ja4, selected_cipher) = build_tls_fingerprint(&tls_profile, grease_mode);
    let ja3_hash = ja3.to_ja3_hash();
    let ja3s_hash = ja3s.to_ja3s_hash();
    let ja4_hash = ja4.to_hash();
    info!(
        profile = %tls_profile,
        bucket = ?tls_bucket,
        grease = ?grease_mode,
        ja3 = %ja3_hash,
        ja3s = %ja3s_hash,
        ja4 = %ja4_hash,
        selected_cipher = format!("0x{selected_cipher:04x}"),
        "TLS server fingerprint configured"
    );

    if let Some(path) = &args.tls_fp_metrics_path {
        let content = format!(
            "# HELP tls_fp_info TLS fingerprint JA3/JA3S/JA4\\n\
             # TYPE tls_fp_info gauge\\n\
             tls_fp_info{{bucket=\"{bucket}\",type=\"ja3\",hash=\"{ja3}\"}} 1\\n\
             tls_fp_info{{bucket=\"{bucket}\",type=\"ja3s\",hash=\"{ja3s}\"}} 1\\n\
             tls_fp_info{{bucket=\"{bucket}\",type=\"ja4\",hash=\"{ja4}\"}} 1\\n",
            bucket = match tls_bucket {
                TlsProfileBucket::Main => "main",
                TlsProfileBucket::Canary => "canary",
            },
            ja3 = ja3_hash,
            ja3s = ja3s_hash,
            ja4 = ja4_hash
        );
        if let Err(e) = fs::write(path, content.as_bytes()) {
            warn!(?e, ?path, "Failed to write tls_fp metrics");
        }
    }

    // Build QUIC server config
    let server_config = build_server_config(certs, key, args.idle_timeout, tls_profile)?;

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
        let rp = replay_cache.clone();
        let pad = padder.clone();
        let st = state.clone();
        let to_tun = to_tun_tx.clone();
        let rotation = rotation_manager.clone();
        let probe = probe_protector.clone();
        let padding_strategy = padding_strategy.clone();
        let cover_rate = args.cover_traffic_rate;
        let cover_pattern = args.cover_traffic_pattern.clone();
        let session_rekey_seconds = args.session_rekey_seconds;
        let session_rekey_bytes = args.session_rekey_bytes;
        let dns_servers = dns_servers.clone();
        let tls_bucket_local = tls_bucket;

        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    let remote = connection.remote_address();
                    info!(%remote, "New VPN connection");

                    if let Err(e) = handle_vpn_client_with_config(
                        connection,
                        hs,
                        rp,
                        pad,
                        st,
                        to_tun,
                        rotation,
                        probe,
                        gateway_ip,
                        mtu,
                        padding_strategy,
                        padding_max_jitter_us,
                        padding_min_size,
                        padding_mtu,
                        cover_rate,
                        cover_pattern,
                        session_rekey_seconds,
                        session_rekey_bytes,
                        dns_servers,
                        tls_bucket_local,
                    )
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

    let _ = rotation_shutdown_tx.send(());
    let _ = rotation_task.await;

    Ok(())
}

/// Handle a single VPN client connection
#[allow(clippy::too_many_arguments)]
async fn handle_vpn_client_with_config(
    connection: quinn::Connection,
    hybrid_server: Arc<HybridServer>,
    replay_cache: Arc<NonceCache>,
    padder: Arc<Padder>,
    state: Arc<RwLock<ServerState>>,
    to_tun_tx: mpsc::Sender<Bytes>,
    rotation: Arc<KeyRotationManager>,
    probe: Arc<ProbeProtector>,
    gateway_ip: Ipv4Addr,
    mtu: u16,
    padding_strategy: String,
    padding_max_jitter_us: u64,
    padding_min_size: usize,
    padding_mtu: u16,
    cover_rate: f64,
    cover_pattern: String,
    session_rekey_seconds: u64,
    session_rekey_bytes: u64,
    dns_servers: Arc<Vec<IpAddr>>,
    tls_bucket: TlsProfileBucket,
) -> Result<()> {
    let remote = connection.remote_address();
    let remote_ip = remote.ip();

    // Probe protection: IP ban/suspicion pre-check
    match probe.check_ip(remote_ip) {
        ProbeDetection::Blocked(reason) => {
            warn!(%remote, %reason, "Probe blocked before handshake");
            connection.close(0u32.into(), b"probe-blocked");
            anyhow::bail!("probe blocked: {reason}");
        }
        ProbeDetection::Suspicious(reason) => {
            warn!(%remote, %reason, "Probe suspicious, continuing with caution");
        }
        ProbeDetection::Legitimate => {}
    }

    // Wait for handshake stream
    let (send, recv) = connection
        .accept_bi()
        .await
        .context("accepting handshake stream")?;

    // Perform hybrid PQ Noise handshake with replay protection
    let mut stream = QuicBiStream::new(send, recv);

    let handshake_start = Instant::now();

    // Issue probe challenge (PoW + padding echo)
    let challenge = probe.issue_challenge(remote_ip);
    let mut challenge_frame = Vec::with_capacity(2 + 1 + 33);
    challenge_frame.extend_from_slice(&(34u16).to_be_bytes()); // length
    challenge_frame.push(1u8); // msg type = challenge
    challenge_frame.extend_from_slice(&challenge.nonce);
    challenge_frame.push(challenge.difficulty);
    stream
        .write_all(&challenge_frame)
        .await
        .context("sending probe challenge")?;
    stream.flush().await.ok();

    // Read challenge response
    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .await
        .context("reading probe response length")?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    if resp_len != 48 {
        probe.record_failure(remote_ip);
        anyhow::bail!("invalid probe response length: {resp_len}");
    }

    let mut resp_buf = vec![0u8; resp_len];
    stream
        .read_exact(&mut resp_buf)
        .await
        .context("reading probe response")?;
    if resp_buf[0] != 2 {
        probe.record_failure(remote_ip);
        anyhow::bail!("invalid probe response type");
    }

    let mut pow = [0u8; 32];
    pow.copy_from_slice(&resp_buf[1..33]);
    let padding_echo = &resp_buf[33..48];

    if !challenge.verify(&pow) {
        probe.record_failure(remote_ip);
        anyhow::bail!("probe PoW failed");
    }

    let server_padding_bytes = padding_schedule_bytes(
        &padding_strategy,
        padding_max_jitter_us,
        padding_min_size,
        padding_mtu,
    );

    if padding_echo != server_padding_bytes.as_slice() {
        probe.record_failure(remote_ip);
        anyhow::bail!("padding schedule mismatch");
    }

    let first_handshake = read_handshake_msg(&mut stream)
        .await
        .context("reading client handshake (msg1)")?;

    if let Err(e) = replay_cache.check_and_record(&first_handshake) {
        warn!(%remote, %e, "Replay attack detected, rejecting handshake");
        connection.close(0u32.into(), b"replay");
        anyhow::bail!("replay attack detected: {e}");
    }

    let (_transport, hybrid_secret) = hybrid_server
        .handshake_ik_with_first(&mut stream, first_handshake, true)
        .await
        .context("hybrid noise handshake")?;

    // Probe protection: timing analysis
    match probe.check_timing(handshake_start.elapsed()) {
        ProbeDetection::Blocked(reason) => {
            warn!(%remote, %reason, "Handshake timing blocked");
            connection.close(0u32.into(), b"probe-timing");
            anyhow::bail!(reason);
        }
        ProbeDetection::Suspicious(reason) => {
            warn!(%remote, %reason, "Handshake timing suspicious");
        }
        ProbeDetection::Legitimate => {}
    }

    // Extract client's public key from handshake for session binding
    // HybridSecret.combined is [u8; 32], so this is always valid
    let client_pubkey: [u8; 32] = hybrid_secret.combined;

    info!(
        %remote,
        secret_prefix = hex::encode(&hybrid_secret.combined[..8]),
        "Client authenticated"
    );

    let session_state = rotation.register_session().await;

    // Allocate or restore session
    let (session_id, client_ip) = {
        let mut st = state.write().await;
        // Cleanup expired sessions periodically
        st.cleanup_expired_sessions();

        // Create new session with IP allocation
        st.create_session(client_pubkey)
            .ok_or_else(|| anyhow::anyhow!("IP pool exhausted"))?
    };

    info!(%remote, client_ip = %client_ip, session_id = %session_id, "Session created");
    debug!(%remote, tls_bucket = ?tls_bucket, "TLS canary bucket applied for client");

    // Send VPN configuration to client with session_id for reconnect
    let mut vpn_config = VpnConfig::new(client_ip, gateway_ip)
        .with_mtu(mtu)
        .with_padding(
            padding_strategy,
            padding_max_jitter_us,
            padding_min_size,
            padding_mtu,
        )
        .with_rotation(session_rekey_seconds, session_rekey_bytes)
        .with_route("0.0.0.0/0") // Full tunnel mode
        .with_session_id(&session_id);

    for dns in dns_servers.iter() {
        vpn_config = vpn_config.with_dns(*dns);
    }

    if let Err(e) = vpn_config.send(&mut stream).await {
        probe.record_failure(remote_ip);
        return Err(e).context("sending VPN config");
    }

    info!(%remote, client_ip = %client_ip, "VPN config sent");

    // Wait for client acknowledgment
    let ack = match ConfigAck::recv(&mut stream).await {
        Ok(a) => a,
        Err(e) => {
            probe.record_failure(remote_ip);
            return Err(e).context("receiving config ack");
        }
    };

    if !ack.accepted {
        let err_msg = ack.error.unwrap_or_else(|| "unknown error".into());
        error!(%remote, %err_msg, "Client rejected config");
        // Remove session and release IP on rejection
        let mut st = state.write().await;
        st.sessions.remove(&session_id);
        st.ip_pool.release(client_ip);
        probe.record_failure(remote_ip);
        anyhow::bail!("client rejected config: {}", err_msg);
    }

    info!(%remote, client_ip = %client_ip, "Client accepted config");
    probe.record_success(remote_ip);

    // Create channel for packets going to this client
    let (client_tx, mut client_rx) = mpsc::channel::<Bytes>(1024);

    // Cover traffic generator
    let cover_config = build_cover_config(cover_rate, &cover_pattern, mtu as usize);
    let mut cover_gen = CoverTrafficGenerator::new(cover_config);

    // Register client session
    {
        let mut st = state.write().await;
        st.clients.insert(
            client_ip,
            ClientSession {
                connection: connection.clone(),
                allocated_ip: client_ip,
                tx: client_tx,
                session_state: session_state.clone(),
            },
        );
    }

    let encapsulator = Arc::new(PacketEncapsulator::new());

    // Spawn task to send packets to client with padding + jitter
    let conn_clone = connection.clone();
    let encap_clone = encapsulator.clone();
    let pad_clone = padder.clone();
    let session_state_tx = session_state.clone();
    let to_client_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(packet) = client_rx.recv() => {
                    let padded = pad_clone.pad(&packet);
                    if let Some(delay) = pad_clone.jitter_delay() { sleep(delay).await; }
                    let datagram = encap_clone.encapsulate(Bytes::from(padded));
                    session_state_tx.record_bytes(datagram.len() as u64);
                    session_state_tx.maybe_rotate_with(|reason| {
                        info!(?reason, "Server session rekey (tx)");
                        conn_clone.force_key_update();
                    });
                    if let Err(e) = conn_clone.send_datagram(datagram) {
                        debug!(%e, "Error sending to client");
                        break;
                    }
                }
                else => break,
            }
        }
    });

    // Forward datagrams from client to TUN
    // Spawn cover traffic task
    let cover_conn = connection.clone();
    let cover_encap = encapsulator.clone();
    let cover_padder = padder.clone();
    let session_state_cover = session_state.clone();
    let cover_task = tokio::spawn(async move {
        loop {
            let delay = cover_gen.next_delay();
            sleep(delay).await;

            let mut packet = cover_gen.generate_packet().data;
            // Reuse padder for size/timing consistency
            cover_padder.pad_in_place(&mut packet);
            if let Some(j) = cover_padder.jitter_delay() {
                sleep(j).await;
            }

            let datagram = cover_encap.encapsulate(Bytes::from(packet));
            // Send through same QUIC connection to be indistinguishable
            session_state_cover.record_bytes(datagram.len() as u64);
            session_state_cover.maybe_rotate_with(|reason| {
                info!(?reason, "Server session rekey (cover)");
                cover_conn.force_key_update();
            });
            if cover_conn.send_datagram(datagram).is_err() {
                break;
            }
        }
    });

    loop {
        match connection.read_datagram().await {
            Ok(datagram) => {
                session_state.record_bytes(datagram.len() as u64);
                session_state.maybe_rotate_with(|reason| {
                    info!(?reason, "Server session rekey (rx)");
                    connection.force_key_update();
                });
                match encapsulator.decapsulate(datagram) {
                    Ok(packet) => {
                        if to_tun_tx.send(packet).await.is_err() {
                            warn!("TUN channel closed");
                            break;
                        }
                    }
                    Err(e) => {
                        warn!(%e, "Decapsulation error");
                    }
                }
            }
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

    // Cleanup - remove from active clients but keep session for reconnect
    to_client_task.abort();
    cover_task.abort();

    {
        let mut st = state.write().await;
        st.clients.remove(&client_ip);
        // Touch session to reset timeout (allows reconnect within SESSION_TIMEOUT)
        st.touch_session(&session_id);
        // Note: IP is NOT released here - session keeps IP reservation for reconnect
    }

    info!(
        %remote,
        client_ip = %client_ip,
        session_id = %session_id,
        "Client disconnected, session preserved for reconnect"
    );

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
            Ok(packet) => match masque_core::tun::IpPacketInfo::parse(&packet) {
                Ok(info) => {
                    let dst_ip = info.dst_addr;
                    let st = state.read().await;
                    if let Some(session) = st.clients.get(&dst_ip) {
                        if session.tx.send(packet).await.is_err() {
                            debug!(dst = %dst_ip, "Client channel closed");
                        }
                    } else {
                        debug!(dst = %dst_ip, "No client for destination");
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

fn parse_grease_mode(mode: &str, seed: u64) -> GreaseMode {
    match mode.to_ascii_lowercase().as_str() {
        "deterministic" | "det" | "fixed" => GreaseMode::Deterministic(seed),
        _ => GreaseMode::Random,
    }
}

fn preferred_tls13_cipher(profile: &TlsProfile) -> u16 {
    profile
        .cipher_suites()
        .into_iter()
        .find(|c| (*c & 0xff00) == 0x1300)
        .unwrap_or(0x1301)
}

fn build_tls_fingerprint(
    profile: &TlsProfile,
    grease_mode: GreaseMode,
) -> (Ja3Fingerprint, Ja3sFingerprint, Ja4Fingerprint, u16) {
    let ja3 = Ja3Fingerprint::from_profile_with_grease(profile, grease_mode);
    let selected_cipher = preferred_tls13_cipher(profile);
    let ja3s = Ja3sFingerprint::from_profile_with_grease(profile, selected_cipher, grease_mode);
    let ja4 = Ja4Fingerprint::from_profile(profile);
    (ja3, ja3s, ja4, selected_cipher)
}

fn build_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    idle_timeout: u64,
    tls_profile: TlsProfile,
) -> Result<ServerConfig> {
    let mut transport_config = TransportConfig::default();
    transport_config.max_idle_timeout(Some(Duration::from_secs(idle_timeout).try_into()?));

    // Enable QUIC datagrams for VPN traffic
    transport_config.datagram_receive_buffer_size(Some(65536));
    transport_config.datagram_send_buffer_size(65536);

    let provider = rustls::crypto::CryptoProvider {
        cipher_suites: tls_profile.rustls_cipher_suites(),
        kx_groups: tls_profile.rustls_kx_groups(),
        ..rustls::crypto::ring::default_provider()
    };

    let mut rustls_config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    rustls_config.alpn_protocols = vec![b"h3".to_vec(), b"masque".to_vec()];
    rustls_config.max_early_data_size = u32::MAX;

    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(rustls_config))
        .context("building rustls QUIC server config")?;

    let mut server_config = ServerConfig::with_crypto(Arc::new(crypto));
    server_config.transport_config(Arc::new(transport_config));

    Ok(server_config)
}

fn parse_padding_strategy(name: &str) -> PaddingStrategy {
    match name.to_ascii_lowercase().as_str() {
        "none" => PaddingStrategy::None,
        "bucket" => PaddingStrategy::Bucket,
        "mtu" => PaddingStrategy::Mtu,
        "rand-bucket" | "random-bucket" | "random" => PaddingStrategy::RandomBucket,
        other => {
            warn!(strategy = %other, "Unknown padding strategy, falling back to random-bucket");
            PaddingStrategy::RandomBucket
        }
    }
}

fn build_padder(args: &Args) -> Padder {
    let strategy = parse_padding_strategy(&args.padding_strategy);
    let mtu = args.padding_mtu.unwrap_or(args.mtu) as usize;

    let config = PaddingConfig {
        strategy,
        mtu,
        jitter_enabled: args.padding_max_jitter_us > 0,
        max_jitter_us: args.padding_max_jitter_us,
        min_packet_size: args.padding_min_size,
    };

    Padder::new(config)
}

fn parse_cover_pattern(name: &str) -> TrafficPattern {
    match name.to_ascii_lowercase().as_str() {
        "https" => TrafficPattern::HttpsBurst,
        "h3" => TrafficPattern::H3Multiplex,
        "webrtc" => TrafficPattern::WebRtcCbr,
        "idle" => TrafficPattern::Idle,
        _ => TrafficPattern::HttpsBurst,
    }
}

fn build_cover_config(rate: f64, pattern: &str, mtu: usize) -> CoverTrafficConfig {
    CoverTrafficConfig {
        pattern: parse_cover_pattern(pattern),
        base_rate_pps: rate,
        rate_jitter: 0.35,
        min_packet_size: 64,
        max_packet_size: mtu.saturating_sub(40).max(64),
        adaptive: true,
        min_interval: Duration::from_millis(5),
    }
}

fn padding_strategy_to_byte(strategy: &str) -> u8 {
    match parse_padding_strategy(strategy) {
        PaddingStrategy::None => 0,
        PaddingStrategy::Bucket => 1,
        PaddingStrategy::RandomBucket => 2,
        PaddingStrategy::Mtu => 3,
    }
}

fn padding_schedule_bytes(
    strategy: &str,
    max_jitter_us: u64,
    min_size: usize,
    mtu: u16,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(15);
    out.push(padding_strategy_to_byte(strategy));
    out.extend_from_slice(&max_jitter_us.to_be_bytes());
    out.extend_from_slice(&(min_size as u32).to_be_bytes());
    out.extend_from_slice(&mtu.to_be_bytes());
    out
}

fn build_probe_protector(args: &Args) -> ProbeProtector {
    let config = ProbeProtectionConfig {
        challenge_enabled: true,
        challenge_difficulty: args.probe_difficulty,
        ban_duration: Duration::from_secs(args.probe_ban_seconds),
        max_failed_attempts: args.probe_max_failed_attempts,
        timing_analysis: true,
        min_handshake_time: Duration::from_millis(args.probe_min_handshake_ms),
        max_handshake_time: Duration::from_millis(args.probe_max_handshake_ms),
    };

    ProbeProtector::new(config)
}

fn resolve_dns_servers(args: &Args) -> Vec<IpAddr> {
    if args.dns_servers.is_empty() {
        DEFAULT_DNS_SERVERS.to_vec()
    } else {
        args.dns_servers.clone()
    }
}

async fn probe_metrics_task(protector: Arc<ProbeProtector>, path: PathBuf, interval_secs: u64) {
    let mut ticker = interval(Duration::from_secs(interval_secs.max(1)));
    loop {
        ticker.tick().await;
        let path = path.clone();
        let protector_clone = protector.clone();
        if let Err(e) = tokio::task::spawn_blocking(move || {
            let content = protector_clone.metrics().to_prometheus("probe");
            let tmp = path.with_extension(".tmp");
            fs::write(&tmp, content.as_bytes())?;
            fs::rename(&tmp, &path)?;
            Ok::<(), std::io::Error>(())
        })
        .await
        .unwrap_or_else(|e| Err(std::io::Error::other(e)))
        {
            warn!(%e, "Failed to persist probe metrics");
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_session_id_uses_osrng() {
        rng::enable_counting();
        rng::reset_osrng_calls();
        let id = generate_session_id();
        assert!(
            rng::osrng_call_count() >= 1,
            "Session ID generator must draw from OsRng"
        );
        // Ensure formatting produced non-empty hex string
        assert!(id.len() >= 24);
    }

    #[test]
    fn dns_flag_parsing_defaults_to_public_resolvers() {
        let args = Args::parse_from(["test", "--cert", "/tmp/cert", "--key", "/tmp/key"]);
        let dns = resolve_dns_servers(&args);
        assert_eq!(dns, DEFAULT_DNS_SERVERS.to_vec());
    }

    #[test]
    fn dns_flag_parsing_accepts_ipv4_and_ipv6() {
        let args = Args::parse_from([
            "test",
            "--cert",
            "/tmp/cert",
            "--key",
            "/tmp/key",
            "--dns-servers",
            "9.9.9.9,2001:4860:4860::8844",
        ]);
        let dns = resolve_dns_servers(&args);
        assert_eq!(
            dns,
            vec![
                IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
                IpAddr::V6("2001:4860:4860::8844".parse().unwrap())
            ]
        );
    }
}
