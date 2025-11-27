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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{broadcast, mpsc, RwLock};
use tokio::time::interval;
use tokio::time::sleep;
use tracing::{debug, error, info, trace, warn, Level};
use tracing_subscriber::FmtSubscriber;

use ipnetwork::IpNetwork;
use masque_core::cover_traffic::CoverTrafficGenerator;
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
use masque_core::tun::{
    enable_ip_forwarding, setup_ipv6_nat, setup_nat_with_config, NatConfig, RouteRule,
    RoutingConfig, RoutingPolicy, RoutingState, TunConfig, TunDevice,
};
use masque_core::vpn_common::{
    build_cover_config, padding_schedule_bytes_raw, parse_grease_mode, parse_padding_strategy,
    preferred_tls13_cipher,
};
use masque_core::vpn_config::{ConfigAck, VpnConfig};
use masque_core::vpn_tunnel::PacketEncapsulator;
use rustls::crypto::SupportedKxGroup;
use rustls::SupportedCipherSuite;
use vpr_crypto::ct_eq_32;
use vpr_crypto::keys::NoiseKeypair;

#[derive(Debug, Default)]
struct SuspicionTracker {
    score: Mutex<f64>,
}

/// Try to detect the default outbound interface from system routing table (Linux "ip route show default").
fn detect_default_iface() -> Option<String> {
    if let Ok(output) = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let mut parts = line.split_whitespace();
                while let Some(tok) = parts.next() {
                    if tok == "dev" {
                        if let Some(iface) = parts.next() {
                            return Some(iface.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

impl SuspicionTracker {
    fn new() -> Self {
        Self {
            score: Mutex::new(0.0),
        }
    }

    fn add(&self, delta: f64) {
        if let Ok(mut s) = self.score.lock() {
            *s = (*s + delta).clamp(0.0, 100.0);
        }
    }

    fn current(&self) -> f64 {
        self.score.lock().map(|s| *s).unwrap_or(0.0)
    }

    fn prometheus(&self, prefix: &str) -> String {
        let val = self.score.lock().map(|s| *s).unwrap_or(0.0);
        format!("{prefix}_score {{}} {val}\n")
    }
}

#[derive(Parser, Debug)]
#[command(name = "vpn-server", version, about = "VPR VPN server with TUN tunnel")]
struct Args {
    /// QUIC bind address
    #[arg(long, default_value = "0.0.0.0:4433")]
    bind: SocketAddr,

    /// TUN device name
    #[arg(long, default_value = "vpr-srv0")]
    tun_name: String,

    /// Server TUN IP address (gateway for clients)
    #[arg(long, default_value = "10.9.0.1")]
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
    #[arg(long, default_value = "10.9.0.2")]
    pool_start: Ipv4Addr,

    /// End of client IP pool
    #[arg(long, default_value = "10.9.0.254")]
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
    #[arg(long, default_value_t = true)]
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

    /// Enable IPv6 support
    #[arg(long)]
    ipv6: bool,

    /// Enable IPv6 NAT masquerading
    #[arg(long)]
    ipv6_nat: bool,

    /// Routing policy: full|split|bypass
    #[arg(long, default_value = "full")]
    routing_policy: String,

    /// Routes to push to clients (CIDR notation, comma-separated)
    #[arg(long, value_delimiter = ',')]
    routes: Vec<String>,

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

    /// Run tls-fp-sync.py on startup to refresh fingerprint profiles
    #[arg(long)]
    tls_fp_sync: bool,

    /// Path to tls-fp-sync log file
    #[arg(long, default_value = "logs/tls-fp-sync.log")]
    tls_fp_sync_log: PathBuf,
}

/// Client session with allocated IP and connection
struct ClientSession {
    #[allow(dead_code)]
    connection: quinn::Connection,
    #[allow(dead_code)]
    allocated_ip: Ipv4Addr,
    /// IPv6 address derived from IPv4 (ULA fd09::/64 + IPv4 suffix)
    #[allow(dead_code)]
    allocated_ip6: Ipv6Addr,
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
    /// Active client sessions indexed by their allocated IPv4
    clients: HashMap<Ipv4Addr, ClientSession>,
    /// Active client senders indexed by their allocated IPv6 (for IPv6 packet routing)
    clients_v6: HashMap<Ipv6Addr, mpsc::Sender<Bytes>>,
    /// Persistent sessions indexed by session_id (for reconnect)
    sessions: HashMap<String, SessionInfo>,
    /// IP address pool
    ip_pool: IpPool,
}

impl ServerState {
    fn new(pool_start: Ipv4Addr, pool_end: Ipv4Addr) -> Self {
        Self {
            clients: HashMap::new(),
            clients_v6: HashMap::new(),
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

/// Convert IPv4 address to IPv6 using ULA prefix fd09::/64
/// Maps 10.9.0.x -> fd09::10:9:0:x
fn ipv4_to_ipv6(ipv4: Ipv4Addr) -> Ipv6Addr {
    let octets = ipv4.octets();
    // ULA prefix fd09:: with IPv4 embedded in last 64 bits
    // Format: fd09:0000:0000:0000:00AA:00BB:00CC:00DD
    Ipv6Addr::new(
        0xfd09,
        0,
        0,
        0,
        u16::from(octets[0]),
        u16::from(octets[1]),
        u16::from(octets[2]),
        u16::from(octets[3]),
    )
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
    let suspicion = Arc::new(SuspicionTracker::new());

    // Create DPI feedback controller for adaptive traffic shaping
    // Note: We use the local SuspicionTracker, not the one from suspicion module
    // For now, we'll update DPI feedback manually from suspicion score in connection handlers
    let dpi_feedback = Arc::new(masque_core::dpi_feedback::DpiFeedbackController::new());

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
        let susp = suspicion.clone();
        let interval = args.probe_metrics_interval;
        tokio::spawn(async move { probe_metrics_task(pp, susp, path, interval).await });
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

    // Legacy log for main profile (actual selection per-connection)
    let main_profile: TlsProfile = args.tls_profile.parse().unwrap_or(TlsProfile::Chrome);
    info!(profile = %main_profile, "TLS profile configured (server, main)");

    // Create TUN device
    let tun_config = TunConfig {
        name: args.tun_name.clone(),
        address: args.tun_addr,
        netmask: args.tun_netmask,
        mtu: args.mtu,
        destination: None,
        address_v6: None,
        prefix_len_v6: None,
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
    } else {
        warn!("IP forwarding disabled by flag; clients will not reach the internet");
    }

    // Setup NAT with improved configuration
    let mut nat_state = RoutingState::new();
    let outbound_iface = match args.outbound_iface.clone() {
        Some(iface) => Some(iface),
        None => detect_default_iface(),
    };

    if let Some(ref iface) = outbound_iface {
        let nat_config = NatConfig {
            outbound_iface: iface.clone(),
            masquerade_ipv4: true,
            masquerade_ipv6: args.ipv6_nat,
            preserve_source: false,
        };
        setup_nat_with_config(tun.name(), &nat_config, &mut nat_state).context("setting up NAT")?;
        info!(
            tun = %tun.name(),
            outbound = %iface,
            ipv6_nat = args.ipv6_nat,
            "NAT configured"
        );
    } else {
        warn!("No outbound interface detected; NAT not configured");
    }

    // Setup IPv6 NAT if requested
    if args.ipv6_nat {
        if let Some(ref iface) = args.outbound_iface {
            setup_ipv6_nat(tun.name(), iface, &mut nat_state).context("setting up IPv6 NAT")?;
        } else {
            warn!("IPv6 NAT requested but no outbound interface specified");
        }
    }

    // TLS fingerprint profiles (main + canary union for rustls config)
    if args.tls_fp_sync {
        let log_path = &args.tls_fp_sync_log;
        let stdout = File::options().append(true).create(true).open(log_path);
        let stderr = File::options().append(true).create(true).open(log_path);
        match (stdout, stderr) {
            (Ok(out), Ok(err)) => {
                let status = Command::new("python")
                    .arg("scripts/tls-fp-sync.py")
                    .arg("--validate-only")
                    .stdout(out)
                    .stderr(err)
                    .status();
                match status {
                    Ok(s) if s.success() => info!(?log_path, "tls-fp-sync validate-only succeeded"),
                    Ok(s) => {
                        warn!(?log_path, code=?s.code(), "tls-fp-sync failed, using existing profiles")
                    }
                    Err(e) => warn!(?e, ?log_path, "Failed to run tls-fp-sync"),
                }
            }
            _ => warn!(?log_path, "Could not open tls-fp-sync log file"),
        }
    }

    let canary_profile = args
        .tls_canary_profile
        .parse()
        .ok()
        .filter(|p: &TlsProfile| !matches!(p, TlsProfile::Custom));
    let grease_mode = parse_grease_mode(&args.tls_grease_mode, args.tls_grease_seed);

    let mut cipher_union = main_profile.rustls_cipher_suites();
    if let Some(cp) = canary_profile {
        for cs in cp.rustls_cipher_suites() {
            if !cipher_union.iter().any(|x| x.suite() == cs.suite()) {
                cipher_union.push(cs);
            }
        }
    }
    let mut kx_union: Vec<&'static dyn SupportedKxGroup> = main_profile.rustls_kx_groups();
    if let Some(cp) = canary_profile {
        for kx in cp.rustls_kx_groups() {
            kx_union.push(kx);
        }
    }

    // Build QUIC server config
    let server_config = build_server_config(
        certs,
        key,
        args.idle_timeout,
        cipher_union.clone(),
        kx_union.clone(),
    )?;

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
    let routing_policy = args.routing_policy.clone();
    let routes = Arc::new(args.routes.clone());
    let ipv6_enabled = args.ipv6;

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
        let suspicion = suspicion.clone();
        let suspicion_score = suspicion.current();
        let dpi_feedback_conn = dpi_feedback.clone();
        let effective_canary = if suspicion_score >= 35.0 {
            0.0
        } else {
            args.tls_canary_percent
        };
        let (tls_profile_selected, tls_bucket_local) = select_tls_profile(
            main_profile,
            canary_profile,
            effective_canary,
            Some(args.tls_canary_seed).filter(|s| *s != 0),
        );
        let routing_policy_clone = routing_policy.clone();
        let routes_clone = routes.clone();
        let ipv6_enabled_clone = ipv6_enabled;

        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    let remote = connection.remote_address();
                    info!(%remote, "New VPN connection");

                    // Per-connection TLS fingerprints for metrics/logging
                    let (ja3, ja3s, ja4, selected_cipher) =
                        build_tls_fingerprint(&tls_profile_selected, grease_mode);
                    let ja3_hash = ja3.to_ja3_hash();
                    let ja3s_hash = ja3s.to_ja3s_hash();
                    let ja4_hash = ja4.to_hash();
                    info!(
                        %remote,
                        profile = %tls_profile_selected,
                        bucket = ?tls_bucket_local,
                        suspicion = suspicion_score,
                        ja3 = %ja3_hash,
                        ja3s = %ja3s_hash,
                        ja4 = %ja4_hash,
                        selected_cipher = format!("0x{selected_cipher:04x}"),
                        "TLS fingerprint selected"
                    );

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
                        suspicion,
                        routing_policy_clone,
                        routes_clone,
                        ipv6_enabled_clone,
                        dpi_feedback_conn.clone(),
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
    suspicion: Arc<SuspicionTracker>,
    routing_policy: String,
    routes: Arc<Vec<String>>,
    ipv6_enabled: bool,
    dpi_feedback: Arc<masque_core::dpi_feedback::DpiFeedbackController>,
) -> Result<()> {
    let remote = connection.remote_address();
    let remote_ip = remote.ip();

    // Probe protection: IP ban/suspicion pre-check
    match probe.check_ip(remote_ip) {
        ProbeDetection::Blocked(reason) => {
            suspicion.add(40.0);
            warn!(%remote, %reason, "Probe blocked before handshake");
            connection.close(0u32.into(), b"probe-blocked");
            anyhow::bail!("probe blocked: {reason}");
        }
        ProbeDetection::Suspicious(reason) => {
            suspicion.add(15.0);
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

    // Read protocol init byte (QUIC streams require client to write first)
    const VPR_PROTOCOL_VERSION: u8 = 0x01;
    let mut init_buf = [0u8; 1];
    stream
        .read_exact(&mut init_buf)
        .await
        .context("reading protocol init")?;
    if init_buf[0] != VPR_PROTOCOL_VERSION {
        anyhow::bail!(
            "unsupported protocol version: {} (expected {})",
            init_buf[0],
            VPR_PROTOCOL_VERSION
        );
    }

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

    if !probe.verify_challenge(remote_ip, &challenge.nonce, &pow) {
        probe.record_failure(remote_ip);
        anyhow::bail!("probe PoW failed");
    }

    let server_padding_bytes = padding_schedule_bytes_raw(
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
            suspicion.add(25.0);
            warn!(%remote, %reason, "Handshake timing blocked");
            connection.close(0u32.into(), b"probe-timing");
            anyhow::bail!(reason);
        }
        ProbeDetection::Suspicious(reason) => {
            suspicion.add(10.0);
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

    // Parse routing policy
    let policy = match routing_policy.to_lowercase().as_str() {
        "split" => RoutingPolicy::Split,
        "bypass" => RoutingPolicy::Bypass,
        _ => RoutingPolicy::Full,
    };

    // Parse routes
    let route_rules: Vec<RouteRule> = routes
        .iter()
        .filter_map(|r| {
            IpNetwork::from_str(r).ok().map(|net| RouteRule {
                destination: net,
                gateway: Some(IpAddr::V4(gateway_ip)),
                metric: 0,
                table: None,
            })
        })
        .collect();

    // Create routing config
    let routing_config = RoutingConfig {
        policy,
        routes: route_rules.clone(),
        dns_servers: dns_servers.as_ref().clone(),
        ipv6_enabled,
    };

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
        .with_suspicion(suspicion.current())
        .with_routing_config(routing_config)
        .with_session_id(&session_id);

    // Add routes for backward compatibility
    if policy == RoutingPolicy::Full {
        vpn_config = vpn_config.with_route("0.0.0.0/0");
    } else {
        for route in routes.iter() {
            vpn_config = vpn_config.with_route(route);
        }
    }

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

    // Register client session (IPv4 + IPv6 dual-stack)
    let client_ip6 = ipv4_to_ipv6(client_ip);
    {
        let mut st = state.write().await;
        st.clients.insert(
            client_ip,
            ClientSession {
                connection: connection.clone(),
                allocated_ip: client_ip,
                allocated_ip6: client_ip6,
                tx: client_tx.clone(),
                session_state: session_state.clone(),
            },
        );
        // Register IPv6 mapping for dual-stack packet routing
        st.clients_v6.insert(client_ip6, client_tx);
    }

    let encapsulator = Arc::new(PacketEncapsulator::new());

    // Spawn task to send packets to client with padding + jitter
    let conn_clone = connection.clone();
    let encap_clone = encapsulator.clone();
    let pad_clone = padder.clone();
    let session_state_tx = session_state.clone();
    let dpi_feedback_tx = dpi_feedback.clone();
    let to_client_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(packet) = client_rx.recv() => {
                    // Update padder suspicion based on DPI feedback
                    let suspicion = dpi_feedback_tx.current_suspicion();
                    pad_clone.update_suspicion(suspicion);

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
                        // Validate IP packet before sending to TUN
                        // Cover traffic generates random data that is not valid IP
                        match masque_core::tun::IpPacketInfo::parse(&packet) {
                            Ok(_info) => {
                                // Valid IP packet - send to TUN
                                if to_tun_tx.send(packet).await.is_err() {
                                    warn!("TUN channel closed");
                                    break;
                                }
                            }
                            Err(_) => {
                                // Not a valid IP packet - likely cover traffic, silently drop
                                trace!(
                                    packet_len = packet.len(),
                                    "Dropping non-IP packet (cover traffic)"
                                );
                            }
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
        st.clients_v6.remove(&client_ip6);
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
                    // Dual-stack: route by IPv4 or IPv6 destination
                    if let Some(dst_ipv4) = info.dst_addr.as_ipv4() {
                        let st = state.read().await;
                        if let Some(session) = st.clients.get(&dst_ipv4) {
                            if session.tx.send(packet).await.is_err() {
                                debug!(dst = %dst_ipv4, "Client channel closed");
                            }
                        } else {
                            debug!(dst = %dst_ipv4, "No client for destination");
                        }
                    } else if let Some(dst_ipv6) = info.dst_addr.as_ipv6() {
                        // IPv6 packet - lookup in clients_v6
                        let st = state.read().await;
                        if let Some(tx) = st.clients_v6.get(&dst_ipv6) {
                            if tx.send(packet).await.is_err() {
                                debug!(dst = %dst_ipv6, "Client channel closed (IPv6)");
                            }
                        } else {
                            // Link-local and multicast IPv6 are common, log at trace
                            trace!(
                                dst = %dst_ipv6,
                                protocol = %info.protocol_name(),
                                "No client for IPv6 destination"
                            );
                        }
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
    cipher_suites: Vec<SupportedCipherSuite>,
    kx_groups: Vec<&'static dyn SupportedKxGroup>,
) -> Result<ServerConfig> {
    let mut transport_config = TransportConfig::default();
    transport_config.max_idle_timeout(Some(Duration::from_secs(idle_timeout).try_into()?));

    // Enable QUIC datagrams for VPN traffic
    transport_config.datagram_receive_buffer_size(Some(65536));
    transport_config.datagram_send_buffer_size(65536);

    // Configure MTU for VPN traffic - set initial MTU high enough for typical networks
    // TUN MTU 1400 + QUIC overhead (~60 bytes) requires UDP payload of ~1460
    // We set initial_mtu to 1500 (standard Ethernet MTU) and enable MTU discovery
    transport_config.initial_mtu(1500);
    transport_config.min_mtu(1280); // IPv6 minimum, safe fallback
    transport_config.mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()));

    let provider = rustls::crypto::CryptoProvider {
        cipher_suites,
        kx_groups,
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

fn build_padder(args: &Args) -> Padder {
    let strategy = parse_padding_strategy(&args.padding_strategy);
    let mtu = args.padding_mtu.unwrap_or(args.mtu) as usize;

    let config = PaddingConfig {
        strategy,
        mtu,
        jitter_enabled: args.padding_max_jitter_us > 0,
        max_jitter_us: args.padding_max_jitter_us,
        min_packet_size: args.padding_min_size,
        adaptive: true,
        high_strategy: PaddingStrategy::Mtu,
        medium_strategy: PaddingStrategy::Bucket,
        low_strategy: PaddingStrategy::RandomBucket,
        high_threshold: 60,
        medium_threshold: 20,
        hysteresis: 5,
    };

    Padder::new(config)
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

async fn probe_metrics_task(
    protector: Arc<ProbeProtector>,
    suspicion: Arc<SuspicionTracker>,
    path: PathBuf,
    interval_secs: u64,
) {
    let mut ticker = interval(Duration::from_secs(interval_secs.max(1)));
    loop {
        ticker.tick().await;
        let path = path.clone();
        let protector_clone = protector.clone();
        let suspicion_clone = suspicion.clone();
        if let Err(e) = tokio::task::spawn_blocking(move || {
            let content = protector_clone.metrics().to_prometheus("probe");
            let susp = suspicion_clone.prometheus("suspicion");
            let tmp = path.with_extension(".tmp");
            fs::write(&tmp, format!("{content}{susp}").as_bytes())?;
            fs::rename(&tmp, &path)?;
            Ok::<(), std::io::Error>(())
        })
        .await
        .unwrap_or_else(|e| {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        }) {
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
