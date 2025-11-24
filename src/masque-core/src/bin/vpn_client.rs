//! VPR VPN Client - Full tunnel mode with TUN device
//!
//! This binary creates a TUN interface and routes traffic through
//! a MASQUE CONNECT-UDP tunnel with hybrid post-quantum encryption.

use anyhow::{Context, Result};
use clap::Parser;
use quinn::{ClientConfig as QuinnClientConfig, Endpoint, TransportConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::Sha256;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

use masque_core::cover_traffic::{CoverTrafficConfig, CoverTrafficGenerator, TrafficPattern};
use masque_core::hybrid_handshake::HybridClient;
use masque_core::key_rotation::{
    rotation_check_task, KeyRotationConfig, KeyRotationManager, SessionKeyLimits, SessionKeyState,
};
use masque_core::padding::{Padder, PaddingConfig, PaddingStrategy};
use masque_core::quic_stream::QuicBiStream;
use masque_core::tls_fingerprint::{
    select_tls_profile, GreaseMode, Ja3Fingerprint, Ja3sFingerprint, Ja4Fingerprint, TlsProfile,
    TlsProfileBucket,
};
use masque_core::tun::{restore_routing, setup_routing, DnsProtection, TunConfig, TunDevice};
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

    /// Session rekey time limit (seconds)
    #[arg(long, default_value = "60")]
    session_rekey_seconds: u64,

    /// Session rekey data limit (bytes)
    #[arg(long, default_value = "1073741824")]
    session_rekey_bytes: u64,

    /// Enable DNS leak protection (overwrites /etc/resolv.conf)
    #[arg(long)]
    dns_protection: bool,

    /// Custom DNS servers to use with DNS protection (IPv4/IPv6, comma-separated)
    /// If not specified, uses DNS servers from VPN config
    #[arg(long, value_delimiter = ',')]
    dns_servers: Vec<IpAddr>,

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

    /// Export JA3/JA3S/JA4 metrics to Prometheus text file
    #[arg(long)]
    tls_fp_metrics_path: Option<PathBuf>,

    /// GREASE mode: random|deterministic
    #[arg(long, default_value = "random")]
    tls_grease_mode: String,

    /// GREASE seed when deterministic mode is selected
    #[arg(long, default_value_t = 0)]
    tls_grease_seed: u64,

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
        .or_else(|| profile.cipher_suites().first().copied())
        .unwrap_or(0x1301)
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

    // Parse TLS profiles (main + canary)
    let main_profile: TlsProfile = args.tls_profile.parse().unwrap_or_else(|_| {
        tracing::warn!(profile = %args.tls_profile, "Unknown TLS profile, using Chrome");
        TlsProfile::Chrome
    });
    let canary_profile = args
        .tls_canary_profile
        .parse()
        .ok()
        .filter(|p: &TlsProfile| !matches!(p, TlsProfile::Custom));
    let grease_mode = parse_grease_mode(&args.tls_grease_mode, args.tls_grease_seed);

    // Suspicion-aware TLS selection: if server reports suspicion >=35, disable canary
    // (config obtained later; before handshake default to 0)
    let server_suspicion = 0.0;
    let effective_canary = if server_suspicion >= 35.0 {
        0.0
    } else {
        args.tls_canary_percent
    };
    let (tls_profile, tls_bucket) = select_tls_profile(
        main_profile,
        canary_profile,
        effective_canary,
        Some(args.tls_canary_seed).filter(|s| *s != 0),
    );

    // Log JA3/JA3S/JA4 fingerprints for debugging
    let ja3 = Ja3Fingerprint::from_profile_with_grease(&tls_profile, grease_mode);
    let ja3s = Ja3sFingerprint::from_profile_with_grease(
        &tls_profile,
        preferred_tls13_cipher(&tls_profile),
        grease_mode,
    );
    let ja4 = Ja4Fingerprint::from_profile(&tls_profile);
    if let Some(path) = &args.tls_fp_metrics_path {
        let content = format!(
            "# HELP tls_fp_info TLS fingerprint JA3/JA3S/JA4 (client)\n\
             # TYPE tls_fp_info gauge\n\
             tls_fp_info{{role=\"client\",bucket=\"{}\",type=\"ja3\",hash=\"{}\"}} 1\n\
             tls_fp_info{{role=\"client\",bucket=\"{}\",type=\"ja3s\",hash=\"{}\"}} 1\n\
             tls_fp_info{{role=\"client\",bucket=\"{}\",type=\"ja4\",hash=\"{}\"}} 1\n",
            match tls_bucket {
                TlsProfileBucket::Main => "main",
                TlsProfileBucket::Canary => "canary",
            },
            ja3.to_ja3_hash(),
            match tls_bucket {
                TlsProfileBucket::Main => "main",
                TlsProfileBucket::Canary => "canary",
            },
            ja3s.to_ja3s_hash(),
            match tls_bucket {
                TlsProfileBucket::Main => "main",
                TlsProfileBucket::Canary => "canary",
            },
            ja4.to_hash()
        );
        if let Err(e) = fs::write(path, content.as_bytes()) {
            tracing::warn!(?e, ?path, "Failed to write client tls_fp metrics");
        }
    }
    info!(
        profile = %tls_profile,
        bucket = ?tls_bucket,
        grease = ?grease_mode,
        ja3_hash = %ja3.to_ja3_hash(),
        ja3s_hash = %ja3s.to_ja3s_hash(),
        ja4 = %ja4.to_string(),
        "TLS fingerprint configured"
    );

    // Build QUIC client config
    let quic_config = build_quic_config(args.insecure, args.idle_timeout, tls_profile)?;

    // Padding config for probe challenge (uses CLI defaults before server config arrives)
    let challenge_padder = Arc::new(build_padder_cli(&args, args.mtu));

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

    // Handle probe challenge before Noise handshake
    handle_probe_challenge(&mut stream, &challenge_padder).await?;

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

    // Suspicion snapshot from server (used for TLS/padding adaptation)
    if let Some(score) = vpn_config.suspicion_score {
        info!(suspicion = %score, "Received suspicion score from server");
    }

    info!(
        client_ip = %vpn_config.client_ip,
        gateway = %vpn_config.gateway,
        mtu = vpn_config.mtu,
        "Received VPN configuration"
    );

    let session_limits = SessionKeyLimits {
        time_limit: Duration::from_secs(
            vpn_config
                .session_rekey_secs
                .unwrap_or(args.session_rekey_seconds),
        ),
        data_limit: vpn_config
            .session_rekey_bytes
            .unwrap_or(args.session_rekey_bytes),
    };

    let rotation_config = KeyRotationConfig {
        session_limits,
        ..KeyRotationConfig::default()
    };
    let rotation_manager = Arc::new(KeyRotationManager::with_config(rotation_config.clone()));
    let session_state = rotation_manager.register_session().await;
    let (rotation_shutdown_tx, rotation_shutdown_rx) = broadcast::channel(1);
    let rotation_task = tokio::spawn(rotation_check_task(
        rotation_manager.clone(),
        rotation_shutdown_rx,
        rotation_config.check_interval,
    ));

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
    if args.dns_protection {
        // Use custom DNS servers if provided, otherwise use VPN config
        let dns_servers = if !args.dns_servers.is_empty() {
            &args.dns_servers
        } else {
            &vpn_config.dns_servers
        };

        if !dns_servers.is_empty() {
            dns_protection
                .enable(dns_servers)
                .context("enabling DNS protection")?;
        } else {
            tracing::warn!("DNS protection enabled but no DNS servers configured");
        }
    }

    let padder = Arc::new(build_padder_from_config(&args, &vpn_config));

    let cover_config = build_cover_config(
        args.cover_traffic_rate,
        &args.cover_traffic_pattern,
        vpn_config.mtu as usize,
    );

    // Сохранить информацию о маршрутизации для восстановления
    let tun_name = tun.name().to_string();
    let gateway = vpn_config.gateway;
    let routing_configured = args.set_default_route;

    // Start VPN tunnel (dns_protection will auto-restore on drop)
    let result = run_vpn_tunnel(tun, connection, padder, cover_config, session_state.clone()).await;

    // Восстановить маршрутизацию при выходе
    if routing_configured {
        if let Err(e) = restore_routing(&tun_name, gateway) {
            tracing::warn!(%e, "Failed to restore routing");
        }
    }

    // Explicitly disable DNS protection on exit
    if dns_protection.is_active() {
        if let Err(e) = dns_protection.disable() {
            tracing::warn!(%e, "Failed to disable DNS protection");
        }
    }

    let _ = rotation_shutdown_tx.send(());
    let _ = rotation_task.await;

    result
}

async fn run_vpn_tunnel(
    tun: TunDevice,
    connection: quinn::Connection,
    padder: Arc<Padder>,
    cover_config: CoverTrafficConfig,
    session_state: Arc<SessionKeyState>,
) -> Result<()> {
    // Split TUN device into reader and writer
    let (tun_reader, tun_writer) = tun.split();

    // Create channels for packet flow
    // TUN -> QUIC channel
    let (tun_tx, tun_rx) = mpsc::channel::<bytes::Bytes>(1024);
    // QUIC -> TUN channel
    let (quic_tx, quic_rx) = mpsc::channel::<bytes::Bytes>(1024);

    let encapsulator = Arc::new(PacketEncapsulator::new());

    // Spawn tasks for bidirectional forwarding + cover traffic
    let conn_clone = connection.clone();
    let encap_clone = encapsulator.clone();
    let tracker_tx = session_state.clone();
    let cover_encap = encapsulator.clone();
    let cover_padder = padder.clone();
    let mut cover_gen = CoverTrafficGenerator::new(cover_config);

    // TUN reader -> channel
    let tun_read_task = tokio::spawn(async move {
        if let Err(e) = tun_to_channel(tun_reader, tun_tx).await {
            error!(%e, "TUN read task error");
        }
    });

    // Channel -> QUIC datagrams (real traffic)
    let pad_clone = padder.clone();
    let tun_to_quic_task = tokio::spawn(async move {
        if let Err(e) = forward_tun_to_quic(
            tun_rx,
            conn_clone,
            encap_clone,
            Some(pad_clone),
            Some(tracker_tx),
        )
        .await
        {
            error!(%e, "TUN->QUIC task error");
        }
    });

    // QUIC datagrams -> channel
    let conn_for_quic_to_tun = connection.clone();
    let tracker_rx = session_state.clone();
    let quic_to_channel_task = tokio::spawn(async move {
        if let Err(e) = forward_quic_to_tun(
            conn_for_quic_to_tun,
            quic_tx,
            encapsulator,
            Some(tracker_rx),
        )
        .await
        {
            error!(%e, "QUIC->TUN task error");
        }
    });

    // Channel -> TUN writer
    let tun_write_task = tokio::spawn(async move {
        if let Err(e) = channel_to_tun(tun_writer, quic_rx).await {
            error!(%e, "TUN write task error");
        }
    });

    // Cover traffic task (client side) — sends through same QUIC connection
    let cover_conn = connection.clone();
    let tracker_cover = session_state.clone();
    let cover_task = tokio::spawn(async move {
        loop {
            let delay = cover_gen.next_delay();
            tokio::time::sleep(delay).await;

            let mut packet = cover_gen.generate_packet().data;
            cover_padder.pad_in_place(&mut packet);
            if let Some(j) = cover_padder.jitter_delay() {
                tokio::time::sleep(j).await;
            }

            let datagram = cover_encap.encapsulate(bytes::Bytes::from(packet));
            tracker_cover.record_bytes(datagram.len() as u64);
            tracker_cover.maybe_rotate_with(|reason| {
                info!(?reason, "Client session rekey (cover)");
                cover_conn.force_key_update();
            });
            if cover_conn.send_datagram(datagram).is_err() {
                break;
            }
        }
    });

    info!("VPN tunnel running. Press Ctrl+C to stop.");

    // Wait for any task to complete (usually means connection lost)
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm =
            signal(SignalKind::terminate()).context("failed to install SIGTERM handler")?;
        let mut sigint =
            signal(SignalKind::interrupt()).context("failed to install SIGINT handler")?;

        tokio::select! {
            result = tun_read_task => {
                info!("TUN reader stopped: {:?}", result);
            }
            result = tun_to_quic_task => {
                info!("TUN->QUIC forwarder stopped: {:?}", result);
            }
            result = quic_to_channel_task => {
                info!("QUIC->TUN forwarder stopped: {:?}", result);
            }
            result = tun_write_task => {
                info!("TUN writer stopped: {:?}", result);
            }
            result = cover_task => {
                info!("Cover traffic task stopped: {:?}", result);
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Ctrl+C received, shutting down gracefully");
            }
            _ = sigterm.recv() => {
                info!("SIGTERM received, shutting down gracefully");
            }
            _ = sigint.recv() => {
                info!("SIGINT received, shutting down gracefully");
            }
        }
    }

    #[cfg(not(unix))]
    {
        tokio::select! {
            result = tun_read_task => {
                info!("TUN reader stopped: {:?}", result);
            }
            result = tun_to_quic_task => {
                info!("TUN->QUIC forwarder stopped: {:?}", result);
            }
            result = quic_to_channel_task => {
                info!("QUIC->TUN forwarder stopped: {:?}", result);
            }
            result = tun_write_task => {
                info!("TUN writer stopped: {:?}", result);
            }
            result = cover_task => {
                info!("Cover traffic task stopped: {:?}", result);
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Ctrl+C received, shutting down gracefully");
            }
        }
    }

    // Задачи уже завершены в select!, просто логируем завершение
    info!("VPN tunnel shutdown complete");
    Ok(())
}

fn build_quic_config(
    insecure: bool,
    idle_timeout: u64,
    tls_profile: TlsProfile,
) -> Result<QuinnClientConfig> {
    tracing::debug!(profile = %tls_profile, "Building QUIC client config");

    let mut transport_config = TransportConfig::default();
    transport_config.max_idle_timeout(Some(Duration::from_secs(idle_timeout).try_into()?));

    // Enable QUIC datagrams for VPN traffic
    transport_config.datagram_receive_buffer_size(Some(65536));
    transport_config.datagram_send_buffer_size(65536);

    // Apply TLS profile cipher suites and key exchange groups
    let cipher_suites = tls_profile.rustls_cipher_suites();
    let kx_groups = tls_profile.rustls_kx_groups();

    tracing::info!(
        profile = %tls_profile,
        cipher_count = cipher_suites.len(),
        kx_count = kx_groups.len(),
        "Applying TLS profile cipher suites"
    );

    // Build custom crypto provider with profile-specific ciphers
    let provider = rustls::crypto::CryptoProvider {
        cipher_suites,
        kx_groups,
        ..rustls::crypto::ring::default_provider()
    };

    let mut crypto_config = if insecure {
        rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth()
    };

    crypto_config.alpn_protocols = vec![b"h3".to_vec(), b"masque".to_vec()];

    let mut client_config = QuinnClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto_config)?,
    ));
    client_config.transport_config(Arc::new(transport_config));

    Ok(client_config)
}

fn build_padder_cli(args: &Args, fallback_mtu: u16) -> Padder {
    let strategy = parse_padding_strategy(&args.padding_strategy);
    let mtu = args.padding_mtu.unwrap_or(fallback_mtu) as usize;

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

fn parse_padding_strategy(name: &str) -> PaddingStrategy {
    match name.to_ascii_lowercase().as_str() {
        "none" => PaddingStrategy::None,
        "bucket" => PaddingStrategy::Bucket,
        "mtu" => PaddingStrategy::Mtu,
        "rand-bucket" | "random-bucket" | "random" => PaddingStrategy::RandomBucket,
        other => {
            tracing::warn!(strategy = %other, "Unknown padding strategy, using rand-bucket");
            PaddingStrategy::RandomBucket
        }
    }
}

fn build_padder_from_config(args: &Args, config: &VpnConfig) -> Padder {
    // Prefer server-provided padding params to stay in sync
    let strategy = config
        .padding_strategy
        .as_deref()
        .map(parse_padding_strategy)
        .unwrap_or_else(|| parse_padding_strategy(&args.padding_strategy));

    let max_jitter_us = config
        .padding_max_jitter_us
        .unwrap_or(args.padding_max_jitter_us);

    let min_size = config.padding_min_size.unwrap_or(args.padding_min_size);

    let mtu = config
        .padding_mtu
        .unwrap_or_else(|| args.padding_mtu.unwrap_or(config.mtu)) as usize;

    let config = PaddingConfig {
        strategy,
        mtu,
        jitter_enabled: max_jitter_us > 0,
        max_jitter_us,
        min_packet_size: min_size,
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
        min_interval: std::time::Duration::from_millis(5),
    }
}

fn padding_strategy_to_byte(strategy: PaddingStrategy) -> u8 {
    match strategy {
        PaddingStrategy::None => 0,
        PaddingStrategy::Bucket => 1,
        PaddingStrategy::RandomBucket => 2,
        PaddingStrategy::Mtu => 3,
    }
}

fn padding_schedule_bytes(padder: &Padder) -> Vec<u8> {
    let cfg = padder.config();
    let mut out = Vec::with_capacity(15);
    out.push(padding_strategy_to_byte(cfg.strategy));
    out.extend_from_slice(&cfg.max_jitter_us.to_be_bytes());
    out.extend_from_slice(&(cfg.min_packet_size as u32).to_be_bytes());
    out.extend_from_slice(&(cfg.mtu as u16).to_be_bytes());
    out
}

fn solve_pow(nonce: &[u8; 32], difficulty: u8) -> [u8; 32] {
    let mut counter: u64 = 0;
    let mut candidate = [0u8; 32];
    loop {
        candidate[..8].copy_from_slice(&counter.to_be_bytes());
        let mut hasher = Sha256::new();
        use sha2::Digest;
        hasher.update(nonce);
        hasher.update(candidate);
        let hash = hasher.finalize();
        let mut ok = true;
        for i in 0..difficulty as usize {
            if hash[i] != 0 {
                ok = false;
                break;
            }
        }
        if ok {
            return candidate;
        }
        counter = counter.wrapping_add(1);
    }
}

async fn handle_probe_challenge(stream: &mut QuicBiStream, padder: &Padder) -> Result<()> {
    use tokio::io::AsyncReadExt;

    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .await
        .context("reading probe challenge length")?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len != 34 {
        anyhow::bail!("unexpected probe challenge length: {len}");
    }

    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .context("reading probe challenge payload")?;

    if buf[0] != 1 {
        anyhow::bail!("unexpected probe challenge type");
    }

    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&buf[1..33]);
    let difficulty = buf[33];

    let solution = solve_pow(&nonce, difficulty);
    let padding_bytes = padding_schedule_bytes(padder);

    let mut resp = Vec::with_capacity(1 + 32 + padding_bytes.len());
    resp.push(2u8);
    resp.extend_from_slice(&solution);
    resp.extend_from_slice(&padding_bytes);

    let len_bytes = (resp.len() as u16).to_be_bytes();
    stream
        .write_all(&len_bytes)
        .await
        .context("writing probe response length")?;
    stream
        .write_all(&resp)
        .await
        .context("writing probe response")?;
    stream.flush().await.ok();

    Ok(())
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
