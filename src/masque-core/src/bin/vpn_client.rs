//! VPR VPN Client - Full tunnel mode with TUN device
//!
//! This binary creates a TUN interface and routes traffic through
//! a MASQUE CONNECT-UDP tunnel with hybrid post-quantum encryption.

use anyhow::{bail, Context, Result};
use clap::Parser;
use quinn::Endpoint;
use std::fs;
use std::fs::File;
use std::net::{IpAddr, SocketAddr};
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::{broadcast, mpsc, oneshot};
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use ipnetwork::IpNetwork;
use masque_core::client::{
    build_padder_cli, build_padder_from_config, build_quic_config, handle_probe_challenge, Args,
    VPR_PROTOCOL_VERSION,
};
use masque_core::cover_traffic::{CoverTrafficConfig, CoverTrafficGenerator};
use masque_core::hybrid_handshake::HybridClient;
use masque_core::key_rotation::{
    rotation_check_task, KeyRotationConfig, KeyRotationManager, SessionKeyLimits, SessionKeyState,
};
use masque_core::network_guard::NetworkStateGuard;
use masque_core::padding::Padder;
use masque_core::quic_stream::QuicBiStream;
use masque_core::tls_fingerprint::{
    select_tls_profile, Ja3Fingerprint, Ja3sFingerprint, Ja4Fingerprint, TlsProfile,
    TlsProfileBucket,
};
use masque_core::tun::{
    restore_routing, restore_split_tunnel, setup_ipv6_routing, setup_policy_routing, setup_routing,
    setup_split_tunnel, DnsProtection, RouteRule, RoutingPolicy, RoutingState, TunConfig,
    TunDevice,
};
use masque_core::vpn_common::{
    build_cover_config, parse_grease_mode, preferred_tls13_cipher, setup_shutdown_signal,
};
use masque_core::vpn_config::{ConfigAck, VpnConfig};
use masque_core::vpn_tunnel::{
    channel_to_tun, forward_quic_to_tun, forward_tun_to_quic, tun_to_channel, PacketEncapsulator,
};
use vpr_crypto::keys::NoiseKeypair;

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

    // Handle --repair mode: restore network from crash and exit
    if args.repair {
        info!("Running network repair mode");
        match NetworkStateGuard::restore_from_crash() {
            Ok(true) => {
                info!("Network configuration restored successfully");
                return Ok(());
            }
            Ok(false) => {
                info!("No orphaned network state found - nothing to repair");
                return Ok(());
            }
            Err(e) => {
                error!(%e, "Failed to restore network configuration");
                return Err(e);
            }
        }
    }

    // Auto-repair: silently restore network from previous crash before starting
    if !args.no_auto_repair {
        match NetworkStateGuard::restore_from_crash() {
            Ok(true) => info!("Auto-repaired network configuration from previous crash"),
            Ok(false) => {}
            Err(e) => warn!(%e, "Auto-repair failed - continuing anyway"),
        }
    }

    // Run diagnostics if requested
    if args.diagnose || args.auto_fix {
        run_diagnostics(&args).await?;
        if !args.auto_fix && args.diagnose {
            info!("Diagnostics complete - exiting");
            return Ok(());
        }
        info!("Diagnostics complete - continuing with VPN connection");
    }

    // Setup graceful shutdown handler
    let shutdown_signal = setup_shutdown_signal();

    run_vpn_client(args, shutdown_signal).await
}

async fn run_diagnostics(args: &Args) -> Result<()> {
    use masque_core::diagnostics::{
        engine::DiagnosticEngine, ssh_client::SshConfig, DiagnosticConfig, FixConsentLevel,
    };

    info!("Running VPN diagnostics");

    // Parse server address for diagnostics
    let (server_ip, server_port) = args
        .server
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("Invalid server address format"))?;
    let server_ip: std::net::IpAddr = server_ip.parse()?;
    let server_port: u16 = server_port.parse()?;

    // Build SSH config if provided
    let ssh_config = if let Some(ssh_host) = args.ssh_host.as_ref() {
        if args.ssh_password.is_some() {
            warn!("SSH password authentication is deprecated. Use --ssh-key instead.");
        }
        Some(SshConfig::new(
            ssh_host,
            args.ssh_port,
            &args.ssh_user,
            args.ssh_key.clone(),
        )?)
    } else {
        None
    };

    let diag_config = DiagnosticConfig {
        auto_fix: args.auto_fix,
        timeout_secs: 10,
        server_addr: Some((server_ip, server_port)),
        privileged: unsafe { libc::geteuid() } == 0,
    };

    let engine = DiagnosticEngine::new(diag_config, ssh_config);
    let context = engine.run_full_diagnostics().await?;

    // Print report
    println!("\n╔═══════════════════════════════════════╗");
    println!("║     VPN Diagnostic Report             ║");
    println!("╚═══════════════════════════════════════╝\n");

    if let Some(client_report) = &context.client_report {
        println!(
            "📋 Client-Side Checks ({} total):",
            client_report.results.len()
        );
        for result in &client_report.results {
            let icon = if result.passed { "✅" } else { "❌" };
            println!("  {} {}: {}", icon, result.check_name, result.message);
        }
        println!();
    }

    if let Some(server_report) = &context.server_report {
        println!(
            "🖥️  Server-Side Checks ({} total):",
            server_report.results.len()
        );
        for result in &server_report.results {
            let icon = if result.passed { "✅" } else { "❌" };
            println!("  {} {}: {}", icon, result.check_name, result.message);
        }
        println!();
    }

    if !context.cross_checks.is_empty() {
        println!("🔄 Cross-Checks ({} total):", context.cross_checks.len());
        for result in &context.cross_checks {
            let icon = if result.passed { "✅" } else { "❌" };
            println!("  {} {}: {}", icon, result.check_name, result.message);
        }
        println!();
    }

    println!("📊 Overall Health: {:?}\n", context.overall_health());

    // Check for critical issues
    if context.has_critical_issues() {
        error!("Critical issues detected! Connection may fail.");
        if !args.auto_fix {
            println!("💡 Tip: Run with --auto-fix to automatically resolve these issues\n");
            return Err(anyhow::anyhow!("Critical diagnostic failures - aborting"));
        }
    }

    // Apply auto-fixes if requested
    if args.auto_fix && !args.dry_run {
        let consent_level = match args.fix_consent.as_str() {
            "auto" => FixConsentLevel::Auto,
            "semi-auto" => FixConsentLevel::SemiAuto,
            "manual" => FixConsentLevel::Manual,
            _ => bail!("Invalid fix-consent level: {}", args.fix_consent),
        };

        let fixable = context.all_auto_fixable_issues();
        if fixable.is_empty() {
            info!("No auto-fixable issues found");
        } else {
            println!("🔧 Applying {} auto-fixes...\n", fixable.len());
            let fix_results = engine.apply_auto_fixes(&context, consent_level).await?;
            for result in fix_results {
                match result {
                    masque_core::diagnostics::fixes::FixResult::Success(msg) => {
                        println!("  ✅ {}", msg);
                    }
                    masque_core::diagnostics::fixes::FixResult::Failed(msg) => {
                        println!("  ❌ {}", msg);
                    }
                    masque_core::diagnostics::fixes::FixResult::Skipped(msg) => {
                        println!("  ⏭️  {}", msg);
                    }
                }
            }
            println!();
        }
    } else if args.dry_run {
        println!("🔍 Dry-run mode: No fixes applied\n");
    }

    Ok(())
}

async fn run_vpn_client(args: Args, shutdown_signal: oneshot::Receiver<()>) -> Result<()> {
    // SECURITY WARNING: --insecure flag
    if args.insecure {
        error!("╔═══════════════════════════════════════════════════════════════════╗");
        error!("║  SECURITY WARNING: TLS CERTIFICATE VERIFICATION IS DISABLED!     ║");
        error!("║  This makes the connection VULNERABLE to man-in-the-middle       ║");
        error!("║  attacks. Your traffic can be intercepted and modified.          ║");
        error!("╚═══════════════════════════════════════════════════════════════════╝");

        #[cfg(not(debug_assertions))]
        {
            let allow_insecure = std::env::var("VPR_ALLOW_INSECURE")
                .map(|v| v == "1" || v.to_lowercase() == "true")
                .unwrap_or(false);

            if !allow_insecure {
                bail!(
                    "Insecure mode is disabled in release builds for security.\n\
                     If you understand the risks and need this for testing, set:\n\
                     VPR_ALLOW_INSECURE=1"
                );
            }
            warn!("VPR_ALLOW_INSECURE=1 is set. Proceeding with disabled certificate verification.");
        }
    }

    info!(server = %args.server, tun_name = %args.tun_name, insecure = args.insecure, "Starting VPR VPN client");

    // Load Noise keys for hybrid PQ handshake
    let client_keypair = NoiseKeypair::load(&args.noise_dir, &args.noise_name)?;
    let server_pub = std::fs::read(&args.server_pub)?;
    let server_addr: SocketAddr = args.server.parse()?;

    // Parse TLS profiles (main + canary)
    let main_profile: TlsProfile = args.tls_profile.parse().unwrap_or(TlsProfile::Chrome);
    let canary_profile = args
        .tls_canary_profile
        .parse()
        .ok()
        .filter(|p: &TlsProfile| !matches!(p, TlsProfile::Custom));

    // Run tls-fp-sync.py if requested
    if args.tls_fp_sync {
        run_tls_fp_sync(&args);
    }

    let grease_mode = parse_grease_mode(&args.tls_grease_mode, args.tls_grease_seed);

    // Suspicion-aware TLS selection
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

    // Log JA3/JA3S/JA4 fingerprints
    log_tls_fingerprints(&args, &tls_profile, tls_bucket, grease_mode);

    // Build QUIC client config
    let quic_config = build_quic_config(
        args.insecure,
        args.idle_timeout,
        tls_profile,
        args.ca_cert.clone(),
    )?;

    // Padding config for probe challenge
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

    info!(remote = %connection.remote_address(), "QUIC connection established");

    // Perform hybrid PQ Noise handshake
    let server_pub_bytes: [u8; 32] = server_pub
        .as_slice()
        .try_into()
        .context("server public key must be 32 bytes")?;

    let hybrid_client = HybridClient::new_ik(&client_keypair.secret_bytes(), &server_pub_bytes);

    // Open bidirectional stream for handshake and config
    let (send, recv) = connection.open_bi().await?;
    let mut stream = QuicBiStream::new(send, recv);

    // Send protocol version byte
    stream.write_all(&[VPR_PROTOCOL_VERSION]).await?;
    stream.flush().await.ok();

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
    let vpn_config = VpnConfig::recv(&mut stream).await?;

    if let Some(score) = vpn_config.suspicion_score {
        info!(suspicion = %score, "Received suspicion score from server");
    }

    info!(
        client_ip = %vpn_config.client_ip,
        gateway = %vpn_config.gateway,
        mtu = vpn_config.mtu,
        "Received VPN configuration"
    );

    // Setup key rotation
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
        address_v6: None,
        prefix_len_v6: None,
    };

    let tun = TunDevice::create(tun_config).await?;
    info!(name = %tun.name(), addr = %vpn_config.client_ip, "TUN device created with server-assigned IP");

    // Send acknowledgment to server
    ConfigAck::ok().send(&mut stream).await?;
    info!("Config acknowledged, starting VPN tunnel");

    // Create network state guard for crash recovery
    let mut network_guard = NetworkStateGuard::new()?;
    network_guard.record_tun_created(tun.name().to_string())?;

    // Setup routing
    let mut routing_state = RoutingState::new();
    setup_client_routing(
        &args,
        &vpn_config,
        &tun,
        server_addr.ip(),
        &mut routing_state,
        &mut network_guard,
    )?;

    // Setup DNS protection
    let mut dns_protection = DnsProtection::new();
    setup_dns_protection(&args, &vpn_config, &mut dns_protection, &mut network_guard)?;

    let padder = Arc::new(build_padder_from_config(&args, &vpn_config));
    let cover_config = build_cover_config(
        args.cover_traffic_rate,
        &args.cover_traffic_pattern,
        vpn_config.mtu as usize,
    );

    // Store info for cleanup
    let tun_name = tun.name().to_string();
    let gateway = vpn_config.gateway;
    let routing_configured = args.set_default_route;
    let routing_config = vpn_config.routing_config.as_ref();
    let use_split_tunnel = args.split_tunnel
        || routing_config
            .map(|c| c.policy == RoutingPolicy::Split)
            .unwrap_or(false);
    let server_ip_for_cleanup = server_addr.ip();

    // Start VPN tunnel with shutdown signal support
    let result = tokio::select! {
        result = run_vpn_tunnel(tun, connection, padder, cover_config, session_state.clone()) => result,
        _ = shutdown_signal => {
            info!("Shutdown signal received - stopping VPN tunnel");
            Ok(())
        }
    };

    // Cleanup
    cleanup_routing(
        use_split_tunnel,
        routing_configured,
        &tun_name,
        gateway,
        server_ip_for_cleanup,
        &mut routing_state,
    );

    if dns_protection.is_active() {
        if let Err(e) = dns_protection.disable() {
            error!(%e, "Failed to restore DNS configuration");
        } else {
            info!("DNS protection disabled, original config restored");
        }
    }

    if let Err(e) = network_guard.cleanup() {
        error!(%e, "Network cleanup failed - run 'vpn-client --repair' to fix");
    }

    let _ = rotation_shutdown_tx.send(());
    let _ = rotation_task.await;

    result
}

fn run_tls_fp_sync(args: &Args) {
    let log_path = &args.tls_fp_sync_log;
    let stdout = File::options().append(true).create(true).open(log_path);
    let stderr = File::options().append(true).create(true).open(log_path);
    if let (Ok(out), Ok(err)) = (stdout, stderr) {
        let status = Command::new("python")
            .arg("scripts/tls-fp-sync.py")
            .arg("--validate-only")
            .stdout(out)
            .stderr(err)
            .status();
        match status {
            Ok(s) if s.success() => {
                tracing::info!(?log_path, "tls-fp-sync validate-only succeeded (client)")
            }
            Ok(s) => {
                tracing::warn!(?log_path, code=?s.code(), "tls-fp-sync failed, using existing profiles")
            }
            Err(e) => tracing::warn!(?e, ?log_path, "Failed to run tls-fp-sync"),
        }
    } else {
        tracing::warn!(?log_path, "Could not open tls-fp-sync log file");
    }
}

fn log_tls_fingerprints(
    args: &Args,
    tls_profile: &TlsProfile,
    tls_bucket: TlsProfileBucket,
    grease_mode: masque_core::tls_fingerprint::GreaseMode,
) {
    let ja3 = Ja3Fingerprint::from_profile_with_grease(tls_profile, grease_mode);
    let ja3s = Ja3sFingerprint::from_profile_with_grease(
        tls_profile,
        preferred_tls13_cipher(tls_profile),
        grease_mode,
    );
    let ja4 = Ja4Fingerprint::from_profile(tls_profile);

    if let Some(path) = &args.tls_fp_metrics_path {
        let bucket_str = match tls_bucket {
            TlsProfileBucket::Main => "main",
            TlsProfileBucket::Canary => "canary",
        };
        let content = format!(
            "# HELP tls_fp_info TLS fingerprint JA3/JA3S/JA4 (client)\n\
             # TYPE tls_fp_info gauge\n\
             tls_fp_info{{role=\"client\",bucket=\"{}\",type=\"ja3\",hash=\"{}\"}} 1\n\
             tls_fp_info{{role=\"client\",bucket=\"{}\",type=\"ja3s\",hash=\"{}\"}} 1\n\
             tls_fp_info{{role=\"client\",bucket=\"{}\",type=\"ja4\",hash=\"{}\"}} 1\n",
            bucket_str,
            ja3.to_ja3_hash(),
            bucket_str,
            ja3s.to_ja3s_hash(),
            bucket_str,
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
}

fn setup_client_routing(
    args: &Args,
    vpn_config: &VpnConfig,
    tun: &TunDevice,
    server_ip: IpAddr,
    routing_state: &mut RoutingState,
    network_guard: &mut NetworkStateGuard,
) -> Result<()> {
    let routing_config = vpn_config.routing_config.as_ref();

    if let Some(config) = routing_config {
        if let Err(e) = config.validate() {
            warn!(%e, "Invalid routing config from server, using defaults");
        }
    }

    let policy = if args.split_tunnel {
        RoutingPolicy::Split
    } else if let Some(config) = routing_config {
        config.policy
    } else {
        RoutingPolicy::Full
    };

    match policy {
        RoutingPolicy::Full => {
            if args.set_default_route {
                let _original_gateway = setup_routing(tun.name(), vpn_config.gateway, server_ip)?;
                network_guard.record_default_route(tun.name().to_string(), None, None)?;
            }
        }
        RoutingPolicy::Split => {
            let routes = parse_routes(args, routing_config, vpn_config.gateway);
            if !routes.is_empty() {
                setup_split_tunnel(
                    tun.name(),
                    IpAddr::V4(vpn_config.gateway),
                    &routes,
                    routing_state,
                )?;
                let route_cidrs: Vec<String> =
                    routes.iter().map(|r| r.destination.to_string()).collect();
                network_guard.record_split_routes(tun.name().to_string(), route_cidrs)?;
            } else {
                warn!("Split tunnel enabled but no routes specified");
            }
        }
        RoutingPolicy::Bypass => {
            warn!("Bypass tunnel policy not fully implemented");
        }
    }

    // Policy-based routing
    if args.policy_routing {
        let routes = parse_routes_with_table(args, routing_config, vpn_config.gateway, 100);
        if !routes.is_empty() {
            setup_policy_routing(
                tun.name(),
                IpAddr::V4(vpn_config.gateway),
                &routes,
                routing_state,
            )?;
        }
    }

    // IPv6 support
    if args.ipv6 || routing_config.map(|c| c.ipv6_enabled).unwrap_or(false) {
        setup_ipv6_if_available(args, vpn_config, tun, routing_state)?;
    }

    Ok(())
}

fn parse_routes(
    args: &Args,
    routing_config: Option<&masque_core::tun::RoutingConfig>,
    gateway: std::net::Ipv4Addr,
) -> Vec<RouteRule> {
    if !args.route.is_empty() {
        args.route
            .iter()
            .filter_map(|r| {
                IpNetwork::from_str(r).ok().map(|net| RouteRule {
                    destination: net,
                    gateway: Some(IpAddr::V4(gateway)),
                    metric: 0,
                    table: None,
                })
            })
            .collect()
    } else if let Some(config) = routing_config {
        config.routes.clone()
    } else {
        vec![]
    }
}

fn parse_routes_with_table(
    args: &Args,
    routing_config: Option<&masque_core::tun::RoutingConfig>,
    gateway: std::net::Ipv4Addr,
    table: u32,
) -> Vec<RouteRule> {
    if !args.route.is_empty() {
        args.route
            .iter()
            .filter_map(|r| {
                IpNetwork::from_str(r).ok().map(|net| RouteRule {
                    destination: net,
                    gateway: Some(IpAddr::V4(gateway)),
                    metric: 0,
                    table: Some(table),
                })
            })
            .collect()
    } else if let Some(config) = routing_config {
        config.routes.clone()
    } else {
        vec![]
    }
}

fn setup_ipv6_if_available(
    _args: &Args,
    vpn_config: &VpnConfig,
    tun: &TunDevice,
    routing_state: &mut RoutingState,
) -> Result<()> {
    let routing_config = vpn_config.routing_config.as_ref();

    if let Some(gateway_v6) = routing_config.and_then(|c| {
        c.routes.iter().find_map(|r| {
            if let IpNetwork::V6(_) = r.destination {
                r.gateway.and_then(|gw| {
                    if let IpAddr::V6(gw_v6) = gw {
                        Some(gw_v6)
                    } else {
                        None
                    }
                })
            } else {
                None
            }
        })
    }) {
        let routes: Vec<RouteRule> = routing_config
            .map(|c| {
                c.routes
                    .iter()
                    .filter(|r| matches!(r.destination, IpNetwork::V6(_)))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();

        if !routes.is_empty() {
            setup_ipv6_routing(tun.name(), gateway_v6, &routes, routing_state)?;
        } else {
            warn!("IPv6 enabled but no IPv6 routes configured");
        }
    } else {
        warn!("IPv6 enabled but no IPv6 gateway configured");
    }

    Ok(())
}

fn setup_dns_protection(
    args: &Args,
    vpn_config: &VpnConfig,
    dns_protection: &mut DnsProtection,
    network_guard: &mut NetworkStateGuard,
) -> Result<()> {
    let routing_config = vpn_config.routing_config.as_ref();

    let should_enable_dns = args.dns_protection
        || routing_config
            .map(|c| !c.dns_servers.is_empty())
            .unwrap_or(false);

    if should_enable_dns {
        let dns_servers = if !args.dns_servers.is_empty() {
            &args.dns_servers
        } else if let Some(routing_cfg) = routing_config {
            if !routing_cfg.dns_servers.is_empty() {
                &routing_cfg.dns_servers
            } else {
                &vpn_config.dns_servers
            }
        } else {
            &vpn_config.dns_servers
        };

        if !dns_servers.is_empty() {
            dns_protection.enable(dns_servers)?;
            network_guard.record_dns_change(masque_core::tun::get_dns_backup_path())?;
            info!(dns_count = dns_servers.len(), ?dns_servers, "DNS leak protection enabled");
        } else {
            warn!("DNS protection requested but no DNS servers available");
        }
    }

    Ok(())
}

fn cleanup_routing(
    use_split_tunnel: bool,
    routing_configured: bool,
    tun_name: &str,
    gateway: std::net::Ipv4Addr,
    server_ip: IpAddr,
    routing_state: &mut RoutingState,
) {
    if use_split_tunnel {
        if let Err(e) = restore_split_tunnel(routing_state) {
            error!(%e, route_count = routing_state.route_count(), "Failed to restore split tunnel routes");
        } else {
            info!("Split tunnel routes restored successfully");
        }
    } else if routing_configured {
        if let Err(e) = restore_routing(tun_name, gateway, Some(server_ip)) {
            error!(%e, tun = %tun_name, gateway = %gateway, "Failed to restore routing");
        } else {
            info!(tun = %tun_name, "Routing restored successfully");
        }
    }
}

async fn run_vpn_tunnel(
    tun: TunDevice,
    connection: quinn::Connection,
    padder: Arc<Padder>,
    cover_config: CoverTrafficConfig,
    session_state: Arc<SessionKeyState>,
) -> Result<()> {
    let (tun_reader, tun_writer) = tun.split();

    let (tun_tx, tun_rx) = mpsc::channel::<bytes::Bytes>(1024);
    let (quic_tx, quic_rx) = mpsc::channel::<bytes::Bytes>(1024);

    let encapsulator = Arc::new(PacketEncapsulator::new());
    let traffic_monitor = Arc::new(masque_core::traffic_monitor::TrafficMonitor::new());

    let conn_clone = connection.clone();
    let encap_clone = encapsulator.clone();
    let tracker_tx = session_state.clone();
    let cover_encap = encapsulator.clone();
    let cover_padder = padder.clone();
    let cover_gen = Arc::new(tokio::sync::Mutex::new(CoverTrafficGenerator::new(
        cover_config,
    )));

    // Spawn traffic monitor update task
    let traffic_monitor_for_cover = traffic_monitor.clone();
    let cover_gen_for_update = cover_gen.clone();
    tokio::spawn(async move {
        let update_interval = std::time::Duration::from_secs(1);
        if let Err(e) = masque_core::vpn_tunnel::traffic_monitor_update_task(
            traffic_monitor_for_cover,
            cover_gen_for_update,
            update_interval,
        )
        .await
        {
            error!(%e, "Traffic monitor update task error");
        }
    });

    // TUN reader -> channel
    let tun_read_task = tokio::spawn(async move {
        if let Err(e) = tun_to_channel(tun_reader, tun_tx).await {
            error!(%e, "TUN read task error");
        }
    });

    let dpi_feedback = Arc::new(masque_core::dpi_feedback::DpiFeedbackController::new());

    // Channel -> QUIC datagrams
    let pad_clone = padder.clone();
    let dpi_feedback_clone = dpi_feedback.clone();
    let traffic_monitor_tx = traffic_monitor.clone();
    let tun_to_quic_task = tokio::spawn(async move {
        if let Err(e) = forward_tun_to_quic(
            tun_rx,
            conn_clone,
            encap_clone,
            Some(pad_clone),
            Some(tracker_tx),
            Some(dpi_feedback_clone),
            Some(traffic_monitor_tx),
        )
        .await
        {
            error!(%e, "TUN->QUIC task error");
        }
    });

    // QUIC datagrams -> channel
    let conn_for_quic_to_tun = connection.clone();
    let tracker_rx = session_state.clone();
    let traffic_monitor_rx = traffic_monitor.clone();
    let quic_to_channel_task = tokio::spawn(async move {
        if let Err(e) = forward_quic_to_tun(
            conn_for_quic_to_tun,
            quic_tx,
            encapsulator,
            Some(tracker_rx),
            Some(traffic_monitor_rx),
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

    // Cover traffic task
    let cover_conn = connection.clone();
    let tracker_cover = session_state.clone();
    let cover_gen_for_task = cover_gen.clone();
    let cover_task = tokio::spawn(async move {
        loop {
            let delay = {
                let gen = cover_gen_for_task.lock().await;
                gen.next_delay()
            };
            tokio::time::sleep(delay).await;

            let mut packet = {
                let mut gen = cover_gen_for_task.lock().await;
                gen.generate_packet().data
            };
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

    // Wait for any task to complete
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sigint = signal(SignalKind::interrupt())?;

        tokio::select! {
            result = tun_read_task => info!("TUN reader stopped: {:?}", result),
            result = tun_to_quic_task => info!("TUN->QUIC forwarder stopped: {:?}", result),
            result = quic_to_channel_task => info!("QUIC->TUN forwarder stopped: {:?}", result),
            result = tun_write_task => info!("TUN writer stopped: {:?}", result),
            result = cover_task => info!("Cover traffic task stopped: {:?}", result),
            _ = tokio::signal::ctrl_c() => info!("Ctrl+C received, shutting down gracefully"),
            _ = sigterm.recv() => info!("SIGTERM received, shutting down gracefully"),
            _ = sigint.recv() => info!("SIGINT received, shutting down gracefully"),
        }
    }

    #[cfg(not(unix))]
    {
        tokio::select! {
            result = tun_read_task => info!("TUN reader stopped: {:?}", result),
            result = tun_to_quic_task => info!("TUN->QUIC forwarder stopped: {:?}", result),
            result = quic_to_channel_task => info!("QUIC->TUN forwarder stopped: {:?}", result),
            result = tun_write_task => info!("TUN writer stopped: {:?}", result),
            result = cover_task => info!("Cover traffic task stopped: {:?}", result),
            _ = tokio::signal::ctrl_c() => info!("Ctrl+C received, shutting down gracefully"),
        }
    }

    info!("VPN tunnel shutdown complete");
    Ok(())
}
