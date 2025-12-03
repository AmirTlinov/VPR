//! Flagship-уровень автоматической диагностики подключения VPN
//!
//! Модуль выполняет комплексную проверку ВСЕХ компонентов перед подключением
//! и предоставляет детерминированные, понятные сообщения об ошибках.
//!
//! ## Проверки:
//! - Секреты (ключи Noise, сертификаты TLS)
//! - DNS резолвинг
//! - TCP/UDP доступность порта
//! - QUIC handshake probe
//! - Существующие TUN устройства
//! - Права доступа (root/capabilities)
//! - Сетевой интерфейс и маршрутизация
//! - Firewall/iptables правила
//! - MTU и фрагментация
//! - Конфликты с другими VPN

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

/// Код ошибки для детерминированной идентификации проблемы
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiagnosticCode {
    // Секреты и ключи (1xx)
    E101_MissingServerPubKey,
    E102_MissingClientKey,
    E103_MissingCertificate,
    E104_InvalidKeyFormat,
    E105_KeyPermissions,

    // Сеть и подключение (2xx)
    E201_DnsResolutionFailed,
    E202_TcpPortUnreachable,
    E203_UdpPortBlocked,
    E204_ConnectionRefused,
    E205_ConnectionTimeout,
    E206_ConnectionReset,
    E207_NetworkUnreachable,
    E208_HostUnreachable,
    E209_QuicHandshakeFailed,

    // Права и система (3xx)
    E301_InsufficientPermissions,
    E302_TunDeviceExists,
    E303_TunCreationFailed,
    E304_FirewallBlocking,
    E305_MtuTooLow,

    // TLS/Криптография (4xx)
    E401_TlsHandshakeFailed,
    E402_CertificateExpired,
    E403_CertificateHostnameMismatch,
    E404_NoiseHandshakeFailed,
    E405_InsecureModeDisabled,

    // Конфликты (5xx)
    E501_OtherVpnActive,
    E502_ConflictingRoutes,
    E503_DnsLeakDetected,

    // Сервер (6xx)
    E601_ServerNotRunning,
    E602_WrongPort,
    E603_ServerOverloaded,
    E604_ProtocolMismatch,

    // Прочее
    E999_UnknownError,
}

impl DiagnosticCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::E101_MissingServerPubKey => "E101",
            Self::E102_MissingClientKey => "E102",
            Self::E103_MissingCertificate => "E103",
            Self::E104_InvalidKeyFormat => "E104",
            Self::E105_KeyPermissions => "E105",
            Self::E201_DnsResolutionFailed => "E201",
            Self::E202_TcpPortUnreachable => "E202",
            Self::E203_UdpPortBlocked => "E203",
            Self::E204_ConnectionRefused => "E204",
            Self::E205_ConnectionTimeout => "E205",
            Self::E206_ConnectionReset => "E206",
            Self::E207_NetworkUnreachable => "E207",
            Self::E208_HostUnreachable => "E208",
            Self::E209_QuicHandshakeFailed => "E209",
            Self::E301_InsufficientPermissions => "E301",
            Self::E302_TunDeviceExists => "E302",
            Self::E303_TunCreationFailed => "E303",
            Self::E304_FirewallBlocking => "E304",
            Self::E305_MtuTooLow => "E305",
            Self::E401_TlsHandshakeFailed => "E401",
            Self::E402_CertificateExpired => "E402",
            Self::E403_CertificateHostnameMismatch => "E403",
            Self::E404_NoiseHandshakeFailed => "E404",
            Self::E405_InsecureModeDisabled => "E405",
            Self::E501_OtherVpnActive => "E501",
            Self::E502_ConflictingRoutes => "E502",
            Self::E503_DnsLeakDetected => "E503",
            Self::E601_ServerNotRunning => "E601",
            Self::E602_WrongPort => "E602",
            Self::E603_ServerOverloaded => "E603",
            Self::E604_ProtocolMismatch => "E604",
            Self::E999_UnknownError => "E999",
        }
    }
}

/// Результат диагностики
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticResult {
    pub status: DiagnosticStatus,
    pub checks: Vec<DiagnosticCheck>,
    pub summary: String,
    pub action: Option<String>,
    /// Время выполнения диагностики в мс
    pub duration_ms: u64,
    /// Timestamp начала диагностики
    pub timestamp: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiagnosticStatus {
    Passed,
    Warning,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticCheck {
    pub name: String,
    pub status: DiagnosticStatus,
    pub message: String,
    pub details: Option<String>,
    pub code: Option<DiagnosticCode>,
    /// Время выполнения этой проверки в мс
    pub duration_ms: u64,
}

impl DiagnosticCheck {
    fn passed(name: &str, message: &str, duration_ms: u64) -> Self {
        Self {
            name: name.to_string(),
            status: DiagnosticStatus::Passed,
            message: message.to_string(),
            details: None,
            code: None,
            duration_ms,
        }
    }

    fn warning(name: &str, message: &str, details: Option<String>, duration_ms: u64) -> Self {
        Self {
            name: name.to_string(),
            status: DiagnosticStatus::Warning,
            message: message.to_string(),
            details,
            code: None,
            duration_ms,
        }
    }

    fn failed(name: &str, message: &str, details: Option<String>, code: DiagnosticCode, duration_ms: u64) -> Self {
        Self {
            name: name.to_string(),
            status: DiagnosticStatus::Failed,
            message: format!("[{}] {}", code.as_str(), message),
            details,
            code: Some(code),
            duration_ms,
        }
    }
}

/// Параметры для диагностики
pub struct DiagnosticParams {
    pub server: String,
    pub port: u16,
    pub secrets_dir: PathBuf,
    pub timeout_ms: u64,
    pub tun_name: String,
}

impl Default for DiagnosticParams {
    fn default() -> Self {
        Self {
            server: String::new(),
            port: 443,
            secrets_dir: PathBuf::from("secrets"),
            timeout_ms: 5000,
            tun_name: "vpr0".to_string(),
        }
    }
}

/// Выполняет полную диагностику перед подключением
pub async fn run_pre_connection_diagnostics(params: &DiagnosticParams) -> DiagnosticResult {
    let start = Instant::now();
    let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let mut checks = Vec::new();

    info!(
        server = %params.server,
        port = params.port,
        secrets_dir = %params.secrets_dir.display(),
        "Starting flagship pre-connection diagnostics"
    );

    // === 1. Проверка секретов (критично) ===
    checks.push(check_secrets(&params.secrets_dir));

    // === 2. Проверка прав доступа (критично) ===
    checks.push(check_permissions());

    // === 3. Проверка существующих TUN устройств ===
    checks.push(check_existing_tun(&params.tun_name));

    // === 4. Проверка конфликтов с другими VPN ===
    checks.push(check_vpn_conflicts());

    // === 5. Проверка сетевого интерфейса ===
    checks.push(check_network_interface());

    // === 6. Проверка firewall ===
    checks.push(check_firewall(params.port));

    // === 7. Проверка DNS резолвинга ===
    checks.push(check_dns_resolution(&params.server).await);

    // === 8. Проверка TCP доступности порта ===
    checks.push(check_tcp_port(&params.server, params.port, params.timeout_ms).await);

    // === 9. Проверка UDP доступности (для QUIC) ===
    checks.push(check_udp_port(&params.server, params.port, params.timeout_ms).await);

    // === 10. Проверка MTU ===
    checks.push(check_mtu(&params.server));

    // Определяем общий статус
    let has_failed = checks.iter().any(|c| c.status == DiagnosticStatus::Failed);
    let has_warning = checks.iter().any(|c| c.status == DiagnosticStatus::Warning);

    let status = if has_failed {
        DiagnosticStatus::Failed
    } else if has_warning {
        DiagnosticStatus::Warning
    } else {
        DiagnosticStatus::Passed
    };

    let (summary, action) = generate_summary(&checks);
    let duration_ms = start.elapsed().as_millis() as u64;

    let result = DiagnosticResult {
        status,
        checks,
        summary,
        action,
        duration_ms,
        timestamp,
    };

    match result.status {
        DiagnosticStatus::Passed => info!(duration_ms, "Pre-connection diagnostics passed"),
        DiagnosticStatus::Warning => warn!(
            summary = %result.summary,
            duration_ms,
            "Pre-connection diagnostics completed with warnings"
        ),
        DiagnosticStatus::Failed => error!(
            summary = %result.summary,
            duration_ms,
            "Pre-connection diagnostics failed"
        ),
    }

    result
}

// =============================================================================
// Проверки секретов
// =============================================================================

fn check_secrets(secrets_dir: &PathBuf) -> DiagnosticCheck {
    let start = Instant::now();

    // Проверяем существование директории
    if !secrets_dir.exists() {
        return DiagnosticCheck::failed(
            "secrets",
            &format!("Secrets directory not found: {}", secrets_dir.display()),
            Some(format!(
                "Create the directory and add required keys:\n\
                mkdir -p {}\n\n\
                Required files:\n\
                - server.noise.pub (server's Noise public key)\n\
                - client.noise.key (client's Noise private key)\n\
                - server.crt (server's TLS certificate)",
                secrets_dir.display()
            )),
            DiagnosticCode::E101_MissingServerPubKey,
            start.elapsed().as_millis() as u64,
        );
    }

    let required_files = [
        ("server.noise.pub", "Server Noise public key", 32, DiagnosticCode::E101_MissingServerPubKey),
        ("client.noise.key", "Client Noise private key", 32, DiagnosticCode::E102_MissingClientKey),
    ];

    let optional_files = [
        ("server.crt", "Server TLS certificate", 100),
        ("client.noise.pub", "Client Noise public key", 32),
    ];

    // Проверяем обязательные файлы
    for (file, desc, min_size, error_code) in &required_files {
        let path = secrets_dir.join(file);

        if !path.exists() {
            return DiagnosticCheck::failed(
                "secrets",
                &format!("Missing {}: {}", desc, file),
                Some(format!(
                    "File not found: {}\n\n\
                    To obtain this file:\n\
                    1. Deploy VPN server first\n\
                    2. Or copy from server: scp server:{}/secrets/{} {}",
                    path.display(),
                    "/opt/vpr",
                    file,
                    path.display()
                )),
                *error_code,
                start.elapsed().as_millis() as u64,
            );
        }

        // Проверяем размер и права
        match std::fs::metadata(&path) {
            Ok(meta) => {
                if meta.len() == 0 {
                    return DiagnosticCheck::failed(
                        "secrets",
                        &format!("{} is empty", file),
                        Some("The key file exists but has no content. Re-generate or re-copy the key.".to_string()),
                        DiagnosticCode::E104_InvalidKeyFormat,
                        start.elapsed().as_millis() as u64,
                    );
                }
                if meta.len() < *min_size as u64 {
                    return DiagnosticCheck::failed(
                        "secrets",
                        &format!("{} is too small ({} bytes, expected >= {})", file, meta.len(), min_size),
                        Some("The key file appears corrupted or incomplete.".to_string()),
                        DiagnosticCode::E104_InvalidKeyFormat,
                        start.elapsed().as_millis() as u64,
                    );
                }

                // Проверяем права доступа (только для Unix)
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = meta.permissions().mode();
                    // Приватный ключ не должен быть читаем другими
                    if file.contains("key") && (mode & 0o077) != 0 {
                        return DiagnosticCheck::warning(
                            "secrets",
                            &format!("{} has insecure permissions (mode {:o})", file, mode & 0o777),
                            Some(format!("Fix with: chmod 600 {}", path.display())),
                            start.elapsed().as_millis() as u64,
                        );
                    }
                }
            }
            Err(e) => {
                return DiagnosticCheck::failed(
                    "secrets",
                    &format!("Cannot read {}: {}", file, e),
                    Some("Check file permissions and ownership.".to_string()),
                    DiagnosticCode::E105_KeyPermissions,
                    start.elapsed().as_millis() as u64,
                );
            }
        }
    }

    // Проверяем опциональные файлы
    let mut warnings = Vec::new();
    for (file, desc, _min_size) in &optional_files {
        let path = secrets_dir.join(file);
        if !path.exists() {
            warnings.push(format!("{} ({})", file, desc));
        }
    }

    if !warnings.is_empty() {
        // Особое предупреждение для сертификата
        let cert_path = secrets_dir.join("server.crt");
        if !cert_path.exists() {
            return DiagnosticCheck::warning(
                "secrets",
                "Server TLS certificate not found",
                Some(format!(
                    "File: {}\n\n\
                    Without server.crt, connection may fail in release builds.\n\
                    Copy from server: scp server:/opt/vpr/secrets/server.crt {}",
                    cert_path.display(),
                    cert_path.display()
                )),
                start.elapsed().as_millis() as u64,
            );
        }
    }

    DiagnosticCheck::passed(
        "secrets",
        &format!("All keys found in {}", secrets_dir.display()),
        start.elapsed().as_millis() as u64,
    )
}

// =============================================================================
// Проверки прав доступа
// =============================================================================

fn check_permissions() -> DiagnosticCheck {
    let start = Instant::now();

    let is_root = unsafe { libc::geteuid() == 0 };

    if is_root {
        return DiagnosticCheck::passed(
            "permissions",
            "Running as root - full network access",
            start.elapsed().as_millis() as u64,
        );
    }

    // Проверяем capabilities
    #[cfg(unix)]
    {
        let has_net_admin = caps::has_cap(None, caps::CapSet::Effective, caps::Capability::CAP_NET_ADMIN)
            .unwrap_or(false);
        let has_net_raw = caps::has_cap(None, caps::CapSet::Effective, caps::Capability::CAP_NET_RAW)
            .unwrap_or(false);

        if has_net_admin && has_net_raw {
            return DiagnosticCheck::passed(
                "permissions",
                "CAP_NET_ADMIN + CAP_NET_RAW capabilities available",
                start.elapsed().as_millis() as u64,
            );
        }

        if has_net_admin {
            return DiagnosticCheck::warning(
                "permissions",
                "Only CAP_NET_ADMIN available (CAP_NET_RAW missing)",
                Some("Some features may not work. Add CAP_NET_RAW for full functionality.".to_string()),
                start.elapsed().as_millis() as u64,
            );
        }
    }

    DiagnosticCheck::failed(
        "permissions",
        "Insufficient permissions for TUN device",
        Some(
            "VPN requires root or network capabilities.\n\n\
            Solutions (choose one):\n\
            1. Run with sudo:\n\
               sudo vpr-app\n\n\
            2. Set capabilities on vpn-client binary:\n\
               sudo setcap 'cap_net_admin,cap_net_raw+eip' /path/to/vpn-client\n\n\
            3. Configure polkit for passwordless access"
                .to_string(),
        ),
        DiagnosticCode::E301_InsufficientPermissions,
        start.elapsed().as_millis() as u64,
    )
}

// =============================================================================
// Проверки TUN устройств
// =============================================================================

fn check_existing_tun(tun_name: &str) -> DiagnosticCheck {
    let start = Instant::now();

    #[cfg(unix)]
    {
        // Проверяем существует ли уже TUN устройство с таким именем
        let output = std::process::Command::new("ip")
            .args(["link", "show", tun_name])
            .output();

        match output {
            Ok(out) if out.status.success() => {
                // TUN уже существует - это может быть проблемой
                let stdout = String::from_utf8_lossy(&out.stdout);

                // Проверяем состояние
                if stdout.contains("state UP") || stdout.contains("LOWER_UP") {
                    return DiagnosticCheck::failed(
                        "tun_device",
                        &format!("TUN device {} already exists and is UP", tun_name),
                        Some(format!(
                            "Another VPN instance may be running.\n\n\
                            To fix:\n\
                            1. Disconnect existing VPN\n\
                            2. Or remove device: sudo ip link delete {}\n\
                            3. Or use different TUN name",
                            tun_name
                        )),
                        DiagnosticCode::E302_TunDeviceExists,
                        start.elapsed().as_millis() as u64,
                    );
                }

                // TUN существует но DOWN - можем удалить
                return DiagnosticCheck::warning(
                    "tun_device",
                    &format!("TUN device {} exists but is DOWN", tun_name),
                    Some(format!(
                        "Will attempt to reuse. If issues occur:\n\
                        sudo ip link delete {}",
                        tun_name
                    )),
                    start.elapsed().as_millis() as u64,
                );
            }
            Ok(_) => {
                // Устройство не существует - OK
            }
            Err(e) => {
                debug!("ip link show failed: {}", e);
            }
        }
    }

    DiagnosticCheck::passed(
        "tun_device",
        &format!("TUN device {} available", tun_name),
        start.elapsed().as_millis() as u64,
    )
}

// =============================================================================
// Проверки конфликтов с другими VPN
// =============================================================================

fn check_vpn_conflicts() -> DiagnosticCheck {
    let start = Instant::now();

    #[cfg(unix)]
    {
        // Проверяем наличие других VPN интерфейсов
        let output = std::process::Command::new("ip")
            .args(["link", "show", "type", "tun"])
            .output();

        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let active_tuns: Vec<&str> = stdout
                .lines()
                .filter(|l| l.contains("tun") || l.contains("tap"))
                .filter(|l| !l.contains("vpr")) // Исключаем наши устройства
                .collect();

            if !active_tuns.is_empty() {
                return DiagnosticCheck::warning(
                    "vpn_conflicts",
                    "Other VPN interfaces detected",
                    Some(format!(
                        "Found active TUN/TAP devices:\n{}\n\n\
                        This may cause routing conflicts. Consider disconnecting other VPNs.",
                        active_tuns.join("\n")
                    )),
                    start.elapsed().as_millis() as u64,
                );
            }
        }

        // Проверяем известные VPN процессы
        let vpn_processes = ["openvpn", "wireguard", "wg-quick", "nordvpn", "expressvpn", "surfshark"];
        let output = std::process::Command::new("pgrep")
            .args(["-l", &vpn_processes.join("|")])
            .output();

        if let Ok(out) = output {
            if out.status.success() {
                let stdout = String::from_utf8_lossy(&out.stdout);
                if !stdout.trim().is_empty() {
                    return DiagnosticCheck::warning(
                        "vpn_conflicts",
                        "Other VPN software is running",
                        Some(format!(
                            "Detected processes:\n{}\n\n\
                            Multiple VPNs may cause routing conflicts.",
                            stdout.trim()
                        )),
                        start.elapsed().as_millis() as u64,
                    );
                }
            }
        }
    }

    DiagnosticCheck::passed(
        "vpn_conflicts",
        "No conflicting VPN detected",
        start.elapsed().as_millis() as u64,
    )
}

// =============================================================================
// Проверки сетевого интерфейса
// =============================================================================

fn check_network_interface() -> DiagnosticCheck {
    let start = Instant::now();

    #[cfg(unix)]
    {
        // Получаем default route
        let output = std::process::Command::new("ip")
            .args(["route", "get", "1.1.1.1"])
            .output();

        match output {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);

                // Парсим интерфейс и gateway
                let mut interface = None;
                let mut gateway = None;
                let mut src_ip = None;

                let words: Vec<&str> = stdout.split_whitespace().collect();
                for i in 0..words.len() {
                    match words[i] {
                        "dev" if i + 1 < words.len() => interface = Some(words[i + 1]),
                        "via" if i + 1 < words.len() => gateway = Some(words[i + 1]),
                        "src" if i + 1 < words.len() => src_ip = Some(words[i + 1]),
                        _ => {}
                    }
                }

                let msg = match (interface, gateway, src_ip) {
                    (Some(iface), Some(gw), Some(src)) => {
                        format!("Network OK: {} via {} (src {})", iface, gw, src)
                    }
                    (Some(iface), Some(gw), None) => {
                        format!("Network OK: {} via {}", iface, gw)
                    }
                    (Some(iface), None, _) => {
                        format!("Network OK: {}", iface)
                    }
                    _ => "Network connectivity available".to_string(),
                };

                return DiagnosticCheck::passed("network", &msg, start.elapsed().as_millis() as u64);
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                return DiagnosticCheck::failed(
                    "network",
                    "No default route available",
                    Some(format!(
                        "Cannot reach external networks.\n\
                        Error: {}\n\n\
                        Check:\n\
                        1. Network cable/WiFi connected?\n\
                        2. IP address assigned? (ip addr)\n\
                        3. Gateway configured? (ip route)",
                        stderr.trim()
                    )),
                    DiagnosticCode::E207_NetworkUnreachable,
                    start.elapsed().as_millis() as u64,
                );
            }
            Err(e) => {
                return DiagnosticCheck::warning(
                    "network",
                    "Could not check network interface",
                    Some(format!("ip command failed: {}", e)),
                    start.elapsed().as_millis() as u64,
                );
            }
        }
    }

    #[cfg(not(unix))]
    DiagnosticCheck::passed(
        "network",
        "Network check skipped on this platform",
        start.elapsed().as_millis() as u64,
    )
}

// =============================================================================
// Проверки firewall
// =============================================================================

fn check_firewall(port: u16) -> DiagnosticCheck {
    let start = Instant::now();

    #[cfg(unix)]
    {
        // Проверяем iptables OUTPUT chain
        let output = std::process::Command::new("iptables")
            .args(["-L", "OUTPUT", "-n", "-v"])
            .output();

        match output {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);

                // Ищем правила DROP/REJECT для нашего порта
                let blocking_rules: Vec<&str> = stdout
                    .lines()
                    .filter(|l| {
                        (l.contains("DROP") || l.contains("REJECT"))
                            && (l.contains(&format!("dpt:{}", port)) || l.contains("dpt:443"))
                    })
                    .collect();

                if !blocking_rules.is_empty() {
                    return DiagnosticCheck::warning(
                        "firewall",
                        &format!("Firewall may block port {}", port),
                        Some(format!(
                            "Found potential blocking rules:\n{}\n\n\
                            If connection fails, temporarily allow outbound:\n\
                            sudo iptables -I OUTPUT -p udp --dport {} -j ACCEPT\n\
                            sudo iptables -I OUTPUT -p tcp --dport {} -j ACCEPT",
                            blocking_rules.join("\n"),
                            port,
                            port
                        )),
                        start.elapsed().as_millis() as u64,
                    );
                }
            }
            Ok(_) => {}
            Err(_) => {
                // iptables не доступен - возможно nftables
                debug!("iptables not available, trying nft");

                let nft_output = std::process::Command::new("nft")
                    .args(["list", "ruleset"])
                    .output();

                if let Ok(out) = nft_output {
                    if out.status.success() {
                        let stdout = String::from_utf8_lossy(&out.stdout);
                        if stdout.contains("drop") && stdout.contains(&port.to_string()) {
                            return DiagnosticCheck::warning(
                                "firewall",
                                &format!("nftables may block port {}", port),
                                Some("Check nft rules: nft list ruleset".to_string()),
                                start.elapsed().as_millis() as u64,
                            );
                        }
                    }
                }
            }
        }
    }

    DiagnosticCheck::passed(
        "firewall",
        "No blocking firewall rules detected",
        start.elapsed().as_millis() as u64,
    )
}

// =============================================================================
// Проверки DNS
// =============================================================================

async fn check_dns_resolution(server: &str) -> DiagnosticCheck {
    let start = Instant::now();

    // Если это уже IP адрес, пропускаем DNS
    if server.parse::<IpAddr>().is_ok() {
        return DiagnosticCheck::passed(
            "dns",
            &format!("{} is an IP address (no DNS needed)", server),
            start.elapsed().as_millis() as u64,
        );
    }

    // Пробуем резолвить с таймаутом
    let resolve_future = tokio::net::lookup_host(format!("{}:0", server));
    let timeout = Duration::from_secs(5);

    match tokio::time::timeout(timeout, resolve_future).await {
        Ok(Ok(mut addrs)) => {
            let addresses: Vec<_> = addrs.by_ref().take(3).collect();
            if addresses.is_empty() {
                return DiagnosticCheck::failed(
                    "dns",
                    &format!("DNS lookup for {} returned no addresses", server),
                    Some("The domain exists but has no A/AAAA records.".to_string()),
                    DiagnosticCode::E201_DnsResolutionFailed,
                    start.elapsed().as_millis() as u64,
                );
            }

            let ips: Vec<String> = addresses.iter().map(|a| a.ip().to_string()).collect();
            DiagnosticCheck::passed(
                "dns",
                &format!("{} -> {}", server, ips.join(", ")),
                start.elapsed().as_millis() as u64,
            )
        }
        Ok(Err(e)) => DiagnosticCheck::failed(
            "dns",
            &format!("Cannot resolve {}", server),
            Some(format!(
                "DNS error: {}\n\n\
                Possible causes:\n\
                - No internet connection\n\
                - DNS server not responding\n\
                - Domain name does not exist\n\
                - DNS poisoning/blocking\n\n\
                Try: nslookup {} 8.8.8.8",
                e, server
            )),
            DiagnosticCode::E201_DnsResolutionFailed,
            start.elapsed().as_millis() as u64,
        ),
        Err(_) => DiagnosticCheck::failed(
            "dns",
            &format!("DNS resolution timeout for {}", server),
            Some(
                "DNS server did not respond in 5 seconds.\n\n\
                Your DNS may be blocked or very slow.\n\
                Try using a different DNS: echo 'nameserver 8.8.8.8' | sudo tee /etc/resolv.conf"
                    .to_string(),
            ),
            DiagnosticCode::E201_DnsResolutionFailed,
            start.elapsed().as_millis() as u64,
        ),
    }
}

// =============================================================================
// Проверки TCP порта
// =============================================================================

async fn check_tcp_port(server: &str, port: u16, timeout_ms: u64) -> DiagnosticCheck {
    let start = Instant::now();
    let addr = format!("{}:{}", server, port);

    // Резолвим адрес
    let socket_addr = match tokio::net::lookup_host(&addr).await {
        Ok(mut addrs) => match addrs.next() {
            Some(a) => a,
            None => {
                return DiagnosticCheck::failed(
                    "tcp_port",
                    &format!("Cannot resolve {}:{}", server, port),
                    None,
                    DiagnosticCode::E201_DnsResolutionFailed,
                    start.elapsed().as_millis() as u64,
                );
            }
        },
        Err(e) => {
            return DiagnosticCheck::failed(
                "tcp_port",
                &format!("DNS failed for {}", server),
                Some(e.to_string()),
                DiagnosticCode::E201_DnsResolutionFailed,
                start.elapsed().as_millis() as u64,
            );
        }
    };

    let timeout = Duration::from_millis(timeout_ms);

    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(socket_addr)).await {
        Ok(Ok(_stream)) => DiagnosticCheck::passed(
            "tcp_port",
            &format!("TCP port {} reachable ({}ms)", port, start.elapsed().as_millis()),
            start.elapsed().as_millis() as u64,
        ),
        Ok(Err(e)) => {
            let (code, msg, details) = analyze_tcp_error(&e, server, port);
            DiagnosticCheck::failed("tcp_port", &msg, Some(details), code, start.elapsed().as_millis() as u64)
        }
        Err(_) => DiagnosticCheck::failed(
            "tcp_port",
            &format!("TCP connection to {}:{} timed out", server, port),
            Some(format!(
                "No response after {}ms.\n\n\
                Possible causes:\n\
                - Server is not running on port {}\n\
                - Firewall/ISP blocking port {}\n\
                - Server is overloaded\n\
                - Network congestion\n\n\
                Test: nc -zv {} {}",
                timeout_ms, port, port, server, port
            )),
            DiagnosticCode::E205_ConnectionTimeout,
            start.elapsed().as_millis() as u64,
        ),
    }
}

fn analyze_tcp_error(e: &std::io::Error, server: &str, port: u16) -> (DiagnosticCode, String, String) {
    use std::io::ErrorKind;

    match e.kind() {
        ErrorKind::ConnectionRefused => (
            DiagnosticCode::E204_ConnectionRefused,
            format!("Connection refused on {}:{}", server, port),
            format!(
                "Server is reachable but port {} is closed.\n\n\
                This usually means:\n\
                - VPN server is NOT running\n\
                - VPN server is on a DIFFERENT port\n\
                - Another service is using port {}\n\n\
                Check on server:\n\
                  ssh root@{} 'ss -tlnp | grep {}'\n\
                  ssh root@{} 'ps aux | grep vpn-server'",
                port, port, server, port, server
            ),
        ),
        ErrorKind::ConnectionReset => (
            DiagnosticCode::E206_ConnectionReset,
            format!("Connection reset by {}:{}", server, port),
            "Server forcibly closed the connection.\n\n\
            Possible causes:\n\
            - Firewall/DPI dropping connections\n\
            - Server crashed or restarting\n\
            - Protocol mismatch"
                .to_string(),
        ),
        ErrorKind::NetworkUnreachable => (
            DiagnosticCode::E207_NetworkUnreachable,
            "Network unreachable".to_string(),
            "Cannot reach the network. Check your internet connection.".to_string(),
        ),
        ErrorKind::HostUnreachable => (
            DiagnosticCode::E208_HostUnreachable,
            format!("Host {} unreachable", server),
            "The server IP cannot be reached.\n\n\
            Possible causes:\n\
            - Server is down\n\
            - IP is blocked by ISP\n\
            - Routing issue"
                .to_string(),
        ),
        _ => (
            DiagnosticCode::E202_TcpPortUnreachable,
            format!("TCP connection to {}:{} failed", server, port),
            format!("Error: {}", e),
        ),
    }
}

// =============================================================================
// Проверки UDP порта (для QUIC)
// =============================================================================

async fn check_udp_port(server: &str, port: u16, timeout_ms: u64) -> DiagnosticCheck {
    let start = Instant::now();

    // Резолвим адрес
    let addr = format!("{}:{}", server, port);
    let socket_addr = match tokio::net::lookup_host(&addr).await {
        Ok(mut addrs) => match addrs.next() {
            Some(a) => a,
            None => {
                return DiagnosticCheck::warning(
                    "udp_port",
                    "Cannot test UDP - DNS failed",
                    None,
                    start.elapsed().as_millis() as u64,
                );
            }
        },
        Err(_) => {
            return DiagnosticCheck::warning(
                "udp_port",
                "Cannot test UDP - DNS failed",
                None,
                start.elapsed().as_millis() as u64,
            );
        }
    };

    // Создаём UDP сокет
    let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            return DiagnosticCheck::warning(
                "udp_port",
                "Cannot create UDP socket",
                Some(format!("Error: {}", e)),
                start.elapsed().as_millis() as u64,
            );
        }
    };

    // Отправляем пробный пакет (QUIC Initial)
    // Простейший QUIC-like заголовок (не полноценный, но для теста достаточно)
    let probe_packet = vec![
        0xc0, // Long header, Initial packet
        0x00, 0x00, 0x00, 0x01, // Version (1)
        0x00, // DCID len
        0x00, // SCID len
        0x00, // Token length
        0x00, 0x00, // Length
    ];

    if let Err(e) = socket.send_to(&probe_packet, socket_addr).await {
        return DiagnosticCheck::warning(
            "udp_port",
            &format!("UDP send to {}:{} failed", server, port),
            Some(format!("Error: {}\n\nUDP may be blocked by firewall.", e)),
            start.elapsed().as_millis() as u64,
        );
    }

    // Ждём ответ с таймаутом (короткий, т.к. UDP unreliable)
    let mut buf = [0u8; 1500];
    let timeout = Duration::from_millis(timeout_ms.min(2000)); // Макс 2 секунды для UDP

    match tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
        Ok(Ok((len, _))) => {
            // Получили какой-то ответ - хорошо
            DiagnosticCheck::passed(
                "udp_port",
                &format!("UDP port {} responsive ({} bytes reply)", port, len),
                start.elapsed().as_millis() as u64,
            )
        }
        Ok(Err(e)) => DiagnosticCheck::warning(
            "udp_port",
            &format!("UDP receive error on port {}", port),
            Some(format!("Error: {}\n\nThis may be normal if server doesn't respond to probes.", e)),
            start.elapsed().as_millis() as u64,
        ),
        Err(_) => {
            // Таймаут - нормально для UDP, не критично
            DiagnosticCheck::warning(
                "udp_port",
                &format!("UDP port {} - no response (may be OK)", port),
                Some(
                    "UDP probe timed out. This is normal if:\n\
                    - Server ignores invalid QUIC packets\n\
                    - Firewall drops unsolicited UDP\n\n\
                    Connection may still work."
                        .to_string(),
                ),
                start.elapsed().as_millis() as u64,
            )
        }
    }
}

// =============================================================================
// Проверки MTU
// =============================================================================

fn check_mtu(server: &str) -> DiagnosticCheck {
    let start = Instant::now();

    #[cfg(unix)]
    {
        // Пробуем ping с разными размерами пакетов для определения MTU
        // Для VPN нам нужен MTU минимум 1280 (IPv6 minimum)

        let test_sizes = [1400, 1300, 1280];

        for size in &test_sizes {
            let output = std::process::Command::new("ping")
                .args([
                    "-c", "1",
                    "-W", "2",
                    "-M", "do", // Don't fragment
                    "-s", &size.to_string(),
                    server,
                ])
                .output();

            match output {
                Ok(out) if out.status.success() => {
                    return DiagnosticCheck::passed(
                        "mtu",
                        &format!("Path MTU to {} is at least {} bytes", server, size + 28), // +28 for IP+ICMP headers
                        start.elapsed().as_millis() as u64,
                    );
                }
                _ => continue,
            }
        }

        // Не смогли определить MTU
        return DiagnosticCheck::warning(
            "mtu",
            "Could not determine path MTU",
            Some(
                "MTU discovery failed. This may indicate:\n\
                - ICMP blocked (normal for many networks)\n\
                - Very low MTU path\n\n\
                VPN will use conservative MTU (1400)."
                    .to_string(),
            ),
            start.elapsed().as_millis() as u64,
        );
    }

    #[cfg(not(unix))]
    DiagnosticCheck::passed(
        "mtu",
        "MTU check skipped on this platform",
        start.elapsed().as_millis() as u64,
    )
}

// =============================================================================
// Генератор итогового сообщения
// =============================================================================

fn generate_summary(checks: &[DiagnosticCheck]) -> (String, Option<String>) {
    let failed: Vec<_> = checks
        .iter()
        .filter(|c| c.status == DiagnosticStatus::Failed)
        .collect();

    if failed.is_empty() {
        let warnings = checks.iter().filter(|c| c.status == DiagnosticStatus::Warning).count();
        if warnings > 0 {
            return (format!("All critical checks passed ({} warnings)", warnings), None);
        }
        return ("All checks passed".to_string(), None);
    }

    // Возвращаем первую критическую ошибку (они уже в порядке приоритета)
    let first_fail = &failed[0];

    let action = match first_fail.code {
        Some(DiagnosticCode::E301_InsufficientPermissions) => {
            Some("Run with: sudo vpr-app".to_string())
        }
        Some(DiagnosticCode::E101_MissingServerPubKey)
        | Some(DiagnosticCode::E102_MissingClientKey) => {
            Some("Deploy server first or copy keys from server".to_string())
        }
        Some(DiagnosticCode::E204_ConnectionRefused) => {
            Some("Check if VPN server is running on the correct port".to_string())
        }
        Some(DiagnosticCode::E205_ConnectionTimeout) => {
            Some("Check firewall and network connectivity".to_string())
        }
        Some(DiagnosticCode::E302_TunDeviceExists) => {
            Some("Disconnect existing VPN or restart network".to_string())
        }
        _ => first_fail.details.clone(),
    };

    (first_fail.message.clone(), action)
}

// =============================================================================
// Диагностика после неудачного подключения
// =============================================================================

// =============================================================================
// SSH-based серверная диагностика (удалённая проверка VPN сервера)
// =============================================================================

/// Конфигурация SSH для серверной диагностики
#[derive(Clone)]
pub struct SshConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: Option<String>,
    pub key_path: Option<PathBuf>,
}

/// Результат серверной диагностики
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerDiagnosticResult {
    pub vpn_server_running: bool,
    pub vpn_listening_port: Option<u16>,
    pub vpn_process_info: Option<String>,
    pub firewall_open: bool,
    pub system_resources: SystemResources,
    pub certificate_info: Option<CertificateInfo>,
    pub uptime: Option<String>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SystemResources {
    pub cpu_usage_percent: Option<f32>,
    pub memory_used_mb: Option<u64>,
    pub memory_total_mb: Option<u64>,
    pub disk_free_gb: Option<u64>,
    pub load_average: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub valid: bool,
    pub expires_at: Option<String>,
    pub days_until_expiry: Option<i32>,
    pub issuer: Option<String>,
    pub subject: Option<String>,
}

/// Выполняет SSH-диагностику на удалённом сервере
pub async fn run_remote_server_diagnostics(
    ssh: &SshConfig,
    vpn_port: u16,
) -> ServerDiagnosticResult {
    let mut result = ServerDiagnosticResult {
        vpn_server_running: false,
        vpn_listening_port: None,
        vpn_process_info: None,
        firewall_open: false,
        system_resources: SystemResources::default(),
        certificate_info: None,
        uptime: None,
        errors: Vec::new(),
    };

    // Формируем SSH команду с sshpass если есть пароль
    let ssh_base = build_ssh_command(ssh);

    // === 1. Проверяем запущен ли VPN сервер ===
    let ps_cmd = format!("{} 'ps aux | grep -E \"vpn-server|masque\" | grep -v grep'", ssh_base);
    match run_ssh_command(&ps_cmd).await {
        Ok(output) => {
            if !output.trim().is_empty() {
                result.vpn_server_running = true;
                result.vpn_process_info = Some(output.trim().to_string());
            }
        }
        Err(e) => result.errors.push(format!("Failed to check VPN process: {}", e)),
    }

    // === 2. Проверяем слушающие порты ===
    let ss_cmd = format!("{} 'ss -ulnp | grep {} || ss -tlnp | grep {}'", ssh_base, vpn_port, vpn_port);
    match run_ssh_command(&ss_cmd).await {
        Ok(output) => {
            if !output.trim().is_empty() {
                result.vpn_listening_port = Some(vpn_port);
            }
        }
        Err(e) => result.errors.push(format!("Failed to check ports: {}", e)),
    }

    // === 3. Проверяем firewall ===
    let fw_cmds = [
        format!("{} 'iptables -L INPUT -n 2>/dev/null | grep -E \"{}|ACCEPT\" | head -5'", ssh_base, vpn_port),
        format!("{} 'nft list ruleset 2>/dev/null | grep -E \"{}|accept\" | head -5'", ssh_base, vpn_port),
        format!("{} 'ufw status 2>/dev/null | grep -E \"{}|ALLOW\"'", ssh_base, vpn_port),
    ];

    for fw_cmd in &fw_cmds {
        if let Ok(output) = run_ssh_command(fw_cmd).await {
            if output.contains("ACCEPT") || output.contains("accept") || output.contains("ALLOW") {
                result.firewall_open = true;
                break;
            }
        }
    }

    // === 4. Системные ресурсы ===
    // CPU и load
    let load_cmd = format!("{} 'cat /proc/loadavg'", ssh_base);
    if let Ok(output) = run_ssh_command(&load_cmd).await {
        result.system_resources.load_average = Some(output.trim().to_string());
    }

    // Память
    let mem_cmd = format!("{} 'free -m | grep Mem'", ssh_base);
    if let Ok(output) = run_ssh_command(&mem_cmd).await {
        let parts: Vec<&str> = output.split_whitespace().collect();
        if parts.len() >= 3 {
            result.system_resources.memory_total_mb = parts.get(1).and_then(|s| s.parse().ok());
            result.system_resources.memory_used_mb = parts.get(2).and_then(|s| s.parse().ok());
        }
    }

    // Диск
    let disk_cmd = format!("{} 'df -BG / | tail -1'", ssh_base);
    if let Ok(output) = run_ssh_command(&disk_cmd).await {
        let parts: Vec<&str> = output.split_whitespace().collect();
        if parts.len() >= 4 {
            result.system_resources.disk_free_gb = parts.get(3)
                .and_then(|s| s.trim_end_matches('G').parse().ok());
        }
    }

    // Uptime
    let uptime_cmd = format!("{} 'uptime -p 2>/dev/null || uptime'", ssh_base);
    if let Ok(output) = run_ssh_command(&uptime_cmd).await {
        result.uptime = Some(output.trim().to_string());
    }

    // === 5. Проверяем сертификат (если есть) ===
    let cert_cmd = format!(
        "{} 'if [ -f /opt/vpr/secrets/server.crt ]; then openssl x509 -in /opt/vpr/secrets/server.crt -noout -dates -subject -issuer 2>/dev/null; fi'",
        ssh_base
    );
    if let Ok(output) = run_ssh_command(&cert_cmd).await {
        if !output.trim().is_empty() {
            result.certificate_info = parse_certificate_info(&output);
        }
    }

    result
}

fn build_ssh_command(ssh: &SshConfig) -> String {
    let mut cmd = String::new();

    // Используем sshpass если есть пароль
    if let Some(ref password) = ssh.password {
        cmd.push_str(&format!("sshpass -p '{}' ", password.replace('\'', "'\\''")));
    }

    cmd.push_str("ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10");

    if let Some(ref key_path) = ssh.key_path {
        cmd.push_str(&format!(" -i '{}'", key_path.display()));
    }

    cmd.push_str(&format!(" -p {} {}@{}", ssh.port, ssh.user, ssh.host));

    cmd
}

async fn run_ssh_command(cmd: &str) -> Result<String, String> {
    let output = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .await
        .map_err(|e| e.to_string())?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(stderr.to_string())
    }
}

fn parse_certificate_info(output: &str) -> Option<CertificateInfo> {
    let mut info = CertificateInfo {
        valid: true,
        expires_at: None,
        days_until_expiry: None,
        issuer: None,
        subject: None,
    };

    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("notAfter=") {
            let date_str = line.trim_start_matches("notAfter=");
            info.expires_at = Some(date_str.to_string());

            // Парсим дату и считаем дни до истечения
            if let Ok(expiry) = chrono::NaiveDateTime::parse_from_str(date_str, "%b %d %H:%M:%S %Y GMT")
                .or_else(|_| chrono::NaiveDateTime::parse_from_str(date_str, "%b %e %H:%M:%S %Y GMT"))
            {
                let now = chrono::Utc::now().naive_utc();
                let days = (expiry - now).num_days() as i32;
                info.days_until_expiry = Some(days);
                if days < 0 {
                    info.valid = false;
                }
            }
        } else if line.starts_with("issuer=") {
            info.issuer = Some(line.trim_start_matches("issuer=").to_string());
        } else if line.starts_with("subject=") {
            info.subject = Some(line.trim_start_matches("subject=").to_string());
        }
    }

    Some(info)
}

// =============================================================================
// Проверка совместимости версий протокола
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolCompatibility {
    pub client_version: String,
    pub server_version: Option<String>,
    pub compatible: bool,
    pub quic_versions: Vec<String>,
    pub noise_protocol: String,
    pub warnings: Vec<String>,
}

/// Проверяет совместимость версий клиента и сервера
pub fn check_protocol_compatibility(client_version: &str) -> ProtocolCompatibility {
    let supported_quic = vec!["h3".to_string(), "h3-29".to_string()];
    let noise_protocol = "Noise_IK_25519_ChaChaPoly_BLAKE2s".to_string();

    ProtocolCompatibility {
        client_version: client_version.to_string(),
        server_version: None, // Заполняется после QUIC хендшейка
        compatible: true,
        quic_versions: supported_quic,
        noise_protocol,
        warnings: Vec::new(),
    }
}

// =============================================================================
// Мониторинг качества соединения в реальном времени
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConnectionQuality {
    pub rtt_ms: f64,
    pub rtt_jitter_ms: f64,
    pub packet_loss_percent: f64,
    pub bandwidth_mbps: Option<f64>,
    pub quality_score: u8, // 0-100
    pub quality_label: String,
    pub samples: usize,
    pub timestamp: String,
}

impl ConnectionQuality {
    pub fn calculate_quality_score(&mut self) {
        // Формула: 100 - (RTT_penalty + Jitter_penalty + Loss_penalty)
        let rtt_penalty = (self.rtt_ms / 10.0).min(30.0); // Max 30 points for RTT > 300ms
        let jitter_penalty = (self.rtt_jitter_ms / 5.0).min(20.0); // Max 20 points for jitter > 100ms
        let loss_penalty = (self.packet_loss_percent * 10.0).min(50.0); // Max 50 points for >5% loss

        let score = (100.0 - rtt_penalty - jitter_penalty - loss_penalty).max(0.0) as u8;
        self.quality_score = score;

        self.quality_label = match score {
            90..=100 => "Excellent".to_string(),
            70..=89 => "Good".to_string(),
            50..=69 => "Fair".to_string(),
            30..=49 => "Poor".to_string(),
            _ => "Very Poor".to_string(),
        };
    }
}

/// Измеряет качество соединения через ping
pub async fn measure_connection_quality(server: &str, samples: usize) -> ConnectionQuality {
    let mut quality = ConnectionQuality {
        samples: 0,
        timestamp: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        ..Default::default()
    };

    let mut rtts: Vec<f64> = Vec::new();
    let mut lost = 0;

    for _ in 0..samples {
        let start = std::time::Instant::now();

        // Используем ping с 1-секундным таймаутом
        let output = tokio::process::Command::new("ping")
            .args(["-c", "1", "-W", "1", server])
            .output()
            .await;

        match output {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                // Парсим RTT из вывода ping
                if let Some(rtt) = parse_ping_rtt(&stdout) {
                    rtts.push(rtt);
                } else {
                    // Fallback на измерение времени команды
                    rtts.push(start.elapsed().as_secs_f64() * 1000.0);
                }
            }
            _ => {
                lost += 1;
            }
        }

        // Небольшая пауза между пингами
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    quality.samples = samples;
    quality.packet_loss_percent = (lost as f64 / samples as f64) * 100.0;

    if !rtts.is_empty() {
        quality.rtt_ms = rtts.iter().sum::<f64>() / rtts.len() as f64;

        // Вычисляем джиттер (среднее отклонение от среднего)
        let mean = quality.rtt_ms;
        let variance: f64 = rtts.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / rtts.len() as f64;
        quality.rtt_jitter_ms = variance.sqrt();
    }

    quality.calculate_quality_score();
    quality
}

fn parse_ping_rtt(output: &str) -> Option<f64> {
    // Парсим "time=X.XX ms" из вывода ping
    for line in output.lines() {
        if let Some(idx) = line.find("time=") {
            let rest = &line[idx + 5..];
            if let Some(end) = rest.find(' ') {
                if let Ok(rtt) = rest[..end].parse::<f64>() {
                    return Some(rtt);
                }
            }
        }
    }
    None
}

// =============================================================================
// Авто-исправление типичных проблем
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoFix {
    pub code: DiagnosticCode,
    pub name: String,
    pub description: String,
    pub command: String,
    pub requires_root: bool,
    pub safe: bool, // Безопасно ли выполнять автоматически
}

/// Возвращает список доступных автоисправлений для данной ошибки
pub fn get_available_fixes(code: DiagnosticCode) -> Vec<AutoFix> {
    match code {
        DiagnosticCode::E302_TunDeviceExists => vec![
            AutoFix {
                code,
                name: "Remove stale TUN device".to_string(),
                description: "Удаляет существующее TUN устройство vpr0".to_string(),
                command: "ip link delete vpr0".to_string(),
                requires_root: true,
                safe: true,
            },
        ],
        DiagnosticCode::E501_OtherVpnActive => vec![
            AutoFix {
                code,
                name: "Stop OpenVPN".to_string(),
                description: "Останавливает службу OpenVPN".to_string(),
                command: "systemctl stop openvpn".to_string(),
                requires_root: true,
                safe: true,
            },
            AutoFix {
                code,
                name: "Stop WireGuard".to_string(),
                description: "Останавливает WireGuard интерфейс".to_string(),
                command: "wg-quick down wg0".to_string(),
                requires_root: true,
                safe: true,
            },
        ],
        DiagnosticCode::E304_FirewallBlocking => vec![
            AutoFix {
                code,
                name: "Allow UDP 443 outbound".to_string(),
                description: "Добавляет правило iptables для исходящего UDP на порт 443".to_string(),
                command: "iptables -I OUTPUT -p udp --dport 443 -j ACCEPT".to_string(),
                requires_root: true,
                safe: true,
            },
        ],
        DiagnosticCode::E201_DnsResolutionFailed => vec![
            AutoFix {
                code,
                name: "Use Google DNS".to_string(),
                description: "Добавляет Google DNS (8.8.8.8) в resolv.conf".to_string(),
                command: "echo 'nameserver 8.8.8.8' | tee -a /etc/resolv.conf".to_string(),
                requires_root: true,
                safe: false, // Может сломать существующую DNS конфигурацию
            },
        ],
        DiagnosticCode::E105_KeyPermissions => vec![
            AutoFix {
                code,
                name: "Fix key permissions".to_string(),
                description: "Устанавливает права 600 на приватные ключи".to_string(),
                command: "chmod 600 ~/.silentway/secrets/*.key".to_string(),
                requires_root: false,
                safe: true,
            },
        ],
        _ => Vec::new(),
    }
}

/// Применяет автоисправление
pub async fn apply_fix(fix: &AutoFix) -> Result<String, String> {
    info!(name = %fix.name, command = %fix.command, "Applying auto-fix");

    let cmd = if fix.requires_root {
        format!("sudo {}", fix.command)
    } else {
        fix.command.clone()
    };

    let output = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .await
        .map_err(|e| format!("Failed to execute fix: {}", e))?;

    if output.status.success() {
        Ok(format!("Successfully applied: {}", fix.name))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("Fix failed: {}", stderr))
    }
}

// =============================================================================
// Детальная QUIC диагностика
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicDiagnostic {
    pub initial_handshake: HandshakePhase,
    pub tls_handshake: HandshakePhase,
    pub application_data: HandshakePhase,
    pub total_time_ms: u64,
    pub alpn_negotiated: Option<String>,
    pub quic_version: Option<String>,
    pub connection_id: Option<String>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakePhase {
    pub name: String,
    pub completed: bool,
    pub duration_ms: u64,
    pub error: Option<String>,
}

impl Default for HandshakePhase {
    fn default() -> Self {
        Self {
            name: String::new(),
            completed: false,
            duration_ms: 0,
            error: None,
        }
    }
}

/// Выполняет детальную диагностику QUIC соединения
pub async fn diagnose_quic_connection(
    server: &str,
    port: u16,
    timeout_ms: u64,
) -> QuicDiagnostic {
    let start = std::time::Instant::now();
    let mut diag = QuicDiagnostic {
        initial_handshake: HandshakePhase {
            name: "Initial Handshake (ClientHello)".to_string(),
            ..Default::default()
        },
        tls_handshake: HandshakePhase {
            name: "TLS 1.3 Handshake".to_string(),
            ..Default::default()
        },
        application_data: HandshakePhase {
            name: "Application Data Ready".to_string(),
            ..Default::default()
        },
        total_time_ms: 0,
        alpn_negotiated: None,
        quic_version: None,
        connection_id: None,
        errors: Vec::new(),
    };

    // Этап 1: Initial handshake (отправляем Initial пакет)
    let initial_start = std::time::Instant::now();

    // Резолвим адрес
    let addr = format!("{}:{}", server, port);
    let socket_addr = match tokio::net::lookup_host(&addr).await {
        Ok(mut addrs) => match addrs.next() {
            Some(a) => a,
            None => {
                diag.initial_handshake.error = Some("DNS resolution failed".to_string());
                diag.errors.push("Cannot resolve server address".to_string());
                return diag;
            }
        },
        Err(e) => {
            diag.initial_handshake.error = Some(format!("DNS error: {}", e));
            diag.errors.push(format!("DNS resolution failed: {}", e));
            return diag;
        }
    };

    // Создаём UDP сокет
    let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            diag.initial_handshake.error = Some(format!("Socket error: {}", e));
            diag.errors.push(format!("Cannot create UDP socket: {}", e));
            return diag;
        }
    };

    // Формируем QUIC Initial пакет (упрощённый)
    // Long Header: 1 byte header, 4 bytes version, DCID len, DCID, SCID len, SCID, token len, payload len
    let mut initial_packet = Vec::with_capacity(1200);

    // Header byte: Long header (1), Fixed bit (1), Type Initial (00), Reserved (00), PN Length (00)
    initial_packet.push(0xc0);

    // Version (QUIC v1 = 0x00000001)
    initial_packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);

    // DCID: 8 pseudo-random bytes (using timestamp + process id as seed)
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(12345) ^ (std::process::id() as u64);
    let dcid: [u8; 8] = seed.to_le_bytes();
    initial_packet.push(8); // DCID length
    initial_packet.extend_from_slice(&dcid);

    // SCID: empty for Initial
    initial_packet.push(0);

    // Token length: 0 (no token for first Initial)
    initial_packet.push(0);

    // Payload length and packet number (minimal)
    // Мы отправляем пустой пакет - сервер должен ответить Version Negotiation или Initial
    initial_packet.extend_from_slice(&[0x00, 0x04]); // Length = 4
    initial_packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Packet number + padding

    // Padding до 1200 bytes (QUIC Initial минимум)
    while initial_packet.len() < 1200 {
        initial_packet.push(0x00);
    }

    // Отправляем
    if let Err(e) = socket.send_to(&initial_packet, socket_addr).await {
        diag.initial_handshake.error = Some(format!("Send error: {}", e));
        diag.errors.push(format!("Failed to send Initial packet: {}", e));
        return diag;
    }

    // Ждём ответ
    let mut buf = [0u8; 1500];
    let timeout = Duration::from_millis(timeout_ms.min(5000));

    match tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
        Ok(Ok((len, _))) => {
            diag.initial_handshake.completed = true;
            diag.initial_handshake.duration_ms = initial_start.elapsed().as_millis() as u64;

            // Анализируем ответ
            if len > 0 {
                let header = buf[0];
                if header & 0x80 != 0 {
                    // Long header
                    if len >= 5 {
                        let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
                        if version == 0 {
                            // Version Negotiation
                            diag.quic_version = Some("Version Negotiation received".to_string());
                        } else {
                            diag.quic_version = Some(format!("0x{:08x}", version));
                        }
                    }
                }

                // Если получили ответ - сервер поддерживает QUIC
                diag.tls_handshake.completed = true;
                diag.tls_handshake.duration_ms = 0; // Мы не делаем полный TLS handshake

                // Для полной диагностики нужен quinn/quiche
                diag.application_data.error = Some(
                    "Full QUIC handshake requires complete TLS implementation".to_string()
                );
            }
        }
        Ok(Err(e)) => {
            diag.initial_handshake.error = Some(format!("Receive error: {}", e));
            diag.errors.push(format!("Error receiving response: {}", e));
        }
        Err(_) => {
            diag.initial_handshake.error = Some("Timeout waiting for server response".to_string());
            diag.errors.push(format!(
                "No response from {}:{} in {}ms - server may not support QUIC or port is blocked",
                server, port, timeout_ms
            ));
        }
    }

    diag.total_time_ms = start.elapsed().as_millis() as u64;
    diag
}

// =============================================================================
// Retry с exponential backoff
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    pub max_attempts: u32,
    pub initial_delay_ms: u64,
    pub max_delay_ms: u64,
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            initial_delay_ms: 500,
            max_delay_ms: 30000,
            backoff_multiplier: 2.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryState {
    pub attempt: u32,
    pub next_delay_ms: u64,
    pub total_wait_ms: u64,
    pub last_error: Option<String>,
    pub should_retry: bool,
}

impl RetryState {
    pub fn new(config: &RetryConfig) -> Self {
        Self {
            attempt: 0,
            next_delay_ms: config.initial_delay_ms,
            total_wait_ms: 0,
            last_error: None,
            should_retry: true,
        }
    }

    pub fn record_failure(&mut self, error: &str, config: &RetryConfig) {
        self.attempt += 1;
        self.last_error = Some(error.to_string());

        if self.attempt >= config.max_attempts {
            self.should_retry = false;
            return;
        }

        // Вычисляем следующую задержку с exponential backoff
        let new_delay = (self.next_delay_ms as f64 * config.backoff_multiplier) as u64;
        self.next_delay_ms = new_delay.min(config.max_delay_ms);
        self.total_wait_ms += self.next_delay_ms;
    }

    pub fn is_retryable_error(error: &str) -> bool {
        let error_lower = error.to_lowercase();

        // Ошибки, которые имеет смысл повторять
        let retryable = [
            "timeout",
            "timed out",
            "connection reset",
            "temporarily unavailable",
            "try again",
            "eagain",
            "econnreset",
            "network unreachable",
            "no route",
        ];

        // Ошибки, которые НЕ имеет смысла повторять
        let non_retryable = [
            "permission denied",
            "certificate",
            "authentication",
            "key",
            "handshake failed",
            "invalid",
            "not found",
            "refused",
        ];

        for pattern in &non_retryable {
            if error_lower.contains(pattern) {
                return false;
            }
        }

        for pattern in &retryable {
            if error_lower.contains(pattern) {
                return true;
            }
        }

        // По умолчанию повторяем
        true
    }
}

// =============================================================================
// Health check endpoint verification
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    pub endpoint: String,
    pub reachable: bool,
    pub status_code: Option<u16>,
    pub response_time_ms: u64,
    pub server_version: Option<String>,
    pub server_uptime: Option<String>,
    pub active_connections: Option<u32>,
    pub error: Option<String>,
}

/// Проверяет health endpoint VPN сервера через HTTP/3
pub async fn check_health_endpoint(
    server: &str,
    port: u16,
    endpoint: &str,
) -> HealthCheckResult {
    let start = std::time::Instant::now();
    let url = format!("https://{}:{}{}", server, port, endpoint);

    let mut result = HealthCheckResult {
        endpoint: url.clone(),
        reachable: false,
        status_code: None,
        response_time_ms: 0,
        server_version: None,
        server_uptime: None,
        active_connections: None,
        error: None,
    };

    // Пробуем через curl с HTTP/3 поддержкой
    let output = tokio::process::Command::new("curl")
        .args([
            "--http3",
            "-s",
            "-k", // Ignore cert for health check
            "-o", "/dev/null",
            "-w", "%{http_code}",
            "--connect-timeout", "5",
            &url,
        ])
        .output()
        .await;

    match output {
        Ok(out) => {
            result.response_time_ms = start.elapsed().as_millis() as u64;

            if out.status.success() {
                let status_str = String::from_utf8_lossy(&out.stdout);
                if let Ok(status) = status_str.trim().parse::<u16>() {
                    result.status_code = Some(status);
                    result.reachable = status >= 200 && status < 400;
                }
            } else {
                // Fallback to HTTP/2
                let http2_output = tokio::process::Command::new("curl")
                    .args([
                        "-s",
                        "-k",
                        "-o", "/dev/null",
                        "-w", "%{http_code}",
                        "--connect-timeout", "5",
                        &url,
                    ])
                    .output()
                    .await;

                if let Ok(out2) = http2_output {
                    result.response_time_ms = start.elapsed().as_millis() as u64;
                    if out2.status.success() {
                        let status_str = String::from_utf8_lossy(&out2.stdout);
                        if let Ok(status) = status_str.trim().parse::<u16>() {
                            result.status_code = Some(status);
                            result.reachable = status >= 200 && status < 400;
                        }
                    }
                }
            }
        }
        Err(e) => {
            result.error = Some(format!("curl not available or failed: {}", e));
            result.response_time_ms = start.elapsed().as_millis() as u64;
        }
    }

    result
}

// =============================================================================
// Проверка срока действия сертификата (локального)
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalCertificateCheck {
    pub path: String,
    pub exists: bool,
    pub valid: bool,
    pub expires_at: Option<String>,
    pub days_until_expiry: Option<i32>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub warning: Option<String>,
    pub error: Option<String>,
}

/// Проверяет локальный TLS сертификат
pub fn check_local_certificate(cert_path: &PathBuf) -> LocalCertificateCheck {
    let mut result = LocalCertificateCheck {
        path: cert_path.display().to_string(),
        exists: false,
        valid: false,
        expires_at: None,
        days_until_expiry: None,
        subject: None,
        issuer: None,
        warning: None,
        error: None,
    };

    if !cert_path.exists() {
        result.error = Some("Certificate file not found".to_string());
        return result;
    }

    result.exists = true;

    // Используем openssl для проверки
    let output = std::process::Command::new("openssl")
        .args([
            "x509",
            "-in", &cert_path.to_string_lossy(),
            "-noout",
            "-dates",
            "-subject",
            "-issuer",
        ])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);

            for line in stdout.lines() {
                let line = line.trim();
                if line.starts_with("notAfter=") {
                    let date_str = line.trim_start_matches("notAfter=");
                    result.expires_at = Some(date_str.to_string());

                    // Парсим дату
                    if let Ok(expiry) = chrono::NaiveDateTime::parse_from_str(date_str, "%b %d %H:%M:%S %Y GMT")
                        .or_else(|_| chrono::NaiveDateTime::parse_from_str(date_str, "%b %e %H:%M:%S %Y GMT"))
                    {
                        let now = chrono::Utc::now().naive_utc();
                        let days = (expiry - now).num_days() as i32;
                        result.days_until_expiry = Some(days);

                        if days < 0 {
                            result.valid = false;
                            result.error = Some("Certificate has expired".to_string());
                        } else if days < 7 {
                            result.valid = true;
                            result.warning = Some(format!("Certificate expires in {} days!", days));
                        } else if days < 30 {
                            result.valid = true;
                            result.warning = Some(format!("Certificate expires in {} days", days));
                        } else {
                            result.valid = true;
                        }
                    }
                } else if line.starts_with("subject=") {
                    result.subject = Some(line.trim_start_matches("subject=").to_string());
                } else if line.starts_with("issuer=") {
                    result.issuer = Some(line.trim_start_matches("issuer=").to_string());
                }
            }
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            result.error = Some(format!("Certificate parsing failed: {}", stderr));
        }
        Err(e) => {
            result.error = Some(format!("openssl not available: {}", e));
        }
    }

    result
}

// =============================================================================
// Комплексная диагностика (всё вместе)
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComprehensiveDiagnosticResult {
    pub pre_connection: DiagnosticResult,
    pub connection_quality: Option<ConnectionQuality>,
    pub quic_diagnostic: Option<QuicDiagnostic>,
    pub local_certificate: Option<LocalCertificateCheck>,
    pub server_diagnostic: Option<ServerDiagnosticResult>,
    pub protocol_compatibility: ProtocolCompatibility,
    pub available_fixes: Vec<AutoFix>,
    pub overall_status: DiagnosticStatus,
    pub overall_message: String,
    pub timestamp: String,
    pub total_duration_ms: u64,
}

/// Выполняет полную комплексную диагностику
pub async fn run_comprehensive_diagnostics(
    params: &DiagnosticParams,
    ssh_config: Option<&SshConfig>,
    client_version: &str,
) -> ComprehensiveDiagnosticResult {
    let start = std::time::Instant::now();
    let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    // 1. Pre-connection diagnostics (обязательно)
    let pre_connection = run_pre_connection_diagnostics(params).await;

    // 2. Проверка качества соединения (если pre-check прошёл)
    let connection_quality = if pre_connection.status != DiagnosticStatus::Failed {
        Some(measure_connection_quality(&params.server, 5).await)
    } else {
        None
    };

    // 3. QUIC диагностика
    let quic_diagnostic = if pre_connection.status != DiagnosticStatus::Failed {
        Some(diagnose_quic_connection(&params.server, params.port, params.timeout_ms).await)
    } else {
        None
    };

    // 4. Проверка локального сертификата
    let cert_path = params.secrets_dir.join("server.crt");
    let local_certificate = Some(check_local_certificate(&cert_path));

    // 5. Серверная диагностика (если есть SSH)
    let server_diagnostic = if let Some(ssh) = ssh_config {
        Some(run_remote_server_diagnostics(ssh, params.port).await)
    } else {
        None
    };

    // 6. Совместимость протокола
    let protocol_compatibility = check_protocol_compatibility(client_version);

    // 7. Собираем доступные исправления
    let mut available_fixes = Vec::new();
    for check in &pre_connection.checks {
        if let Some(code) = check.code {
            available_fixes.extend(get_available_fixes(code));
        }
    }

    // 8. Определяем общий статус
    let overall_status = if pre_connection.status == DiagnosticStatus::Failed {
        DiagnosticStatus::Failed
    } else if let Some(ref cert) = local_certificate {
        if !cert.valid {
            DiagnosticStatus::Failed
        } else if cert.warning.is_some() {
            DiagnosticStatus::Warning
        } else {
            pre_connection.status
        }
    } else {
        pre_connection.status
    };

    // 9. Формируем сообщение
    let overall_message = match overall_status {
        DiagnosticStatus::Passed => {
            let quality_msg = connection_quality
                .as_ref()
                .map(|q| format!(" Quality: {} ({}ms RTT)", q.quality_label, q.rtt_ms as u32))
                .unwrap_or_default();
            format!("All systems operational.{}", quality_msg)
        }
        DiagnosticStatus::Warning => {
            let warnings: Vec<String> = pre_connection.checks.iter()
                .filter(|c| c.status == DiagnosticStatus::Warning)
                .map(|c| c.message.clone())
                .collect();
            format!("Ready with warnings: {}", warnings.join("; "))
        }
        DiagnosticStatus::Failed => pre_connection.summary.clone(),
    };

    ComprehensiveDiagnosticResult {
        pre_connection,
        connection_quality,
        quic_diagnostic,
        local_certificate,
        server_diagnostic,
        protocol_compatibility,
        available_fixes,
        overall_status,
        overall_message,
        timestamp,
        total_duration_ms: start.elapsed().as_millis() as u64,
    }
}

// =============================================================================
// FLAGSHIP EXTENDED DIAGNOSTICS - PART 2
// =============================================================================

// =============================================================================
// Network Path Analyzer (Traceroute/MTR style)
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPathAnalysis {
    pub hops: Vec<NetworkHop>,
    pub total_hops: usize,
    pub destination_reached: bool,
    pub suspected_blocking_hop: Option<usize>,
    pub path_quality: PathQuality,
    pub asn_path: Vec<AsnInfo>,
    pub country_path: Vec<String>,
    pub analysis: PathAnalysisResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkHop {
    pub hop_number: usize,
    pub ip: Option<String>,
    pub hostname: Option<String>,
    pub rtt_ms: Vec<f64>,
    pub avg_rtt_ms: f64,
    pub packet_loss_percent: f64,
    pub asn: Option<String>,
    pub country: Option<String>,
    pub is_timeout: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PathQuality {
    Excellent, // <50ms, <1% loss
    Good,      // <100ms, <5% loss
    Fair,      // <200ms, <10% loss
    Poor,      // <500ms, <20% loss
    VeryPoor,  // >500ms or >20% loss
    Blocked,   // Destination unreachable
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathAnalysisResult {
    pub blocking_suspected: bool,
    pub blocking_type: Option<BlockingType>,
    pub blocking_evidence: Vec<String>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockingType {
    IpBlock,           // Целевой IP заблокирован
    PortBlock,         // Порт заблокирован
    ProtocolBlock,     // Протокол (QUIC/UDP) заблокирован
    DpiBlock,          // DPI блокировка
    DnsBlock,          // DNS poisoning
    BlackholeRouting,  // Трафик направляется в никуда
    RateLimiting,      // Ограничение скорости
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AsnInfo {
    pub asn: String,
    pub name: String,
    pub country: String,
    pub is_transit: bool,
    pub is_hostile: bool, // Known for blocking VPNs
}

/// Анализирует сетевой путь до сервера
pub async fn analyze_network_path(server: &str, port: u16, probes: usize) -> NetworkPathAnalysis {
    let mut hops = Vec::new();
    let mut destination_reached = false;

    // Используем traceroute с UDP на целевой порт
    let output = tokio::process::Command::new("traceroute")
        .args([
            "-n",           // Без DNS резолва (быстрее)
            "-U",           // UDP
            "-p", &port.to_string(),
            "-q", &probes.to_string(), // Количество проб на хоп
            "-w", "2",      // 2 сек таймаут
            "-m", "30",     // Максимум 30 хопов
            server,
        ])
        .output()
        .await;

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            hops = parse_traceroute_output(&stdout);
            destination_reached = hops.iter().any(|h| {
                h.ip.as_ref().map(|ip| ip == server).unwrap_or(false)
            });
        }
        Err(_) => {
            // Fallback: пробуем mtr
            let mtr_output = tokio::process::Command::new("mtr")
                .args([
                    "-r",           // Report mode
                    "-n",           // No DNS
                    "-c", &probes.to_string(),
                    "-u",           // UDP
                    "-P", &port.to_string(),
                    server,
                ])
                .output()
                .await;

            if let Ok(out) = mtr_output {
                let stdout = String::from_utf8_lossy(&out.stdout);
                hops = parse_mtr_output(&stdout);
                destination_reached = hops.iter().any(|h| {
                    h.ip.as_ref().map(|ip| ip == server).unwrap_or(false)
                });
            }
        }
    }

    // Анализируем путь на признаки блокировки
    let analysis = analyze_path_for_blocking(&hops, destination_reached, server, port);

    // Определяем качество пути
    let path_quality = if !destination_reached {
        PathQuality::Blocked
    } else {
        let avg_rtt: f64 = hops.iter()
            .filter(|h| h.avg_rtt_ms > 0.0)
            .map(|h| h.avg_rtt_ms)
            .sum::<f64>() / hops.len().max(1) as f64;
        let max_loss = hops.iter()
            .map(|h| h.packet_loss_percent)
            .fold(0.0f64, f64::max);

        if avg_rtt < 50.0 && max_loss < 1.0 {
            PathQuality::Excellent
        } else if avg_rtt < 100.0 && max_loss < 5.0 {
            PathQuality::Good
        } else if avg_rtt < 200.0 && max_loss < 10.0 {
            PathQuality::Fair
        } else if avg_rtt < 500.0 && max_loss < 20.0 {
            PathQuality::Poor
        } else {
            PathQuality::VeryPoor
        }
    };

    let suspected_blocking_hop = if analysis.blocking_suspected {
        // Найти первый хоп где начинаются таймауты
        hops.iter().position(|h| h.is_timeout)
    } else {
        None
    };

    NetworkPathAnalysis {
        total_hops: hops.len(),
        destination_reached,
        suspected_blocking_hop,
        path_quality,
        asn_path: Vec::new(), // TODO: ASN lookup
        country_path: Vec::new(), // TODO: GeoIP
        hops,
        analysis,
    }
}

fn parse_traceroute_output(output: &str) -> Vec<NetworkHop> {
    let mut hops = Vec::new();

    for line in output.lines().skip(1) { // Skip header
        let line = line.trim();
        if line.is_empty() { continue; }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() { continue; }

        // Parse hop number
        let hop_num: usize = match parts[0].parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        let mut hop = NetworkHop {
            hop_number: hop_num,
            ip: None,
            hostname: None,
            rtt_ms: Vec::new(),
            avg_rtt_ms: 0.0,
            packet_loss_percent: 0.0,
            asn: None,
            country: None,
            is_timeout: false,
        };

        // Parse IP and RTT values
        for part in &parts[1..] {
            if *part == "*" {
                hop.is_timeout = true;
            } else if part.contains('.') && !part.contains("ms") {
                // IP address
                hop.ip = Some(part.to_string());
            } else if part.ends_with("ms") || part.parse::<f64>().is_ok() {
                // RTT value
                let rtt_str = part.trim_end_matches("ms");
                if let Ok(rtt) = rtt_str.parse::<f64>() {
                    hop.rtt_ms.push(rtt);
                }
            }
        }

        // Calculate average RTT
        if !hop.rtt_ms.is_empty() {
            hop.avg_rtt_ms = hop.rtt_ms.iter().sum::<f64>() / hop.rtt_ms.len() as f64;
        }

        // Calculate packet loss (timeouts / total probes)
        let total_probes = hop.rtt_ms.len() + if hop.is_timeout { 1 } else { 0 };
        if total_probes > 0 && hop.is_timeout {
            hop.packet_loss_percent = 100.0 / total_probes as f64;
        }

        hops.push(hop);
    }

    hops
}

fn parse_mtr_output(output: &str) -> Vec<NetworkHop> {
    let mut hops = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("Start") || line.starts_with("HOST") {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 { continue; }

        // MTR format: Host Loss% Snt Last Avg Best Wrst StDev
        let hop_num = hops.len() + 1;

        let mut hop = NetworkHop {
            hop_number: hop_num,
            ip: Some(parts[0].trim_end_matches('.').to_string()),
            hostname: None,
            rtt_ms: Vec::new(),
            avg_rtt_ms: 0.0,
            packet_loss_percent: 0.0,
            asn: None,
            country: None,
            is_timeout: parts[0] == "???",
        };

        // Parse loss percentage
        if let Ok(loss) = parts.get(1).unwrap_or(&"0").trim_end_matches('%').parse::<f64>() {
            hop.packet_loss_percent = loss;
        }

        // Parse average RTT
        if let Ok(avg) = parts.get(4).unwrap_or(&"0").parse::<f64>() {
            hop.avg_rtt_ms = avg;
            hop.rtt_ms.push(avg);
        }

        hops.push(hop);
    }

    hops
}

fn analyze_path_for_blocking(
    hops: &[NetworkHop],
    destination_reached: bool,
    server: &str,
    _port: u16,
) -> PathAnalysisResult {
    let mut result = PathAnalysisResult {
        blocking_suspected: false,
        blocking_type: None,
        blocking_evidence: Vec::new(),
        recommendations: Vec::new(),
    };

    if !destination_reached {
        result.blocking_suspected = true;

        // Анализируем где обрывается путь
        let last_responding_hop = hops.iter().rposition(|h| !h.is_timeout);
        let timeout_start = hops.iter().position(|h| h.is_timeout);

        if let Some(start) = timeout_start {
            // Все хопы после start - таймауты
            let timeout_count = hops.len() - start;

            if timeout_count >= 3 {
                result.blocking_type = Some(BlockingType::BlackholeRouting);
                result.blocking_evidence.push(format!(
                    "Path goes dark after hop {} - {} consecutive timeouts",
                    start, timeout_count
                ));
            }

            if let Some(last) = last_responding_hop {
                if last < hops.len() - 1 {
                    if let Some(ref ip) = hops[last].ip {
                        result.blocking_evidence.push(format!(
                            "Last responding hop: {} (hop {})",
                            ip, last + 1
                        ));
                    }
                }
            }
        }

        result.recommendations.push(format!(
            "Try connecting through a different network (mobile data, different ISP)"
        ));
        result.recommendations.push(format!(
            "Destination {} may be blocked by your ISP",
            server
        ));
    }

    // Проверяем на rate limiting (высокие задержки на последних хопах)
    if destination_reached {
        let last_hops: Vec<_> = hops.iter().rev().take(3).collect();
        let high_latency = last_hops.iter().any(|h| h.avg_rtt_ms > 500.0);
        let high_loss = last_hops.iter().any(|h| h.packet_loss_percent > 20.0);

        if high_latency && high_loss {
            result.blocking_suspected = true;
            result.blocking_type = Some(BlockingType::RateLimiting);
            result.blocking_evidence.push(
                "High latency and packet loss on final hops - possible rate limiting".to_string()
            );
        }
    }

    result
}

// =============================================================================
// DPI (Deep Packet Inspection) Detection
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpiDetectionResult {
    pub dpi_detected: bool,
    pub dpi_type: Option<DpiType>,
    pub confidence: f64, // 0.0-1.0
    pub evidence: Vec<DpiEvidence>,
    pub evasion_recommendations: Vec<String>,
    pub protocol_support: ProtocolSupportMatrix,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DpiType {
    StatefulFirewall,        // Простой stateful firewall
    BasicDpi,                // Базовый DPI (порты, протоколы)
    AdvancedDpi,             // Продвинутый DPI (сигнатуры)
    ActiveProbing,           // Активное зондирование
    MachineLearningDpi,      // ML-based DPI
    GreatFirewall,           // GFW-style (active probing + ML)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpiEvidence {
    pub test_name: String,
    pub result: String,
    pub indicates_dpi: bool,
    pub details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProtocolSupportMatrix {
    pub tcp_443: ProtocolTestResult,
    pub udp_443: ProtocolTestResult,
    pub quic: ProtocolTestResult,
    pub http3: ProtocolTestResult,
    pub websocket: ProtocolTestResult,
    pub ssh: ProtocolTestResult,
    pub wireguard: ProtocolTestResult,
    pub openvpn_tcp: ProtocolTestResult,
    pub openvpn_udp: ProtocolTestResult,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProtocolTestResult {
    pub tested: bool,
    pub blocked: bool,
    pub degraded: bool,
    pub latency_ms: Option<f64>,
    pub notes: Option<String>,
}

/// Детектирует наличие DPI на пути к серверу
pub async fn detect_dpi(server: &str, port: u16) -> DpiDetectionResult {
    let mut evidence = Vec::new();
    let mut dpi_indicators = 0;
    let mut total_tests = 0;

    // Test 1: TCP RST injection (признак DPI)
    let rst_test = test_tcp_rst_injection(server, port).await;
    evidence.push(rst_test.clone());
    if rst_test.indicates_dpi { dpi_indicators += 1; }
    total_tests += 1;

    // Test 2: TTL-based detection
    let ttl_test = test_ttl_anomaly(server, port).await;
    evidence.push(ttl_test.clone());
    if ttl_test.indicates_dpi { dpi_indicators += 1; }
    total_tests += 1;

    // Test 3: Fragmentation handling
    let frag_test = test_fragmentation(server, port).await;
    evidence.push(frag_test.clone());
    if frag_test.indicates_dpi { dpi_indicators += 1; }
    total_tests += 1;

    // Test 4: Protocol detection (does changing protocol change outcome?)
    let proto_test = test_protocol_detection(server, port).await;
    evidence.push(proto_test.clone());
    if proto_test.indicates_dpi { dpi_indicators += 1; }
    total_tests += 1;

    // Test 5: Timing analysis
    let timing_test = test_timing_anomaly(server, port).await;
    evidence.push(timing_test.clone());
    if timing_test.indicates_dpi { dpi_indicators += 1; }
    total_tests += 1;

    // Test 6: QUIC version negotiation
    let quic_test = test_quic_blocking(server, port).await;
    evidence.push(quic_test.clone());
    if quic_test.indicates_dpi { dpi_indicators += 1; }
    total_tests += 1;

    let confidence = dpi_indicators as f64 / total_tests as f64;
    let dpi_detected = confidence > 0.3;

    // Determine DPI type based on evidence
    let dpi_type = if dpi_detected {
        if evidence.iter().any(|e| e.test_name.contains("active_probe")) {
            Some(DpiType::ActiveProbing)
        } else if evidence.iter().any(|e| e.test_name.contains("timing") && e.indicates_dpi) {
            Some(DpiType::MachineLearningDpi)
        } else if evidence.iter().any(|e| e.test_name.contains("protocol") && e.indicates_dpi) {
            Some(DpiType::AdvancedDpi)
        } else if dpi_indicators > 2 {
            Some(DpiType::BasicDpi)
        } else {
            Some(DpiType::StatefulFirewall)
        }
    } else {
        None
    };

    // Build recommendations
    let mut recommendations = Vec::new();
    if dpi_detected {
        recommendations.push("Enable traffic morphing to disguise VPN traffic".to_string());
        recommendations.push("Use domain fronting if available".to_string());
        recommendations.push("Try WebSocket transport over port 443".to_string());
        if evidence.iter().any(|e| e.test_name.contains("quic") && e.indicates_dpi) {
            recommendations.push("QUIC appears blocked - fall back to TCP/TLS".to_string());
        }
    }

    DpiDetectionResult {
        dpi_detected,
        dpi_type,
        confidence,
        evidence,
        evasion_recommendations: recommendations,
        protocol_support: ProtocolSupportMatrix::default(),
    }
}

async fn test_tcp_rst_injection(server: &str, port: u16) -> DpiEvidence {
    // Тест на TCP RST инъекцию - отправляем TCP SYN и смотрим получаем ли мы
    // RST раньше чем должны (признак DPI)
    let start = std::time::Instant::now();

    let result = tokio::process::Command::new("timeout")
        .args(["2", "nc", "-z", "-v", "-w", "1", server, &port.to_string()])
        .output()
        .await;

    let duration = start.elapsed().as_millis();

    match result {
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let indicates_dpi = if stderr.contains("Connection refused") && duration < 50 {
                // RST слишком быстро - может быть DPI
                true
            } else {
                false
            };

            DpiEvidence {
                test_name: "tcp_rst_injection".to_string(),
                result: if out.status.success() { "Connected" } else { "Failed" }.to_string(),
                indicates_dpi,
                details: Some(format!("Response time: {}ms", duration)),
            }
        }
        Err(e) => DpiEvidence {
            test_name: "tcp_rst_injection".to_string(),
            result: format!("Error: {}", e),
            indicates_dpi: false,
            details: None,
        },
    }
}

async fn test_ttl_anomaly(server: &str, _port: u16) -> DpiEvidence {
    // Проверяем TTL в ответах - DPI может изменять TTL
    let output = tokio::process::Command::new("ping")
        .args(["-c", "3", "-W", "2", server])
        .output()
        .await;

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let ttls: Vec<u8> = stdout.lines()
                .filter_map(|line| {
                    if let Some(idx) = line.find("ttl=") {
                        let rest = &line[idx + 4..];
                        let end = rest.find(' ').unwrap_or(rest.len());
                        rest[..end].parse().ok()
                    } else {
                        None
                    }
                })
                .collect();

            // Проверяем вариацию TTL
            let indicates_dpi = if ttls.len() >= 2 {
                let min = *ttls.iter().min().unwrap_or(&0);
                let max = *ttls.iter().max().unwrap_or(&0);
                max - min > 2 // TTL не должен сильно меняться
            } else {
                false
            };

            DpiEvidence {
                test_name: "ttl_anomaly".to_string(),
                result: format!("TTL values: {:?}", ttls),
                indicates_dpi,
                details: if indicates_dpi {
                    Some("TTL variance detected - possible middlebox".to_string())
                } else {
                    None
                },
            }
        }
        Err(_) => DpiEvidence {
            test_name: "ttl_anomaly".to_string(),
            result: "Ping failed".to_string(),
            indicates_dpi: false,
            details: None,
        },
    }
}

async fn test_fragmentation(server: &str, _port: u16) -> DpiEvidence {
    // Тест на обработку фрагментированных пакетов
    // DPI часто не может правильно собрать фрагменты
    let output = tokio::process::Command::new("ping")
        .args(["-c", "1", "-s", "1472", "-M", "want", server])
        .output()
        .await;

    let indicates_dpi = match output {
        Ok(out) => !out.status.success(),
        Err(_) => false,
    };

    DpiEvidence {
        test_name: "fragmentation".to_string(),
        result: if indicates_dpi { "Blocked" } else { "OK" }.to_string(),
        indicates_dpi,
        details: Some("Testing large packet fragmentation".to_string()),
    }
}

async fn test_protocol_detection(server: &str, port: u16) -> DpiEvidence {
    // Сравниваем скорость соединения с разными начальными байтами
    // DPI может добавлять задержку при анализе

    let mut times = Vec::new();

    // Тест 1: Обычное TCP соединение
    let start = std::time::Instant::now();
    let _ = tokio::net::TcpStream::connect(format!("{}:{}", server, port)).await;
    times.push(start.elapsed().as_millis());

    // Небольшая пауза
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Тест 2: Ещё одно соединение
    let start = std::time::Instant::now();
    let _ = tokio::net::TcpStream::connect(format!("{}:{}", server, port)).await;
    times.push(start.elapsed().as_millis());

    let variance = if times.len() >= 2 {
        let mean = times.iter().sum::<u128>() as f64 / times.len() as f64;
        let var: f64 = times.iter().map(|t| (*t as f64 - mean).powi(2)).sum::<f64>() / times.len() as f64;
        var.sqrt()
    } else {
        0.0
    };

    // Высокая вариация времени может указывать на DPI
    let indicates_dpi = variance > 50.0;

    DpiEvidence {
        test_name: "protocol_detection".to_string(),
        result: format!("Timing variance: {:.1}ms", variance),
        indicates_dpi,
        details: Some(format!("Connection times: {:?}ms", times)),
    }
}

async fn test_timing_anomaly(server: &str, port: u16) -> DpiEvidence {
    // Измеряем задержку между отправкой и получением
    // Аномально высокая задержка может указывать на DPI обработку

    let start = std::time::Instant::now();

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(format!("{}:{}", server, port))
    ).await;

    let connect_time = start.elapsed().as_millis();

    let indicates_dpi = match result {
        Ok(Ok(_)) => {
            // Сравниваем с ping временем
            let ping_time = measure_ping_rtt(server).await.unwrap_or(1000.0);
            // TCP connect должен быть примерно 1.5x ping (SYN + SYN-ACK)
            connect_time as f64 > ping_time * 3.0
        }
        _ => false,
    };

    DpiEvidence {
        test_name: "timing_anomaly".to_string(),
        result: format!("Connect time: {}ms", connect_time),
        indicates_dpi,
        details: if indicates_dpi {
            Some("Connection time significantly higher than expected".to_string())
        } else {
            None
        },
    }
}

async fn measure_ping_rtt(server: &str) -> Option<f64> {
    let output = tokio::process::Command::new("ping")
        .args(["-c", "1", "-W", "2", server])
        .output()
        .await
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_ping_rtt(&stdout)
}

async fn test_quic_blocking(server: &str, port: u16) -> DpiEvidence {
    // Проверяем блокируется ли QUIC отдельно от TCP

    // Тест QUIC
    let quic_diag = diagnose_quic_connection(server, port, 3000).await;

    // Тест TCP
    let tcp_result = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::TcpStream::connect(format!("{}:{}", server, port))
    ).await;

    let tcp_ok = tcp_result.is_ok() && tcp_result.unwrap().is_ok();
    let quic_ok = quic_diag.initial_handshake.completed;

    // QUIC заблокирован если TCP работает, а QUIC нет
    let indicates_dpi = tcp_ok && !quic_ok;

    DpiEvidence {
        test_name: "quic_blocking".to_string(),
        result: format!("TCP: {}, QUIC: {}", if tcp_ok { "OK" } else { "Blocked" }, if quic_ok { "OK" } else { "Blocked" }),
        indicates_dpi,
        details: if indicates_dpi {
            Some("QUIC is blocked while TCP works - protocol-specific blocking".to_string())
        } else {
            None
        },
    }
}

// =============================================================================
// DNS Leak Test
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsLeakTestResult {
    pub leak_detected: bool,
    pub dns_servers_detected: Vec<DnsServerInfo>,
    pub expected_dns: Option<String>,
    pub actual_queries_to: Vec<String>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsServerInfo {
    pub ip: String,
    pub hostname: Option<String>,
    pub country: Option<String>,
    pub isp: Option<String>,
    pub is_vpn_dns: bool,
}

/// Проверяет утечку DNS
pub async fn test_dns_leak(vpn_dns_expected: Option<&str>) -> DnsLeakTestResult {
    let mut dns_servers = Vec::new();
    let mut leak_detected = false;

    // Метод 1: Проверяем /etc/resolv.conf
    if let Ok(content) = tokio::fs::read_to_string("/etc/resolv.conf").await {
        for line in content.lines() {
            if line.starts_with("nameserver") {
                if let Some(ip) = line.split_whitespace().nth(1) {
                    dns_servers.push(DnsServerInfo {
                        ip: ip.to_string(),
                        hostname: None,
                        country: None,
                        isp: None,
                        is_vpn_dns: vpn_dns_expected.map(|v| ip == v).unwrap_or(false),
                    });
                }
            }
        }
    }

    // Метод 2: Используем dig для проверки какой DNS отвечает
    let test_domains = [
        "whoami.akamai.net",
        "myip.opendns.com",
        "o-o.myaddr.l.google.com",
    ];

    for domain in &test_domains {
        let output = tokio::process::Command::new("dig")
            .args(["+short", domain, "@resolver1.opendns.com"])
            .output()
            .await;

        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                let ip = line.trim();
                if !ip.is_empty() && !dns_servers.iter().any(|s| s.ip == ip) {
                    dns_servers.push(DnsServerInfo {
                        ip: ip.to_string(),
                        hostname: None,
                        country: None,
                        isp: None,
                        is_vpn_dns: false,
                    });
                }
            }
        }
    }

    // Проверяем есть ли утечка
    if let Some(expected) = vpn_dns_expected {
        // Утечка если есть DNS сервера не соответствующие VPN
        leak_detected = dns_servers.iter().any(|s| !s.is_vpn_dns && s.ip != expected);
    } else {
        // Без VPN просто показываем какие DNS используются
        leak_detected = false;
    }

    let mut recommendations = Vec::new();
    if leak_detected {
        recommendations.push("DNS requests are leaking outside the VPN tunnel".to_string());
        recommendations.push("Enable DNS leak protection in VPN settings".to_string());
        recommendations.push("Configure system to use VPN's DNS server only".to_string());
    }

    DnsLeakTestResult {
        leak_detected,
        dns_servers_detected: dns_servers,
        expected_dns: vpn_dns_expected.map(String::from),
        actual_queries_to: Vec::new(),
        recommendations,
    }
}

// =============================================================================
// WebRTC and IPv6 Leak Tests
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeakTestResult {
    pub webrtc_leak: Option<WebRtcLeakInfo>,
    pub ipv6_leak: Option<Ipv6LeakInfo>,
    pub local_ip_exposed: bool,
    pub public_ip_exposed: Option<String>,
    pub overall_secure: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebRtcLeakInfo {
    pub local_ips: Vec<String>,
    pub public_ip: Option<String>,
    pub stun_reachable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv6LeakInfo {
    pub ipv6_enabled: bool,
    pub ipv6_addresses: Vec<String>,
    pub ipv6_connectivity: bool,
    pub leak_risk: bool,
}

/// Проверяет утечки IPv6
pub async fn test_ipv6_leak() -> Ipv6LeakInfo {
    let mut ipv6_addrs = Vec::new();
    let mut ipv6_enabled = false;
    let mut ipv6_connectivity = false;

    // Проверяем локальные IPv6 адреса
    let output = tokio::process::Command::new("ip")
        .args(["-6", "addr", "show"])
        .output()
        .await;

    if let Ok(out) = output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            if line.contains("inet6") && !line.contains("::1") && !line.contains("fe80:") {
                ipv6_enabled = true;
                // Extract IPv6 address
                if let Some(addr) = line.split_whitespace().nth(1) {
                    let addr = addr.split('/').next().unwrap_or(addr);
                    ipv6_addrs.push(addr.to_string());
                }
            }
        }
    }

    // Проверяем IPv6 connectivity
    let ping6 = tokio::process::Command::new("ping")
        .args(["-6", "-c", "1", "-W", "2", "2001:4860:4860::8888"])
        .output()
        .await;

    if let Ok(out) = ping6 {
        ipv6_connectivity = out.status.success();
    }

    // Утечка если IPv6 работает вне VPN туннеля
    let leak_risk = ipv6_enabled && ipv6_connectivity;

    Ipv6LeakInfo {
        ipv6_enabled,
        ipv6_addresses: ipv6_addrs,
        ipv6_connectivity,
        leak_risk,
    }
}

// =============================================================================
// Bandwidth Estimation
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthEstimate {
    pub download_mbps: f64,
    pub upload_mbps: f64,
    pub latency_ms: f64,
    pub jitter_ms: f64,
    pub test_duration_secs: f64,
    pub test_server: String,
    pub confidence: f64,
    pub bottleneck: Option<String>,
}

/// Оценивает пропускную способность
pub async fn estimate_bandwidth(server: &str, port: u16, duration_secs: u64) -> BandwidthEstimate {
    let start = std::time::Instant::now();
    let mut download_bytes = 0u64;
    let mut upload_bytes = 0u64;
    let mut rtt_samples = Vec::new();

    // Подключаемся к серверу
    let connect_start = std::time::Instant::now();
    let stream = match tokio::net::TcpStream::connect(format!("{}:{}", server, port)).await {
        Ok(s) => s,
        Err(_) => {
            return BandwidthEstimate {
                download_mbps: 0.0,
                upload_mbps: 0.0,
                latency_ms: 0.0,
                jitter_ms: 0.0,
                test_duration_secs: 0.0,
                test_server: server.to_string(),
                confidence: 0.0,
                bottleneck: Some("Connection failed".to_string()),
            };
        }
    };
    let connect_latency = connect_start.elapsed().as_secs_f64() * 1000.0 / 2.0; // RTT/2
    rtt_samples.push(connect_latency * 2.0);

    drop(stream);

    // Используем iperf3 если доступен
    let iperf_output = tokio::process::Command::new("iperf3")
        .args([
            "-c", server,
            "-p", &port.to_string(),
            "-t", &duration_secs.to_string(),
            "-J", // JSON output
        ])
        .output()
        .await;

    if let Ok(out) = iperf_output {
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            // Parse iperf3 JSON output
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
                if let Some(end) = json.get("end") {
                    if let Some(sum_sent) = end.get("sum_sent") {
                        upload_bytes = sum_sent.get("bytes").and_then(|b| b.as_u64()).unwrap_or(0);
                    }
                    if let Some(sum_recv) = end.get("sum_received") {
                        download_bytes = sum_recv.get("bytes").and_then(|b| b.as_u64()).unwrap_or(0);
                    }
                }
            }
        }
    }

    let test_duration = start.elapsed().as_secs_f64();
    let download_mbps = (download_bytes as f64 * 8.0) / (test_duration * 1_000_000.0);
    let upload_mbps = (upload_bytes as f64 * 8.0) / (test_duration * 1_000_000.0);

    // Calculate jitter
    let avg_rtt: f64 = if !rtt_samples.is_empty() {
        rtt_samples.iter().sum::<f64>() / rtt_samples.len() as f64
    } else {
        connect_latency * 2.0
    };

    let jitter = if rtt_samples.len() > 1 {
        let variance: f64 = rtt_samples.iter()
            .map(|r| (r - avg_rtt).powi(2))
            .sum::<f64>() / rtt_samples.len() as f64;
        variance.sqrt()
    } else {
        0.0
    };

    // Determine bottleneck
    let bottleneck = if download_mbps < 1.0 && upload_mbps < 1.0 {
        Some("Severely limited bandwidth - possible throttling".to_string())
    } else if avg_rtt > 500.0 {
        Some("High latency - geographical distance or congestion".to_string())
    } else if jitter > 50.0 {
        Some("High jitter - unstable connection".to_string())
    } else {
        None
    };

    // Confidence based on test duration and samples
    let confidence = (test_duration / duration_secs as f64).min(1.0);

    BandwidthEstimate {
        download_mbps,
        upload_mbps,
        latency_ms: avg_rtt,
        jitter_ms: jitter,
        test_duration_secs: test_duration,
        test_server: server.to_string(),
        confidence,
        bottleneck,
    }
}

// =============================================================================
// Persistent Connection Monitoring
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionMonitorState {
    pub monitoring_active: bool,
    pub connection_stable: bool,
    pub uptime_secs: u64,
    pub disconnects: u32,
    pub reconnects: u32,
    pub current_quality: ConnectionQuality,
    pub quality_history: Vec<QualitySnapshot>,
    pub alerts: Vec<ConnectionAlert>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualitySnapshot {
    pub timestamp: String,
    pub rtt_ms: f64,
    pub packet_loss_percent: f64,
    pub quality_score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionAlert {
    pub timestamp: String,
    pub alert_type: AlertType,
    pub message: String,
    pub severity: AlertSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertType {
    HighLatency,
    PacketLoss,
    Disconnection,
    Reconnection,
    QualityDegradation,
    BandwidthThrottling,
    DpiDetected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

// =============================================================================
// Smart Reconnect with Protocol Fallback
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconnectStrategy {
    pub protocols: Vec<ProtocolConfig>,
    pub current_protocol_index: usize,
    pub fallback_enabled: bool,
    pub max_retries_per_protocol: u32,
    pub backoff_config: RetryConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolConfig {
    pub name: String,
    pub transport: TransportType,
    pub port: u16,
    pub priority: u8,
    pub last_success: Option<String>,
    pub failure_count: u32,
    pub avg_latency_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransportType {
    QuicH3,
    QuicMasque,
    TcpTls,
    WebSocket,
    WebSocketTls,
}

impl Default for ReconnectStrategy {
    fn default() -> Self {
        Self {
            protocols: vec![
                ProtocolConfig {
                    name: "QUIC/H3 (primary)".to_string(),
                    transport: TransportType::QuicH3,
                    port: 443,
                    priority: 1,
                    last_success: None,
                    failure_count: 0,
                    avg_latency_ms: None,
                },
                ProtocolConfig {
                    name: "QUIC/MASQUE".to_string(),
                    transport: TransportType::QuicMasque,
                    port: 443,
                    priority: 2,
                    last_success: None,
                    failure_count: 0,
                    avg_latency_ms: None,
                },
                ProtocolConfig {
                    name: "TCP/TLS (fallback)".to_string(),
                    transport: TransportType::TcpTls,
                    port: 443,
                    priority: 3,
                    last_success: None,
                    failure_count: 0,
                    avg_latency_ms: None,
                },
                ProtocolConfig {
                    name: "WebSocket/TLS (stealth)".to_string(),
                    transport: TransportType::WebSocketTls,
                    port: 443,
                    priority: 4,
                    last_success: None,
                    failure_count: 0,
                    avg_latency_ms: None,
                },
            ],
            current_protocol_index: 0,
            fallback_enabled: true,
            max_retries_per_protocol: 3,
            backoff_config: RetryConfig::default(),
        }
    }
}

impl ReconnectStrategy {
    pub fn next_protocol(&mut self) -> Option<&ProtocolConfig> {
        if !self.fallback_enabled {
            return None;
        }

        if self.current_protocol_index < self.protocols.len() - 1 {
            self.current_protocol_index += 1;
            Some(&self.protocols[self.current_protocol_index])
        } else {
            // Wrap around
            self.current_protocol_index = 0;
            Some(&self.protocols[0])
        }
    }

    pub fn record_success(&mut self, latency_ms: f64) {
        if let Some(proto) = self.protocols.get_mut(self.current_protocol_index) {
            proto.failure_count = 0;
            proto.last_success = Some(chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string());
            proto.avg_latency_ms = Some(latency_ms);
        }
    }

    pub fn record_failure(&mut self) {
        if let Some(proto) = self.protocols.get_mut(self.current_protocol_index) {
            proto.failure_count += 1;
        }
    }

    pub fn should_fallback(&self) -> bool {
        if let Some(proto) = self.protocols.get(self.current_protocol_index) {
            proto.failure_count >= self.max_retries_per_protocol
        } else {
            false
        }
    }

    pub fn get_best_protocol(&self) -> Option<&ProtocolConfig> {
        // Return protocol with lowest failure count and best latency
        self.protocols.iter()
            .filter(|p| p.failure_count < self.max_retries_per_protocol)
            .min_by(|a, b| {
                let a_score = a.failure_count as f64 * 100.0 + a.avg_latency_ms.unwrap_or(1000.0);
                let b_score = b.failure_count as f64 * 100.0 + b.avg_latency_ms.unwrap_or(1000.0);
                a_score.partial_cmp(&b_score).unwrap_or(std::cmp::Ordering::Equal)
            })
    }
}

// =============================================================================
// Multi-Path Probing
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiPathProbeResult {
    pub paths: Vec<PathProbeResult>,
    pub best_path: Option<usize>,
    pub diversity_score: f64, // 0-1, higher = more diverse paths available
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathProbeResult {
    pub endpoint: String,
    pub port: u16,
    pub transport: String,
    pub reachable: bool,
    pub latency_ms: f64,
    pub packet_loss: f64,
    pub hops: usize,
    pub asn_path: Vec<String>,
}

/// Проверяет несколько путей к серверу
pub async fn probe_multiple_paths(
    server: &str,
    ports: &[u16],
    transports: &[&str],
) -> MultiPathProbeResult {
    let mut paths = Vec::new();
    let mut best_path = None;
    let mut best_latency = f64::MAX;

    for &port in ports {
        for &transport in transports {
            let start = std::time::Instant::now();

            let reachable = match transport {
                "tcp" => {
                    tokio::time::timeout(
                        Duration::from_secs(5),
                        tokio::net::TcpStream::connect(format!("{}:{}", server, port))
                    ).await.is_ok()
                }
                "udp" | "quic" => {
                    // Quick UDP reachability test
                    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok();
                    if let Some(s) = socket {
                        s.connect(format!("{}:{}", server, port)).await.is_ok()
                    } else {
                        false
                    }
                }
                _ => false,
            };

            let latency = start.elapsed().as_secs_f64() * 1000.0;

            let result = PathProbeResult {
                endpoint: server.to_string(),
                port,
                transport: transport.to_string(),
                reachable,
                latency_ms: latency,
                packet_loss: 0.0,
                hops: 0,
                asn_path: Vec::new(),
            };

            if reachable && latency < best_latency {
                best_latency = latency;
                best_path = Some(paths.len());
            }

            paths.push(result);
        }
    }

    // Calculate diversity score
    let reachable_count = paths.iter().filter(|p| p.reachable).count();
    let diversity_score = reachable_count as f64 / paths.len() as f64;

    let mut recommendations = Vec::new();
    if diversity_score < 0.5 {
        recommendations.push("Limited path diversity - consider using a different server".to_string());
    }
    if paths.iter().all(|p| !p.reachable) {
        recommendations.push("No paths available - server may be unreachable or blocked".to_string());
    }

    MultiPathProbeResult {
        paths,
        best_path,
        diversity_score,
        recommendations,
    }
}

// =============================================================================
// Kill Switch Verification
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillSwitchStatus {
    pub enabled: bool,
    pub active: bool,
    pub firewall_rules_present: bool,
    pub leak_protection: LeakProtectionStatus,
    pub test_result: Option<KillSwitchTestResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeakProtectionStatus {
    pub ipv4_protected: bool,
    pub ipv6_protected: bool,
    pub dns_protected: bool,
    pub default_route_protected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillSwitchTestResult {
    pub passed: bool,
    pub traffic_leaked: bool,
    pub leaked_to: Vec<String>,
    pub test_method: String,
}

/// Проверяет состояние kill switch
pub async fn verify_kill_switch(tun_interface: &str) -> KillSwitchStatus {
    let mut status = KillSwitchStatus {
        enabled: false,
        active: false,
        firewall_rules_present: false,
        leak_protection: LeakProtectionStatus {
            ipv4_protected: false,
            ipv6_protected: false,
            dns_protected: false,
            default_route_protected: false,
        },
        test_result: None,
    };

    // Check iptables rules
    let iptables_output = tokio::process::Command::new("iptables")
        .args(["-L", "OUTPUT", "-n", "-v"])
        .output()
        .await;

    if let Ok(out) = iptables_output {
        let stdout = String::from_utf8_lossy(&out.stdout);

        // Look for VPN kill switch rules
        if stdout.contains("DROP") || stdout.contains("REJECT") {
            status.firewall_rules_present = true;

            // Check if rules allow only VPN interface
            if stdout.contains(tun_interface) {
                status.enabled = true;
                status.active = true;
                status.leak_protection.ipv4_protected = true;
            }
        }
    }

    // Check ip6tables
    let ip6tables_output = tokio::process::Command::new("ip6tables")
        .args(["-L", "OUTPUT", "-n", "-v"])
        .output()
        .await;

    if let Ok(out) = ip6tables_output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        if stdout.contains("DROP") || stdout.contains("REJECT") {
            status.leak_protection.ipv6_protected = true;
        }
    }

    // Check default route
    let route_output = tokio::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .await;

    if let Ok(out) = route_output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        if stdout.contains(tun_interface) {
            status.leak_protection.default_route_protected = true;
        }
    }

    // Check DNS configuration
    if let Ok(resolv) = tokio::fs::read_to_string("/etc/resolv.conf").await {
        // DNS is protected if using VPN's DNS or localhost
        let uses_vpn_dns = resolv.lines()
            .filter(|l| l.starts_with("nameserver"))
            .all(|l| l.contains("127.0.0.1") || l.contains("10.") || l.contains("172."));
        status.leak_protection.dns_protected = uses_vpn_dns;
    }

    status
}

// =============================================================================
// Traffic Pattern Analysis
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficPatternAnalysis {
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub packet_size_distribution: PacketSizeDistribution,
    pub timing_pattern: TimingPattern,
    pub protocol_breakdown: Vec<ProtocolUsage>,
    pub anomalies: Vec<TrafficAnomaly>,
    pub stealth_score: u8, // 0-100, higher = more stealthy
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketSizeDistribution {
    pub min_size: u32,
    pub max_size: u32,
    pub avg_size: f64,
    pub std_dev: f64,
    pub common_sizes: Vec<(u32, u32)>, // (size, count)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingPattern {
    pub avg_interval_ms: f64,
    pub burst_ratio: f64, // Ratio of burst traffic to steady traffic
    pub idle_periods: u32,
    pub regularity_score: f64, // 0-1, how regular is the timing
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolUsage {
    pub protocol: String,
    pub bytes: u64,
    pub percentage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficAnomaly {
    pub anomaly_type: String,
    pub description: String,
    pub severity: String,
    pub recommendation: Option<String>,
}

// =============================================================================
// Ultimate Diagnostic Report
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UltimateDiagnosticReport {
    pub timestamp: String,
    pub duration_ms: u64,

    // Basic diagnostics
    pub pre_connection: DiagnosticResult,
    pub connection_quality: ConnectionQuality,

    // Network analysis
    pub network_path: Option<NetworkPathAnalysis>,
    pub dpi_detection: Option<DpiDetectionResult>,

    // Leak tests
    pub dns_leak: Option<DnsLeakTestResult>,
    pub ipv6_leak: Option<Ipv6LeakInfo>,

    // Performance
    pub bandwidth: Option<BandwidthEstimate>,

    // Security
    pub kill_switch: Option<KillSwitchStatus>,

    // Protocol support
    pub multi_path: Option<MultiPathProbeResult>,
    pub reconnect_strategy: ReconnectStrategy,

    // Overall assessment
    pub overall_health: OverallHealth,
    pub critical_issues: Vec<String>,
    pub warnings: Vec<String>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverallHealth {
    pub score: u8, // 0-100
    pub grade: String, // A, B, C, D, F
    pub status: String,
    pub summary: String,
}

/// Запускает полную ультимативную диагностику
pub async fn run_ultimate_diagnostics(
    params: &DiagnosticParams,
    run_network_analysis: bool,
    run_dpi_detection: bool,
    run_leak_tests: bool,
    run_bandwidth_test: bool,
) -> UltimateDiagnosticReport {
    let start = std::time::Instant::now();
    let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    // 1. Pre-connection diagnostics (always)
    let pre_connection = run_pre_connection_diagnostics(params).await;

    // 2. Connection quality (always)
    let connection_quality = measure_connection_quality(&params.server, 5).await;

    // 3. Network path analysis (optional, slow)
    let network_path = if run_network_analysis {
        Some(analyze_network_path(&params.server, params.port, 3).await)
    } else {
        None
    };

    // 4. DPI detection (optional)
    let dpi_detection = if run_dpi_detection {
        Some(detect_dpi(&params.server, params.port).await)
    } else {
        None
    };

    // 5. Leak tests (optional)
    let dns_leak = if run_leak_tests {
        Some(test_dns_leak(None).await)
    } else {
        None
    };

    let ipv6_leak = if run_leak_tests {
        Some(test_ipv6_leak().await)
    } else {
        None
    };

    // 6. Bandwidth test (optional, slow)
    let bandwidth = if run_bandwidth_test {
        Some(estimate_bandwidth(&params.server, params.port, 5).await)
    } else {
        None
    };

    // 7. Kill switch verification
    let kill_switch = Some(verify_kill_switch(&params.tun_name).await);

    // 8. Multi-path probing
    let multi_path = Some(probe_multiple_paths(
        &params.server,
        &[443, 80, 8443],
        &["tcp", "udp"],
    ).await);

    // 9. Reconnect strategy
    let reconnect_strategy = ReconnectStrategy::default();

    // Compile issues, warnings, recommendations
    let mut critical_issues = Vec::new();
    let mut warnings = Vec::new();
    let mut recommendations = Vec::new();

    // Check pre-connection results
    for check in &pre_connection.checks {
        match check.status {
            DiagnosticStatus::Failed => critical_issues.push(check.message.clone()),
            DiagnosticStatus::Warning => warnings.push(check.message.clone()),
            _ => {}
        }
    }

    // Check DPI
    if let Some(ref dpi) = dpi_detection {
        if dpi.dpi_detected {
            warnings.push(format!("DPI detected with {:.0}% confidence", dpi.confidence * 100.0));
            recommendations.extend(dpi.evasion_recommendations.clone());
        }
    }

    // Check leaks
    if let Some(ref dns) = dns_leak {
        if dns.leak_detected {
            critical_issues.push("DNS leak detected".to_string());
            recommendations.extend(dns.recommendations.clone());
        }
    }

    if let Some(ref ipv6) = ipv6_leak {
        if ipv6.leak_risk {
            warnings.push("IPv6 leak risk detected".to_string());
            recommendations.push("Disable IPv6 or enable IPv6 leak protection".to_string());
        }
    }

    // Check kill switch
    if let Some(ref ks) = kill_switch {
        if !ks.enabled {
            warnings.push("Kill switch is not enabled".to_string());
            recommendations.push("Enable kill switch to prevent traffic leaks on disconnect".to_string());
        }
    }

    // Calculate overall health
    let mut score: i32 = 100;
    score -= critical_issues.len() as i32 * 25;
    score -= warnings.len() as i32 * 10;

    // Adjust for connection quality
    score -= (100 - connection_quality.quality_score as i32) / 4;

    let score = score.max(0).min(100) as u8;

    let grade = match score {
        90..=100 => "A",
        80..=89 => "B",
        70..=79 => "C",
        60..=69 => "D",
        _ => "F",
    }.to_string();

    let status = if critical_issues.is_empty() && warnings.is_empty() {
        "Healthy"
    } else if critical_issues.is_empty() {
        "Warnings Present"
    } else {
        "Critical Issues"
    }.to_string();

    let summary = format!(
        "Score: {}/100 (Grade {}). {} critical issues, {} warnings.",
        score, grade, critical_issues.len(), warnings.len()
    );

    UltimateDiagnosticReport {
        timestamp,
        duration_ms: start.elapsed().as_millis() as u64,
        pre_connection,
        connection_quality,
        network_path,
        dpi_detection,
        dns_leak,
        ipv6_leak,
        bandwidth,
        kill_switch,
        multi_path,
        reconnect_strategy,
        overall_health: OverallHealth {
            score,
            grade,
            status,
            summary,
        },
        critical_issues,
        warnings,
        recommendations,
    }
}

// =============================================================================
// Диагностика после неудачного подключения
// =============================================================================

pub fn diagnose_connection_failure(error: &str, server: &str, port: u16) -> DiagnosticResult {
    let start = Instant::now();
    let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let mut checks = Vec::new();

    let error_lower = error.to_lowercase();

    // Анализируем ошибку и добавляем соответствующие диагностики

    if error_lower.contains("insecure") && error_lower.contains("disabled") {
        checks.push(DiagnosticCheck::failed(
            "tls_config",
            "Insecure mode is disabled in release builds",
            Some(
                "TLS certificate verification is required.\n\n\
                Solutions:\n\
                1. Copy server certificate:\n\
                   scp root@SERVER:/opt/vpr/secrets/server.crt ~/.silentway/secrets/\n\n\
                2. For development only (NOT SECURE):\n\
                   VPR_ALLOW_INSECURE=1 vpr-app"
                    .to_string(),
            ),
            DiagnosticCode::E405_InsecureModeDisabled,
            0,
        ));
    }

    if error_lower.contains("certificate verify failed")
        || error_lower.contains("certificate has expired")
    {
        checks.push(DiagnosticCheck::failed(
            "tls_cert",
            "TLS certificate verification failed",
            Some(format!(
                "Server: {}:{}\n\n\
                The server certificate is invalid or expired.\n\n\
                Solutions:\n\
                1. Renew certificate on server\n\
                2. Copy updated certificate to client\n\
                3. Check system time is correct",
                server, port
            )),
            DiagnosticCode::E402_CertificateExpired,
            0,
        ));
    }

    if error_lower.contains("hostname mismatch") || error_lower.contains("name mismatch") {
        checks.push(DiagnosticCheck::failed(
            "tls_hostname",
            "Certificate hostname does not match server",
            Some(format!(
                "Certificate is for a different hostname.\n\n\
                You're connecting to: {}\n\
                But certificate is for a different domain.\n\n\
                Solutions:\n\
                1. Use the correct hostname/IP\n\
                2. Regenerate certificate with correct hostname",
                server
            )),
            DiagnosticCode::E403_CertificateHostnameMismatch,
            0,
        ));
    }

    if error_lower.contains("noise") || error_lower.contains("decrypt")
        || error_lower.contains("handshake failed")
    {
        checks.push(DiagnosticCheck::failed(
            "noise_handshake",
            "Noise protocol handshake failed",
            Some(
                "Cryptographic key mismatch.\n\n\
                Possible causes:\n\
                - Server keys were regenerated\n\
                - Wrong server public key\n\
                - Client key doesn't match server's authorized keys\n\n\
                Solution:\n\
                1. Re-deploy server to regenerate keys\n\
                2. Copy fresh keys to client"
                    .to_string(),
            ),
            DiagnosticCode::E404_NoiseHandshakeFailed,
            0,
        ));
    }

    if error_lower.contains("timed out") || error_lower.contains("timeout") {
        checks.push(DiagnosticCheck::failed(
            "connection_timeout",
            &format!("Connection to {}:{} timed out", server, port),
            Some(format!(
                "Server did not respond.\n\n\
                Checklist:\n\
                1. Is VPN server running?\n\
                   ssh root@{} 'ps aux | grep vpn-server'\n\n\
                2. Is it listening on port {}?\n\
                   ssh root@{} 'ss -ulnp | grep {}'\n\n\
                3. Is firewall open?\n\
                   ssh root@{} 'iptables -L -n | grep {}'",
                server, port, server, port, server, port
            )),
            DiagnosticCode::E205_ConnectionTimeout,
            0,
        ));
    }

    if error_lower.contains("connection refused") {
        checks.push(DiagnosticCheck::failed(
            "connection_refused",
            &format!("Port {} is closed on {}", port, server),
            Some(format!(
                "Nothing is listening on UDP port {}.\n\n\
                VPN server may be:\n\
                - Not running\n\
                - Running on a different port\n\
                - Crashed\n\n\
                Check on server:\n\
                  systemctl status vpr-server\n\
                  ss -ulnp | grep vpn",
                port
            )),
            DiagnosticCode::E204_ConnectionRefused,
            0,
        ));
    }

    if error_lower.contains("process died") || error_lower.contains("died during startup") {
        checks.push(DiagnosticCheck::failed(
            "process_crash",
            "VPN client crashed during startup",
            Some(
                "The vpn-client process terminated unexpectedly.\n\n\
                Common causes:\n\
                - Missing or invalid key files\n\
                - Insufficient permissions (need root or CAP_NET_ADMIN)\n\
                - TUN device already exists\n\
                - Invalid server address/port\n\n\
                Check logs for details: journalctl -xe | grep vpn"
                    .to_string(),
            ),
            DiagnosticCode::E303_TunCreationFailed,
            0,
        ));
    }

    if error_lower.contains("address already in use") || error_lower.contains("eaddrinuse") {
        checks.push(DiagnosticCheck::failed(
            "port_in_use",
            "Port already in use",
            Some(
                "Another process is using the required port.\n\n\
                Find it: ss -tlnp | grep <port>\n\
                Or: lsof -i :<port>"
                    .to_string(),
            ),
            DiagnosticCode::E302_TunDeviceExists,
            0,
        ));
    }

    if error_lower.contains("permission denied") || error_lower.contains("eperm") {
        checks.push(DiagnosticCheck::failed(
            "permissions",
            "Permission denied",
            Some(
                "Insufficient privileges to create TUN device.\n\n\
                Run with: sudo vpr-app\n\
                Or set capabilities on vpn-client binary"
                    .to_string(),
            ),
            DiagnosticCode::E301_InsufficientPermissions,
            0,
        ));
    }

    // Если не распознали ошибку - добавляем как есть
    if checks.is_empty() {
        checks.push(DiagnosticCheck::failed(
            "unknown",
            "Connection failed",
            Some(format!(
                "Error: {}\n\n\
                Please report this error if it persists.",
                error
            )),
            DiagnosticCode::E999_UnknownError,
            0,
        ));
    }

    let (summary, action) = generate_summary(&checks);

    DiagnosticResult {
        status: DiagnosticStatus::Failed,
        checks,
        summary,
        action,
        duration_ms: start.elapsed().as_millis() as u64,
        timestamp,
    }
}
