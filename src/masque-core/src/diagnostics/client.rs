//! Client-side VPN diagnostics

use super::{DiagnosticConfig, DiagnosticReport, DiagnosticResult, Fix, HealthStatus, Protocol, Severity, Side};
use anyhow::{Context, Result};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

#[allow(clippy::disallowed_types)] // TcpStream is OK for diagnostics, not VPN traffic
use std::net::TcpStream;

/// Run all client-side diagnostic checks
pub async fn run_diagnostics(config: &DiagnosticConfig) -> Result<DiagnosticReport> {
    let mut results = Vec::new();

    // Check 1: Noise keys exist
    results.push(check_noise_keys_exist(config)?);

    // Check 2: CA certificate exists (if not insecure)
    results.push(check_ca_cert_exists(config)?);

    // Check 3: Server reachability (TCP/UDP)
    if let Some((server_ip, port)) = config.server_addr {
        results.push(check_server_tcp_reachable(server_ip, port));
        results.push(check_server_udp_port_open(server_ip, port));
    }

    // Check 4: DNS resolution
    results.push(check_dns_resolution());

    // Check 5: Kill switch conflicts
    if config.privileged {
        results.push(check_killswitch_conflicts()?);
    }

    // Check 6: Root/sudo privileges
    results.push(check_root_privileges());

    // Check 7: TUN device support
    if config.privileged {
        results.push(check_tun_support()?);
    }

    // Determine overall health
    let overall_status = determine_health(&results);

    Ok(DiagnosticReport {
        timestamp: std::time::SystemTime::now(),
        side: Side::Client,
        results,
        overall_status,
    })
}

fn check_noise_keys_exist(_config: &DiagnosticConfig) -> Result<DiagnosticResult> {
    // Assume noise_dir is 'secrets' by default
    let noise_dir = PathBuf::from("secrets");
    let client_key = noise_dir.join("client.noise.key");
    let client_pub = noise_dir.join("client.noise.pub");
    let server_pub = noise_dir.join("server.noise.pub");

    let all_exist = client_key.exists() && client_pub.exists() && server_pub.exists();

    Ok(DiagnosticResult {
        check_name: "Noise Keys Present".to_string(),
        passed: all_exist,
        severity: Severity::Critical,
        message: if all_exist {
            "All Noise protocol keys found".to_string()
        } else {
            format!(
                "Missing Noise keys: client.key={}, client.pub={}, server.pub={}",
                client_key.exists(),
                client_pub.exists(),
                server_pub.exists()
            )
        },
        fix: if !all_exist {
            Some(Fix::RunCommand {
                command: "vpn-client-keygen".to_string(),
                description: "Generate new Noise protocol keys".to_string(),
            })
        } else {
            None
        },
        auto_fixable: false, // Requires coordination with server
    })
}

fn check_ca_cert_exists(_config: &DiagnosticConfig) -> Result<DiagnosticResult> {
    let ca_cert = PathBuf::from("secrets/server.crt");
    let exists = ca_cert.exists();

    Ok(DiagnosticResult {
        check_name: "CA Certificate Present".to_string(),
        passed: exists,
        severity: Severity::Warning,
        message: if exists {
            "Server CA certificate found".to_string()
        } else {
            "Server CA certificate not found (will use --insecure or webpki roots)".to_string()
        },
        fix: if !exists {
            Some(Fix::RunCommand {
                command: "scp server:/path/to/server.crt secrets/".to_string(),
                description: "Download server certificate".to_string(),
            })
        } else {
            None
        },
        auto_fixable: false,
    })
}

#[allow(clippy::disallowed_types)] // TcpStream OK for diagnostics
fn check_server_tcp_reachable(server: IpAddr, port: u16) -> DiagnosticResult {
    let addr = format!("{}:{}", server, port);
    let reachable = TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(5)).is_ok();

    DiagnosticResult {
        check_name: "Server TCP Reachability".to_string(),
        passed: reachable,
        severity: Severity::Error,
        message: if reachable {
            format!("Server {}:{} is reachable via TCP", server, port)
        } else {
            format!("Server {}:{} is NOT reachable via TCP (firewall/routing issue?)", server, port)
        },
        fix: if !reachable {
            Some(Fix::RunCommand {
                command: format!("ssh server 'ufw allow {}/tcp'", port),
                description: format!("Open TCP port {} on server", port),
            })
        } else {
            None
        },
        auto_fixable: false, // Requires server access
    }
}

fn check_server_udp_port_open(server: IpAddr, port: u16) -> DiagnosticResult {
    // UDP check is tricky - we can't know if it's open without sending QUIC packets
    // This is a simplified check
    DiagnosticResult {
        check_name: "Server UDP Port Status".to_string(),
        passed: true, // Assume OK for now
        severity: Severity::Info,
        message: format!(
            "UDP port {}:{} check skipped (requires QUIC handshake to verify)",
            server, port
        ),
        fix: Some(Fix::OpenFirewallPort {
            port,
            protocol: Protocol::Udp,
        }),
        auto_fixable: false,
    }
}

fn check_dns_resolution() -> DiagnosticResult {
    // Try to resolve a known DNS name
    let test_host = "google.com";
    let resolved = std::net::ToSocketAddrs::to_socket_addrs(&format!("{}:443", test_host)).is_ok();

    DiagnosticResult {
        check_name: "DNS Resolution".to_string(),
        passed: resolved,
        severity: Severity::Warning,
        message: if resolved {
            "DNS resolution working".to_string()
        } else {
            format!("DNS resolution failed for {}", test_host)
        },
        fix: if !resolved {
            Some(Fix::FlushDns)
        } else {
            None
        },
        auto_fixable: true,
    }
}

fn check_killswitch_conflicts() -> Result<DiagnosticResult> {
    // Check if nftables/iptables has conflicting rules
    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new("nft")
            .arg("list")
            .arg("tables")
            .output()
            .context("Failed to run nft")?;

        let tables = String::from_utf8_lossy(&output.stdout);
        let has_vpr_table = tables.contains("vpr_killswitch");

        Ok(DiagnosticResult {
            check_name: "Kill Switch State".to_string(),
            passed: true,
            severity: Severity::Info,
            message: if has_vpr_table {
                "VPR kill switch table exists (may be active)".to_string()
            } else {
                "No VPR kill switch table found".to_string()
            },
            fix: None,
            auto_fixable: false,
        })
    }

    #[cfg(not(target_os = "linux"))]
    Ok(DiagnosticResult {
        check_name: "Kill Switch State".to_string(),
        passed: true,
        severity: Severity::Info,
        message: "Kill switch check not implemented for this platform".to_string(),
        fix: None,
        auto_fixable: false,
    })
}

fn check_root_privileges() -> DiagnosticResult {
    let is_root = unsafe { libc::geteuid() } == 0;

    DiagnosticResult {
        check_name: "Root Privileges".to_string(),
        passed: is_root,
        severity: Severity::Critical,
        message: if is_root {
            "Running with root privileges".to_string()
        } else {
            "NOT running as root (required for TUN/firewall operations)".to_string()
        },
        fix: if !is_root {
            Some(Fix::RunCommand {
                command: "sudo vpn-client ...".to_string(),
                description: "Re-run with sudo".to_string(),
            })
        } else {
            None
        },
        auto_fixable: false,
    }
}

fn check_tun_support() -> Result<DiagnosticResult> {
    // Check if /dev/net/tun exists
    #[cfg(target_os = "linux")]
    {
        let tun_dev = std::path::Path::new("/dev/net/tun");
        let exists = tun_dev.exists();

        Ok(DiagnosticResult {
            check_name: "TUN Device Support".to_string(),
            passed: exists,
            severity: Severity::Critical,
            message: if exists {
                "TUN device support available".to_string()
            } else {
                "/dev/net/tun not found (kernel module missing?)".to_string()
            },
            fix: if !exists {
                Some(Fix::RunCommand {
                    command: "modprobe tun".to_string(),
                    description: "Load TUN kernel module".to_string(),
                })
            } else {
                None
            },
            auto_fixable: true,
        })
    }

    #[cfg(not(target_os = "linux"))]
    Ok(DiagnosticResult {
        check_name: "TUN Device Support".to_string(),
        passed: true,
        severity: Severity::Info,
        message: "TUN support check not implemented for this platform".to_string(),
        fix: None,
        auto_fixable: false,
    })
}

fn determine_health(results: &[DiagnosticResult]) -> HealthStatus {
    let critical_failures = results
        .iter()
        .filter(|r| !r.passed && r.severity == Severity::Critical)
        .count();
    let error_failures = results
        .iter()
        .filter(|r| !r.passed && r.severity == Severity::Error)
        .count();
    let warning_failures = results
        .iter()
        .filter(|r| !r.passed && r.severity == Severity::Warning)
        .count();

    if critical_failures > 0 {
        HealthStatus::Critical
    } else if error_failures > 0 {
        HealthStatus::Unhealthy
    } else if warning_failures > 0 {
        HealthStatus::Degraded
    } else {
        HealthStatus::Healthy
    }
}
