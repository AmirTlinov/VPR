//! Server-side VPN diagnostics

use super::{DiagnosticConfig, DiagnosticReport, DiagnosticResult, Fix, HealthStatus, Protocol, Severity, Side};
use anyhow::{Context, Result};
use std::path::PathBuf;

/// Run all server-side diagnostic checks
pub async fn run_diagnostics(config: &DiagnosticConfig) -> Result<DiagnosticReport> {
    let mut results = Vec::new();

    // Check 1: Noise server keys exist
    results.push(check_noise_server_key_exists(config)?);

    // Check 2: TLS certificate valid
    results.push(check_tls_certificate_valid(config)?);

    // Check 3: UDP port listening
    if let Some((_, port)) = config.server_addr {
        results.push(check_udp_port_listening(port)?);
        results.push(check_tcp_port_listening(port)?);
        results.push(check_firewall_allows_vpn_port(port)?);
    }

    // Check 4: IP forwarding enabled
    if config.privileged {
        results.push(check_ip_forwarding_enabled()?);
        results.push(check_nat_masquerade_configured()?);
        results.push(check_tun_interface_exists()?);
    }

    // Check 5: Client keys in storage
    results.push(check_client_keys_in_storage()?);

    // Check 6: System resources
    results.push(check_system_resources()?);

    // Check 7: IP pool availability
    results.push(check_ip_pool_availability()?);

    // Determine overall health
    let overall_status = determine_health(&results);

    Ok(DiagnosticReport {
        timestamp: std::time::SystemTime::now(),
        side: Side::Server,
        results,
        overall_status,
    })
}

fn check_noise_server_key_exists(_config: &DiagnosticConfig) -> Result<DiagnosticResult> {
    // Assume noise_dir is 'secrets' by default
    let noise_dir = PathBuf::from("secrets");
    let server_key = noise_dir.join("server.noise.key");
    let server_pub = noise_dir.join("server.noise.pub");

    let all_exist = server_key.exists() && server_pub.exists();

    Ok(DiagnosticResult {
        check_name: "Noise Server Keys Present".to_string(),
        passed: all_exist,
        severity: Severity::Critical,
        message: if all_exist {
            "Server Noise protocol keys found".to_string()
        } else {
            format!(
                "Missing server Noise keys: server.key={}, server.pub={}",
                server_key.exists(),
                server_pub.exists()
            )
        },
        fix: if !all_exist {
            Some(Fix::RunCommand {
                command: "vpr-keygen server".to_string(),
                description: "Generate new server Noise protocol keys".to_string(),
            })
        } else {
            None
        },
        auto_fixable: true,
    })
}

fn check_tls_certificate_valid(_config: &DiagnosticConfig) -> Result<DiagnosticResult> {
    let server_crt = PathBuf::from("secrets/server.crt");
    let server_key = PathBuf::from("secrets/server.key");

    let cert_exists = server_crt.exists() && server_key.exists();

    if !cert_exists {
        return Ok(DiagnosticResult {
            check_name: "TLS Certificate Present".to_string(),
            passed: false,
            severity: Severity::Critical,
            message: format!(
                "TLS certificate missing: server.crt={}, server.key={}",
                server_crt.exists(),
                server_key.exists()
            ),
            fix: Some(Fix::RegenerateCertificate {
                cn: "vpn-server".to_string(),
                san: vec!["DNS:vpn.example.com".to_string()],
            }),
            auto_fixable: true,
        });
    }

    // TODO: Check certificate expiry using openssl or x509-parser crate
    // For now, just check existence

    Ok(DiagnosticResult {
        check_name: "TLS Certificate Present".to_string(),
        passed: true,
        severity: Severity::Critical,
        message: "TLS certificate found".to_string(),
        fix: None,
        auto_fixable: false,
    })
}

fn check_udp_port_listening(port: u16) -> Result<DiagnosticResult> {
    // Check if UDP port is listening using netstat or ss
    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new("ss")
            .args(["-ulpn"])
            .output()
            .context("Failed to run ss")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let port_str = format!(":{}", port);
        let listening = stdout.lines().any(|line| line.contains(&port_str));

        Ok(DiagnosticResult {
            check_name: "UDP Port Listening".to_string(),
            passed: listening,
            severity: Severity::Critical,
            message: if listening {
                format!("Server is listening on UDP port {}", port)
            } else {
                format!("Server is NOT listening on UDP port {} (QUIC endpoint not started?)", port)
            },
            fix: if !listening {
                Some(Fix::RestartVpnService)
            } else {
                None
            },
            auto_fixable: false,
        })
    }

    #[cfg(not(target_os = "linux"))]
    Ok(DiagnosticResult {
        check_name: "UDP Port Listening".to_string(),
        passed: true,
        severity: Severity::Info,
        message: "Port listening check not implemented for this platform".to_string(),
        fix: None,
        auto_fixable: false,
    })
}

fn check_tcp_port_listening(port: u16) -> Result<DiagnosticResult> {
    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new("ss")
            .args(["-tlpn"])
            .output()
            .context("Failed to run ss")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let port_str = format!(":{}", port);
        let listening = stdout.lines().any(|line| line.contains(&port_str));

        Ok(DiagnosticResult {
            check_name: "TCP Port Listening".to_string(),
            passed: listening,
            severity: Severity::Warning,
            message: if listening {
                format!("Server is listening on TCP port {}", port)
            } else {
                format!("Server is NOT listening on TCP port {} (optional fallback)", port)
            },
            fix: None,
            auto_fixable: false,
        })
    }

    #[cfg(not(target_os = "linux"))]
    Ok(DiagnosticResult {
        check_name: "TCP Port Listening".to_string(),
        passed: true,
        severity: Severity::Info,
        message: "Port listening check not implemented for this platform".to_string(),
        fix: None,
        auto_fixable: false,
    })
}

fn check_firewall_allows_vpn_port(port: u16) -> Result<DiagnosticResult> {
    #[cfg(target_os = "linux")]
    {
        // Check nftables/iptables for port rules
        let nft_output = std::process::Command::new("nft")
            .args(["list", "ruleset"])
            .output();

        if let Ok(output) = nft_output {
            let rules = String::from_utf8_lossy(&output.stdout);
            let port_str = format!("{}", port);
            let allows_udp = rules.contains(&port_str) && rules.contains("udp") && rules.contains("accept");

            return Ok(DiagnosticResult {
                check_name: "Firewall Allows VPN Port".to_string(),
                passed: allows_udp,
                severity: Severity::Error,
                message: if allows_udp {
                    format!("Firewall allows UDP port {}", port)
                } else {
                    format!("Firewall may be blocking UDP port {} (no explicit allow rule found)", port)
                },
                fix: if !allows_udp {
                    Some(Fix::OpenFirewallPort {
                        port,
                        protocol: Protocol::Udp,
                    })
                } else {
                    None
                },
                auto_fixable: true,
            });
        }

        // Fallback: check UFW if nft failed
        let ufw_output = std::process::Command::new("ufw")
            .arg("status")
            .output();

        if let Ok(output) = ufw_output {
            let status = String::from_utf8_lossy(&output.stdout);
            let port_str = format!("{}/udp", port);
            let allows = status.contains(&port_str) && status.contains("ALLOW");

            return Ok(DiagnosticResult {
                check_name: "Firewall Allows VPN Port".to_string(),
                passed: allows,
                severity: Severity::Error,
                message: if allows {
                    format!("UFW allows UDP port {}", port)
                } else {
                    format!("UFW may be blocking UDP port {}", port)
                },
                fix: if !allows {
                    Some(Fix::OpenFirewallPort {
                        port,
                        protocol: Protocol::Udp,
                    })
                } else {
                    None
                },
                auto_fixable: true,
            });
        }
    }

    Ok(DiagnosticResult {
        check_name: "Firewall Allows VPN Port".to_string(),
        passed: true,
        severity: Severity::Info,
        message: "Firewall check not available (no nftables/ufw found)".to_string(),
        fix: None,
        auto_fixable: false,
    })
}

fn check_ip_forwarding_enabled() -> Result<DiagnosticResult> {
    #[cfg(target_os = "linux")]
    {
        let ipv4_forward = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
            .context("Failed to read ip_forward")?;

        let enabled = ipv4_forward.trim() == "1";

        Ok(DiagnosticResult {
            check_name: "IP Forwarding Enabled".to_string(),
            passed: enabled,
            severity: Severity::Critical,
            message: if enabled {
                "IPv4 forwarding is enabled".to_string()
            } else {
                "IPv4 forwarding is DISABLED (VPN routing will not work)".to_string()
            },
            fix: if !enabled {
                Some(Fix::RunCommand {
                    command: "sysctl -w net.ipv4.ip_forward=1".to_string(),
                    description: "Enable IP forwarding".to_string(),
                })
            } else {
                None
            },
            auto_fixable: true,
        })
    }

    #[cfg(not(target_os = "linux"))]
    Ok(DiagnosticResult {
        check_name: "IP Forwarding Enabled".to_string(),
        passed: true,
        severity: Severity::Info,
        message: "IP forwarding check not implemented for this platform".to_string(),
        fix: None,
        auto_fixable: false,
    })
}

fn check_nat_masquerade_configured() -> Result<DiagnosticResult> {
    #[cfg(target_os = "linux")]
    {
        // Check for NAT masquerade rules in nftables
        let output = std::process::Command::new("nft")
            .args(["list", "ruleset"])
            .output();

        if let Ok(output) = output {
            let rules = String::from_utf8_lossy(&output.stdout);
            let has_masquerade = rules.contains("masquerade") || rules.contains("MASQUERADE");

            return Ok(DiagnosticResult {
                check_name: "NAT Masquerade Configured".to_string(),
                passed: has_masquerade,
                severity: Severity::Error,
                message: if has_masquerade {
                    "NAT masquerade is configured".to_string()
                } else {
                    "NAT masquerade NOT configured (VPN clients can't reach internet)".to_string()
                },
                fix: if !has_masquerade {
                    Some(Fix::RunCommand {
                        command: "nft add rule ip nat postrouting oifname eth0 masquerade".to_string(),
                        description: "Add NAT masquerade rule".to_string(),
                    })
                } else {
                    None
                },
                auto_fixable: false, // Too risky, may conflict with existing rules
            });
        }
    }

    Ok(DiagnosticResult {
        check_name: "NAT Masquerade Configured".to_string(),
        passed: true,
        severity: Severity::Info,
        message: "NAT masquerade check not available".to_string(),
        fix: None,
        auto_fixable: false,
    })
}

fn check_client_keys_in_storage() -> Result<DiagnosticResult> {
    // Check if any client public keys exist in secrets/
    let secrets_dir = PathBuf::from("secrets");

    if !secrets_dir.exists() {
        return Ok(DiagnosticResult {
            check_name: "Client Keys in Storage".to_string(),
            passed: false,
            severity: Severity::Warning,
            message: "Secrets directory does not exist".to_string(),
            fix: Some(Fix::RunCommand {
                command: "mkdir -p secrets".to_string(),
                description: "Create secrets directory".to_string(),
            }),
            auto_fixable: true,
        });
    }

    // Count client.noise.pub files (assumes clients upload their keys)
    let client_keys = std::fs::read_dir(&secrets_dir)
        .context("Failed to read secrets directory")?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .map(|name| name.starts_with("client") && name.ends_with(".noise.pub"))
                .unwrap_or(false)
        })
        .count();

    Ok(DiagnosticResult {
        check_name: "Client Keys in Storage".to_string(),
        passed: client_keys > 0,
        severity: Severity::Info,
        message: format!("Found {} client public key(s) in storage", client_keys),
        fix: if client_keys == 0 {
            Some(Fix::RunCommand {
                command: "echo 'Clients need to upload their public keys via SCP'".to_string(),
                description: "Waiting for client keys".to_string(),
            })
        } else {
            None
        },
        auto_fixable: false,
    })
}

fn check_tun_interface_exists() -> Result<DiagnosticResult> {
    #[cfg(target_os = "linux")]
    {
        // Check if any vpr* TUN interface exists
        let output = std::process::Command::new("ip")
            .args(["link", "show"])
            .output()
            .context("Failed to run ip link")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let has_tun = stdout.lines().any(|line| line.contains("vpr") || line.contains("tun"));

        Ok(DiagnosticResult {
            check_name: "TUN Interface Exists".to_string(),
            passed: has_tun,
            severity: Severity::Info,
            message: if has_tun {
                "VPN TUN interface is active".to_string()
            } else {
                "No VPN TUN interface found (server not handling clients yet)".to_string()
            },
            fix: None,
            auto_fixable: false,
        })
    }

    #[cfg(not(target_os = "linux"))]
    Ok(DiagnosticResult {
        check_name: "TUN Interface Exists".to_string(),
        passed: true,
        severity: Severity::Info,
        message: "TUN check not implemented for this platform".to_string(),
        fix: None,
        auto_fixable: false,
    })
}

fn check_system_resources() -> Result<DiagnosticResult> {
    // Basic resource check - just ensure system is responsive
    // TODO: Add actual CPU/memory/disk checks using sysinfo crate

    Ok(DiagnosticResult {
        check_name: "System Resources".to_string(),
        passed: true,
        severity: Severity::Info,
        message: "System resources check not implemented yet".to_string(),
        fix: None,
        auto_fixable: false,
    })
}

fn check_ip_pool_availability() -> Result<DiagnosticResult> {
    // Check if IP pool has available addresses
    // TODO: Integrate with actual IP pool manager

    Ok(DiagnosticResult {
        check_name: "IP Pool Availability".to_string(),
        passed: true,
        severity: Severity::Info,
        message: "IP pool check not implemented yet".to_string(),
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
