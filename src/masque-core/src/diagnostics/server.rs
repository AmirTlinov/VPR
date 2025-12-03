//! Server-side VPN diagnostics

use super::{
    DiagnosticConfig, DiagnosticReport, DiagnosticResult, Fix, HealthStatus, Protocol, Severity,
    Side,
};
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
            Some(Fix::ManualInstruction {
                instruction: "vpr-keygen server".to_string(),
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
            check_name: "TLS Certificate Valid".to_string(),
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

    // Parse certificate and check expiry
    match check_certificate_expiry(&server_crt) {
        Ok(expiry_info) => Ok(expiry_info),
        Err(e) => Ok(DiagnosticResult {
            check_name: "TLS Certificate Valid".to_string(),
            passed: false,
            severity: Severity::Warning,
            message: format!("Failed to parse certificate: {}", e),
            fix: Some(Fix::RegenerateCertificate {
                cn: "vpn-server".to_string(),
                san: vec!["DNS:vpn.example.com".to_string()],
            }),
            auto_fixable: true,
        }),
    }
}

/// Check certificate expiry using x509-parser
fn check_certificate_expiry(cert_path: &PathBuf) -> Result<DiagnosticResult> {
    use x509_parser::prelude::*;

    let cert_pem = std::fs::read_to_string(cert_path)
        .context("Failed to read certificate file")?;

    let (_, pem) = parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to parse PEM: {:?}", e))?;

    let (_, cert) = parse_x509_certificate(&pem.contents)
        .map_err(|e| anyhow::anyhow!("Failed to parse X509: {:?}", e))?;

    let validity = cert.validity();
    let not_after = validity.not_after.timestamp();
    let not_before = validity.not_before.timestamp();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    // Check if certificate is not yet valid
    if now < not_before {
        return Ok(DiagnosticResult {
            check_name: "TLS Certificate Valid".to_string(),
            passed: false,
            severity: Severity::Critical,
            message: "Certificate is not yet valid (notBefore is in the future)".to_string(),
            fix: Some(Fix::RegenerateCertificate {
                cn: "vpn-server".to_string(),
                san: vec!["DNS:vpn.example.com".to_string()],
            }),
            auto_fixable: true,
        });
    }

    // Check if certificate has expired
    if now > not_after {
        return Ok(DiagnosticResult {
            check_name: "TLS Certificate Valid".to_string(),
            passed: false,
            severity: Severity::Critical,
            message: "Certificate has EXPIRED! Regenerate immediately.".to_string(),
            fix: Some(Fix::RegenerateCertificate {
                cn: "vpn-server".to_string(),
                san: vec!["DNS:vpn.example.com".to_string()],
            }),
            auto_fixable: true,
        });
    }

    // Calculate days until expiry
    let seconds_until_expiry = not_after - now;
    let days_until_expiry = seconds_until_expiry / 86400;

    // Warning thresholds
    const CRITICAL_DAYS: i64 = 7;
    const WARNING_DAYS: i64 = 30;

    if days_until_expiry <= CRITICAL_DAYS {
        return Ok(DiagnosticResult {
            check_name: "TLS Certificate Valid".to_string(),
            passed: false,
            severity: Severity::Critical,
            message: format!(
                "Certificate expires in {} days! Regenerate urgently.",
                days_until_expiry
            ),
            fix: Some(Fix::RegenerateCertificate {
                cn: "vpn-server".to_string(),
                san: vec!["DNS:vpn.example.com".to_string()],
            }),
            auto_fixable: true,
        });
    }

    if days_until_expiry <= WARNING_DAYS {
        return Ok(DiagnosticResult {
            check_name: "TLS Certificate Valid".to_string(),
            passed: true,
            severity: Severity::Warning,
            message: format!(
                "Certificate expires in {} days. Consider regenerating soon.",
                days_until_expiry
            ),
            fix: Some(Fix::RegenerateCertificate {
                cn: "vpn-server".to_string(),
                san: vec!["DNS:vpn.example.com".to_string()],
            }),
            auto_fixable: true,
        });
    }

    // Certificate is valid and not expiring soon
    Ok(DiagnosticResult {
        check_name: "TLS Certificate Valid".to_string(),
        passed: true,
        severity: Severity::Info,
        message: format!(
            "Certificate valid for {} more days",
            days_until_expiry
        ),
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
                format!(
                    "Server is NOT listening on UDP port {} (QUIC endpoint not started?)",
                    port
                )
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
                format!(
                    "Server is NOT listening on TCP port {} (optional fallback)",
                    port
                )
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
            let allows_udp =
                rules.contains(&port_str) && rules.contains("udp") && rules.contains("accept");

            return Ok(DiagnosticResult {
                check_name: "Firewall Allows VPN Port".to_string(),
                passed: allows_udp,
                severity: Severity::Error,
                message: if allows_udp {
                    format!("Firewall allows UDP port {}", port)
                } else {
                    format!(
                        "Firewall may be blocking UDP port {} (no explicit allow rule found)",
                        port
                    )
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
        let ufw_output = std::process::Command::new("ufw").arg("status").output();

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
                Some(Fix::ManualInstruction {
                    instruction: "sysctl -w net.ipv4.ip_forward=1".to_string(),
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
                    Some(Fix::ManualInstruction {
                        instruction: "nft add rule ip nat postrouting oifname eth0 masquerade"
                            .to_string(),
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
            fix: Some(Fix::ManualInstruction {
                instruction: "mkdir -p secrets".to_string(),
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
            Some(Fix::ManualInstruction {
                instruction: "echo 'Clients need to upload their public keys via SCP'".to_string(),
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
        let has_tun = stdout
            .lines()
            .any(|line| line.contains("vpr") || line.contains("tun"));

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
    #[cfg(target_os = "linux")]
    {
        let mut issues = Vec::new();
        let mut stats = Vec::new();

        // Check memory from /proc/meminfo
        if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
            let mut mem_total: u64 = 0;
            let mut mem_available: u64 = 0;

            for line in meminfo.lines() {
                if line.starts_with("MemTotal:") {
                    mem_total = parse_proc_kb(line);
                } else if line.starts_with("MemAvailable:") {
                    mem_available = parse_proc_kb(line);
                }
            }

            if mem_total > 0 {
                let mem_used_pct = 100 - (mem_available * 100 / mem_total);
                stats.push(format!("RAM: {}% used ({}/{} MB)",
                    mem_used_pct,
                    (mem_total - mem_available) / 1024,
                    mem_total / 1024
                ));

                if mem_used_pct > 90 {
                    issues.push("Memory usage critical (>90%)");
                } else if mem_used_pct > 80 {
                    issues.push("Memory usage high (>80%)");
                }
            }
        }

        // Check CPU load from /proc/loadavg
        if let Ok(loadavg) = std::fs::read_to_string("/proc/loadavg") {
            let parts: Vec<&str> = loadavg.split_whitespace().collect();
            if let Some(load1) = parts.first() {
                if let Ok(load) = load1.parse::<f64>() {
                    // Get CPU count
                    let cpus = std::thread::available_parallelism()
                        .map(|p| p.get())
                        .unwrap_or(1);
                    let load_per_cpu = load / cpus as f64;

                    stats.push(format!("Load: {:.2} ({} CPUs)", load, cpus));

                    if load_per_cpu > 2.0 {
                        issues.push("CPU load very high");
                    } else if load_per_cpu > 1.0 {
                        issues.push("CPU load elevated");
                    }
                }
            }
        }

        // Check disk space using df output
        if let Ok(output) = std::process::Command::new("df")
            .args(["-h", "/"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 {
                    let usage_str = parts[4].trim_end_matches('%');
                    if let Ok(usage) = usage_str.parse::<u32>() {
                        stats.push(format!("Disk: {}% used", usage));
                        if usage > 95 {
                            issues.push("Disk space critical (>95%)");
                        } else if usage > 85 {
                            issues.push("Disk space low (>85%)");
                        }
                    }
                }
            }
        }

        let passed = issues.is_empty();
        let severity = if issues.iter().any(|i| i.contains("critical")) {
            Severity::Critical
        } else if issues.iter().any(|i| i.contains("high") || i.contains("low")) {
            Severity::Warning
        } else {
            Severity::Info
        };

        let message = if passed {
            format!("System OK: {}", stats.join(", "))
        } else {
            format!("{} | {}", issues.join("; "), stats.join(", "))
        };

        Ok(DiagnosticResult {
            check_name: "System Resources".to_string(),
            passed,
            severity,
            message,
            fix: if !passed {
                Some(Fix::ManualInstruction {
                    instruction: "Check system resources and consider scaling".to_string(),
                    description: "Review memory/CPU/disk usage".to_string(),
                })
            } else {
                None
            },
            auto_fixable: false,
        })
    }

    #[cfg(not(target_os = "linux"))]
    Ok(DiagnosticResult {
        check_name: "System Resources".to_string(),
        passed: true,
        severity: Severity::Info,
        message: "System resources check not implemented for this platform".to_string(),
        fix: None,
        auto_fixable: false,
    })
}

/// Parse KB value from /proc/meminfo line like "MemTotal:       16384000 kB"
#[cfg(target_os = "linux")]
fn parse_proc_kb(line: &str) -> u64 {
    line.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn check_ip_pool_availability() -> Result<DiagnosticResult> {
    // Check VPN IP pool by examining active connections on TUN interface
    #[cfg(target_os = "linux")]
    {
        // Default pool: 10.9.0.2 - 10.9.0.254 = 253 addresses
        const POOL_SIZE: u32 = 253;

        // Count active VPN clients by checking ARP/neighbors on vpr interface
        let active_clients = count_active_vpn_clients();

        let available = POOL_SIZE.saturating_sub(active_clients);
        let usage_pct = (active_clients * 100) / POOL_SIZE;

        let (passed, severity) = if usage_pct >= 95 {
            (false, Severity::Critical)
        } else if usage_pct >= 80 {
            (true, Severity::Warning)
        } else {
            (true, Severity::Info)
        };

        Ok(DiagnosticResult {
            check_name: "IP Pool Availability".to_string(),
            passed,
            severity,
            message: format!(
                "{} active clients, {} IPs available ({}% pool used)",
                active_clients, available, usage_pct
            ),
            fix: if !passed {
                Some(Fix::ManualInstruction {
                    instruction: "Expand IP pool or add another server".to_string(),
                    description: "IP pool nearly exhausted".to_string(),
                })
            } else {
                None
            },
            auto_fixable: false,
        })
    }

    #[cfg(not(target_os = "linux"))]
    Ok(DiagnosticResult {
        check_name: "IP Pool Availability".to_string(),
        passed: true,
        severity: Severity::Info,
        message: "IP pool check not implemented for this platform".to_string(),
        fix: None,
        auto_fixable: false,
    })
}

/// Count active VPN clients by checking neighbors on vpr* interfaces
#[cfg(target_os = "linux")]
fn count_active_vpn_clients() -> u32 {
    // Try to count neighbors on vpr interface
    if let Ok(output) = std::process::Command::new("ip")
        .args(["neigh", "show", "dev", "vpr-srv"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        return stdout.lines()
            .filter(|line| line.contains("10.9.0.") && !line.contains("FAILED"))
            .count() as u32;
    }

    // Alternative: check /proc/net/arp for 10.9.0.* addresses
    if let Ok(arp) = std::fs::read_to_string("/proc/net/arp") {
        return arp.lines()
            .filter(|line| line.contains("10.9.0."))
            .count() as u32;
    }

    0
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
