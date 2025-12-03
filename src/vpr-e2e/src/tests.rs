//! VPN connection tests

use crate::config::E2eConfig;
use crate::report::TestResult;
use std::process::Stdio;
use std::time::Instant;
use tokio::process::Command;

/// Test runner for VPN connection
pub struct TestRunner {
    config: E2eConfig,
    tun_name: String,
}

impl TestRunner {
    pub fn new(config: E2eConfig) -> Self {
        let tun_name = config.client.tun_name.clone();
        Self { config, tun_name }
    }

    /// Run all configured tests
    pub async fn run_all(&self) -> Vec<TestResult> {
        let mut results = Vec::new();

        if self.config.tests.ping {
            results.push(self.test_ping().await);
        }
        if self.config.tests.dns {
            results.push(self.test_dns().await);
        }
        if self.config.tests.external {
            results.push(self.test_external_connectivity().await);
        }
        if self.config.tests.latency {
            results.push(self.test_latency().await);
        }
        if self.config.tests.throughput {
            results.push(self.test_throughput().await);
        }

        results
    }

    /// Test ping to VPN gateway
    pub async fn test_ping(&self) -> TestResult {
        let start = Instant::now();
        let test_name = "ping_gateway";
        let gateway = "10.9.0.1";

        tracing::info!("Running ping test to {}", gateway);

        let result = Command::new("ping")
            .args([
                "-c",
                &self.config.tests.ping_count.to_string(),
                "-W",
                "5",
                "-I",
                &self.tun_name,
                gateway,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await;

        match result {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let (packets_sent, packets_recv, loss) = parse_ping_stats(&stdout);
                let rtt = parse_ping_rtt(&stdout);

                TestResult {
                    name: test_name.into(),
                    passed: packets_recv > 0,
                    duration_ms: start.elapsed().as_millis() as u64,
                    details: Some(format!(
                        "Sent: {}, Received: {}, Loss: {:.1}%, RTT: {:.1}ms",
                        packets_sent, packets_recv, loss, rtt
                    )),
                    metrics: Some(serde_json::json!({
                        "packets_sent": packets_sent,
                        "packets_received": packets_recv,
                        "packet_loss_percent": loss,
                        "rtt_avg_ms": rtt,
                    })),
                    error: None,
                }
            }
            Ok(output) => TestResult {
                name: test_name.into(),
                passed: false,
                duration_ms: start.elapsed().as_millis() as u64,
                details: None,
                metrics: None,
                error: Some(String::from_utf8_lossy(&output.stderr).to_string()),
            },
            Err(e) => TestResult {
                name: test_name.into(),
                passed: false,
                duration_ms: start.elapsed().as_millis() as u64,
                details: None,
                metrics: None,
                error: Some(e.to_string()),
            },
        }
    }

    /// Test DNS resolution through VPN tunnel
    pub async fn test_dns(&self) -> TestResult {
        let start = Instant::now();
        let test_name = "dns_resolution";

        tracing::info!("Running DNS test through VPN");

        // Use curl with DNS-over-HTTPS to ensure traffic goes through VPN interface
        // This is more reliable than dig which doesn't support interface binding well
        let result = Command::new("curl")
            .args([
                "-s",
                "--max-time",
                "10",
                "--interface",
                &self.tun_name,
                "https://dns.google/resolve?name=google.com&type=A",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await;

        match result {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                // Parse DoH JSON response
                let resolved = stdout.contains("\"Answer\"");
                let ip = extract_dns_ip(&stdout);

                TestResult {
                    name: test_name.into(),
                    passed: resolved,
                    duration_ms: start.elapsed().as_millis() as u64,
                    details: Some(format!(
                        "DNS via VPN: {} (resolved: {})",
                        ip.as_deref().unwrap_or("N/A"),
                        resolved
                    )),
                    metrics: Some(serde_json::json!({
                        "resolved": resolved,
                        "ip": ip,
                        "method": "DoH via VPN interface",
                    })),
                    error: if resolved {
                        None
                    } else {
                        Some("DNS resolution failed".into())
                    },
                }
            }
            Ok(output) => TestResult {
                name: test_name.into(),
                passed: false,
                duration_ms: start.elapsed().as_millis() as u64,
                details: None,
                metrics: None,
                error: Some(String::from_utf8_lossy(&output.stderr).to_string()),
            },
            Err(e) => TestResult {
                name: test_name.into(),
                passed: false,
                duration_ms: start.elapsed().as_millis() as u64,
                details: None,
                metrics: None,
                error: Some(e.to_string()),
            },
        }
    }

    /// Test external connectivity (get public IP)
    pub async fn test_external_connectivity(&self) -> TestResult {
        let start = Instant::now();
        let test_name = "external_connectivity";

        tracing::info!("Running external connectivity test");

        let result = Command::new("curl")
            .args([
                "-s",
                "--max-time",
                "10",
                "--interface",
                &self.tun_name,
                "https://ifconfig.me",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await;

        match result {
            Ok(output) if output.status.success() => {
                let external_ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let is_vpn_ip = external_ip == self.config.server.host;

                TestResult {
                    name: test_name.into(),
                    passed: !external_ip.is_empty(),
                    duration_ms: start.elapsed().as_millis() as u64,
                    details: Some(format!(
                        "External IP: {} (VPN: {})",
                        external_ip,
                        if is_vpn_ip { "yes" } else { "no" }
                    )),
                    metrics: Some(serde_json::json!({
                        "external_ip": external_ip,
                        "is_vpn_ip": is_vpn_ip,
                    })),
                    error: None,
                }
            }
            Ok(output) => TestResult {
                name: test_name.into(),
                passed: false,
                duration_ms: start.elapsed().as_millis() as u64,
                details: None,
                metrics: None,
                error: Some(String::from_utf8_lossy(&output.stderr).to_string()),
            },
            Err(e) => TestResult {
                name: test_name.into(),
                passed: false,
                duration_ms: start.elapsed().as_millis() as u64,
                details: None,
                metrics: None,
                error: Some(e.to_string()),
            },
        }
    }

    /// Test latency to multiple endpoints (parallel for speed)
    pub async fn test_latency(&self) -> TestResult {
        let start = Instant::now();
        let test_name = "latency";

        tracing::info!("Running parallel latency tests");

        // Ping multiple endpoints in parallel
        let endpoints = ["8.8.8.8", "1.1.1.1", "9.9.9.9"];
        let tun = self.tun_name.clone();

        // Spawn all pings concurrently
        let futures: Vec<_> = endpoints
            .iter()
            .map(|&endpoint| {
                let tun_name = tun.clone();
                async move {
                    let output = Command::new("ping")
                        .args(["-c", "3", "-W", "3", "-I", &tun_name, endpoint])
                        .stdout(Stdio::piped())
                        .output()
                        .await;

                    match output {
                        Ok(out) if out.status.success() => {
                            let stdout = String::from_utf8_lossy(&out.stdout);
                            let rtt = parse_ping_rtt(&stdout);
                            if rtt > 0.0 {
                                Some((endpoint, rtt))
                            } else {
                                None
                            }
                        }
                        _ => None,
                    }
                }
            })
            .collect();

        // Wait for all pings to complete
        let results = futures::future::join_all(futures).await;
        let latencies: Vec<(&&str, f64)> = results
            .iter()
            .filter_map(|r| r.as_ref().map(|(e, rtt)| (e, *rtt)))
            .collect();

        if latencies.is_empty() {
            return TestResult {
                name: test_name.into(),
                passed: false,
                duration_ms: start.elapsed().as_millis() as u64,
                details: None,
                metrics: None,
                error: Some("Could not measure latency to any endpoint".into()),
            };
        }

        let rtts: Vec<f64> = latencies.iter().map(|(_, rtt)| *rtt).collect();
        let avg_latency: f64 = rtts.iter().sum::<f64>() / rtts.len() as f64;
        let min_latency = rtts.iter().cloned().fold(f64::INFINITY, f64::min);
        let max_latency = rtts.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

        TestResult {
            name: test_name.into(),
            passed: true,
            duration_ms: start.elapsed().as_millis() as u64,
            details: Some(format!(
                "Latency: min={:.1}ms, avg={:.1}ms, max={:.1}ms ({} endpoints)",
                min_latency,
                avg_latency,
                max_latency,
                latencies.len()
            )),
            metrics: Some(serde_json::json!({
                "latency_min_ms": min_latency,
                "latency_avg_ms": avg_latency,
                "latency_max_ms": max_latency,
                "samples": latencies.len(),
                "endpoints": latencies.iter().map(|(e, rtt)| {
                    serde_json::json!({"host": e, "rtt_ms": rtt})
                }).collect::<Vec<_>>(),
            })),
            error: None,
        }
    }

    /// Test throughput with fallback URLs
    pub async fn test_throughput(&self) -> TestResult {
        let start = Instant::now();
        let test_name = "throughput";

        tracing::info!("Running throughput test");

        // Try multiple speedtest URLs (fallback if one is unavailable)
        let speedtest_urls = [
            "http://speedtest.tele2.net/1MB.zip",
            "http://proof.ovh.net/files/1Mb.dat",
            "http://ipv4.download.thinkbroadband.com/1MB.zip",
        ];

        for url in speedtest_urls {
            let result = Command::new("curl")
                .args([
                    "-s",
                    "-w",
                    "%{speed_download}",
                    "-o",
                    "/dev/null",
                    "--max-time",
                    "30",
                    "--interface",
                    &self.tun_name,
                    url,
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .await;

            if let Ok(output) = result {
                if output.status.success() {
                    let speed_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if let Ok(speed_bytes) = speed_str.parse::<f64>() {
                        if speed_bytes > 0.0 {
                            let speed_mbps = (speed_bytes * 8.0) / 1_000_000.0;

                            return TestResult {
                                name: test_name.into(),
                                passed: speed_mbps > 0.1,
                                duration_ms: start.elapsed().as_millis() as u64,
                                details: Some(format!("Download: {:.2} Mbps", speed_mbps)),
                                metrics: Some(serde_json::json!({
                                    "download_mbps": speed_mbps,
                                    "download_bytes_sec": speed_bytes,
                                    "source": url,
                                })),
                                error: None,
                            };
                        }
                    }
                }
            }
            tracing::debug!("Speedtest URL {} failed, trying next", url);
        }

        TestResult {
            name: test_name.into(),
            passed: false,
            duration_ms: start.elapsed().as_millis() as u64,
            details: None,
            metrics: None,
            error: Some("All speedtest URLs failed".into()),
        }
    }
}

/// Extract IP from DoH JSON response
fn extract_dns_ip(json: &str) -> Option<String> {
    // Simple extraction: look for "data":"<ip>"
    if let Some(start) = json.find("\"data\":\"") {
        let rest = &json[start + 8..];
        if let Some(end) = rest.find('"') {
            return Some(rest[..end].to_string());
        }
    }
    None
}

/// Parse ping statistics from output
fn parse_ping_stats(output: &str) -> (u32, u32, f64) {
    // Parse: "3 packets transmitted, 3 received, 0% packet loss"
    for line in output.lines() {
        if line.contains("packets transmitted") {
            let parts: Vec<&str> = line.split(',').collect();
            let sent = parts
                .first()
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let recv = parts
                .get(1)
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let loss = if sent > 0 {
                ((sent - recv) as f64 / sent as f64) * 100.0
            } else {
                100.0
            };
            return (sent, recv, loss);
        }
    }
    (0, 0, 100.0)
}

/// Parse RTT from ping output
fn parse_ping_rtt(output: &str) -> f64 {
    // Parse: "rtt min/avg/max/mdev = 70.976/119.118/148.413/34.307 ms"
    for line in output.lines() {
        if line.contains("rtt") || line.contains("round-trip") {
            if let Some(stats) = line.split('=').nth(1) {
                let parts: Vec<&str> = stats.trim().split('/').collect();
                if parts.len() >= 2 {
                    return parts[1].trim().parse().unwrap_or(0.0);
                }
            }
        }
    }
    0.0
}
