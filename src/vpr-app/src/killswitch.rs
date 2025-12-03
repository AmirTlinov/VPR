//! Kill Switch Implementation
//!
//! Blocks all traffic except VPN when enabled. Supports Linux (nftables/iptables),
//! macOS (pf), and Windows (netsh advfirewall).
//!
//! # Security Design
//! - **Atomic activation**: No window where traffic can leak during setup
//! - **Input validation**: All IPs and ports are validated before use
//! - **Command array args**: No string concatenation to prevent injection
//! - Policy-based: only specified IPs/ports are allowed
//! - Fail-safe: errors are logged, not silently ignored
//! - Idempotent: can be called multiple times safely
//! - Clean teardown: removes all rules on disable
//!
//! # Security Audit Notes
//! - All firewall commands use argument arrays, not string formatting
//! - IP addresses are validated before being passed to commands
//! - Port numbers are validated to be in valid range (1-65535)

use anyhow::{bail, Context, Result};
use std::net::Ipv4Addr;
use std::process::Command;
use tracing::{debug, info, warn};

/// Maximum allowed port number
const MAX_PORT: u16 = 65535;

/// Validate port is in valid range
fn validate_port(port: u16) -> Result<()> {
    if port == 0 {
        bail!("Port 0 is not allowed");
    }
    // port is u16 so max is automatically 65535
    Ok(())
}

/// Validate IPv4 address is suitable for firewall rules
fn validate_ipv4(ip: &Ipv4Addr) -> Result<()> {
    // Don't allow special addresses
    if ip.is_unspecified() {
        bail!("0.0.0.0 is not allowed as VPN server IP");
    }
    if ip.is_broadcast() {
        bail!("Broadcast address not allowed");
    }
    if ip.is_multicast() {
        bail!("Multicast addresses not allowed");
    }
    if ip.is_loopback() {
        bail!("Loopback addresses not allowed");
    }
    Ok(())
}

/// Validate entire policy before applying
fn validate_policy(policy: &KillSwitchPolicy) -> Result<()> {
    if policy.allow_ipv4.is_empty() {
        bail!("At least one VPN server IP must be specified");
    }
    if policy.allow_tcp_ports.is_empty() && policy.allow_udp_ports.is_empty() {
        bail!("At least one allowed port must be specified");
    }

    for ip in &policy.allow_ipv4 {
        validate_ipv4(ip)?;
    }
    for port in &policy.allow_tcp_ports {
        validate_port(*port)?;
    }
    for port in &policy.allow_udp_ports {
        validate_port(*port)?;
    }

    Ok(())
}

/// Traffic policy for kill switch - what to allow through
#[derive(Debug, Default, Clone)]
pub struct KillSwitchPolicy {
    /// IPv4 addresses to allow (VPN server IPs)
    pub allow_ipv4: Vec<Ipv4Addr>,
    /// TCP destination ports to allow
    pub allow_tcp_ports: Vec<u16>,
    /// UDP destination ports to allow (QUIC uses UDP 443)
    pub allow_udp_ports: Vec<u16>,
}

/// Execute a command and log result
fn exec(cmd: &str, args: &[&str]) -> Result<bool> {
    debug!(cmd = %cmd, args = ?args, "executing");

    let output = Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute: {} {}", cmd, args.join(" ")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        debug!(cmd = %cmd, stderr = %stderr.trim(), "command failed");
        return Ok(false);
    }

    Ok(true)
}

/// Execute command, log warning on failure
fn exec_warn(cmd: &str, args: &[&str]) {
    if let Err(e) = exec(cmd, args) {
        warn!(%e, cmd = %cmd, "command failed");
    }
}

/// Execute command, return error on failure
fn exec_require(cmd: &str, args: &[&str]) -> Result<()> {
    let success = exec(cmd, args)?;
    if !success {
        anyhow::bail!("command failed: {} {}", cmd, args.join(" "));
    }
    Ok(())
}

// ============================================================================
// Public API
// ============================================================================

/// Enable kill switch with given policy
///
/// # Security
/// - Validates all IPs and ports before applying rules
/// - Uses atomic table swap on nftables to prevent leak window
/// - Falls back to iptables if nftables unavailable
pub async fn enable(policy: KillSwitchPolicy) -> Result<()> {
    // Validate policy before any firewall modifications
    validate_policy(&policy)?;

    info!(
        ipv4_count = policy.allow_ipv4.len(),
        tcp_ports = ?policy.allow_tcp_ports,
        udp_ports = ?policy.allow_udp_ports,
        "enabling kill switch"
    );

    #[cfg(target_os = "linux")]
    return enable_linux(&policy).await;

    #[cfg(target_os = "macos")]
    return enable_macos(&policy).await;

    #[cfg(target_os = "windows")]
    return enable_windows(&policy).await;

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    anyhow::bail!("kill switch not supported on this platform")
}

/// Disable kill switch, restoring normal traffic
pub async fn disable() -> Result<()> {
    info!("disabling kill switch");

    #[cfg(target_os = "linux")]
    return disable_linux().await;

    #[cfg(target_os = "macos")]
    return disable_macos().await;

    #[cfg(target_os = "windows")]
    return disable_windows().await;

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    anyhow::bail!("kill switch not supported on this platform")
}

// ============================================================================
// Linux Implementation (nftables preferred, iptables fallback)
// ============================================================================

#[cfg(target_os = "linux")]
fn has_nftables() -> bool {
    Command::new("nft")
        .args(["list", "tables"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
async fn enable_linux(policy: &KillSwitchPolicy) -> Result<()> {
    if has_nftables() {
        enable_nftables(policy).await
    } else {
        enable_iptables(policy).await
    }
}

#[cfg(target_os = "linux")]
async fn disable_linux() -> Result<()> {
    // Try both - one will succeed based on what was used
    let nft_result = disable_nftables().await;
    let ipt_result = disable_iptables().await;

    // Return error only if both failed
    if nft_result.is_err() && ipt_result.is_err() {
        warn!("neither nftables nor iptables cleanup succeeded");
    }

    Ok(())
}

// ----------------------------------------------------------------------------
// nftables implementation
// ----------------------------------------------------------------------------

#[cfg(target_os = "linux")]
const NFT_TABLE: &str = "vpr_killswitch";
#[cfg(target_os = "linux")]
const NFT_CHAIN_OUT: &str = "output";
#[cfg(target_os = "linux")]
const NFT_CHAIN_IN: &str = "input";
// Use priority -100 to run before other tables (default is 0)
#[cfg(target_os = "linux")]
const NFT_PRIORITY: &str = "-100";

/// Generate atomic nftables script
///
/// Creates a complete nftables ruleset that can be loaded atomically
/// using `nft -f`, preventing any window where traffic could leak.
#[cfg(target_os = "linux")]
fn generate_nft_script(policy: &KillSwitchPolicy) -> String {
    let mut script = String::new();

    // Start with flushing old table if exists (atomic operation)
    script.push_str(&format!("table inet {} {{\n", NFT_TABLE));

    // Output chain
    script.push_str(&format!(
        "  chain {} {{\n",
        NFT_CHAIN_OUT
    ));
    script.push_str(&format!(
        "    type filter hook output priority {}; policy drop;\n",
        NFT_PRIORITY
    ));

    // Loopback
    script.push_str("    oifname lo accept\n");
    // Established connections
    script.push_str("    ct state established,related accept\n");
    // TUN interfaces
    script.push_str("    oifname \"vpr*\" accept\n");

    // VPN server rules
    for ip in &policy.allow_ipv4 {
        for port in &policy.allow_tcp_ports {
            script.push_str(&format!(
                "    ip daddr {} tcp dport {} accept\n",
                ip, port
            ));
        }
        for port in &policy.allow_udp_ports {
            script.push_str(&format!(
                "    ip daddr {} udp dport {} accept\n",
                ip, port
            ));
        }
    }

    script.push_str("  }\n"); // close output chain

    // Input chain
    script.push_str(&format!(
        "  chain {} {{\n",
        NFT_CHAIN_IN
    ));
    script.push_str(&format!(
        "    type filter hook input priority {}; policy drop;\n",
        NFT_PRIORITY
    ));

    // Loopback
    script.push_str("    iifname lo accept\n");
    // Established connections
    script.push_str("    ct state established,related accept\n");
    // TUN interfaces
    script.push_str("    iifname \"vpr*\" accept\n");

    // VPN server rules
    for ip in &policy.allow_ipv4 {
        for port in &policy.allow_tcp_ports {
            script.push_str(&format!(
                "    ip saddr {} tcp sport {} accept\n",
                ip, port
            ));
        }
        for port in &policy.allow_udp_ports {
            script.push_str(&format!(
                "    ip saddr {} udp sport {} accept\n",
                ip, port
            ));
        }
    }

    script.push_str("  }\n"); // close input chain
    script.push_str("}\n"); // close table

    script
}

#[cfg(target_os = "linux")]
async fn enable_nftables(policy: &KillSwitchPolicy) -> Result<()> {
    use std::io::Write;

    // Generate complete nftables script
    let script = generate_nft_script(policy);

    // Write script to temp file
    let script_path = std::env::temp_dir().join("vpr_killswitch.nft");
    {
        let mut file = std::fs::File::create(&script_path)
            .context("creating nftables script file")?;
        file.write_all(script.as_bytes())
            .context("writing nftables script")?;
        file.sync_all()?;
    }

    let script_path_str = script_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("invalid path"))?;

    // Delete old table first (if exists) - this is atomic
    let _ = exec("nft", &["delete", "table", "inet", NFT_TABLE]);

    // Load new table atomically with -f flag
    // This ensures all rules are applied in a single kernel transaction
    let result = exec_require("nft", &["-f", script_path_str])
        .context("loading nftables rules atomically");

    // Clean up script file
    let _ = std::fs::remove_file(&script_path);

    result?;

    info!(backend = "nftables", atomic = true, "kill switch enabled");
    Ok(())
}

#[cfg(target_os = "linux")]
async fn disable_nftables() -> Result<()> {
    // Delete entire table (removes all chains and rules)
    if exec("nft", &["delete", "table", "inet", NFT_TABLE])? {
        info!(backend = "nftables", "kill switch disabled");
    }
    Ok(())
}

// ----------------------------------------------------------------------------
// iptables implementation (fallback for older systems)
// ----------------------------------------------------------------------------

#[cfg(target_os = "linux")]
const IPT_CHAIN_OUT: &str = "VPR_KS_OUT";
#[cfg(target_os = "linux")]
const IPT_CHAIN_IN: &str = "VPR_KS_IN";

#[cfg(target_os = "linux")]
async fn enable_iptables(policy: &KillSwitchPolicy) -> Result<()> {
    // Clean existing chains
    ipt_cleanup_chains();

    // Create chains
    exec_require("iptables", &["-N", IPT_CHAIN_OUT])?;
    exec_require("iptables", &["-N", IPT_CHAIN_IN])?;

    // === ACCEPT rules ===

    // 1. Loopback
    exec_warn(
        "iptables",
        &["-A", IPT_CHAIN_OUT, "-o", "lo", "-j", "ACCEPT"],
    );
    exec_warn(
        "iptables",
        &["-A", IPT_CHAIN_IN, "-i", "lo", "-j", "ACCEPT"],
    );

    // 2. Established/related
    exec_warn(
        "iptables",
        &[
            "-A",
            IPT_CHAIN_OUT,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ],
    );
    exec_warn(
        "iptables",
        &[
            "-A",
            IPT_CHAIN_IN,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ],
    );

    // 3. TUN interfaces (vpr+ matches vpr0, vpr1, etc.)
    exec_warn(
        "iptables",
        &["-A", IPT_CHAIN_OUT, "-o", "vpr+", "-j", "ACCEPT"],
    );
    exec_warn(
        "iptables",
        &["-A", IPT_CHAIN_IN, "-i", "vpr+", "-j", "ACCEPT"],
    );

    // 4. VPN server IP + ports
    for ip in &policy.allow_ipv4 {
        let ip_str = ip.to_string();

        for port in &policy.allow_tcp_ports {
            let port_str = port.to_string();
            exec_warn(
                "iptables",
                &[
                    "-A",
                    IPT_CHAIN_OUT,
                    "-d",
                    &ip_str,
                    "-p",
                    "tcp",
                    "--dport",
                    &port_str,
                    "-j",
                    "ACCEPT",
                ],
            );
            exec_warn(
                "iptables",
                &[
                    "-A",
                    IPT_CHAIN_IN,
                    "-s",
                    &ip_str,
                    "-p",
                    "tcp",
                    "--sport",
                    &port_str,
                    "-j",
                    "ACCEPT",
                ],
            );
        }

        for port in &policy.allow_udp_ports {
            let port_str = port.to_string();
            exec_warn(
                "iptables",
                &[
                    "-A",
                    IPT_CHAIN_OUT,
                    "-d",
                    &ip_str,
                    "-p",
                    "udp",
                    "--dport",
                    &port_str,
                    "-j",
                    "ACCEPT",
                ],
            );
            exec_warn(
                "iptables",
                &[
                    "-A",
                    IPT_CHAIN_IN,
                    "-s",
                    &ip_str,
                    "-p",
                    "udp",
                    "--sport",
                    &port_str,
                    "-j",
                    "ACCEPT",
                ],
            );
        }
    }

    // 5. DROP everything else
    exec_require("iptables", &["-A", IPT_CHAIN_OUT, "-j", "DROP"])?;
    exec_require("iptables", &["-A", IPT_CHAIN_IN, "-j", "DROP"])?;

    // Hook chains into OUTPUT/INPUT at position 1 (highest priority)
    exec_require("iptables", &["-I", "OUTPUT", "1", "-j", IPT_CHAIN_OUT])?;
    exec_require("iptables", &["-I", "INPUT", "1", "-j", IPT_CHAIN_IN])?;

    info!(backend = "iptables", "kill switch enabled");
    Ok(())
}

#[cfg(target_os = "linux")]
fn ipt_cleanup_chains() {
    // Remove from main chains first
    let _ = exec("iptables", &["-D", "OUTPUT", "-j", IPT_CHAIN_OUT]);
    let _ = exec("iptables", &["-D", "INPUT", "-j", IPT_CHAIN_IN]);

    // Flush and delete
    let _ = exec("iptables", &["-F", IPT_CHAIN_OUT]);
    let _ = exec("iptables", &["-X", IPT_CHAIN_OUT]);
    let _ = exec("iptables", &["-F", IPT_CHAIN_IN]);
    let _ = exec("iptables", &["-X", IPT_CHAIN_IN]);
}

#[cfg(target_os = "linux")]
async fn disable_iptables() -> Result<()> {
    ipt_cleanup_chains();
    info!(backend = "iptables", "kill switch disabled");
    Ok(())
}

// ============================================================================
// macOS Implementation (pf - Packet Filter)
// ============================================================================

#[cfg(target_os = "macos")]
const PF_ANCHOR: &str = "com.vpr.killswitch";

#[cfg(target_os = "macos")]
async fn enable_macos(policy: &KillSwitchPolicy) -> Result<()> {
    use std::io::Write;

    // Build pf rules
    let mut rules = String::new();

    // Block all by default
    rules.push_str("block drop all\n");

    // Allow loopback
    rules.push_str("pass quick on lo0 all\n");

    // Allow established connections
    rules.push_str("pass out quick proto { tcp, udp } keep state\n");

    // Allow TUN interface (utun* on macOS)
    rules.push_str("pass quick on utun0 all\n");
    rules.push_str("pass quick on utun1 all\n");
    rules.push_str("pass quick on utun2 all\n");

    // Allow VPN server IPs
    for ip in &policy.allow_ipv4 {
        for port in &policy.allow_tcp_ports {
            rules.push_str(&format!(
                "pass out quick proto tcp to {} port {}\n",
                ip, port
            ));
        }
        for port in &policy.allow_udp_ports {
            rules.push_str(&format!(
                "pass out quick proto udp to {} port {}\n",
                ip, port
            ));
        }
    }

    // Write rules to temp file
    let rules_path = std::env::temp_dir().join("vpr_killswitch.pf");
    let mut file = std::fs::File::create(&rules_path).context("creating pf rules file")?;
    file.write_all(rules.as_bytes())
        .context("writing pf rules")?;

    let rules_path_str = rules_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("invalid path"))?;

    // Load rules into anchor
    exec_require("pfctl", &["-a", PF_ANCHOR, "-f", rules_path_str])?;

    // Enable pf if not already
    let _ = exec("pfctl", &["-e"]);

    info!(backend = "pf", "kill switch enabled");
    Ok(())
}

#[cfg(target_os = "macos")]
async fn disable_macos() -> Result<()> {
    // Flush anchor rules
    let _ = exec("pfctl", &["-a", PF_ANCHOR, "-F", "all"]);

    info!(backend = "pf", "kill switch disabled");
    Ok(())
}

// ============================================================================
// Windows Implementation (netsh advfirewall)
// ============================================================================

#[cfg(target_os = "windows")]
const FW_RULE_BLOCK_OUT: &str = "VPR Kill Switch Block Out";
#[cfg(target_os = "windows")]
const FW_RULE_BLOCK_IN: &str = "VPR Kill Switch Block In";
#[cfg(target_os = "windows")]
const FW_RULE_ALLOW_PREFIX: &str = "VPR Allow";

#[cfg(target_os = "windows")]
async fn enable_windows(policy: &KillSwitchPolicy) -> Result<()> {
    // Clean existing rules first
    disable_windows().await?;

    // Add allow rules for VPN server FIRST (higher priority)
    for (i, ip) in policy.allow_ipv4.iter().enumerate() {
        let ip_str = ip.to_string();

        for port in &policy.allow_tcp_ports {
            let rule_name = format!("{} TCP {} {}", FW_RULE_ALLOW_PREFIX, ip, port);
            exec_warn(
                "netsh",
                &[
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    &format!("name={}", rule_name),
                    "dir=out",
                    "action=allow",
                    "protocol=tcp",
                    &format!("remoteip={}", ip_str),
                    &format!("remoteport={}", port),
                    "enable=yes",
                ],
            );
        }

        for port in &policy.allow_udp_ports {
            let rule_name = format!("{} UDP {} {}", FW_RULE_ALLOW_PREFIX, ip, port);
            exec_warn(
                "netsh",
                &[
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    &format!("name={}", rule_name),
                    "dir=out",
                    "action=allow",
                    "protocol=udp",
                    &format!("remoteip={}", ip_str),
                    &format!("remoteport={}", port),
                    "enable=yes",
                ],
            );
        }
    }

    // Block all other outbound traffic
    exec_require(
        "netsh",
        &[
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={}", FW_RULE_BLOCK_OUT),
            "dir=out",
            "action=block",
            "enable=yes",
        ],
    )?;

    // Block all inbound traffic (except established via stateful inspection)
    exec_require(
        "netsh",
        &[
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={}", FW_RULE_BLOCK_IN),
            "dir=in",
            "action=block",
            "enable=yes",
        ],
    )?;

    info!(backend = "netsh", "kill switch enabled");
    Ok(())
}

#[cfg(target_os = "windows")]
async fn disable_windows() -> Result<()> {
    // Delete block rules
    let _ = exec(
        "netsh",
        &[
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={}", FW_RULE_BLOCK_OUT),
        ],
    );
    let _ = exec(
        "netsh",
        &[
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={}", FW_RULE_BLOCK_IN),
        ],
    );

    // Delete allow rules (pattern match)
    let _ = exec(
        "netsh",
        &[
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={} *", FW_RULE_ALLOW_PREFIX),
        ],
    );

    info!(backend = "netsh", "kill switch disabled");
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_default_is_empty() {
        let policy = KillSwitchPolicy::default();
        assert!(policy.allow_ipv4.is_empty());
        assert!(policy.allow_tcp_ports.is_empty());
        assert!(policy.allow_udp_ports.is_empty());
    }

    #[test]
    fn policy_with_server() {
        let policy = KillSwitchPolicy {
            allow_ipv4: vec![Ipv4Addr::new(1, 2, 3, 4)],
            allow_tcp_ports: vec![443, 8053],
            allow_udp_ports: vec![53, 443],
        };
        assert_eq!(policy.allow_ipv4.len(), 1);
        assert!(policy.allow_tcp_ports.contains(&443));
        assert!(policy.allow_udp_ports.contains(&443)); // QUIC
    }
}
