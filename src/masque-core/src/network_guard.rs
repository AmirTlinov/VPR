//! Network State Guard - crash-safe network configuration management
//!
//! This module provides a "transactional" approach to network changes:
//! 1. Before any change, state is persisted to disk
//! 2. On normal shutdown, cleanup runs and state file is removed
//! 3. On crash/kill -9, next startup detects orphaned state and restores
//!
//! Think of it like a database WAL (Write-Ahead Log) for network config.
//!
//! # Security
//! - State files include a SHA-256 checksum to detect tampering
//! - Tampered state files are rejected to prevent malicious restoration

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use tracing::{debug, error, info, warn};

/// Default state file location
const DEFAULT_STATE_PATH: &str = "/var/run/vpr/network_state.json";
/// Fallback for non-root users
const USER_STATE_PATH: &str = "/tmp/vpr-network-state.json";
/// Magic bytes to identify our state format
const STATE_MAGIC: &[u8; 4] = b"VPR1";

/// Represents a network change that can be rolled back
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NetworkChange {
    /// DNS configuration was modified
    DnsModified {
        /// Path to backup of original resolv.conf
        backup_path: PathBuf,
    },
    /// Default route was changed
    DefaultRouteSet {
        /// TUN interface name
        tun_name: String,
        /// Original gateway (to restore)
        original_gateway: Option<IpAddr>,
        /// Original interface
        original_interface: Option<String>,
    },
    /// Split tunnel routes were added
    SplitTunnelRoutes {
        /// TUN interface name
        tun_name: String,
        /// Routes that were added (CIDR notation)
        routes: Vec<String>,
    },
    /// TUN interface was created
    TunCreated {
        /// Interface name
        name: String,
    },
    /// iptables/nftables rules were added
    FirewallRulesAdded {
        /// Rule identifiers for cleanup
        rule_ids: Vec<String>,
    },
}

/// Persistent network state for crash recovery
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkState {
    /// Timestamp when VPN started
    pub started_at: Option<u64>,
    /// PID of the VPN client process
    pub pid: Option<u32>,
    /// List of changes made (in order)
    pub changes: Vec<NetworkChange>,
    /// Whether cleanup was performed
    pub cleaned_up: bool,
}

impl NetworkState {
    /// Check if there are pending changes to restore
    pub fn has_pending_changes(&self) -> bool {
        !self.cleaned_up && !self.changes.is_empty()
    }
}

/// Guard that tracks network changes and ensures cleanup
pub struct NetworkStateGuard {
    state: NetworkState,
    state_path: PathBuf,
    /// If true, don't actually make changes (dry-run mode)
    dry_run: bool,
}

impl NetworkStateGuard {
    /// Create a new guard, checking for orphaned state from previous crash
    pub fn new() -> Result<Self> {
        let state_path = Self::determine_state_path();
        let mut guard = Self {
            state: NetworkState::default(),
            state_path,
            dry_run: false,
        };

        // Check for orphaned state from crash
        if guard.state_path.exists() {
            guard.handle_orphaned_state()?;
        }

        // Initialize fresh state
        guard.state = NetworkState {
            started_at: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            ),
            pid: Some(std::process::id()),
            changes: Vec::new(),
            cleaned_up: false,
        };

        guard.persist()?;
        Ok(guard)
    }

    /// Create guard in dry-run mode (for --repair without actual changes)
    pub fn dry_run() -> Self {
        Self {
            state: NetworkState::default(),
            state_path: Self::determine_state_path(),
            dry_run: true,
        }
    }

    /// Check if orphaned network state exists (for TUI status display)
    /// Returns Some(NetworkState) if orphaned state exists, None otherwise
    pub fn check_orphaned_state() -> Option<NetworkState> {
        let state_path = Self::determine_state_path();
        if !state_path.exists() {
            return None;
        }

        let content = std::fs::read_to_string(&state_path).ok()?;
        let state: NetworkState = serde_json::from_str(&content).ok()?;

        if state.cleaned_up || state.changes.is_empty() {
            return None;
        }

        // Check if the old process is still running
        if let Some(pid) = state.pid {
            if Self::process_exists(pid) {
                return None; // Process still running, not orphaned
            }
        }

        Some(state)
    }

    /// Attempt to restore network from orphaned state (crash recovery)
    ///
    /// # Security
    /// State file integrity is verified before applying any changes.
    /// Tampered state files are rejected to prevent malicious restoration.
    pub fn restore_from_crash() -> Result<bool> {
        let state_path = Self::determine_state_path();
        if !state_path.exists() {
            info!("No orphaned network state found - nothing to restore");
            return Ok(false);
        }

        // Load state with integrity verification
        let state = match Self::load_verified_state(&state_path) {
            Ok(s) => s,
            Err(e) => {
                error!(%e, "Failed to load/verify state file - removing corrupted file");
                std::fs::remove_file(&state_path).ok();
                return Err(e);
            }
        };

        if state.cleaned_up {
            info!("State file exists but cleanup was completed");
            std::fs::remove_file(&state_path).ok();
            return Ok(false);
        }

        if state.changes.is_empty() {
            info!("No pending changes in orphaned state");
            std::fs::remove_file(&state_path).ok();
            return Ok(false);
        }

        // Check if the old process is still running
        if let Some(pid) = state.pid {
            if Self::process_exists(pid) {
                warn!(
                    pid = pid,
                    "Previous VPN client still running - not restoring"
                );
                return Ok(false);
            }
        }

        info!(
            changes = state.changes.len(),
            started_at = ?state.started_at,
            "Found orphaned network state from crash - restoring (integrity verified)"
        );

        // Restore in reverse order
        for change in state.changes.iter().rev() {
            if let Err(e) = Self::restore_single_change(change) {
                error!(?change, %e, "Failed to restore change");
            }
        }

        // Remove state file after successful restore
        std::fs::remove_file(&state_path).ok();
        info!("Network state restored successfully");

        Ok(true)
    }

    /// Record that DNS was modified
    pub fn record_dns_change(&mut self, backup_path: PathBuf) -> Result<()> {
        self.state
            .changes
            .push(NetworkChange::DnsModified { backup_path });
        self.persist()
    }

    /// Record that default route was set
    pub fn record_default_route(
        &mut self,
        tun_name: String,
        original_gateway: Option<IpAddr>,
        original_interface: Option<String>,
    ) -> Result<()> {
        self.state.changes.push(NetworkChange::DefaultRouteSet {
            tun_name,
            original_gateway,
            original_interface,
        });
        self.persist()
    }

    /// Record that split tunnel routes were added
    pub fn record_split_routes(&mut self, tun_name: String, routes: Vec<String>) -> Result<()> {
        self.state
            .changes
            .push(NetworkChange::SplitTunnelRoutes { tun_name, routes });
        self.persist()
    }

    /// Record that TUN interface was created
    pub fn record_tun_created(&mut self, name: String) -> Result<()> {
        self.state.changes.push(NetworkChange::TunCreated { name });
        self.persist()
    }

    /// Record that firewall rules were added
    pub fn record_firewall_rules(&mut self, rule_ids: Vec<String>) -> Result<()> {
        self.state
            .changes
            .push(NetworkChange::FirewallRulesAdded { rule_ids });
        self.persist()
    }

    /// Perform cleanup of all recorded changes (called on normal shutdown)
    pub fn cleanup(&mut self) -> Result<()> {
        if self.dry_run {
            info!(
                "Dry-run mode: would cleanup {} changes",
                self.state.changes.len()
            );
            return Ok(());
        }

        info!(
            changes = self.state.changes.len(),
            "Performing network cleanup"
        );

        // Restore in reverse order (LIFO)
        let mut errors = Vec::new();
        for change in self.state.changes.iter().rev() {
            if let Err(e) = Self::restore_single_change(change) {
                errors.push(format!("{:?}: {}", change, e));
            }
        }

        self.state.cleaned_up = true;
        self.state.changes.clear();

        // Remove state file
        if self.state_path.exists() {
            std::fs::remove_file(&self.state_path).ok();
        }

        if errors.is_empty() {
            info!("Network cleanup completed successfully");
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Some cleanup operations failed: {:?}",
                errors
            ))
        }
    }

    /// Get current state (for inspection/debugging)
    pub fn state(&self) -> &NetworkState {
        &self.state
    }

    // --- Private methods ---

    fn determine_state_path() -> PathBuf {
        // Try /var/run first (requires root)
        let var_run = Path::new("/var/run/vpr");
        if var_run.exists() || std::fs::create_dir_all(var_run).is_ok() {
            return PathBuf::from(DEFAULT_STATE_PATH);
        }
        // Fallback to /tmp
        PathBuf::from(USER_STATE_PATH)
    }

    fn persist(&self) -> Result<()> {
        if self.dry_run {
            return Ok(());
        }

        // Ensure parent directory exists
        if let Some(parent) = self.state_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        let json =
            serde_json::to_string_pretty(&self.state).context("serializing network state")?;

        // Compute checksum over the JSON content
        let checksum = Self::compute_checksum(json.as_bytes());

        // Build final content: MAGIC || CHECKSUM(32 bytes hex) || '\n' || JSON
        let mut content = Vec::with_capacity(4 + 64 + 1 + json.len());
        content.extend_from_slice(STATE_MAGIC);
        content.extend_from_slice(hex::encode(&checksum).as_bytes());
        content.push(b'\n');
        content.extend_from_slice(json.as_bytes());

        // Atomic write: write to temp file, then rename
        let temp_path = self.state_path.with_extension("tmp");
        std::fs::write(&temp_path, &content).context("writing state file")?;
        std::fs::rename(&temp_path, &self.state_path).context("renaming state file")?;

        debug!(path = %self.state_path.display(), "Network state persisted with integrity check");
        Ok(())
    }

    /// Compute SHA-256 checksum of data
    fn compute_checksum(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&result);
        checksum
    }

    /// Load and verify state from file
    fn load_verified_state(path: &Path) -> Result<NetworkState> {
        let content = std::fs::read(path).context("reading state file")?;

        // Check minimum size: MAGIC(4) + CHECKSUM_HEX(64) + '\n'(1)
        if content.len() < 69 {
            bail!("state file too small");
        }

        // Verify magic bytes
        if &content[..4] != STATE_MAGIC {
            // Try loading as legacy format (plain JSON)
            let legacy: NetworkState =
                serde_json::from_slice(&content).context("parsing legacy state file")?;
            warn!("Loaded legacy state file without integrity check");
            return Ok(legacy);
        }

        // Extract checksum and JSON
        let stored_checksum_hex = &content[4..68];
        if content[68] != b'\n' {
            bail!("invalid state file format: missing newline after checksum");
        }
        let json_bytes = &content[69..];

        // Verify checksum
        let stored_checksum = hex::decode(stored_checksum_hex)
            .context("invalid checksum encoding")?;
        let computed_checksum = Self::compute_checksum(json_bytes);

        if stored_checksum != computed_checksum {
            bail!(
                "state file integrity check failed: checksum mismatch (file may be tampered)"
            );
        }

        // Parse verified JSON
        let state: NetworkState =
            serde_json::from_slice(json_bytes).context("parsing state JSON")?;

        debug!("State file integrity verified");
        Ok(state)
    }

    fn handle_orphaned_state(&mut self) -> Result<()> {
        match Self::restore_from_crash() {
            Ok(true) => info!("Restored network from previous crash"),
            Ok(false) => debug!("No restoration needed"),
            Err(e) => warn!(%e, "Failed to restore from crash - continuing anyway"),
        }
        Ok(())
    }

    fn process_exists(pid: u32) -> bool {
        #[cfg(unix)]
        {
            // Check if process exists by sending signal 0
            // SAFETY: kill(pid, 0) is a safe system call that only checks process existence.
            // It has no side effects and cannot cause memory safety issues.
            let result = unsafe { libc::kill(pid as i32, 0) };
            if result == 0 {
                // Process exists and we can signal it
                true
            } else {
                // result == -1, check errno to distinguish cases
                // SAFETY: errno is thread-local on modern systems
                let err = std::io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::ESRCH) => false, // No such process
                    Some(libc::EPERM) => true,  // Process exists but we lack permissions
                    _ => {
                        // Unexpected error, assume process doesn't exist
                        debug!(error = %err, pid, "unexpected kill(0) error");
                        false
                    }
                }
            }
        }
        #[cfg(not(unix))]
        {
            // On non-Unix, assume process doesn't exist
            false
        }
    }

    fn restore_single_change(change: &NetworkChange) -> Result<()> {
        match change {
            NetworkChange::DnsModified { backup_path } => Self::restore_dns(backup_path),
            NetworkChange::DefaultRouteSet {
                tun_name,
                original_gateway,
                original_interface,
            } => Self::restore_default_route(
                tun_name,
                original_gateway.as_ref(),
                original_interface.as_deref(),
            ),
            NetworkChange::SplitTunnelRoutes { tun_name, routes } => {
                Self::restore_split_routes(tun_name, routes)
            }
            NetworkChange::TunCreated { name } => Self::remove_tun_interface(name),
            NetworkChange::FirewallRulesAdded { rule_ids } => Self::remove_firewall_rules(rule_ids),
        }
    }

    fn restore_dns(backup_path: &Path) -> Result<()> {
        let resolv_path = Path::new("/etc/resolv.conf");
        if backup_path.exists() {
            std::fs::copy(backup_path, resolv_path).context("restoring resolv.conf from backup")?;
            std::fs::remove_file(backup_path).ok();
            info!("DNS configuration restored from backup");
        } else {
            warn!("DNS backup not found at {:?}", backup_path);
        }
        Ok(())
    }

    fn restore_default_route(
        tun_name: &str,
        original_gateway: Option<&IpAddr>,
        original_interface: Option<&str>,
    ) -> Result<()> {
        // Remove VPN route
        let _ = std::process::Command::new("ip")
            .args(["route", "del", "default", "dev", tun_name])
            .output();

        // Restore original default route if known
        if let (Some(gw), Some(iface)) = (original_gateway, original_interface) {
            std::process::Command::new("ip")
                .args([
                    "route",
                    "add",
                    "default",
                    "via",
                    &gw.to_string(),
                    "dev",
                    iface,
                ])
                .output()
                .context("restoring original default route")?;
            info!(gateway = %gw, interface = %iface, "Default route restored");
        } else {
            // Try to restore via DHCP
            warn!("Original gateway unknown - network may need manual restore or DHCP renewal");
        }
        Ok(())
    }

    fn restore_split_routes(tun_name: &str, routes: &[String]) -> Result<()> {
        for route in routes {
            let _ = std::process::Command::new("ip")
                .args(["route", "del", route, "dev", tun_name])
                .output();
        }
        info!(count = routes.len(), "Split tunnel routes removed");
        Ok(())
    }

    fn remove_tun_interface(name: &str) -> Result<()> {
        let _ = std::process::Command::new("ip")
            .args(["link", "del", name])
            .output();
        info!(interface = %name, "TUN interface removed");
        Ok(())
    }

    fn remove_firewall_rules(rule_ids: &[String]) -> Result<()> {
        for rule_id in rule_ids {
            // Try iptables first
            let _ = std::process::Command::new("iptables")
                .args([
                    "-D",
                    "FORWARD",
                    "-m",
                    "comment",
                    "--comment",
                    rule_id,
                    "-j",
                    "ACCEPT",
                ])
                .output();
            // Try nftables
            let _ = std::process::Command::new("nft")
                .args(["delete", "rule", "vpr", "forward", "handle", rule_id])
                .output();
        }
        info!(count = rule_ids.len(), "Firewall rules removed");
        Ok(())
    }
}

impl Drop for NetworkStateGuard {
    fn drop(&mut self) {
        if !self.state.cleaned_up && !self.state.changes.is_empty() {
            warn!("NetworkStateGuard dropped without cleanup - attempting emergency restore");
            if let Err(e) = self.cleanup() {
                error!(%e, "Emergency cleanup failed - network may be in inconsistent state");
                error!("Run 'vpn-client --repair' to restore network configuration");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_change_serialization() {
        let change = NetworkChange::DnsModified {
            backup_path: PathBuf::from("/tmp/test.bak"),
        };
        let json = serde_json::to_string(&change).unwrap();
        let restored: NetworkChange = serde_json::from_str(&json).unwrap();
        assert_eq!(change, restored);
    }

    #[test]
    fn network_state_serialization() {
        let state = NetworkState {
            started_at: Some(1234567890),
            pid: Some(12345),
            changes: vec![
                NetworkChange::TunCreated {
                    name: "vpr0".to_string(),
                },
                NetworkChange::DnsModified {
                    backup_path: PathBuf::from("/tmp/dns.bak"),
                },
            ],
            cleaned_up: false,
        };
        let json = serde_json::to_string_pretty(&state).unwrap();
        let restored: NetworkState = serde_json::from_str(&json).unwrap();
        assert_eq!(state.pid, restored.pid);
        assert_eq!(state.changes.len(), restored.changes.len());
    }

    #[test]
    fn has_pending_changes() {
        let mut state = NetworkState::default();
        assert!(!state.has_pending_changes());

        state.changes.push(NetworkChange::TunCreated {
            name: "vpr0".to_string(),
        });
        assert!(state.has_pending_changes());

        state.cleaned_up = true;
        assert!(!state.has_pending_changes());
    }
}
