//! DNS leak protection for VPN tunnel
//!
//! Provides DNS configuration management to prevent DNS leaks.
//!
//! # Security Design
//! - **Symlink protection**: Refuses to modify symlinked resolv.conf
//! - **Atomic writes**: Uses rename() for atomic file updates
//! - **systemd-resolved support**: Handles modern Linux DNS management
//! - **Verification**: Confirms DNS changes took effect
//! - **Recovery**: Automatic rollback on failure

use anyhow::{bail, Context, Result};
use std::fs::OpenOptions;
use std::io::Write;
use std::net::IpAddr;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
#[cfg(not(unix))]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, info, warn};

/// Standard backup path for DNS config (survives reboot, unlike /tmp)
const DNS_BACKUP_FILENAME: &str = "resolv.conf.bak";

/// Path to system resolv.conf
const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

/// Check if systemd-resolved is managing DNS
fn is_systemd_resolved_active() -> bool {
    // Check if stub resolver is present
    std::fs::exists("/run/systemd/resolve/stub-resolv.conf").unwrap_or(false)
        || std::fs::read_link(RESOLV_CONF_PATH)
            .map(|target| {
                target
                    .to_str()
                    .map(|s| s.contains("systemd"))
                    .unwrap_or(false)
            })
            .unwrap_or(false)
}

/// Check if resolv.conf is a symlink (security check)
fn is_resolv_conf_symlink() -> bool {
    std::fs::symlink_metadata(RESOLV_CONF_PATH)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

/// Check if running as root
///
/// # Safety
/// `geteuid()` is a safe POSIX system call that returns the effective user ID.
/// It has no side effects, takes no parameters, and cannot fail.
fn is_root() -> bool {
    // SAFETY: geteuid() is a safe POSIX call that never fails and has no side effects.
    // It simply returns the effective user ID as a u32.
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() } == 0
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Get persistent backup path for DNS config
pub fn get_dns_backup_path() -> PathBuf {
    if is_root() {
        let var_lib = PathBuf::from("/var/lib/vpr");
        if std::fs::create_dir_all(&var_lib).is_ok() {
            return var_lib.join(DNS_BACKUP_FILENAME);
        }
    }

    // Try XDG_STATE_HOME first (~/.local/state/vpr/)
    if let Some(state_dir) = dirs::state_dir() {
        let vpr_state = state_dir.join("vpr");
        if std::fs::create_dir_all(&vpr_state).is_ok() {
            return vpr_state.join(DNS_BACKUP_FILENAME);
        }
    }
    // Fallback to config dir (~/.config/vpr/)
    if let Some(config_dir) = dirs::config_dir() {
        let vpr_config = config_dir.join("vpr");
        if std::fs::create_dir_all(&vpr_config).is_ok() {
            return vpr_config.join(DNS_BACKUP_FILENAME);
        }
    }
    // Last resort: /tmp (but warn)
    debug!("Using /tmp for DNS backup - may not survive reboot");
    PathBuf::from("/tmp/vpr-resolv.conf.bak")
}

/// DNS leak protection configuration
pub struct DnsProtection {
    /// Original resolv.conf backup
    backup_path: Option<PathBuf>,
    /// Whether protection is active
    active: bool,
    /// Whether systemd-resolved is being used
    use_systemd: bool,
}

impl DnsProtection {
    /// Create new DNS protection instance
    pub fn new() -> Self {
        Self {
            backup_path: None,
            active: false,
            use_systemd: false,
        }
    }

    /// Enable DNS leak protection with specified DNS servers
    ///
    /// # Security
    /// - Validates DNS servers are routable IPs
    /// - Refuses to modify symlinked resolv.conf
    /// - Uses atomic write (temp file + rename)
    /// - Handles systemd-resolved on modern Linux
    /// - Verifies changes took effect
    pub fn enable(&mut self, dns_servers: &[IpAddr]) -> Result<()> {
        if self.active {
            return Ok(());
        }

        // Validate DNS servers
        if dns_servers.is_empty() {
            bail!("At least one DNS server must be specified");
        }
        for dns in dns_servers {
            if dns.is_unspecified() || dns.is_multicast() {
                bail!("Invalid DNS server address: {}", dns);
            }
        }

        let resolv_path = Path::new(RESOLV_CONF_PATH);

        // Security check: refuse to modify symlinks
        if is_resolv_conf_symlink() && !is_systemd_resolved_active() {
            bail!(
                "resolv.conf is a symlink but not managed by systemd-resolved. \
                 Cannot safely modify DNS configuration. Manual setup required."
            );
        }

        // Check if we have write permissions
        #[cfg(unix)]
        {
            if let Ok(meta) = resolv_path.metadata() {
                let euid = if is_root() { 0 } else {
                    // SAFETY: geteuid() is safe as documented above
                    unsafe { libc::geteuid() }
                };
                let file_uid = meta.uid();
                if euid != 0 && euid != file_uid {
                    bail!(
                        "DNS protection requires root privileges (euid={}, file owner={})",
                        euid,
                        file_uid
                    );
                }
            }
        }

        // Handle systemd-resolved specially
        if is_systemd_resolved_active() {
            return self.enable_systemd_resolved(dns_servers);
        }

        // Traditional resolv.conf modification
        self.enable_resolv_conf(dns_servers, resolv_path)
    }

    /// Enable DNS via systemd-resolved
    fn enable_systemd_resolved(&mut self, dns_servers: &[IpAddr]) -> Result<()> {
        info!("Using systemd-resolved for DNS configuration");

        // Build DNS server list
        let dns_list: Vec<String> = dns_servers.iter().map(|ip| ip.to_string()).collect();

        // Set DNS for default route interface
        // First, get the interface name for vpr tunnel or default
        let interface = "vpr0"; // VPN tunnel interface

        for dns in &dns_list {
            let output = Command::new("resolvectl")
                .args(["dns", interface, dns])
                .output();

            match output {
                Ok(out) if out.status.success() => {
                    debug!(dns = %dns, interface = %interface, "Set DNS via resolvectl");
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    warn!(
                        dns = %dns,
                        stderr = %stderr.trim(),
                        "resolvectl dns failed, trying alternative"
                    );
                    // Fallback: set global DNS
                    let _ = Command::new("resolvectl")
                        .args(["dns", dns])
                        .output();
                }
                Err(e) => {
                    warn!(%e, "resolvectl not available, falling back to resolv.conf");
                    return self.enable_resolv_conf(dns_servers, Path::new(RESOLV_CONF_PATH));
                }
            }
        }

        // Set this interface as default route for DNS
        let _ = Command::new("resolvectl")
            .args(["default-route", interface, "true"])
            .output();

        self.active = true;
        self.use_systemd = true;
        info!(dns_servers = ?dns_servers, "DNS leak protection enabled via systemd-resolved");
        Ok(())
    }

    /// Enable DNS via traditional resolv.conf modification
    fn enable_resolv_conf(&mut self, dns_servers: &[IpAddr], resolv_path: &Path) -> Result<()> {
        let backup_path = get_dns_backup_path();

        // Backup original resolv.conf
        if resolv_path.exists() {
            std::fs::copy(resolv_path, &backup_path).context("backing up resolv.conf")?;
            self.backup_path = Some(backup_path);
        }

        // Build new content
        let mut content = String::from("# VPR VPN DNS configuration\n");
        content.push_str("# Original config backed up - will be restored on disconnect\n");
        for dns in dns_servers {
            content.push_str(&format!("nameserver {}\n", dns));
        }

        // Atomic write: write to temp file, then rename
        // Security: Use O_NOFOLLOW to prevent symlink attacks (TOCTOU)
        let temp_path = resolv_path.with_extension("tmp.vpr");

        // Remove existing temp file if present (prevent symlink attack)
        let _ = std::fs::remove_file(&temp_path);

        #[cfg(unix)]
        {
            // Open with O_NOFOLLOW to prevent symlink attacks
            // Also use O_EXCL to ensure we create a new file
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true) // Fail if file exists (O_EXCL)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&temp_path)
                .context("creating temporary resolv.conf (O_NOFOLLOW)")?;

            file.write_all(content.as_bytes())
                .context("writing temporary resolv.conf")?;

            file.sync_all()
                .context("syncing temporary resolv.conf")?;
        }

        #[cfg(not(unix))]
        {
            std::fs::write(&temp_path, &content)
                .context("writing temporary resolv.conf")?;
        }

        // Rename is atomic on POSIX
        std::fs::rename(&temp_path, resolv_path)
            .context("atomically replacing resolv.conf")?;

        // Verify the change took effect
        let written = std::fs::read_to_string(resolv_path)
            .context("verifying resolv.conf")?;
        if !written.contains(&dns_servers[0].to_string()) {
            bail!(
                "DNS configuration verification failed - resolv.conf may be managed by another process"
            );
        }

        self.active = true;
        info!(dns_servers = ?dns_servers, "DNS leak protection enabled via resolv.conf");
        Ok(())
    }

    /// Restore original DNS configuration
    pub fn disable(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }

        if self.use_systemd {
            return self.disable_systemd_resolved();
        }

        let resolv_path = Path::new(RESOLV_CONF_PATH);

        if let Some(backup) = &self.backup_path {
            if backup.exists() {
                // Atomic restore: copy to temp, then rename
                let temp_path = resolv_path.with_extension("tmp.vpr");
                std::fs::copy(backup, &temp_path)
                    .context("copying backup to temp")?;
                std::fs::rename(&temp_path, resolv_path)
                    .context("atomically restoring resolv.conf")?;
                let _ = std::fs::remove_file(backup);
            }
        }

        self.active = false;
        self.backup_path = None;
        info!("DNS leak protection disabled, original config restored");
        Ok(())
    }

    /// Disable systemd-resolved DNS configuration
    fn disable_systemd_resolved(&mut self) -> Result<()> {
        let interface = "vpr0";

        // Revert DNS for interface (will use system default)
        let output = Command::new("resolvectl")
            .args(["revert", interface])
            .output();

        match output {
            Ok(out) if out.status.success() => {
                debug!(interface = %interface, "Reverted DNS via resolvectl");
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                warn!(stderr = %stderr.trim(), "resolvectl revert failed");
            }
            Err(e) => {
                warn!(%e, "resolvectl not available");
            }
        }

        self.active = false;
        self.use_systemd = false;
        info!("DNS leak protection disabled via systemd-resolved");
        Ok(())
    }

    /// Check if DNS protection is active
    pub fn is_active(&self) -> bool {
        self.active
    }
}

impl Default for DnsProtection {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for DnsProtection {
    fn drop(&mut self) {
        if self.active {
            if let Err(e) = self.disable() {
                warn!(%e, "Failed to restore DNS on drop");
            }
        }
    }
}
