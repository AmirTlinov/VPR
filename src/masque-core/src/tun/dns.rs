//! DNS leak protection for VPN tunnel
//!
//! Provides DNS configuration management to prevent DNS leaks.

use anyhow::{bail, Context, Result};
use std::net::IpAddr;
use std::path::PathBuf;
use tracing::{debug, info, warn};

/// Standard backup path for DNS config (survives reboot, unlike /tmp)
const DNS_BACKUP_FILENAME: &str = "resolv.conf.bak";

/// Get persistent backup path for DNS config
pub fn get_dns_backup_path() -> PathBuf {
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
}

impl DnsProtection {
    /// Create new DNS protection instance
    pub fn new() -> Self {
        Self {
            backup_path: None,
            active: false,
        }
    }

    /// Enable DNS leak protection with specified DNS servers
    pub fn enable(&mut self, dns_servers: &[IpAddr]) -> Result<()> {
        if self.active {
            return Ok(());
        }

        let resolv_path = std::path::Path::new("/etc/resolv.conf");
        let backup_path = get_dns_backup_path();

        // Check if we have write permissions (typically requires root)
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if let Ok(meta) = resolv_path.metadata() {
                // Check if we're root (uid 0) or owner
                // SAFETY: libc::geteuid() is a safe POSIX system call that returns the effective
                // user ID of the calling process. It has no side effects, takes no parameters,
                // and cannot fail. The returned uid_t is a simple integer value.
                let euid = unsafe { libc::geteuid() };
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

        // Backup original resolv.conf
        if resolv_path.exists() {
            std::fs::copy(resolv_path, &backup_path).context("backing up resolv.conf")?;
            self.backup_path = Some(backup_path);
        }

        // Write new resolv.conf with VPN DNS servers
        let mut content = String::from("# VPR VPN DNS configuration\n");
        for dns in dns_servers {
            content.push_str(&format!("nameserver {}\n", dns));
        }

        std::fs::write(resolv_path, &content).context("writing resolv.conf")?;

        self.active = true;
        info!(dns_servers = ?dns_servers, "DNS leak protection enabled");
        Ok(())
    }

    /// Restore original DNS configuration
    pub fn disable(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }

        let resolv_path = std::path::Path::new("/etc/resolv.conf");

        if let Some(backup) = &self.backup_path {
            if backup.exists() {
                std::fs::copy(backup, resolv_path).context("restoring resolv.conf")?;
                let _ = std::fs::remove_file(backup);
            }
        }

        self.active = false;
        self.backup_path = None;
        info!("DNS leak protection disabled, original config restored");
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
