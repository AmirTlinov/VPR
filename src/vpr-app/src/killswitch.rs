//! Kill Switch Implementation
//!
//! Блокирует весь трафик при отключении VPN через iptables/nftables.
//! Поддерживает Linux/macOS/Windows.

use anyhow::{Context, Result};
use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::Ipv4Addr;
use std::process::Command;
use tracing::{info, warn};

fn run(cmd: &str, args: &[&str]) -> Result<()> {
    if env::var("KILLSWITCH_DRY_RUN").ok().as_deref() == Some("1") {
        if let Ok(path) = env::var("KILLSWITCH_DRY_RUN_LOG") {
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .context("opening dry-run log")?;
            writeln!(file, "{} {}", cmd, args.join(" ")).ok();
        }
        return Ok(());
    }

    let status = Command::new(cmd)
        .args(args)
        .status()
        .context("spawn command")?;
    if !status.success() {
        warn!(cmd = %cmd, args = ?args, "command failed");
    }
    Ok(())
}

/// Политика разрешённого трафика при активном kill switch
#[derive(Debug, Default, Clone)]
pub struct KillSwitchPolicy {
    pub allow_ipv4: Vec<Ipv4Addr>,
    pub allow_tcp_ports: Vec<u16>,
    pub allow_udp_ports: Vec<u16>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::NamedTempFile;

    #[test]
    fn policy_allows_server_and_ports() {
        let policy = KillSwitchPolicy {
            allow_ipv4: vec![Ipv4Addr::new(1, 2, 3, 4)],
            allow_tcp_ports: vec![443],
            allow_udp_ports: vec![53],
        };
        assert_eq!(policy.allow_ipv4.len(), 1);
        assert!(policy.allow_tcp_ports.contains(&443));
        assert!(policy.allow_udp_ports.contains(&53));
    }

    #[tokio::test]
    async fn iptables_dry_run_writes_commands() {
        let log = NamedTempFile::new().unwrap();
        std::env::set_var("KILLSWITCH_DRY_RUN", "1");
        std::env::set_var("KILLSWITCH_DRY_RUN_LOG", log.path());

        let policy = KillSwitchPolicy {
            allow_ipv4: vec![Ipv4Addr::new(10, 0, 0, 1)],
            allow_tcp_ports: vec![443],
            allow_udp_ports: vec![53],
        };

        enable_iptables(&policy).await.unwrap();

        let content = fs::read_to_string(log.path()).unwrap();
        assert!(content.contains("iptables -N VPR_KS_OUT"));
        assert!(content.contains("-A VPR_KS_OUT -d 10.0.0.1 -p tcp --dport 443"));
        assert!(content.contains("-A VPR_KS_OUT -j DROP"));
    }
}

/// Включить kill switch с политикой разрешённого трафика
pub async fn enable(policy: KillSwitchPolicy) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        enable_linux(&policy).await
    }

    #[cfg(target_os = "macos")]
    {
        enable_macos().await
    }

    #[cfg(target_os = "windows")]
    {
        enable_windows().await
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        anyhow::bail!("Kill switch not supported on this platform");
    }
}

/// Отключить kill switch (разрешить трафик)
pub async fn disable() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        disable_linux().await
    }

    #[cfg(target_os = "macos")]
    {
        disable_macos().await
    }

    #[cfg(target_os = "windows")]
    {
        disable_windows().await
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        anyhow::bail!("Kill switch not supported on this platform");
    }
}

#[cfg(target_os = "linux")]
async fn enable_linux(policy: &KillSwitchPolicy) -> Result<()> {
    // Проверить, используется ли nftables или iptables
    let uses_nftables = Command::new("nft")
        .arg("list")
        .arg("tables")
        .output()
        .is_ok();

    if uses_nftables {
        enable_nftables(policy).await
    } else {
        enable_iptables(policy).await
    }
}

#[cfg(target_os = "linux")]
async fn enable_nftables(policy: &KillSwitchPolicy) -> Result<()> {
    // Создать таблицу и цепочку для kill switch, если их нет
    let create_table = Command::new("nft")
        .args(["create", "table", "inet", "vpr_killswitch"])
        .output();

    // Игнорируем ошибку, если таблица уже существует
    let _ = create_table;

    // Создать цепочки для input/output
    let _ = Command::new("nft")
        .args(["delete", "chain", "inet", "vpr_killswitch", "output"])
        .status();
    let _ = Command::new("nft")
        .args(["delete", "chain", "inet", "vpr_killswitch", "input"])
        .status();

    let _ = Command::new("nft")
        .args([
            "create",
            "chain",
            "inet",
            "vpr_killswitch",
            "output",
            "{ type filter hook output priority 0; }",
        ])
        .status();
    let _ = Command::new("nft")
        .args([
            "create",
            "chain",
            "inet",
            "vpr_killswitch",
            "input",
            "{ type filter hook input priority 0; }",
        ])
        .status();

    // Разрешить loopback (output + input)
    let _ = Command::new("nft")
        .args([
            "add",
            "rule",
            "inet",
            "vpr_killswitch",
            "output",
            "oifname",
            "lo",
            "accept",
        ])
        .status();
    let _ = Command::new("nft")
        .args([
            "add",
            "rule",
            "inet",
            "vpr_killswitch",
            "input",
            "iifname",
            "lo",
            "accept",
        ])
        .status();

    // Разрешить established/related соединения ПЕРВЫМИ (эффективнее)
    let _ = Command::new("nft")
        .args([
            "add",
            "rule",
            "inet",
            "vpr_killswitch",
            "input",
            "ct",
            "state",
            "established,related",
            "accept",
        ])
        .status();
    let _ = Command::new("nft")
        .args([
            "add",
            "rule",
            "inet",
            "vpr_killswitch",
            "output",
            "ct",
            "state",
            "established,related",
            "accept",
        ])
        .status();

    // Разрешить трафик через TUN интерфейс (vpr*)
    let _ = Command::new("nft")
        .args([
            "add",
            "rule",
            "inet",
            "vpr_killswitch",
            "output",
            "oifname",
            "vpr*",
            "accept",
        ])
        .status();
    let _ = Command::new("nft")
        .args([
            "add",
            "rule",
            "inet",
            "vpr_killswitch",
            "input",
            "iifname",
            "vpr*",
            "accept",
        ])
        .status();

    for ip in &policy.allow_ipv4 {
        let ip_str = ip.to_string();
        for port in &policy.allow_tcp_ports {
            // Исходящий TCP
            let _ = Command::new("nft")
                .args([
                    "add",
                    "rule",
                    "inet",
                    "vpr_killswitch",
                    "output",
                    "ip",
                    "daddr",
                    &ip_str,
                    "tcp",
                    "dport",
                    &port.to_string(),
                    "accept",
                ])
                .status();
            // Входящий TCP (ответы от сервера)
            let _ = Command::new("nft")
                .args([
                    "add",
                    "rule",
                    "inet",
                    "vpr_killswitch",
                    "input",
                    "ip",
                    "saddr",
                    &ip_str,
                    "tcp",
                    "sport",
                    &port.to_string(),
                    "accept",
                ])
                .status();
        }
        for port in &policy.allow_udp_ports {
            // Исходящий UDP
            let _ = Command::new("nft")
                .args([
                    "add",
                    "rule",
                    "inet",
                    "vpr_killswitch",
                    "output",
                    "ip",
                    "daddr",
                    &ip_str,
                    "udp",
                    "dport",
                    &port.to_string(),
                    "accept",
                ])
                .status();
            // Входящий UDP (ответы от сервера - критично для QUIC!)
            let _ = Command::new("nft")
                .args([
                    "add",
                    "rule",
                    "inet",
                    "vpr_killswitch",
                    "input",
                    "ip",
                    "saddr",
                    &ip_str,
                    "udp",
                    "sport",
                    &port.to_string(),
                    "accept",
                ])
                .status();
        }
    }

    // Drop всё остальное
    let status = Command::new("nft")
        .args(["add", "rule", "inet", "vpr_killswitch", "output", "drop"])
        .status()
        .context("adding nftables drop rule")?;
    let _ = Command::new("nft")
        .args(["add", "rule", "inet", "vpr_killswitch", "input", "drop"])
        .status();

    if !status.success() {
        warn!("nftables rule may already exist");
    }

    info!(allow_ipv4 = ?policy.allow_ipv4, "Kill switch enabled (nftables)");
    Ok(())
}

#[cfg(target_os = "linux")]
async fn enable_iptables(policy: &KillSwitchPolicy) -> Result<()> {
    // Создать/очистить цепочки для исходящего и входящего трафика
    let _ = run("iptables", &["-D", "OUTPUT", "-j", "VPR_KS_OUT"]);
    let _ = run("iptables", &["-D", "INPUT", "-j", "VPR_KS_IN"]);
    let _ = run("iptables", &["-F", "VPR_KS_OUT"]);
    let _ = run("iptables", &["-F", "VPR_KS_IN"]);
    let _ = run("iptables", &["-X", "VPR_KS_OUT"]);
    let _ = run("iptables", &["-X", "VPR_KS_IN"]);
    let _ = run("iptables", &["-N", "VPR_KS_OUT"]);
    let _ = run("iptables", &["-N", "VPR_KS_IN"]);

    // Разрешить loopback
    let _ = run(
        "iptables",
        &["-A", "VPR_KS_OUT", "-o", "lo", "-j", "ACCEPT"],
    );
    let _ = run(
        "iptables",
        &["-A", "VPR_KS_IN", "-i", "lo", "-j", "ACCEPT"],
    );

    // Разрешить established/related (критично для QUIC)
    let _ = run(
        "iptables",
        &[
            "-A",
            "VPR_KS_IN",
            "-m",
            "state",
            "--state",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ],
    );

    // Разрешить TUN интерфейс
    let _ = run(
        "iptables",
        &["-A", "VPR_KS_OUT", "-o", "vpr+", "-j", "ACCEPT"],
    );
    let _ = run(
        "iptables",
        &["-A", "VPR_KS_IN", "-i", "vpr+", "-j", "ACCEPT"],
    );

    // Разрешить целевые IPv4/порты
    for ip in &policy.allow_ipv4 {
        for port in &policy.allow_tcp_ports {
            // Исходящий TCP
            let _ = run(
                "iptables",
                &[
                    "-A",
                    "VPR_KS_OUT",
                    "-d",
                    &ip.to_string(),
                    "-p",
                    "tcp",
                    "--dport",
                    &port.to_string(),
                    "-j",
                    "ACCEPT",
                ],
            );
            // Входящий TCP
            let _ = run(
                "iptables",
                &[
                    "-A",
                    "VPR_KS_IN",
                    "-s",
                    &ip.to_string(),
                    "-p",
                    "tcp",
                    "--sport",
                    &port.to_string(),
                    "-j",
                    "ACCEPT",
                ],
            );
        }

        for port in &policy.allow_udp_ports {
            // Исходящий UDP
            let _ = run(
                "iptables",
                &[
                    "-A",
                    "VPR_KS_OUT",
                    "-d",
                    &ip.to_string(),
                    "-p",
                    "udp",
                    "--dport",
                    &port.to_string(),
                    "-j",
                    "ACCEPT",
                ],
            );
            // Входящий UDP (критично для QUIC!)
            let _ = run(
                "iptables",
                &[
                    "-A",
                    "VPR_KS_IN",
                    "-s",
                    &ip.to_string(),
                    "-p",
                    "udp",
                    "--sport",
                    &port.to_string(),
                    "-j",
                    "ACCEPT",
                ],
            );
        }
    }

    // Блок по умолчанию
    run("iptables", &["-A", "VPR_KS_OUT", "-j", "DROP"]).context("adding iptables DROP rule")?;
    let _ = run("iptables", &["-A", "VPR_KS_IN", "-j", "DROP"]);

    // Подключить цепочки первыми правилами
    run("iptables", &["-I", "OUTPUT", "1", "-j", "VPR_KS_OUT"])
        .context("attaching VPR_KS_OUT to OUTPUT")?;
    let _ = run("iptables", &["-I", "INPUT", "1", "-j", "VPR_KS_IN"]);

    info!(allow_ipv4 = ?policy.allow_ipv4, "Kill switch enabled (iptables)");
    Ok(())
}

#[cfg(target_os = "linux")]
async fn disable_linux() -> Result<()> {
    let uses_nftables = Command::new("nft")
        .arg("list")
        .arg("tables")
        .output()
        .is_ok();

    if uses_nftables {
        disable_nftables().await
    } else {
        disable_iptables().await
    }
}

#[cfg(target_os = "linux")]
async fn disable_nftables() -> Result<()> {
    // Удалить все правила из цепочки
    let flush = Command::new("nft")
        .args(["flush", "chain", "inet", "vpr_killswitch", "input"])
        .status();

    let _ = flush;

    // Удалить цепочку
    let delete_chain = Command::new("nft")
        .args(["delete", "chain", "inet", "vpr_killswitch", "input"])
        .status();

    let _ = delete_chain;

    // Удалить таблицу
    let delete_table = Command::new("nft")
        .args(["delete", "table", "inet", "vpr_killswitch"])
        .status();

    let _ = delete_table;

    info!("Kill switch disabled (nftables)");
    Ok(())
}

#[cfg(target_os = "linux")]
async fn disable_iptables() -> Result<()> {
    // Открепить цепочки от OUTPUT и INPUT
    let _ = run("iptables", &["-D", "OUTPUT", "-j", "VPR_KS_OUT"]);
    let _ = run("iptables", &["-D", "INPUT", "-j", "VPR_KS_IN"]);

    // Очистить и удалить цепочки
    let _ = run("iptables", &["-F", "VPR_KS_OUT"]);
    let _ = run("iptables", &["-X", "VPR_KS_OUT"]);
    let _ = run("iptables", &["-F", "VPR_KS_IN"]);
    let _ = run("iptables", &["-X", "VPR_KS_IN"]);

    info!("Kill switch disabled (iptables)");
    Ok(())
}

#[cfg(target_os = "macos")]
async fn enable_macos() -> Result<()> {
    // macOS использует pfctl (Packet Filter)
    // Создать временный файл с правилами
    let rules = r#"
block out all
block in all
"#;

    let temp_file = std::env::temp_dir().join("vpr_killswitch.pf");
    std::fs::write(&temp_file, rules).context("writing pf rules file")?;

    // Загрузить правила
    let temp_file_str = temp_file
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid temp file path"))?;
    let status = Command::new("pfctl")
        .args(["-f", temp_file_str])
        .status()
        .context("loading pf rules")?;

    if !status.success() {
        anyhow::bail!("Failed to enable kill switch with pfctl");
    }

    // Включить pf, если еще не включен
    let _ = Command::new("pfctl").arg("-e").status();

    info!("Kill switch enabled (pfctl)");
    Ok(())
}

#[cfg(target_os = "macos")]
async fn disable_macos() -> Result<()> {
    // Удалить правила (загрузить пустой файл)
    let temp_file = std::env::temp_dir().join("vpr_killswitch_empty.pf");
    std::fs::write(&temp_file, "").context("writing empty pf rules file")?;

    let temp_file_str = temp_file
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid temp file path"))?;
    let status = Command::new("pfctl")
        .args(["-f", temp_file_str])
        .status()
        .context("disabling pf rules")?;

    if !status.success() {
        warn!("pfctl disable may have failed");
    }

    info!("Kill switch disabled (pfctl)");
    Ok(())
}

#[cfg(target_os = "windows")]
async fn enable_windows() -> Result<()> {
    // Windows использует netsh для управления firewall
    // Блокировать все исходящие соединения
    let status = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=VPR Kill Switch Outbound",
            "dir=out",
            "action=block",
            "enable=yes",
        ])
        .status()
        .context("adding Windows firewall outbound rule")?;

    if !status.success() {
        warn!("Windows firewall rule may already exist");
    }

    // Блокировать все входящие соединения
    let status = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=VPR Kill Switch Inbound",
            "dir=in",
            "action=block",
            "enable=yes",
        ])
        .status()
        .context("adding Windows firewall inbound rule")?;

    if !status.success() {
        warn!("Windows firewall rule may already exist");
    }

    info!("Kill switch enabled (Windows Firewall)");
    Ok(())
}

#[cfg(target_os = "windows")]
async fn disable_windows() -> Result<()> {
    // Удалить исходящее правило
    let _ = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            "name=VPR Kill Switch Outbound",
        ])
        .status();

    // Удалить входящее правило
    let _ = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            "name=VPR Kill Switch Inbound",
        ])
        .status();

    info!("Kill switch disabled (Windows Firewall)");
    Ok(())
}
