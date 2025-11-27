//! VPN Client Process Manager
//!
//! Управляет жизненным циклом процесса vpn-client:
//! - Запуск и остановка процесса
//! - Мониторинг состояния через IPC/сигналы
//! - Graceful shutdown
//! - Обработка ошибок и переподключение

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::process::Command as TokioCommand;
use tokio::sync::{broadcast, RwLock};
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};

/// Статус VPN процесса
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessStatus {
    Stopped,
    Starting,
    Running,
    Stopping,
    Error,
}

/// Статистика VPN соединения
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VpnStatistics {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub connected_at: Option<chrono::DateTime<chrono::Utc>>,
    pub uptime_seconds: u64,
}

/// Конфигурация для запуска VPN клиента
#[derive(Debug, Clone)]
pub struct VpnClientConfig {
    pub server: String,
    pub server_name: String,
    pub port: u16,
    pub tun_name: String,
    pub noise_dir: PathBuf,
    pub noise_name: String,
    pub server_pub: PathBuf,
    pub ca_cert: Option<PathBuf>,
    pub set_default_route: bool,
    pub dns_protection: bool,
    pub dns_servers: Vec<std::net::IpAddr>,
    pub tls_profile: String,
    pub insecure: bool,
    pub killswitch: bool,
}

impl Default for VpnClientConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            server_name: "localhost".to_string(),
            port: 443,
            tun_name: "vpr0".to_string(),
            noise_dir: PathBuf::from("secrets"),
            noise_name: "client".to_string(),
            server_pub: PathBuf::from("secrets/server.noise.pub"),
            ca_cert: Some(PathBuf::from("secrets/server.crt")),
            set_default_route: true,
            dns_protection: true,
            dns_servers: vec![],
            tls_profile: "chrome".to_string(),
            insecure: false,
            killswitch: false,
        }
    }
}

/// Менеджер процесса VPN клиента
pub struct VpnProcessManager {
    process: Arc<RwLock<Option<tokio::process::Child>>>,
    status: Arc<RwLock<ProcessStatus>>,
    statistics: Arc<RwLock<VpnStatistics>>,
    status_tx: broadcast::Sender<ProcessStatus>,
    statistics_tx: broadcast::Sender<VpnStatistics>,
    config: Arc<RwLock<Option<VpnClientConfig>>>,
}

impl VpnProcessManager {
    /// Создать новый менеджер процессов
    pub fn new() -> Self {
        let (status_tx, _) = broadcast::channel(16);
        let (statistics_tx, _) = broadcast::channel(16);

        Self {
            process: Arc::new(RwLock::new(None)),
            status: Arc::new(RwLock::new(ProcessStatus::Stopped)),
            statistics: Arc::new(RwLock::new(VpnStatistics::default())),
            status_tx,
            statistics_tx,
            config: Arc::new(RwLock::new(None)),
        }
    }

    /// Получить текущий статус
    pub async fn get_status(&self) -> ProcessStatus {
        *self.status.read().await
    }

    /// Получить статистику
    pub async fn get_statistics(&self) -> VpnStatistics {
        self.statistics.read().await.clone()
    }

    /// Подписаться на изменения статуса
    pub fn subscribe_status(&self) -> broadcast::Receiver<ProcessStatus> {
        self.status_tx.subscribe()
    }

    /// Подписаться на изменения статистики
    pub fn subscribe_statistics(&self) -> broadcast::Receiver<VpnStatistics> {
        self.statistics_tx.subscribe()
    }

    /// Найти путь к бинарнику vpn-client
    fn find_vpn_client_binary() -> Result<PathBuf> {
        // 1) Пользовательский override через переменную окружения
        if let Ok(path) = std::env::var("VPR_VPN_CLIENT") {
            let p = PathBuf::from(path);
            if p.exists() {
                info!(path = %p.display(), "Using VPR_VPN_CLIENT from env");
                return Ok(p);
            }
        }

        // 2) Попробуем найти рядом с самим бинарем приложения (bundle/standalone сценарий)
        if let Ok(exe_path) = std::env::current_exe() {
            info!(exe = %exe_path.display(), "Current executable path");
            if let Some(exe_dir) = exe_path.parent() {
                let local_candidates = [
                    exe_dir.join("vpn-client"),
                    exe_dir.join("vpn_client"),
                    exe_dir.join("../vpn-client"),
                    exe_dir.join("../vpn_client"),
                    exe_dir.join("../../vpn-client"),
                    exe_dir.join("../../vpn_client"),
                    // Tauri dev mode: exe is in target/debug/vpr-app
                    exe_dir.join("vpn-client"),
                ];
                for candidate in &local_candidates {
                    if candidate.exists() {
                        info!(path = %candidate.display(), "Found vpn-client near exe");
                        return Ok(candidate
                            .canonicalize()
                            .unwrap_or_else(|_| candidate.clone()));
                    }
                }
            }
        }

        // 3) Классические пути
        let mut candidates: Vec<PathBuf> = vec![
            PathBuf::from("./vpn-client"),
            PathBuf::from("./vpn_client"),
            PathBuf::from("./target/debug/vpn-client"),
            PathBuf::from("./target/release/vpn-client"),
            PathBuf::from("/usr/local/bin/vpn-client"),
            PathBuf::from("/usr/local/bin/vpn_client"),
            PathBuf::from("/usr/bin/vpn-client"),
            PathBuf::from("/usr/bin/vpn_client"),
        ];

        // 4) PATH (оба имени)
        if let Ok(path) = which::which("vpn-client") {
            candidates.push(path);
        }
        if let Ok(path) = which::which("vpn_client") {
            candidates.push(path);
        }

        // 5) target/{debug,release} относительно workspace (dev сценарий)
        if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
            let manifest_path = PathBuf::from(manifest_dir);
            if let Some(workspace_root) = manifest_path.parent().and_then(|p| p.parent()) {
                let target_dir = workspace_root
                    .join("target")
                    .join(if cfg!(debug_assertions) {
                        "debug"
                    } else {
                        "release"
                    });

                candidates.push(target_dir.join("vpn_client"));
                candidates.push(target_dir.join("vpn-client"));
            }
        }

        // 6) Относительно текущей рабочей директории
        if let Ok(cwd) = std::env::current_dir() {
            candidates.push(cwd.join("target/debug/vpn-client"));
            candidates.push(cwd.join("target/release/vpn-client"));
        }

        for candidate in &candidates {
            if candidate.exists() {
                info!(path = %candidate.display(), "Found vpn-client");
                return Ok(candidate.clone());
            }
        }

        // Логируем все проверенные пути для отладки
        error!(
            candidates = ?candidates.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            "vpn-client binary not found in any location"
        );

        anyhow::bail!(
            "vpn-client binary not found. Set VPR_VPN_CLIENT=/path/to/vpn-client or build with: cargo build --bin vpn-client"
        )
    }

    /// Запустить VPN клиент
    pub async fn start(&self, config: VpnClientConfig) -> Result<()> {
        let mut status = self.status.write().await;
        if *status != ProcessStatus::Stopped && *status != ProcessStatus::Error {
            return Err(anyhow::anyhow!(
                "VPN process is already running or starting"
            ));
        }

        *status = ProcessStatus::Starting;
        let _ = self.status_tx.send(ProcessStatus::Starting);
        drop(status);

        // Сохранить конфигурацию
        *self.config.write().await = Some(config.clone());

        // Найти бинарник
        let binary_path = Self::find_vpn_client_binary().context("finding vpn-client binary")?;

        // Требуются root-права или cap_net_admin/cap_net_raw на vpn-client
        #[cfg(unix)]
        {
            let has_caps = Self::binary_has_caps(&binary_path)?;
            // SAFETY: libc::geteuid() is always safe - it's a read-only syscall with no side effects
            if unsafe { libc::geteuid() } != 0 && !has_caps {
                return Err(anyhow::anyhow!(
                    "root privileges or CAP_NET_ADMIN/CAP_NET_RAW on vpn-client required for TUN/nftables"
                ));
            }
        }

        // Log all config parameters for debugging
        info!(
            binary = %binary_path.display(),
            server = %config.server,
            port = config.port,
            server_name = %config.server_name,
            tun_name = %config.tun_name,
            noise_dir = %config.noise_dir.display(),
            noise_name = %config.noise_name,
            server_pub = %config.server_pub.display(),
            insecure = config.insecure,
            "Starting VPN client with config"
        );

        // Построить команду запуска
        // VPN client needs root privileges for TUN device creation
        // Если уже root — запускаем напрямую, иначе через pkexec
        // SAFETY: libc::geteuid() is always safe - it's a read-only syscall with no side effects
        let is_root = unsafe { libc::geteuid() } == 0;

        let has_binary_caps = Self::binary_has_caps(&binary_path).unwrap_or(false);
        let mut cmd = if is_root || has_binary_caps {
            // Run directly if we are root or vpn-client binary has CAP_NET_ADMIN/RAW
            TokioCommand::new(&binary_path)
        } else {
            // Fall back to pkexec prompt
            let mut c = TokioCommand::new("pkexec");
            c.arg(&binary_path);
            c
        };
        cmd.arg("--server")
            .arg(format!("{}:{}", config.server, config.port))
            .arg("--server-name")
            .arg(&config.server_name)
            .arg("--tun-name")
            .arg(&config.tun_name)
            .arg("--noise-dir")
            .arg(&config.noise_dir)
            .arg("--noise-name")
            .arg(&config.noise_name)
            .arg("--server-pub")
            .arg(&config.server_pub)
            .arg("--tls-profile")
            .arg(&config.tls_profile);

        if config.set_default_route {
            cmd.arg("--set-default-route");
        }

        if config.dns_protection {
            cmd.arg("--dns-protection");
            if !config.dns_servers.is_empty() {
                let dns_str = config
                    .dns_servers
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                cmd.arg("--dns-servers").arg(dns_str);
            }
        }

        if let Some(ca_cert) = &config.ca_cert {
            cmd.arg("--ca-cert").arg(ca_cert);
        }

        if config.insecure {
            cmd.arg("--insecure");
        }

        // Настроить вывод процесса для логирования
        // В production можно перенаправить в файл логов
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        cmd.stdin(std::process::Stdio::null());

        // Установить переменные окружения для процесса
        cmd.env("RUST_LOG", "info");

        // Логируем полную команду для отладки
        info!(is_root = is_root, "Spawning vpn-client process");

        // Запустить процесс
        let mut child = cmd.spawn().context("spawning vpn-client process")?;

        // Сохранить процесс
        let process_handle = child.id();

        // Запустить задачу для чтения stdout/stderr
        if let Some(stdout) = child.stdout.take() {
            let stdout_reader = tokio::io::BufReader::new(stdout);
            tokio::spawn(async move {
                use tokio::io::AsyncBufReadExt;
                let mut lines = stdout_reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    info!(target: "vpn-client", "[stdout] {}", line);
                }
            });
        }

        if let Some(stderr) = child.stderr.take() {
            let stderr_reader = tokio::io::BufReader::new(stderr);
            tokio::spawn(async move {
                use tokio::io::AsyncBufReadExt;
                let mut lines = stderr_reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    warn!(target: "vpn-client", "[stderr] {}", line);
                }
            });
        }

        *self.process.write().await = Some(child);

        info!(pid = process_handle, "VPN client process started");

        // Запустить задачи мониторинга
        let status_clone = self.status.clone();
        let status_tx_clone = self.status_tx.clone();
        let process_clone = self.process.clone();
        let statistics_clone = self.statistics.clone();
        let statistics_tx_clone = self.statistics_tx.clone();
        let config_clone = self.config.clone();

        // Мониторинг процесса
        tokio::spawn(async move {
            Self::monitor_process(
                process_clone,
                status_clone,
                status_tx_clone,
                statistics_clone,
                statistics_tx_clone,
                config_clone,
            )
            .await;
        });

        // Обновить статус на Running через небольшую задержку,
        // НО только если процесс всё ещё жив И TUN устройство создано
        let status_clone = self.status.clone();
        let status_tx_clone = self.status_tx.clone();
        let statistics_clone = self.statistics.clone();
        let process_for_check = self.process.clone();
        let tun_name = config.tun_name.clone();
        tokio::spawn(async move {
            // Ждём до 10 секунд пока TUN устройство появится
            let mut tun_created = false;
            for i in 0..20 {
                sleep(Duration::from_millis(500)).await;

                // Проверяем что процесс всё ещё жив
                let process_alive = {
                    let mut process_guard = process_for_check.write().await;
                    if let Some(child) = process_guard.as_mut() {
                        match child.try_wait() {
                            Ok(Some(exit_status)) => {
                                error!(
                                    exit_code = ?exit_status.code(),
                                    "VPN client process exited"
                                );
                                false
                            }
                            Ok(None) => true,
                            Err(e) => {
                                error!(%e, "Failed to check process status");
                                false
                            }
                        }
                    } else {
                        false
                    }
                };

                if !process_alive {
                    let mut status = status_clone.write().await;
                    *status = ProcessStatus::Error;
                    let _ = status_tx_clone.send(ProcessStatus::Error);
                    error!("VPN client process died");
                    return;
                }

                // Проверяем TUN устройство
                let tun_check = std::process::Command::new("ip")
                    .args(["link", "show", &tun_name])
                    .output();

                if let Ok(output) = tun_check {
                    if output.status.success() {
                        tun_created = true;
                        info!(tun = %tun_name, attempt = i + 1, "TUN device created");
                        break;
                    }
                }

                if i % 4 == 0 {
                    info!(tun = %tun_name, attempt = i + 1, "Waiting for TUN device...");
                }
            }

            let mut status = status_clone.write().await;
            if *status == ProcessStatus::Starting {
                if tun_created {
                    *status = ProcessStatus::Running;
                    let _ = status_tx_clone.send(ProcessStatus::Running);

                    let mut stats = statistics_clone.write().await;
                    stats.connected_at = Some(chrono::Utc::now());
                    info!("VPN connected successfully");
                } else {
                    *status = ProcessStatus::Error;
                    let _ = status_tx_clone.send(ProcessStatus::Error);
                    error!("VPN connection failed - TUN device not created within 10s");
                }
            }
        });

        Ok(())
    }

    /// Остановить VPN клиент
    pub async fn stop(&self) -> Result<()> {
        let mut status = self.status.write().await;
        if *status == ProcessStatus::Stopped || *status == ProcessStatus::Stopping {
            return Ok(());
        }

        *status = ProcessStatus::Stopping;
        let _ = self.status_tx.send(ProcessStatus::Stopping);
        drop(status);

        // Отключить kill switch перед остановкой
        if let Some(config) = self.config.read().await.as_ref() {
            if config.killswitch {
                if let Err(e) = self.disable_killswitch().await {
                    warn!(%e, "Failed to disable kill switch");
                }
            }
        }

        // Получить процесс и отправить SIGTERM
        let mut process_guard = self.process.write().await;
        if let Some(mut child) = process_guard.take() {
            info!("Sending SIGTERM to VPN client process");

            #[cfg(unix)]
            {
                use nix::sys::signal::{self, Signal};
                use nix::unistd::Pid;

                if let Some(pid) = child.id() {
                    if let Err(e) = signal::kill(Pid::from_raw(pid as i32), Signal::SIGTERM) {
                        warn!(%e, "Failed to send SIGTERM, trying kill");
                        drop(child.kill().await);
                    }
                } else {
                    drop(child.kill().await);
                }
            }

            #[cfg(not(unix))]
            {
                drop(child.kill().await);
            }

            // Подождать завершения процесса (graceful shutdown)
            let timeout = Duration::from_secs(5);
            let start = std::time::Instant::now();

            loop {
                if start.elapsed() > timeout {
                    warn!("Process did not terminate gracefully, forcing kill");
                    drop(child.kill().await);
                    break;
                }

                match child.try_wait() {
                    Ok(Some(status)) => {
                        info!(exit_code = ?status.code(), "VPN client process terminated");
                        break;
                    }
                    Ok(None) => {
                        sleep(Duration::from_millis(100)).await;
                    }
                    Err(e) => {
                        error!(%e, "Error waiting for process");
                        break;
                    }
                }
            }
        }

        // Обновить статус
        *self.status.write().await = ProcessStatus::Stopped;
        let _ = self.status_tx.send(ProcessStatus::Stopped);

        // Сбросить статистику
        *self.statistics.write().await = VpnStatistics::default();

        Ok(())
    }

    /// Мониторинг процесса (запускается в отдельной задаче)
    async fn monitor_process(
        process: Arc<RwLock<Option<tokio::process::Child>>>,
        status: Arc<RwLock<ProcessStatus>>,
        status_tx: broadcast::Sender<ProcessStatus>,
        statistics: Arc<RwLock<VpnStatistics>>,
        statistics_tx: broadcast::Sender<VpnStatistics>,
        config: Arc<RwLock<Option<VpnClientConfig>>>,
    ) {
        loop {
            sleep(Duration::from_secs(1)).await;

            // Проверить статус процесса
            let process_exited = {
                let mut process_guard = process.write().await;
                if let Some(child) = process_guard.as_mut() {
                    match child.try_wait() {
                        Ok(Some(exit_status)) => {
                            warn!(exit_code = ?exit_status.code(), "VPN client process exited unexpectedly");
                            Some(exit_status)
                        }
                        Ok(None) => {
                            // Процесс все еще работает
                            None
                        }
                        Err(e) => {
                            error!(%e, "Error checking process status");
                            break;
                        }
                    }
                } else {
                    break;
                }
            };

            if let Some(_exit_status) = process_exited {
                // Обновить статус
                *status.write().await = ProcessStatus::Error;
                let _ = status_tx.send(ProcessStatus::Error);

                // Если включен kill switch, оставить его активным
                if let Some(cfg) = config.read().await.as_ref() {
                    if cfg.killswitch {
                        // Лучше восстановить связь пользователю, чем держать вечный блок
                        if let Err(e) = crate::killswitch::disable().await {
                            warn!(%e, "Failed to disable kill switch after process exit");
                        }
                    }
                }

                // Удалить процесс из менеджера
                *process.write().await = None;
                break;
            } else {
                // Процесс все еще работает, обновить статистику
                let mut stats = statistics.write().await;
                if let Some(connected_at) = stats.connected_at {
                    stats.uptime_seconds = chrono::Utc::now()
                        .signed_duration_since(connected_at)
                        .num_seconds() as u64;
                }
                let _ = statistics_tx.send(stats.clone());
            }
        }
    }

    /// Включить kill switch
    pub async fn enable_killswitch(
        &self,
        policy: crate::killswitch::KillSwitchPolicy,
    ) -> Result<()> {
        crate::killswitch::enable(policy).await
    }

    /// Отключить kill switch
    pub async fn disable_killswitch(&self) -> Result<()> {
        crate::killswitch::disable().await
    }

    /// Check if vpn-client binary already carries CAP_NET_ADMIN and CAP_NET_RAW.
    fn binary_has_caps(path: &std::path::Path) -> anyhow::Result<bool> {
        let output = std::process::Command::new("getcap").arg(path).output();
        let out = match output {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
            _ => return Ok(false),
        };
        Ok(out.contains("cap_net_admin") && out.contains("cap_net_raw"))
    }
}

impl Default for VpnProcessManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn manager_starts_in_stopped_state() {
        let manager = VpnProcessManager::new();
        assert_eq!(manager.get_status().await, ProcessStatus::Stopped);
    }

    #[tokio::test]
    async fn manager_default_statistics_are_zero() {
        let manager = VpnProcessManager::new();
        let stats = manager.get_statistics().await;
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.bytes_received, 0);
    }

    #[tokio::test]
    async fn stop_when_stopped_is_noop() {
        let manager = VpnProcessManager::new();
        let result = manager.stop().await;
        assert!(result.is_ok());
    }

    #[test]
    fn config_default_values() {
        let config = VpnClientConfig::default();
        assert_eq!(config.port, 443);
        assert!(!config.insecure);
    }

    #[test]
    fn process_manager_default_impl() {
        let manager = VpnProcessManager::default();
        // Just verify the Default impl works
        let _ = manager;
    }
}
