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
                return Ok(p);
            }
        }

        // 2) Попробуем найти рядом с самим бинарем приложения (bundle/standalone сценарий)
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                let local_candidates = [
                    exe_dir.join("vpn-client"),
                    exe_dir.join("vpn_client"),
                    exe_dir.join("../vpn-client"),
                    exe_dir.join("../vpn_client"),
                    exe_dir.join("../../vpn-client"),
                    exe_dir.join("../../vpn_client"),
                ];
                if let Some(found) = local_candidates.iter().find(|p| p.exists()) {
                    return Ok(found.canonicalize().unwrap_or_else(|_| (*found).clone()));
                }
            }
        }

        // 3) Классические пути
        let mut candidates: Vec<PathBuf> = vec![
            PathBuf::from("./vpn-client"),
            PathBuf::from("./vpn_client"),
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

        if let Some(found) = candidates.into_iter().find(|p| p.exists()) {
            return Ok(found);
        }

        anyhow::bail!(
            "vpn-client binary not found. Set VPR_VPN_CLIENT=/path/to/vpn-client or build with: cargo build --bin vpn_client"
        )
    }

    /// Запустить VPN клиент
    pub async fn start(&self, config: VpnClientConfig) -> Result<()> {
        // Требуются root-права для TUN/nftables
        #[cfg(unix)]
        {
            if unsafe { libc::geteuid() } != 0 {
                return Err(anyhow::anyhow!(
                    "root privileges required to create TUN and nftables rules"
                ));
            }
        }

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

        info!(binary = %binary_path.display(), "Starting VPN client");

        // Построить команду запуска
        let mut cmd = TokioCommand::new(&binary_path);
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

        // Запустить процесс
        let child = cmd.spawn().context("spawning vpn-client process")?;

        // Сохранить процесс
        let process_handle = child.id();
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
        // НО только если процесс всё ещё жив
        let status_clone = self.status.clone();
        let status_tx_clone = self.status_tx.clone();
        let statistics_clone = self.statistics.clone();
        let process_for_check = self.process.clone();
        tokio::spawn(async move {
            sleep(Duration::from_millis(500)).await;
            
            // Проверяем что процесс всё ещё жив
            let process_alive = {
                let mut process_guard = process_for_check.write().await;
                if let Some(child) = process_guard.as_mut() {
                    match child.try_wait() {
                        Ok(Some(exit_status)) => {
                            // Процесс уже завершился — это ошибка!
                            error!(
                                exit_code = ?exit_status.code(),
                                "VPN client process exited immediately after start"
                            );
                            false
                        }
                        Ok(None) => true, // Процесс всё ещё работает
                        Err(e) => {
                            error!(%e, "Failed to check process status");
                            false
                        }
                    }
                } else {
                    false // Процесс не существует
                }
            };
            
            let mut status = status_clone.write().await;
            if *status == ProcessStatus::Starting {
                if process_alive {
                    *status = ProcessStatus::Running;
                    let _ = status_tx_clone.send(ProcessStatus::Running);

                    // Обновить статистику
                    let mut stats = statistics_clone.write().await;
                    stats.connected_at = Some(chrono::Utc::now());
                    info!("VPN client confirmed running");
                } else {
                    *status = ProcessStatus::Error;
                    let _ = status_tx_clone.send(ProcessStatus::Error);
                    error!("VPN client failed to start - process died within 500ms");
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
                        let _ = child.kill();
                    }
                } else {
                    let _ = child.kill();
                }
            }

            #[cfg(not(unix))]
            {
                let _ = child.kill();
            }

            // Подождать завершения процесса (graceful shutdown)
            let timeout = Duration::from_secs(5);
            let start = std::time::Instant::now();

            loop {
                if start.elapsed() > timeout {
                    warn!("Process did not terminate gracefully, forcing kill");
                    let _ = child.kill();
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
}

impl Default for VpnProcessManager {
    fn default() -> Self {
        Self::new()
    }
}
