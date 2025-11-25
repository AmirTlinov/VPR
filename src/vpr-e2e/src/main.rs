//! VPR E2E Test Runner
//!
//! Automated end-to-end testing for VPR VPN.
//!
//! Usage:
//!   # Quick test with existing server
//!   vpr-e2e --host 64.176.70.203 --password 'secret'
//!
//!   # Full deployment + test
//!   vpr-e2e --host 64.176.70.203 --password 'secret' --deploy
//!
//!   # Generate sample config
//!   vpr-e2e --init-config

mod config;
mod deployer;
mod report;
mod tests;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::process::Command;

use config::E2eConfig;
use deployer::Deployer;
use report::E2eReport;
use tests::TestRunner;

/// Maximum time to wait for TUN device creation
const TUN_WAIT_TIMEOUT_SECS: u64 = 30;

/// Time to wait for connection to stabilize after TUN creation
const CONNECTION_STABILIZE_SECS: u64 = 2;

#[derive(Parser)]
#[command(name = "vpr-e2e")]
#[command(about = "VPR E2E Test Runner - automated deployment and testing")]
#[command(version)]
struct Cli {
    /// Server IP address
    #[arg(long, env = "VPR_E2E_HOST")]
    host: Option<String>,

    /// SSH password (or use VPR_E2E_PASSWORD env var)
    #[arg(long, env = "VPR_E2E_PASSWORD")]
    password: Option<String>,

    /// SSH user
    #[arg(long, default_value = "root")]
    user: String,

    /// VPN port
    #[arg(long, default_value = "4433")]
    port: u16,

    /// Deploy/update server before testing
    #[arg(long)]
    deploy: bool,

    /// Force rebuild of binaries
    #[arg(long)]
    rebuild: bool,

    /// Skip TLS verification (testing only!)
    #[arg(long)]
    insecure: bool,

    /// Config file path
    #[arg(long, short)]
    config: Option<PathBuf>,

    /// Output directory
    #[arg(long, default_value = "logs/e2e")]
    output: PathBuf,

    /// Verbose output
    #[arg(long, short)]
    verbose: bool,

    /// Initialize sample config file
    #[arg(long)]
    init_config: bool,

    /// Keep VPN connection alive after tests
    #[arg(long)]
    keep_alive: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Deploy server only (no tests)
    Deploy,
    /// Run tests only (server must be running)
    Test,
    /// Show server status and logs
    Status,
    /// Stop remote server
    Stop,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let filter = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    // Handle init-config
    if cli.init_config {
        let path = PathBuf::from("config/e2e.json");
        E2eConfig::create_sample(&path)?;
        println!("Sample config created at: {:?}", path);
        println!("Edit the file and run: vpr-e2e --config config/e2e.json");
        return Ok(());
    }

    // Load config
    let mut config = E2eConfig::load(cli.config.as_ref())?;

    // Override with CLI args
    if let Some(host) = cli.host {
        config.server.host = host;
    }
    if let Some(password) = cli.password {
        config.server.password = Some(password);
    }
    config.server.user = cli.user;
    config.server.vpn_port = cli.port;
    config.client.insecure = cli.insecure;
    config.output.dir = cli.output;
    config.output.verbose = cli.verbose;

    config.validate()?;

    // Create output directory
    std::fs::create_dir_all(&config.output.dir)?;

    // Handle subcommands
    match cli.command {
        Some(Commands::Deploy) => {
            deploy_only(&config).await?;
        }
        Some(Commands::Test) => {
            test_only(&config).await?;
        }
        Some(Commands::Status) => {
            show_status(&config).await?;
        }
        Some(Commands::Stop) => {
            stop_server(&config).await?;
        }
        None => {
            // Full E2E test
            run_full_e2e(&config, cli.deploy, cli.rebuild, cli.keep_alive).await?;
        }
    }

    Ok(())
}

async fn deploy_only(config: &E2eConfig) -> Result<()> {
    println!("{}", "═".repeat(60).blue());
    println!("{}", " VPR Server Deployment ".bold().blue());
    println!("{}", "═".repeat(60).blue());

    let deployer = Deployer::new(config.clone());

    deployer.test_connection().await?;
    deployer.prepare_server().await?;
    deploy_binaries(&deployer, config, false).await?;
    deployer.ensure_server_keys().await?;
    deployer.stop_server().await?;
    deployer.start_server().await?;

    println!("{}", "Server deployed and running!".green().bold());
    Ok(())
}

async fn test_only(config: &E2eConfig) -> Result<()> {
    println!("{}", "═".repeat(60).blue());
    println!("{}", " VPR Connection Test ".bold().blue());
    println!("{}", "═".repeat(60).blue());

    let deployer = Deployer::new(config.clone());

    // Verify server is running
    if !deployer.is_server_running().await {
        anyhow::bail!("Server is not running. Use --deploy to start it.");
    }

    // Sync keys
    sync_keys(&deployer, config).await?;

    // Start client and run tests
    let report = run_client_tests(config).await?;
    report.print_summary();

    if !report.all_passed() {
        std::process::exit(1);
    }

    Ok(())
}

async fn show_status(config: &E2eConfig) -> Result<()> {
    let deployer = Deployer::new(config.clone());

    println!("Server: {}:{}", config.server.host, config.server.vpn_port);

    if deployer.is_server_running().await {
        println!("Status: {}", "RUNNING".green());
        println!("\nRecent logs:");
        let logs = deployer.get_server_logs(20).await?;
        println!("{}", logs);
    } else {
        println!("Status: {}", "STOPPED".red());
    }

    Ok(())
}

async fn stop_server(config: &E2eConfig) -> Result<()> {
    let deployer = Deployer::new(config.clone());
    deployer.stop_server().await?;
    println!("{}", "Server stopped".green());
    Ok(())
}

async fn run_full_e2e(
    config: &E2eConfig,
    deploy: bool,
    rebuild: bool,
    keep_alive: bool,
) -> Result<()> {
    let start = Instant::now();

    println!("{}", "═".repeat(60).blue());
    println!("{}", " VPR E2E Test Suite ".bold().blue());
    println!("{}", "═".repeat(60).blue());

    let deployer = Deployer::new(config.clone());

    // Test SSH connection
    let pb = progress_spinner("Testing SSH connection...");
    deployer.test_connection().await?;
    pb.finish_with_message("SSH connection OK");

    // Deploy if requested or server not running
    if deploy || !deployer.is_server_running().await {
        let pb = progress_spinner("Preparing server...");
        deployer.prepare_server().await?;
        pb.finish_with_message("Server prepared");

        deploy_binaries(&deployer, config, rebuild).await?;

        let pb = progress_spinner("Generating server keys...");
        deployer.ensure_server_keys().await?;
        pb.finish_with_message("Keys ready");

        let pb = progress_spinner("Starting VPN server...");
        deployer.stop_server().await?;
        deployer.start_server().await?;
        pb.finish_with_message("Server started");
    }

    // Sync keys
    sync_keys(&deployer, config).await?;

    // Run client tests
    let mut report = run_client_tests(config).await?;

    // Get server logs
    report.server_logs = deployer.get_server_logs(30).await.ok();

    // Save reports
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    if config.output.json {
        let path = config.output.dir.join(format!("report_{}.json", timestamp));
        report.save_json(&path)?;
        println!("JSON report: {:?}", path);
    }
    if config.output.markdown {
        let path = config.output.dir.join(format!("report_{}.md", timestamp));
        report.save_markdown(&path)?;
        println!("Markdown report: {:?}", path);
    }

    report.print_summary();

    println!("Total time: {:?}", start.elapsed());

    if keep_alive {
        println!(
            "\n{}",
            "VPN connection kept alive. Press Ctrl+C to stop.".yellow()
        );
        tokio::signal::ctrl_c().await?;
    }

    if !report.all_passed() {
        std::process::exit(1);
    }

    Ok(())
}

async fn deploy_binaries(deployer: &Deployer, config: &E2eConfig, rebuild: bool) -> Result<()> {
    let project_dir = std::env::current_dir()?;

    // Check if we need to build
    let server_binary = project_dir.join("target/release/vpn-server");
    let keygen_binary = project_dir.join("target/release/vpr-keygen");

    let need_build = rebuild || !server_binary.exists() || !keygen_binary.exists();

    if need_build {
        let pb = progress_spinner("Building VPN binaries...");

        let status = Command::new("cargo")
            .args([
                "build",
                "--release",
                "-p",
                "masque-core",
                "-p",
                "vpr-crypto",
            ])
            .current_dir(&project_dir)
            .stdout(if config.output.verbose {
                Stdio::inherit()
            } else {
                Stdio::null()
            })
            .stderr(if config.output.verbose {
                Stdio::inherit()
            } else {
                Stdio::null()
            })
            .status()
            .await?;

        if !status.success() {
            pb.finish_with_message("Build failed!");
            anyhow::bail!("Failed to build binaries");
        }
        pb.finish_with_message("Build complete");
    }

    // Check if server binary needs update
    if !deployer.server_binary_exists().await? || rebuild {
        let pb = progress_spinner("Uploading server binary...");
        deployer.deploy_server_binary(&server_binary).await?;
        pb.finish_with_message("Server binary uploaded");

        let pb = progress_spinner("Uploading keygen binary...");
        deployer.deploy_keygen_binary(&keygen_binary).await?;
        pb.finish_with_message("Keygen binary uploaded");
    }

    Ok(())
}

async fn sync_keys(deployer: &Deployer, config: &E2eConfig) -> Result<()> {
    let pb = progress_spinner("Syncing cryptographic keys...");

    // Create local secrets dir
    std::fs::create_dir_all(&config.client.secrets_dir)?;

    // Download server public key
    let server_pub = config.client.secrets_dir.join("server.noise.pub");
    deployer.download_server_pubkey(&server_pub).await?;

    // Generate client keys if needed
    let client_key = config.client.secrets_dir.join("client.noise.key");
    if !client_key.exists() {
        let keygen = std::env::current_dir()?.join("target/release/vpr-keygen");
        let secrets_dir_str = config
            .client
            .secrets_dir
            .to_str()
            .context("secrets_dir must be valid UTF-8")?;

        let status = Command::new(&keygen)
            .args([
                "gen-noise-key",
                "--name",
                "client",
                "--output",
                secrets_dir_str,
            ])
            .status()
            .await?;

        if !status.success() {
            anyhow::bail!("Failed to generate client keys");
        }
    }

    pb.finish_with_message("Keys synced");
    Ok(())
}

async fn run_client_tests(config: &E2eConfig) -> Result<E2eReport> {
    let mut report = E2eReport::new(
        config.server.host.clone(),
        config.server.vpn_port,
        config.client.tls_profile.clone(),
    );

    // Start VPN client
    let pb = progress_spinner("Starting VPN client...");

    let mut client = start_vpn_client(config).await?;

    // Wait for TUN device
    let tun_name = &config.client.tun_name;
    let mut attempts = 0;
    while attempts < TUN_WAIT_TIMEOUT_SECS {
        let output = Command::new("ip")
            .args(["link", "show", tun_name])
            .output()
            .await?;

        if output.status.success() {
            break;
        }

        // Check if client died - capture stderr for diagnostics
        if let Ok(Some(status)) = client.try_wait() {
            pb.finish_with_message("Client failed!");
            let stderr = capture_child_stderr(&mut client).await;
            anyhow::bail!(
                "VPN client exited with status: {:?}\nClient stderr:\n{}",
                status,
                if stderr.is_empty() {
                    "(no output)"
                } else {
                    &stderr
                }
            );
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
        attempts += 1;
    }

    if attempts >= TUN_WAIT_TIMEOUT_SECS {
        let _ = client.kill().await;
        let _ = client.wait().await; // Prevent zombie process
        anyhow::bail!(
            "TUN device not created after {} seconds",
            TUN_WAIT_TIMEOUT_SECS
        );
    }

    pb.finish_with_message("VPN connected");

    // Wait for connection to stabilize
    tokio::time::sleep(Duration::from_secs(CONNECTION_STABILIZE_SECS)).await;

    // Run tests
    let test_runner = TestRunner::new(config.clone());
    let results = test_runner.run_all().await;

    for result in results {
        report.add_test(result);
    }

    // Stop client and wait to prevent zombie
    let _ = client.kill().await;
    let _ = client.wait().await;

    // Cleanup TUN
    let _ = Command::new("ip")
        .args(["link", "del", tun_name])
        .status()
        .await;

    Ok(report)
}

async fn start_vpn_client(config: &E2eConfig) -> Result<tokio::process::Child> {
    let project_dir = std::env::current_dir()?;
    let client_binary = project_dir.join("target/release/vpn-client");

    let secrets_dir_str = config
        .client
        .secrets_dir
        .to_str()
        .context("secrets_dir must be valid UTF-8")?;

    let server_pub_path = config.client.secrets_dir.join("server.noise.pub");
    let server_pub_str = server_pub_path
        .to_str()
        .context("server_pub path must be valid UTF-8")?;

    let mut cmd = Command::new("sudo");
    cmd.arg(&client_binary);
    cmd.args([
        "--server",
        &format!("{}:{}", config.server.host, config.server.vpn_port),
        "--server-name",
        &config.server.host,
        "--tun-name",
        &config.client.tun_name,
        "--noise-dir",
        secrets_dir_str,
        "--noise-name",
        "client",
        "--server-pub",
        server_pub_str,
        "--tls-profile",
        &config.client.tls_profile,
    ]);

    if config.client.insecure {
        cmd.arg("--insecure");
    }

    cmd.env("RUST_LOG", "info");
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let child = cmd.spawn().context("Failed to start VPN client")?;
    Ok(child)
}

fn progress_spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.blue} {msg}")
            .unwrap(),
    );
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(Duration::from_millis(100));
    pb
}

/// Capture stderr from a child process for diagnostics
async fn capture_child_stderr(child: &mut tokio::process::Child) -> String {
    use tokio::io::AsyncReadExt;

    if let Some(mut stderr) = child.stderr.take() {
        let mut buf = String::new();
        match tokio::time::timeout(Duration::from_secs(2), stderr.read_to_string(&mut buf)).await {
            Ok(Ok(_)) => buf,
            _ => String::new(),
        }
    } else {
        String::new()
    }
}
