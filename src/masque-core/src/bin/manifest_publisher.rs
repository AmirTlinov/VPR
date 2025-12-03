//! Manifest Publisher Service
//!
//! HTTP service that publishes bootstrap manifests encoded in RSS feeds
//! using steganographic techniques. The RSS feed appears as a normal
//! news/blog feed while containing encoded manifest data.
//!
//! Usage:
//!   manifest_publisher --bind 0.0.0.0:8080 --manifest-path /path/to/manifest.json

use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use clap::Parser;
use masque_core::stego_rss::{StegoMethod, StegoRssConfig, StegoRssEncoder};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use vpr_crypto::manifest::{ManifestPayload, SignedManifest};

#[derive(Parser, Debug)]
#[command(name = "manifest_publisher")]
#[command(about = "Publishes bootstrap manifests via steganographic RSS feeds")]
struct Args {
    /// Bind address for HTTP server
    #[arg(long, default_value = "0.0.0.0:8080")]
    bind: SocketAddr,

    /// Path to manifest file (JSON)
    #[arg(long)]
    manifest_path: Option<PathBuf>,

    /// RSS feed title (cover text)
    #[arg(long, default_value = "Tech News Feed")]
    feed_title: String,

    /// RSS feed description (cover text)
    #[arg(long, default_value = "Latest technology news and updates")]
    feed_description: String,

    /// RSS feed link (cover URL)
    #[arg(long, default_value = "https://example.com/feed")]
    feed_link: String,

    /// Steganographic method to use
    #[arg(long, default_value = "hybrid")]
    stego_method: String,

    /// Minimum number of RSS items
    #[arg(long, default_value_t = 10)]
    min_items: usize,

    /// Maximum number of RSS items
    #[arg(long, default_value_t = 50)]
    max_items: usize,

    /// Enable auto-reload of manifest file
    #[arg(long, default_value_t = false)]
    auto_reload: bool,

    /// Reload interval in seconds
    #[arg(long, default_value_t = 60)]
    reload_interval: u64,
}

/// Application state
#[derive(Clone)]
struct AppState {
    /// Current manifest (signed)
    manifest: Arc<RwLock<Option<SignedManifest>>>,
    /// Current manifest payload (unsigned)
    payload: Arc<RwLock<Option<ManifestPayload>>>,
    /// RSS encoder configuration
    encoder_config: StegoRssConfig,
    /// Manifest file path (if provided)
    manifest_path: Option<PathBuf>,
}

impl AppState {
    fn new(config: StegoRssConfig, manifest_path: Option<PathBuf>) -> Self {
        Self {
            manifest: Arc::new(RwLock::new(None)),
            payload: Arc::new(RwLock::new(None)),
            encoder_config: config,
            manifest_path,
        }
    }

    async fn load_manifest(&self) -> Result<()> {
        if let Some(ref path) = self.manifest_path {
            let content = fs::read_to_string(path)
                .await
                .context("failed to read manifest file")?;

            // Try to parse as SignedManifest first
            if let Ok(manifest) = serde_json::from_str::<SignedManifest>(&content) {
                // Parse payload from JSON string
                if let Ok(payload) = serde_json::from_str::<ManifestPayload>(&manifest.payload) {
                    *self.manifest.write().await = Some(manifest);
                    *self.payload.write().await = Some(payload);
                    info!("Loaded signed manifest from {}", path.display());
                    return Ok(());
                }
            }

            // Try to parse as ManifestPayload
            if let Ok(payload) = serde_json::from_str::<ManifestPayload>(&content) {
                *self.payload.write().await = Some(payload);
                info!("Loaded manifest payload from {}", path.display());
                return Ok(());
            }

            return Err(anyhow::anyhow!("failed to parse manifest file"));
        }

        Ok(())
    }

    async fn get_rss_feed(&self) -> Result<String> {
        let mut encoder = StegoRssEncoder::new(self.encoder_config.clone());

        // Try to encode signed manifest first
        {
            let manifest_guard = self.manifest.read().await;
            if let Some(ref manifest) = *manifest_guard {
                return encoder.encode_manifest(manifest);
            }
        }

        // Fallback to payload
        let payload_guard = self.payload.read().await;
        if let Some(ref payload) = *payload_guard {
            return encoder.encode_payload(payload);
        }

        Err(anyhow::anyhow!("no manifest loaded"))
    }
}

/// Handle RSS feed request
async fn handle_rss_feed(State(state): State<AppState>) -> Response {
    match state.get_rss_feed().await {
        Ok(rss_xml) => (
            StatusCode::OK,
            [
                ("Content-Type", "application/rss+xml; charset=utf-8"),
                ("Cache-Control", "public, max-age=300"),
            ],
            rss_xml,
        )
            .into_response(),
        Err(e) => {
            error!("Failed to generate RSS feed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to generate RSS feed: {}", e),
            )
                .into_response()
        }
    }
}

/// Handle health check
async fn handle_health(State(state): State<AppState>) -> Response {
    let has_manifest = {
        let manifest_guard = state.manifest.read().await;
        let payload_guard = state.payload.read().await;
        manifest_guard.is_some() || payload_guard.is_some()
    };

    if has_manifest {
        (StatusCode::OK, "OK").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "No manifest loaded").into_response()
    }
}

/// Handle manifest update (POST /update)
async fn handle_update(State(state): State<AppState>, body: String) -> Response {
    // Try to parse as SignedManifest
    if let Ok(manifest) = serde_json::from_str::<SignedManifest>(&body) {
        // Parse payload from JSON string
        if let Ok(payload) = serde_json::from_str::<ManifestPayload>(&manifest.payload) {
            *state.manifest.write().await = Some(manifest);
            *state.payload.write().await = Some(payload);
            info!("Updated manifest via API");
            return (StatusCode::OK, "Manifest updated").into_response();
        }
    }

    // Try to parse as ManifestPayload
    if let Ok(payload) = serde_json::from_str::<ManifestPayload>(&body) {
        *state.payload.write().await = Some(payload);
        info!("Updated manifest payload via API");
        return (StatusCode::OK, "Manifest payload updated").into_response();
    }

    (
        StatusCode::BAD_REQUEST,
        "Invalid manifest format (expected SignedManifest or ManifestPayload JSON)",
    )
        .into_response()
}

/// Background task to reload manifest file periodically
async fn reload_task(state: AppState, interval_secs: u64) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        if let Err(e) = state.load_manifest().await {
            warn!("Failed to reload manifest: {}", e);
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    // Parse steganographic method
    let stego_method = match args.stego_method.to_lowercase().as_str() {
        "whitespace" => StegoMethod::Whitespace,
        "base64" | "base64content" => StegoMethod::Base64Content,
        "ordering" => StegoMethod::Ordering,
        "timestamp" => StegoMethod::Timestamp,
        "hybrid" => StegoMethod::Hybrid,
        _ => {
            warn!("Unknown stego method '{}', using hybrid", args.stego_method);
            StegoMethod::Hybrid
        }
    };

    // Create encoder configuration
    let encoder_config = StegoRssConfig {
        method: stego_method,
        feed_title: args.feed_title.clone(),
        feed_description: args.feed_description.clone(),
        feed_link: args.feed_link.clone(),
        min_items: args.min_items,
        max_items: args.max_items,
        random_order: true,
        seed: None,
    };

    // Create application state
    let state = AppState::new(encoder_config, args.manifest_path.clone());

    // Load initial manifest if path provided
    if args.manifest_path.is_some() {
        if let Err(e) = state.load_manifest().await {
            warn!("Failed to load initial manifest: {}", e);
        }
    }

    // Spawn reload task if auto-reload enabled
    if args.auto_reload && args.manifest_path.is_some() {
        let reload_state = state.clone();
        tokio::spawn(async move {
            reload_task(reload_state, args.reload_interval).await;
        });
        info!("Auto-reload enabled (interval: {}s)", args.reload_interval);
    }

    // Build router
    let app = Router::new()
        .route("/feed", get(handle_rss_feed))
        .route("/rss", get(handle_rss_feed)) // Alias
        .route("/health", get(handle_health))
        .route("/update", post(handle_update))
        .with_state(state);

    // Start server
    info!("Starting Manifest Publisher Service on {}", args.bind);
    info!("RSS feed available at: http://{}/feed", args.bind);
    info!("Health check: http://{}/health", args.bind);
    info!("Update endpoint: POST http://{}/update", args.bind);

    let listener = tokio::net::TcpListener::bind(args.bind)
        .await
        .context("failed to bind to address")?;

    axum::serve(listener, app)
        .await
        .context("HTTP server error")?;

    Ok(())
}
