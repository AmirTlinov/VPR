use anyhow::{anyhow, bail, Context, Result};
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bytes::Bytes;
use clap::Parser;
use config as config_rs;
use masque_core::cert_manager::{CertificateManager, CertificateManagerConfig};
use odoh_rs::{
    compose, decrypt_query, encrypt_response, parse, ObliviousDoHConfig, ObliviousDoHConfigs,
    ObliviousDoHKeyPair, ObliviousDoHMessage, ObliviousDoHMessagePlaintext, ResponseNonce,
    ODOH_HTTP_HEADER,
};

use quinn::{Connecting, Endpoint, TransportConfig};
use rand::{rngs::OsRng, RngCore};
use rcgen::generate_simple_self_signed;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    ServerConfig,
};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::HashMap,
    fs,
    io::BufReader,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

const ODOH_DEFAULT_KEM: u16 = 0x0020;
const ODOH_DEFAULT_KDF: u16 = 0x0001;
const ODOH_DEFAULT_AEAD: u16 = 0x0001;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "0.0.0.0:8053")]
    bind: SocketAddr,
    #[arg(long, default_value = "1.1.1.1:53")]
    upstream: SocketAddr,
    #[arg(long, default_value = "0.0.0.0:8853")]
    doq_bind: SocketAddr,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    odoh_enable: bool,
    #[arg(long)]
    odoh_seed: Option<PathBuf>,
    /// Domain for automatic certificate management via ACME
    #[arg(long)]
    cert_domain: Option<String>,
    /// ACME directory URL (e.g., https://acme-v02.api.letsencrypt.org/directory)
    #[arg(long)]
    acme_directory_url: Option<String>,
    /// Certificate storage directory
    #[arg(long)]
    cert_dir: Option<PathBuf>,
}

#[derive(Clone)]
struct AppState {
    upstream: SocketAddr,
    odoh: Option<OdohRuntime>,
    cert_manager: Option<Arc<RwLock<CertificateManager>>>,
    cert_domain: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct FileConfig {
    bind: Option<SocketAddr>,
    upstream: Option<SocketAddr>,
    doq_bind: Option<SocketAddr>,
    doq_cert: Option<PathBuf>,
    doq_key: Option<PathBuf>,
    odoh_enable: Option<bool>,
    odoh_seed: Option<PathBuf>,
    cert_domain: Option<String>,
    acme_directory_url: Option<String>,
    cert_dir: Option<PathBuf>,
}

struct CertMaterial {
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

#[derive(Clone)]
struct OdohRuntime {
    key_pair: Arc<ObliviousDoHKeyPair>,
    configs_blob: Bytes,
}

impl OdohRuntime {
    fn new(key_pair: ObliviousDoHKeyPair) -> Result<Self> {
        let configs: ObliviousDoHConfigs =
            vec![ObliviousDoHConfig::from(key_pair.public().clone())].into();
        let blob = compose(&configs)
            .context("serializing ODoH configs")?
            .freeze();
        Ok(Self {
            key_pair: Arc::new(key_pair),
            configs_blob: blob,
        })
    }

    fn configs(&self) -> Bytes {
        self.configs_blob.clone()
    }

    fn key_pair(&self) -> Arc<ObliviousDoHKeyPair> {
        self.key_pair.clone()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install rustls crypto provider (required in rustls 0.23+)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let file_cfg = args
        .config
        .as_ref()
        .map(|p| load_config(p.as_path()))
        .transpose()?;
    let bind = file_cfg
        .as_ref()
        .and_then(|cfg| cfg.bind)
        .unwrap_or(args.bind);
    let upstream = file_cfg
        .as_ref()
        .and_then(|cfg| cfg.upstream)
        .unwrap_or(args.upstream);
    let doq_bind = file_cfg
        .as_ref()
        .and_then(|cfg| cfg.doq_bind)
        .unwrap_or(args.doq_bind);
    let doq_cert = file_cfg
        .as_ref()
        .and_then(|cfg| cfg.doq_cert.as_ref())
        .cloned();
    let doq_key = file_cfg
        .as_ref()
        .and_then(|cfg| cfg.doq_key.as_ref())
        .cloned();
    let odoh_enable = file_cfg
        .as_ref()
        .and_then(|cfg| cfg.odoh_enable)
        .unwrap_or(args.odoh_enable);
    let odoh_seed = args
        .odoh_seed
        .clone()
        .or_else(|| file_cfg.as_ref().and_then(|cfg| cfg.odoh_seed.clone()));

    let cert_domain = file_cfg
        .as_ref()
        .and_then(|cfg| cfg.cert_domain.clone())
        .or(args.cert_domain.clone());

    let acme_directory_url = file_cfg
        .as_ref()
        .and_then(|cfg| cfg.acme_directory_url.clone())
        .or(args.acme_directory_url.clone());

    let cert_dir = file_cfg
        .as_ref()
        .and_then(|cfg| cfg.cert_dir.clone())
        .or(args.cert_dir.clone());

    // Initialize Certificate Manager if domain is provided
    let cert_manager = if let Some(domain) = &cert_domain {
        let mut cert_config = CertificateManagerConfig::new()?;
        if let Some(dir) = cert_dir {
            cert_config.cert_dir = dir;
        }
        if let Some(acme_url) = acme_directory_url {
            cert_config.acme_config.directory_url = acme_url;
        } else {
            // Default to Let's Encrypt staging for safety
            cert_config.acme_config.directory_url =
                "https://acme-staging-v02.api.letsencrypt.org/directory".to_string();
            warn!(
                "Using Let's Encrypt staging environment - set acme_directory_url for production"
            );
        }

        match CertificateManager::new(cert_config).await {
            Ok(manager) => {
                info!("Certificate Manager initialized for domain: {}", domain);
                Some(Arc::new(RwLock::new(manager)))
            }
            Err(e) => {
                warn!("Failed to initialize Certificate Manager: {} - falling back to manual cert/key", e);
                None
            }
        }
    } else {
        None
    };

    // Ensure certificate exists if Certificate Manager is enabled
    if let (Some(ref manager), Some(ref domain)) = (&cert_manager, &cert_domain) {
        let mut mgr = manager.write().await;
        if mgr.get_certificate_info(domain).await?.is_none() {
            info!(
                "No certificate found for domain {}, attempting to obtain via ACME...",
                domain
            );
            if let Err(e) = mgr.obtain_certificate(domain).await {
                warn!(
                    "Failed to obtain certificate: {} - will use self-signed fallback",
                    e
                );
            }
        } else {
            // Check if renewal is needed
            if mgr.renew_if_needed(domain).await?.is_some() {
                info!("Certificate renewed for domain: {}", domain);
            }
        }
    }

    let odoh_runtime = if odoh_enable {
        let runtime = init_odoh_state(odoh_seed.as_ref())?;
        if odoh_seed.is_none() {
            info!("ODoH enabled with ephemeral key (no seed provided)");
        }
        Some(runtime)
    } else {
        None
    };

    let state = Arc::new(AppState {
        upstream,
        odoh: odoh_runtime,
        cert_manager: cert_manager.clone(),
        cert_domain: cert_domain.clone(),
    });

    // Prepare certificate material once for all listeners
    let cert_material = Arc::new(
        load_cert_material(doq_cert.as_ref(), doq_key.as_ref(), &state)
            .await
            .context("loading certificate material")?,
    );

    let rustls_config = build_rustls_config(&cert_material)?;

    let http_state = state.clone();
    let http_task = tokio::spawn(async move {
        let app = Router::new()
            .route("/dns-query", get(handle_get).post(handle_post))
            .route("/.well-known/odohconfigs", get(handle_odoh_configs))
            .route("/odoh-query", post(handle_odoh_query))
            .with_state(http_state);

        info!(
            "DoH gateway (TLS) listening on {} upstream {}",
            bind, upstream
        );
        axum_server::bind_rustls(bind, rustls_config)
            .serve(app.into_make_service())
            .await
            .context("serving DoH over TLS")?;
        Ok::<_, anyhow::Error>(())
    });

    // Spawn certificate renewal task if Certificate Manager is enabled
    if let (Some(ref manager), Some(ref domain)) = (&cert_manager, &cert_domain) {
        let manager_clone = manager.clone();
        let domain_clone = domain.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3600)); // Check every hour
            loop {
                interval.tick().await;
                let mut mgr = manager_clone.write().await;
                if mgr
                    .renew_if_needed(&domain_clone)
                    .await
                    .ok()
                    .flatten()
                    .is_some()
                {
                    info!(
                        "Certificate automatically renewed for domain: {}",
                        domain_clone
                    );
                }
            }
        });
    }

    let doq_task = tokio::spawn(run_doq(doq_bind, cert_material.clone(), state.clone()));

    let (http_res, doq_res) = tokio::join!(http_task, doq_task);
    http_res??;
    doq_res??;
    Ok(())
}

async fn handle_get(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let encoded = params
        .get("dns")
        .ok_or_else(|| fail(anyhow!("missing dns parameter")))?;
    let body = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|err| fail(anyhow!(err)))?;
    let resp = resolve(&state, body.into()).await.map_err(fail)?;
    Ok(success_response(resp))
}

async fn handle_post(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let resp = resolve(&state, body).await.map_err(fail)?;
    Ok(success_response(resp))
}

async fn handle_odoh_configs(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let odoh = state
        .odoh
        .as_ref()
        .ok_or_else(|| fail(anyhow!("ODoH disabled")))?;
    Ok((
        [
            ("content-type", ODOH_HTTP_HEADER),
            ("cache-control", "no-store"),
        ],
        odoh.configs(),
    ))
}

async fn handle_odoh_query(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let odoh = state
        .odoh
        .as_ref()
        .ok_or_else(|| fail(anyhow!("ODoH disabled")))?;
    let key_pair = odoh.key_pair();

    let mut cursor = body.clone();
    let odoh_msg: ObliviousDoHMessage = parse(&mut cursor).map_err(|err| fail(anyhow!(err)))?;
    let (query_plain, secret) =
        decrypt_query(&odoh_msg, &key_pair).map_err(|err| fail(anyhow!(err)))?;

    let dns_query = query_plain.clone().into_msg();
    let response_body = resolve(&state, dns_query).await.map_err(fail)?;
    let response_plain =
        ObliviousDoHMessagePlaintext::new(response_body.clone(), query_plain.padding_len());

    let mut nonce = ResponseNonce::default();
    OsRng.fill_bytes(&mut nonce);
    let encrypted = encrypt_response(&query_plain, &response_plain, secret, nonce)
        .map_err(|err| fail(anyhow!(err)))?;
    let payload = compose(&encrypted)
        .map_err(|err| fail(anyhow!(err)))?
        .freeze();

    Ok((
        [
            ("content-type", ODOH_HTTP_HEADER),
            ("cache-control", "no-store"),
        ],
        payload,
    ))
}

async fn resolve(state: &AppState, query: Bytes) -> Result<Bytes> {
    let socket = UdpSocket::bind(("0.0.0.0", 0)).await?;
    socket.send_to(&query, state.upstream).await?;
    let mut buf = vec![0u8; 2048];
    let (len, _) = socket.recv_from(&mut buf).await?;
    buf.truncate(len);
    Ok(Bytes::from(buf))
}

fn success_response(body: Bytes) -> impl IntoResponse {
    (
        [
            ("content-type", "application/dns-message"),
            ("cache-control", "no-store"),
        ],
        body,
    )
}

fn fail(err: anyhow::Error) -> (StatusCode, Json<serde_json::Value>) {
    error!(?err, "DoH request failed");
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": err.to_string()})),
    )
}

fn load_config(path: &Path) -> Result<FileConfig> {
    let builder = config_rs::Config::builder().add_source(config_rs::File::from(path));
    let cfg = builder
        .build()
        .context("reading config")?
        .try_deserialize()
        .context("parsing config")?;
    Ok(cfg)
}

async fn run_doq(bind: SocketAddr, certs: Arc<CertMaterial>, state: Arc<AppState>) -> Result<()> {
    let server_config = build_quic_config(&certs)?;
    let endpoint = Endpoint::server(server_config, bind)?;
    info!("DoQ listening on {}", bind);
    while let Some(incoming) = endpoint.accept().await {
        let state = state.clone();
        tokio::spawn(async move {
            match incoming.accept() {
                Ok(connecting) => {
                    if let Err(err) = handle_doq_connection(connecting, state).await {
                        error!(%err, "DoQ connection error");
                    }
                }
                Err(err) => error!(%err, "Failed to accept DoQ connection"),
            }
        });
    }
    Ok(())
}

async fn handle_doq_connection(
    conn: Connecting,
    state: Arc<AppState>,
) -> Result<(), anyhow::Error> {
    let connection = conn.await?;
    loop {
        match connection.accept_bi().await {
            Ok((mut send, mut recv)) => {
                let query = read_quic_frame(&mut recv).await?;
                let resp = resolve(&state, query.into()).await?;
                write_quic_frame(&mut send, &resp).await?;
                send.finish()?;
            }
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => break,
            Err(quinn::ConnectionError::ConnectionClosed(_)) => break,
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

async fn read_quic_frame(stream: &mut quinn::RecvStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_quic_frame(stream: &mut quinn::SendStream, data: &[u8]) -> Result<()> {
    if data.len() > u16::MAX as usize {
        bail!("DNS payload too large");
    }
    let len_buf = (data.len() as u16).to_be_bytes();
    stream.write_all(&len_buf).await?;
    stream.write_all(data).await?;
    Ok(())
}

async fn load_cert_material(
    cert: Option<&PathBuf>,
    key: Option<&PathBuf>,
    state: &AppState,
) -> Result<CertMaterial> {
    if let (Some(cert_path), Some(key_path)) = (cert, key) {
        return Ok(CertMaterial {
            certs: load_certs(cert_path)?,
            key: load_key(key_path)?,
        });
    }

    if let (Some(ref manager), Some(ref domain)) = (&state.cert_manager, &state.cert_domain) {
        let mgr = manager.read().await;
        match mgr.load_certificate(domain).await {
            Ok((loaded_certs, loaded_key)) => {
                info!(
                    "Loaded certificate from Certificate Manager for domain: {}",
                    domain
                );
                return Ok(CertMaterial {
                    certs: loaded_certs.into_iter().collect(),
                    key: loaded_key.clone_key(),
                });
            }
            Err(e) => {
                warn!("Failed to load certificate from Certificate Manager: {} - using self-signed fallback", e);
                let generated = generate_simple_self_signed([domain.clone()])?;
                let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
                    generated.signing_key.serialize_der(),
                ));
                let cert = CertificateDer::from(generated.cert.der().to_vec());
                return Ok(CertMaterial {
                    certs: vec![cert],
                    key,
                });
            }
        }
    }

    // Fallback to self-signed certificate
    let generated = generate_simple_self_signed(["localhost".into()])?;
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
        generated.signing_key.serialize_der(),
    ));
    let cert = CertificateDer::from(generated.cert.der().to_vec());
    Ok(CertMaterial {
        certs: vec![cert],
        key,
    })
}

fn build_quic_config(material: &CertMaterial) -> Result<quinn::ServerConfig> {
    let mut server_config =
        quinn::ServerConfig::with_single_cert(material.certs.clone(), material.key.clone_key())?;
    server_config.transport = Arc::new(TransportConfig::default());
    Ok(server_config)
}

fn build_rustls_config(material: &CertMaterial) -> Result<RustlsConfig> {
    let certs = material.certs.clone();
    let key = material.key.clone_key();

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(config)))
}

fn load_certs(path: &PathBuf) -> Result<Vec<CertificateDer<'static>>> {
    let file = fs::File::open(path).with_context(|| format!("reading cert {path:?}"))?;
    let mut reader = BufReader::new(file);
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certs = certs.context("parsing certs")?;
    if certs.is_empty() {
        bail!("no certificates found in {path:?}");
    }
    Ok(certs.into_iter().collect())
}

fn load_key(path: &PathBuf) -> Result<PrivateKeyDer<'static>> {
    let file = fs::File::open(path).with_context(|| format!("reading key {path:?}"))?;
    let mut reader = BufReader::new(file);
    match rustls_pemfile::private_key(&mut reader).context("parsing private key")? {
        Some(key) => Ok(key),
        None => bail!("no private key in {path:?}"),
    }
}

fn init_odoh_state(seed: Option<&PathBuf>) -> Result<OdohRuntime> {
    let ikm = if let Some(path) = seed {
        let data = fs::read(path).with_context(|| format!("reading odoh_seed {path:?}"))?;
        if data.is_empty() {
            bail!("odoh_seed {path:?} is empty");
        }
        data
    } else {
        let mut buffer = [0u8; 32];
        OsRng.fill_bytes(&mut buffer);
        buffer.to_vec()
    };
    let key_pair = ObliviousDoHKeyPair::from_parameters(
        ODOH_DEFAULT_KEM,
        ODOH_DEFAULT_KDF,
        ODOH_DEFAULT_AEAD,
        &ikm,
    );
    OdohRuntime::new(key_pair)
}
