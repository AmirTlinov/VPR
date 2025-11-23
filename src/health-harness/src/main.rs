use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use clap::Parser;
use odoh_rs::{
    compose, decrypt_response, encrypt_query, parse, ObliviousDoHConfigs, ObliviousDoHMessage,
    ObliviousDoHMessagePlaintext, ODOH_HTTP_HEADER,
};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::ClientConfig;
use rand::{rngs::StdRng, SeedableRng};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig as RustlsClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use rustls_native_certs::load_native_certs;
use serde::Serialize;
use serde_json;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::time::timeout;
use url::Url;

#[derive(Parser, Debug)]
#[command(about = "VPR health harness", version)]
struct Args {
    #[arg(long)]
    doh_url: Option<String>,
    #[arg(long)]
    doq_addr: Option<String>,
    #[arg(long)]
    odoh_url: Option<String>,
    #[arg(long)]
    odoh_config_url: Option<String>,
    #[arg(long, default_value = "example.com")]
    name: String,
    #[arg(long, default_value_t = 5)]
    timeout_secs: u64,
    #[arg(long)]
    server_name: Option<String>,
    #[arg(long, default_value_t = false)]
    insecure_tls: bool,
    #[arg(long, default_value_t = 1)]
    samples: usize,
}

#[derive(Serialize)]
struct TransportResult {
    transport: String,
    ok: bool,
    latency_ms: u128,
    jitter_ms: f32,
    bytes_out: usize,
    bytes_in: usize,
    samples: u32,
    rcode: Option<u8>,
    status_code: Option<u16>,
    detail: Option<String>,
}

impl TransportResult {
    fn success(
        name: &str,
        latency_ms: u128,
        jitter_ms: f32,
        out: usize,
        r#in: usize,
        samples: usize,
    ) -> Self {
        Self {
            transport: name.to_string(),
            ok: true,
            latency_ms,
            jitter_ms,
            bytes_out: out,
            bytes_in: r#in,
            samples: samples as u32,
            rcode: None,
            status_code: None,
            detail: None,
        }
    }

    fn error(name: &str, err: &anyhow::Error) -> Self {
        Self {
            transport: name.to_string(),
            ok: false,
            latency_ms: 0,
            jitter_ms: 0.0,
            bytes_out: 0,
            bytes_in: 0,
            samples: 0,
            rcode: None,
            status_code: None,
            detail: Some(err.to_string()),
        }
    }
}

#[derive(Serialize)]
struct HealthReport {
    target: String,
    query: String,
    results: Vec<TransportResult>,
    suspicion: f32,
    generated_at: u64,
}

fn latency_stats(latencies: &[u128]) -> (u128, f32) {
    if latencies.is_empty() {
        return (0, 0.0);
    }
    let total: u128 = latencies.iter().sum();
    let avg = total / latencies.len() as u128;
    if latencies.len() == 1 {
        return (avg, 0.0);
    }
    let mut jitter = 0.0_f32;
    for window in latencies.windows(2) {
        let diff = window[0] as i128 - window[1] as i128;
        jitter += diff.abs() as f32;
    }
    let denom = (latencies.len() - 1) as f32;
    (avg, jitter / denom)
}

fn compute_suspicion(results: &[TransportResult]) -> f32 {
    let mut score: f32 = 0.0;
    for res in results {
        if !res.ok {
            score += 0.5_f32;
            continue;
        }
        if res.latency_ms > 1500 {
            score += 0.2_f32;
        } else if res.latency_ms > 800 {
            score += 0.1_f32;
        }
        if res.jitter_ms > 250.0 {
            score += 0.1_f32;
        } else if res.jitter_ms > 120.0 {
            score += 0.05_f32;
        }
        if let Some(rcode) = res.rcode {
            if rcode != 0 {
                score += 0.2_f32;
            }
        }
    }
    score.clamp(0.0_f32, 1.0_f32)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if args.doh_url.is_none() && args.doq_addr.is_none() && args.odoh_url.is_none() {
        bail!("Specify at least one transport to probe");
    }
    let query = build_query(&args.name)?;
    let timeout = Duration::from_secs(args.timeout_secs);
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .danger_accept_invalid_certs(args.insecure_tls)
        .timeout(timeout)
        .build()
        .context("building reqwest client")?;
    let samples = args.samples.max(1);

    let mut results = Vec::new();

    if let Some(url) = args.doh_url.as_deref() {
        match check_doh(&client, url, &query, samples).await {
            Ok(res) => results.push(res),
            Err(err) => results.push(TransportResult::error("doh", &err)),
        }
    }

    if let Some(addr) = args.doq_addr.as_deref() {
        let server_name = args.server_name.as_deref().unwrap_or("localhost");
        match check_doq(
            addr,
            server_name,
            &query,
            args.insecure_tls,
            timeout,
            samples,
        )
        .await
        {
            Ok(res) => results.push(res),
            Err(err) => results.push(TransportResult::error("doq", &err)),
        }
    }

    if let Some(url) = args.odoh_url.as_deref() {
        let cfg_url = derive_config_url(url, args.odoh_config_url.as_deref())?;
        match check_odoh(&client, &query, url, &cfg_url, samples).await {
            Ok(res) => results.push(res),
            Err(err) => results.push(TransportResult::error("odoh", &err)),
        }
    }

    let target_label = args
        .server_name
        .clone()
        .or_else(|| args.doh_url.clone())
        .unwrap_or_else(|| args.name.clone());
    let suspicion = compute_suspicion(&results);
    let generated_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let report = HealthReport {
        target: target_label,
        query: args.name.clone(),
        results,
        suspicion,
        generated_at,
    };
    let json = serde_json::to_string(&report)?;
    println!("HEALTH_REPORT {}", json);
    if report.results.iter().any(|r| !r.ok) {
        bail!("health probes failed");
    }

    println!("[ok] health probes finished");
    Ok(())
}

async fn check_doh(
    client: &reqwest::Client,
    url: &str,
    payload: &[u8],
    samples: usize,
) -> Result<TransportResult> {
    println!("[doh] -> {}", url);
    let mut latencies = Vec::with_capacity(samples);
    let mut total_out = 0usize;
    let mut total_in = 0usize;
    let mut last_status = None;
    let mut last_rcode = None;
    for _ in 0..samples {
        let start = Instant::now();
        let resp = client
            .post(url)
            .header("content-type", "application/dns-message")
            .body(payload.to_vec())
            .send()
            .await
            .with_context(|| format!("DoH request to {url}"))?;
        let status = resp.status();
        let body = resp.bytes().await?;
        let rcode = verify_dns(body.as_ref())?;
        let latency = start.elapsed().as_millis();
        println!("[doh] <- {} bytes status {}", body.len(), status);
        latencies.push(latency);
        total_out += payload.len();
        total_in += body.len();
        last_status = Some(status.as_u16());
        last_rcode = Some(rcode);
    }
    let (avg_latency, jitter) = latency_stats(&latencies);
    let denom = samples.max(1);
    let mut result = TransportResult::success(
        "doh",
        avg_latency,
        jitter,
        total_out / denom,
        total_in / denom,
        denom,
    );
    result.status_code = last_status;
    result.rcode = last_rcode;
    Ok(result)
}

async fn check_odoh(
    client: &reqwest::Client,
    payload: &[u8],
    odoh_url: &str,
    config_url: &str,
    samples: usize,
) -> Result<TransportResult> {
    println!("[odoh] configs {}", config_url);
    let configs_bytes = client
        .get(config_url)
        .header("accept", ODOH_HTTP_HEADER)
        .send()
        .await
        .with_context(|| format!("fetching {config_url}"))?
        .bytes()
        .await?;
    let mut cfg_buf = Bytes::from(configs_bytes);
    let configs: ObliviousDoHConfigs = parse(&mut cfg_buf).context("parsing ODoH configs")?;
    let config = configs
        .supported()
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no supported ODoH configs"))?;
    let config_contents = config.into();
    let mut latencies = Vec::with_capacity(samples);
    let mut total_out = 0usize;
    let mut total_in = 0usize;
    let mut last_rcode = None;
    for _ in 0..samples {
        let mut rng = StdRng::from_os_rng();
        let query_plain = ObliviousDoHMessagePlaintext::new(payload, 0);
        let (encrypted_query, client_secret) =
            encrypt_query(&query_plain, &config_contents, &mut rng)?;
        let serialized = compose(&encrypted_query)?.freeze();
        println!("[odoh] -> {}", odoh_url);
        let start = Instant::now();
        let resp = client
            .post(odoh_url)
            .header("content-type", ODOH_HTTP_HEADER)
            .body(serialized.clone())
            .send()
            .await?
            .bytes()
            .await?;
        let mut resp_buf = resp.clone();
        let message: ObliviousDoHMessage = parse(&mut resp_buf).context("parsing ODoH response")?;
        let decrypted = decrypt_response(&query_plain, &message, client_secret)?;
        let answer = decrypted.into_msg();
        let rcode = verify_dns(answer.as_ref())?;
        let latency = start.elapsed().as_millis();
        println!("[odoh] <- {} bytes", resp.len());
        latencies.push(latency);
        total_out += serialized.len();
        total_in += resp.len();
        last_rcode = Some(rcode);
    }
    let (avg_latency, jitter) = latency_stats(&latencies);
    let denom = samples.max(1);
    let mut result = TransportResult::success(
        "odoh",
        avg_latency,
        jitter,
        total_out / denom,
        total_in / denom,
        denom,
    );
    result.rcode = last_rcode;
    Ok(result)
}

async fn check_doq(
    addr: &str,
    server_name: &str,
    payload: &[u8],
    insecure: bool,
    timeout_dur: Duration,
    samples: usize,
) -> Result<TransportResult> {
    println!("[doq] -> {}", addr);
    let server_addr: SocketAddr = addr.parse().context("parsing DoQ addr")?;
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;
    endpoint.set_default_client_config(client_config(insecure)?);
    let mut latencies = Vec::with_capacity(samples);
    let mut total_out = 0usize;
    let mut total_in = 0usize;
    let mut last_rcode = None;
    for _ in 0..samples {
        let connecting = endpoint
            .connect(server_addr, server_name)
            .context("connect DoQ init")?;
        let start = Instant::now();
        let connection = timeout(timeout_dur, connecting).await??;
        let (mut send, mut recv) = connection.open_bi().await?;
        write_frame(&mut send, payload).await?;
        send.finish()?;
        let response = read_frame(&mut recv).await?;
        let rcode = verify_dns(&response)?;
        let latency = start.elapsed().as_millis();
        println!("[doq] <- {} bytes", response.len());
        latencies.push(latency);
        total_out += payload.len();
        total_in += response.len();
        last_rcode = Some(rcode);
    }
    let (avg_latency, jitter) = latency_stats(&latencies);
    let denom = samples.max(1);
    let mut result = TransportResult::success(
        "doq",
        avg_latency,
        jitter,
        total_out / denom,
        total_in / denom,
        denom,
    );
    result.rcode = last_rcode;
    Ok(result)
}

fn build_query(name: &str) -> Result<Vec<u8>> {
    if name.is_empty() {
        bail!("query name is empty");
    }
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&0x1234u16.to_be_bytes());
    buf.extend_from_slice(&0x0100u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    for label in name.split('.') {
        if label.len() > 63 {
            bail!("label too long: {label}");
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    Ok(buf)
}

fn verify_dns(resp: &[u8]) -> Result<u8> {
    if resp.len() < 12 {
        bail!("DNS payload too short ({} bytes)", resp.len());
    }
    let rcode = resp[3] & 0x0F;
    if rcode != 0 {
        bail!("DNS response returned rcode {rcode}");
    }
    Ok(rcode)
}

fn derive_config_url(odoh_url: &str, override_url: Option<&str>) -> Result<String> {
    if let Some(explicit) = override_url {
        return Ok(explicit.to_string());
    }
    let mut url = Url::parse(odoh_url)?;
    url.set_path("/.well-known/odohconfigs");
    url.set_query(None);
    Ok(url.to_string())
}

async fn write_frame(stream: &mut quinn::SendStream, payload: &[u8]) -> Result<()> {
    if payload.len() > u16::MAX as usize {
        bail!("payload too large");
    }
    let len = (payload.len() as u16).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(payload).await?;
    Ok(())
}

async fn read_frame(stream: &mut quinn::RecvStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

fn client_config(insecure: bool) -> Result<ClientConfig> {
    let builder = RustlsClientConfig::builder();
    let crypto = if insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        for cert in load_native_certs().context("loading native certs")? {
            let _ = roots.add(cert);
        }
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    let mut crypto = Arc::new(crypto);
    if let Some(cfg) = Arc::get_mut(&mut crypto) {
        cfg.alpn_protocols = vec![b"doq".to_vec()];
    }
    let tls_config = QuicClientConfig::try_from(crypto).context("building QUIC TLS config")?;
    Ok(ClientConfig::new(Arc::new(tls_config)))
}

#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        use SignatureScheme::*;
        vec![
            RSA_PSS_SHA512,
            RSA_PSS_SHA384,
            RSA_PSS_SHA256,
            RSA_PKCS1_SHA512,
            RSA_PKCS1_SHA384,
            RSA_PKCS1_SHA256,
            ECDSA_NISTP521_SHA512,
            ECDSA_NISTP384_SHA384,
            ECDSA_NISTP256_SHA256,
            ED25519,
        ]
    }
}
